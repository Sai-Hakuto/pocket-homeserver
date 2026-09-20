#!/usr/bin/env bash
#
# apps/kavita.sh — install + supervise Kavita (the self-hosted manga / comic /
# ebook server) as an OPTIONAL app behind the loopback Caddy edge, on
# books.${DOMAIN}.
#
# What it does (idempotent — review before running):
#   1. downloads the pinned kavita-linux-arm64 release tarball (exact version +
#      sha256, fail-closed supply-chain check) into ${DATA_DIR}/binaries,
#   2. extracts the self-contained .NET build into the userland at /opt/Kavita
#      (the tarball ships a top-level Kavita/ dir → /opt/Kavita/Kavita + wwwroot/),
#      and installs system ICU (libicu72) which the self-contained build needs,
#   3. PRE-SEEDS a hardened 0600 config/appsettings.json BEFORE first start
#      (IpAddresses=127.0.0.1, Port=9124, BaseUrl="/", a strong off-argv TokenKey)
#      because Kavita's first run otherwise auto-generates one bound to "0.0.0.0,::"
#      — a LAN-exposure window — and ASSERTS the loopback bind fail-closed,
#   4. keeps ALL state (kavita.db + -wal/-shm, covers, cache, thumbnails, logs,
#      bookmarks, backups AND appsettings.json) on ext4 ($HOME/.pocket/kavita,
#      bind-mounted to /opt/Kavita/config) — NEVER on the exFAT SD card,
#   5. bind-mounts the user's read-only BULK library (KAVITA_LIBRARY_DIR, default
#      ${DATA_DIR}/books — exFAT is fine for read-mostly media) into the userland,
#   6. writes a self-contained Caddy vhost + validates fail-closed (no Caddy restart),
#   7. supervises the single binary on loopback via the shared lib.
#
# ┌── STORAGE TIER — READ THIS ─────────────────────────────────────────────────
# │ Kavita keeps its SQLite DB (kavita.db + -wal/-shm), cover-image cache,
# │ thumbnails, logs, temp and appsettings.json under <cwd>/config (verified
# │ against Kavita.Services/DirectoryService.cs @ v0.9.0.2). SQLite WAL needs real
# │ fsync + atomic rename + POSIX locks, which the exFAT SD card does NOT provide,
# │ so the config dir MUST live on ext4 ($HOME/.pocket/kavita). This script REFUSES
# │ to put it under DATA_DIR (exFAT) fail-closed. Only the read-only BULK library
# │ (your books/comics) may sit on the SD card.
# └─────────────────────────────────────────────────────────────────────────────
#
# ┌── NETWORK TIER — READ THIS ─────────────────────────────────────────────────
# │ Kavita DEFAULTS to binding "0.0.0.0,::" (Kavita.Common/Configuration.cs
# │ DefaultIpAddresses). In proot, which shares the phone's network namespace,
# │ that = exposed on the phone's real Wi-Fi/cellular interfaces. We force loopback
# │ by setting IpAddresses=127.0.0.1 in a PRE-SEEDED appsettings.json and assert it
# │ fail-closed. Kestrel's bind logic (Kavita.Server/Program.cs): it ListenAnyIP()s
# │ if IpAddresses is empty OR equals the default OR OsInfo.IsDocker is true —
# │ otherwise it Listen()s only the parsed addresses. THEREFORE we must NEVER set
# │ DOTNET_RUNNING_IN_CONTAINER (it flips OsInfo.IsDocker, which IGNORES IpAddresses
# │ and binds all interfaces). This is the verified past-outage class.
# └─────────────────────────────────────────────────────────────────────────────
#
# AUTH MODEL: by DEFAULT Kavita is gated at the Cloudflare edge (Cloudflare Access,
# configured by you in the dashboard — NOT here) and Kavita keeps its OWN native
# login. The catch-all (the Angular SPA + its XHR /api calls, which ride the CF
# Access cookie once you log in) is what the optional Matrix-SSO forward_auth gate
# would cover. BUT OPDS clients (Panels, Tachiyomi, Chunky, …) hit /api/opds/* with
# an api-key-IN-THE-URL and CANNOT follow a 302-to-login, so /api/opds/* is reverse-
# proxied DIRECTLY (BEFORE the gateable catch-all) and must be exempted in CF Access
# too (use a path bypass or an Access service token). The api-key in the OPDS URL is
# Kavita's own auth for those paths. See docs/APP_AUTH.md + the closing notes.
#
# Generalized from the memos + vaultwarden app patterns; review before running.

set -euo pipefail
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"

load_env
require_var DOMAIN   "your apex domain (DNS on Cloudflare)"
require_var DATA_DIR "folder on your large volume / SD card"
require_cmd proot-distro
require_cmd curl

# NOTE: enabling/disabling is handled by install.sh (it only runs this when
# ENABLE_KAVITA=true), so this script does not re-check the flag.

in_debian() { proot-distro login debian -- bash -lc "$1"; }

# ── Pinned release ───────────────────────────────────────────────────────────
# Pin an EXACT Kavita version + sha256 (the bare hex sha256sum output of the
# arm64 release tarball) rather than tracking "latest", so the download fails
# closed on any corruption/tampering. Both are env-overridable (and centrally
# pinned in config/versions.env) without editing this file.
#
# To upgrade: bump KAVITA_VER and KAVITA_SHA256 *together* (hash the new tarball:
#   sha256sum kavita-linux-arm64.tar.gz
# ), then re-run. Kavita's data (DB + covers + settings) persists across upgrades
# because it lives on ext4 at $HOME/.pocket/kavita.
KAVITA_VER="${KAVITA_VER:-0.9.0.2}"
KAVITA_SHA256="${KAVITA_SHA256:-8c80a35765d35b82018938084050f8057318bbbf840e0b3d80d2a72dc5ba136e}"
KAVITA_TARBALL="kavita-linux-arm64.tar.gz"
KAVITA_URL="${KAVITA_URL:-https://github.com/Kareadita/Kavita/releases/download/v${KAVITA_VER}/${KAVITA_TARBALL}}"

# ── Service coordinates ──────────────────────────────────────────────────────
KAVITA_PORT="${KAVITA_PORT:-9124}"        # loopback bind; only Caddy reaches it
KAVITA_HOST="books.${DOMAIN}"             # public hostname (via the CF Tunnel)
INSTALL_PARENT=/opt                        # in userland — tarball extracts Kavita/ here
INSTALL_DIR=/opt/Kavita                    # in userland — top-level dir from the tarball
BIN="${INSTALL_DIR}/Kavita"                # in userland — /opt/Kavita/Kavita (capital K)
# Kavita reads config/appsettings.json RELATIVE to its working directory and writes
# kavita.db + covers + cache + logs under <cwd>/config, so the working dir is the
# install dir and the config dir is /opt/Kavita/config (the ext4 bind target).
CONFIG_MOUNT="${INSTALL_DIR}/config"       # in userland — bind target (DB/settings/cache)
APPSETTINGS="${CONFIG_MOUNT}/appsettings.json"

# ── Storage tiers ────────────────────────────────────────────────────────────
# ALL state (kavita.db + -wal/-shm, covers, cache, thumbnails, logs, bookmarks,
# backups, appsettings.json) on ext4 (NOT exFAT). SQLite WAL needs real fsync +
# atomic rename + unix locks.
DATA_BACKING="${HOME}/.pocket/kavita"      # on ext4 (host) — survives a rootfs rebuild
# Read-only BULK media library: exFAT SD is fine for read-mostly media. The user
# points Kavita at this mount during first-run library setup.
KAVITA_LIBRARY_DIR="${KAVITA_LIBRARY_DIR:-${DATA_DIR}/books}"
LIBRARY_MOUNT=/library                      # in userland — read-only bind target
CACHE_DIR="${DATA_DIR}/binaries"
KAVITA_LOCAL="${CACHE_DIR}/${KAVITA_TARBALL}"

# ── Data dir on ext4 — refuse DATA_DIR (exFAT) fail-closed ───────────────────
assert_ext4 "${DATA_BACKING}" "Kavita config dir"
mkdir -p "${DATA_BACKING}" "${CACHE_DIR}" || die "cannot create ${DATA_BACKING} on ext4"
chmod 700 "${DATA_BACKING}" 2>/dev/null || true

# Create the read-only bulk library dir if it does not exist yet (so first-run
# library setup has a target). A user-supplied path on the SD card is expected.
mkdir -p "${KAVITA_LIBRARY_DIR}" 2>/dev/null || warn "could not create ${KAVITA_LIBRARY_DIR} — create it yourself, then point Kavita at ${LIBRARY_MOUNT}"

# ── Preflight: the userland must exist ───────────────────────────────────────
in_debian 'true' >/dev/null 2>&1 || die "proot-distro debian not reachable — install the userland first (run scripts/install.sh)"

# ── 1. Download the release tarball, sha256-verified fail-closed ─────────────
# fetch_verified (from common.sh) reuses a cached copy that already matches the
# pin, and deletes + aborts on any mismatch.
fetch_verified "${KAVITA_URL}" "${KAVITA_LOCAL}" "${KAVITA_SHA256}"
ok "Kavita v${KAVITA_VER} tarball ready at ${KAVITA_LOCAL} ($(wc -c < "${KAVITA_LOCAL}") bytes)"

# ── 2. Extract into the userland (/opt → /opt/Kavita) + verify it is present ──
# proot-distro manages the rootfs path, so go through `proot-distro login` and
# stream the tarball in over stdin (no hardcoded rootfs location). The tarball
# carries a top-level Kavita/ dir, so extracting into /opt yields /opt/Kavita.
say "extracting Kavita into the userland (${INSTALL_DIR})"
in_debian "mkdir -p ${INSTALL_PARENT}"
proot-distro login debian -- bash -lc "tar -xzf - -C ${INSTALL_PARENT} && chmod +x ${BIN}" \
  < "${KAVITA_LOCAL}" || die "failed to extract Kavita into the userland"
in_debian "[ -x ${BIN} ]" || die "Kavita binary missing after extract at ${BIN}"
ok "Kavita extracted to ${INSTALL_DIR} (binary ${BIN})"

# ── 3. Runtime dependency: system ICU (libicu72) ─────────────────────────────
# Kavita ships a self-contained .NET build that still needs the system ICU
# libraries to start (globalization); without libicu72 the process exits at boot.
# POCKET_ICU_FIX: do NOT hardcode the ICU package name. Debian renames it every
# release (bookworm: libicu72, trixie: libicu76), and proot-distro installs
# whatever is current, so the hardcoded name breaks on a fresh userland.
say "ensuring system ICU is installed in the userland (the self-contained .NET build needs it)"
in_debian 'dpkg -l 2>/dev/null | grep -qE "^ii +libicu[0-9]+" && exit 0; export DEBIAN_FRONTEND=noninteractive; apt-get update -qq; p=$(apt-cache search --names-only "^libicu[0-9]+$" | cut -d" " -f1 | sort -V | tail -1); [ -n "$p" ] || { echo "no libicuN package in this Debian release"; exit 1; }; echo "installing $p"; apt-get install -y --no-install-recommends "$p"' \
  || die "failed to install system ICU in the userland — Kavita will not start without it"
ok "system ICU present in the userland"

# ── 4. Config dir bind target + read-only library mountpoint in the userland ─
in_debian "mkdir -p '${CONFIG_MOUNT}' '${LIBRARY_MOUNT}'" \
  || die "failed to create the ${CONFIG_MOUNT} / ${LIBRARY_MOUNT} mountpoints in the userland"

# ── 5. PRE-SEED a hardened 0600 appsettings.json (loopback bind, strong key) ──
# ┌── SECURITY-LOAD-BEARING ───────────────────────────────────────────────────
# │ We write appsettings.json BEFORE the first start so Kavita never auto-generates
# │ one bound to "0.0.0.0,::" (its DefaultIpAddresses). IpAddresses=127.0.0.1 (≠ the
# │ default, ≠ empty) makes Kestrel Listen() on loopback ONLY (verified against
# │ Kavita.Server/Program.cs). The TokenKey is the JWT session-signing key: Kavita
# │ auto-generates a base64(256-byte) key only while TokenKey still starts with the
# │ literal "super secret unguessable key" — so a strong custom key both disables
# │ that rewrite AND avoids the brief generate-on-first-run window. We generate it
# │ OFF-ARGV inside the userland with umask 077 (openssl rand -base64 64 = 512 bits,
# │ well above the 256-bit floor) so the secret never lands on a command line, in a
# │ process list, or in the host shell. The file is written 0600. Keys verified
# │ exact against Kavita.Server/config/appsettings.json @ v0.9.0.2: TokenKey, Port,
# │ IpAddresses, BaseUrl, Cache.
# │
# │ Idempotent: if a hardened appsettings.json with the loopback bind already
# │ exists (a prior run / your edits), we KEEP it — never clobber a key you rotated
# │ or settings Kavita rewrote — and only re-assert the bind below.
# └────────────────────────────────────────────────────────────────────────────
if in_debian "[ -f '${APPSETTINGS}' ]" \
   && in_debian "grep -Eq '\"IpAddresses\"[[:space:]]*:[[:space:]]*\"127\.0\.0\.1\"' '${APPSETTINGS}'"; then
  ok "existing hardened appsettings.json found (loopback bind) — keeping it"
else
  say "pre-seeding the hardened ${APPSETTINGS} (chmod 600; loopback bind; off-argv TokenKey)"
  # The TokenKey is generated INSIDE the userland and written straight to the file
  # under umask 077 — it is never expanded by the host shell and never on argv.
  proot-distro login debian -- bash -lc '
    set -e
    f="$1"
    port="$2"
    umask 077
    command -v openssl >/dev/null 2>&1 || { export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y --no-install-recommends openssl >/dev/null; }
    # 512-bit random key (>= the 256-bit floor); strip "/" so it stays one JSON-safe
    # token, matching how Kavita itself sanitizes its auto-generated key.
    tk="$(openssl rand -base64 64 | tr -d "\n" | tr -d "/")"
    cat > "$f" <<JSON
{
  "TokenKey": "${tk}",
  "Port": ${port},
  "IpAddresses": "127.0.0.1",
  "BaseUrl": "/",
  "Cache": 75
}
JSON
    chmod 600 "$f"
  ' _seed "${APPSETTINGS}" "${KAVITA_PORT}" \
    || die "failed to pre-seed ${APPSETTINGS} in the userland"
  ok "wrote ${APPSETTINGS} (chmod 600, IpAddresses=127.0.0.1, Port=${KAVITA_PORT}, strong TokenKey)"
fi

# ── 6. FAIL-CLOSED loopback assert ───────────────────────────────────────────
# Refuse to start a LAN-exposed reader: require the loopback bind AND reject the
# 0.0.0.0 / :: defaults outright. proot shares the phone's network namespace, so
# 0.0.0.0 here = reachable on the phone's real interfaces.
say "asserting the Kavita bind is loopback (guards against the 0.0.0.0,:: default)"
in_debian "grep -Eq '\"IpAddresses\"[[:space:]]*:[[:space:]]*\"127\.0\.0\.1\"' '${APPSETTINGS}'" \
  || die "IpAddresses is NOT 127.0.0.1 — refusing to start a LAN-exposed Kavita (check ${APPSETTINGS})"
in_debian "grep -Eq '\"IpAddresses\"[[:space:]]*:[[:space:]]*\"(0\.0\.0\.0|::|)\"' '${APPSETTINGS}'" \
  && die "Kavita appsettings.json binds 0.0.0.0/::/empty — refusing to start (check ${APPSETTINGS})" || true
ok "Kavita bind confirmed loopback (127.0.0.1)"

# ── POCKET_KAVITA_BIND_FIX ───────────────────────────────────────────────────
# The seed above lives INSIDE the userland at ${CONFIG_MOUNT}. At run time
# start-stack.sh bind-mounts ${DATA_BACKING} OVER that directory, which hides the
# file — Kavita then reports "Could not find file '.../appsettings.json'" and
# falls back to 0.0.0.0/::,port 5000. Mirror it to the host dir that actually
# becomes the config dir, so the hardened settings survive the bind.
if [ ! -f "${DATA_BACKING}/appsettings.json" ]; then
  say "mirroring appsettings.json to the bind source (${DATA_BACKING})"
  mkdir -p "${DATA_BACKING}"
  in_debian "cat '${APPSETTINGS}'" > "${DATA_BACKING}/appsettings.json" \
    || die "failed to mirror appsettings.json to ${DATA_BACKING}"
  chmod 600 "${DATA_BACKING}/appsettings.json"
  ok "appsettings.json mirrored to ${DATA_BACKING} (chmod 600)"
else
  ok "appsettings.json already present in ${DATA_BACKING} — keeping it"
fi
grep -Eq '"IpAddresses"[[:space:]]*:[[:space:]]*"127\.0\.0\.1"' "${DATA_BACKING}/appsettings.json" \
  || die "the appsettings.json Kavita will actually read (${DATA_BACKING}) is NOT loopback-bound"
ok "bind-source appsettings.json confirmed loopback"

# In-userland launcher: cd into the install dir (Kavita reads config/appsettings.json
# RELATIVE to its working directory), then exec the binary. We deliberately do NOT
# export DOTNET_RUNNING_IN_CONTAINER — setting it flips OsInfo.IsDocker, which makes
# Kestrel ignore IpAddresses and ListenAnyIP() (LAN-exposed). No secrets on argv.
proot-distro login debian -- bash -lc "umask 077; cat > '${INSTALL_DIR}/run.sh'" <<LAUNCH
#!/bin/bash
# Runs INSIDE the Debian userland; started + kept alive by apps/kavita.sh.
# DO NOT set DOTNET_RUNNING_IN_CONTAINER — it would force a 0.0.0.0 bind.
cd '${INSTALL_DIR}' || exit 1
exec ./Kavita
LAUNCH
in_debian "chmod +x '${INSTALL_DIR}/run.sh'" || die "failed to make ${INSTALL_DIR}/run.sh executable"

# ── 7. Caddy vhost → /etc/caddy/apps/kavita.caddy (validate fail-closed) ─────
# A self-contained site block so enabling Kavita never requires hand-editing the
# core Caddyfile (it imports /etc/caddy/apps/*.caddy). The listener style MUST
# match the other vhosts: explicit `http://<host>:${CADDY_PORT}` + `bind
# ${CADDY_BIND}` (plain HTTP on the shared high loopback port; the Cloudflare
# Tunnel terminates public TLS).
#
# OPDS EXEMPTION: /api/opds/* is reverse-proxied DIRECTLY in a handle block that
# PRECEDES the gateable catch-all, because OPDS readers carry an api-key in the URL
# and cannot follow a 302-to-login. The api-key is Kavita's own auth for those
# paths. The Angular SPA + its XHR /api/* calls ride the CF Access cookie once you
# have logged in, so they stay under the catch-all (and under the optional gate).
#
# This heredoc is UNQUOTED so the shell expands ${DOMAIN}, ${CADDY_BIND},
# ${CADDY_PORT}, and ${KAVITA_PORT}.
say "writing the Kavita vhost to /etc/caddy/apps/kavita.caddy in the userland"
in_debian "mkdir -p /etc/caddy/apps"
if ! proot-distro login debian -- bash -lc 'cat > /etc/caddy/apps/kavita.caddy' <<EOF
# books.${DOMAIN} — Kavita (manga / comic / ebook server).
# Written by scripts/apps/kavita.sh. Loopback-only; the Cloudflare Tunnel forwards
# public traffic here and (by default) Cloudflare Access gates the hostname at the
# edge — see docs/APP_AUTH.md. OPDS (/api/opds/*) is EXEMPT: those clients send an
# api-key in the URL and cannot do an interactive login.
http://books.${DOMAIN}:${CADDY_PORT} {
	bind ${CADDY_BIND}

	header {
		Strict-Transport-Security "max-age=31536000; includeSubDomains"
		X-Content-Type-Options nosniff
		X-Frame-Options SAMEORIGIN
		Referrer-Policy no-referrer
		-Server
	}

	# OPDS API — EXEMPT from the interactive gate. OPDS readers (Panels, Tachiyomi,
	# Chunky, …) hit /api/opds/<apiKey>/... with the api-key IN THE URL and CANNOT
	# follow a 302-to-login, so this handle PRECEDES the catch-all and reverse-proxies
	# OPDS straight to the backend. The api-key is Kavita's own auth here. If you also
	# enable the optional Matrix-SSO gateway below, this block keeps OPDS working; in
	# Cloudflare Access you must add a matching path bypass for /api/opds/* (or use an
	# Access service token) so the edge does not 302 these requests either.
	handle /api/opds/* {
		reverse_proxy 127.0.0.1:${KAVITA_PORT}
	}

	# OPTIONAL Matrix-SSO gateway add-on (advanced; see docs/APP_AUTH.md).
	# By default this stays COMMENTED OUT: the hostname is gated by Cloudflare Access
	# at the edge and Kavita keeps its own native login. To front the browser UI with
	# the Matrix-SSO gateway instead, run that add-on and uncomment the three parts
	# INSIDE the catch-all `handle` below. They live inside this handle block (NOT at
	# site level) so Caddy's directive ordering cannot hoist forward_auth ahead of the
	# OPDS `handle /api/opds/*` above — OPDS stays exempt regardless of ordering. The
	# /authgw/* handler keeps the login form reachable (else the 302-to-login loops),
	# request_header strips any client-forged Remote-User before the gate, and
	# forward_auth gates everything else (the SPA + its XHR /api calls ride the cookie):
	handle {
		# handle /authgw/* {
		# 	reverse_proxy 127.0.0.1:9095 {
		# 		header_up X-Real-IP {client_ip}
		# 	}
		# }
		# request_header -Remote-User
		# forward_auth 127.0.0.1:9095 {
		# 	uri /authgw/verify
		# 	copy_headers Remote-User
		# }

		# Everything else (the Angular SPA + its XHR /api/* calls + WebSocket) → backend.
		# Caddy auto-upgrades the SignalR WebSocket; no separate rule needed.
		reverse_proxy 127.0.0.1:${KAVITA_PORT}
	}
}
EOF
then
  die "failed to write /etc/caddy/apps/kavita.caddy into the userland"
fi

# Validate the WHOLE Caddyfile (which imports our new app block) fail-closed, so
# we never leave a broken edge config in place.
say "validating the Caddyfile inside the userland"
in_debian 'caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile' \
  || die "caddy validate FAILED — refusing to leave a broken vhost in /etc/caddy/apps/kavita.caddy"
ok "Kavita vhost written + Caddyfile validates"

# NOTE: we do NOT restart Caddy here. During a full install the stack is started
# afterward (scripts/start-stack.sh). If the stack is ALREADY running, the new
# vhost is not live until Caddy reloads — see the closing notes.

# ── 8. Supervise Kavita on loopback ──────────────────────────────────────────
# The config dir is the ext4 bind so kavita.db + WAL + covers + cache land on a
# real filesystem; the bulk library is bound READ-ONLY from the SD card. The
# launcher cds into ${INSTALL_DIR} so config/appsettings.json resolves. The lib's
# supervisor respawns it on crash with an identity-checked pidfile.
say "supervising Kavita (.NET build in the userland, bind 127.0.0.1:${KAVITA_PORT})"
supervise kavita -- \
  proot-distro login debian \
  --bind "${DATA_BACKING}:${CONFIG_MOUNT}" \
  --bind "${KAVITA_LIBRARY_DIR}:${LIBRARY_MOUNT}" \
  -- bash "${INSTALL_DIR}/run.sh"

# ── 8b. FAIL-CLOSED post-start loopback backstop (ss wildcard check) ─────────
# Kavita defaults to "0.0.0.0,::"; the appsettings.json IpAddresses assert above
# is backed by an empirical socket audit — refuse to leave a wildcard listener for
# :${KAVITA_PORT} running. See assert_loopback_listener in lib/common.sh.
assert_loopback_listener kavita "${KAVITA_PORT}"

# ── 9. Best-effort health check ──────────────────────────────────────────────
# /api/health is an unauthenticated ([AllowAnonymous]) liveness endpoint that
# returns 200 "Ok" (Kavita.Server/Controllers/HealthController.cs). The .NET cold
# start under proot can take a while, so poll generously. A non-200 here is a
# WARNING (the supervisor keeps retrying), not fatal.
say "waiting for Kavita to answer on 127.0.0.1:${KAVITA_PORT}/api/health"
healthy=0
for _ in $(seq 1 60); do
  if curl -fsS -m 3 -o /dev/null "http://127.0.0.1:${KAVITA_PORT}/api/health" 2>/dev/null; then
    healthy=1; break
  fi
  sleep 2
done
if [ "${healthy}" -eq 1 ]; then
  ok "Kavita healthy on 127.0.0.1:${KAVITA_PORT}"
else
  warn "Kavita not yet answering on :${KAVITA_PORT} — check ${POCKET_LOG_DIR}/kavita.log (the .NET cold start is slow; the supervisor keeps retrying)"
fi

# ── 10. Closing notes (manual Cloudflare + first-run + hardening) ────────────
cat >&2 <<EOF

$(ok "Kavita installed + supervised on 127.0.0.1:${KAVITA_PORT} (config on ${DATA_BACKING}; library bound read-only from ${KAVITA_LIBRARY_DIR})" 2>&1)

  FIRST RUN: open ${KAVITA_HOST} and create your admin account, then add a Library
  pointing at  ${LIBRARY_MOUNT}  (that is your ${KAVITA_LIBRARY_DIR} bind, read-only
  inside the userland). Put your books/comics/manga there on the SD card.

  PERFORMANCE — direct-play by default (opt-in to the heavy paths): leave library
  scans conservative and do NOT add huge libraries at once on a phone. Kavita does
  NOT transcode (it serves files directly), which is the light path — keep it that
  way. Cover/thumbnail generation + full scans are CPU/IO heavy; trigger big scans
  manually when the phone is on power, not on a schedule.

  Manual steps to finish (in the Cloudflare dashboard — NOT done by this script):
    1. Public hostname: add a Public Hostname in your Cloudflare Tunnel:
         ${KAVITA_HOST}  ->  http://localhost:${CADDY_PORT}   (plain HTTP; the tunnel
       terminates public TLS).
    2. Cloudflare Access: add an Access application/policy covering ${KAVITA_HOST}
       so only people you allow can reach the browser UI. By default this is the
       primary gate in front of Kavita's own login.
    3. OPDS EXEMPTION: OPDS readers (Panels, Tachiyomi, Chunky, …) call
         ${KAVITA_HOST}/api/opds/<your-api-key>/...
       with the api-key in the URL and CANNOT complete an interactive Access login.
       Add a CF Access path BYPASS for  /api/opds/*  on this hostname (or attach an
       Access SERVICE TOKEN for those paths). The vhost already reverse-proxies
       /api/opds/* directly, so it stays reachable through the tunnel; the Cloudflare
       layer is the remaining gate to exempt. The per-user api-key is Kavita's own
       auth for OPDS. See docs/APP_AUTH.md.

  Upgrades: bump KAVITA_VER + KAVITA_SHA256 together (sha256sum the new
  kavita-linux-arm64.tar.gz) and re-run. Your data persists on ${DATA_BACKING}.

  If the stack is ALREADY running, reload Caddy so the new vhost goes live:
         bash ${POCKET_ROOT}/scripts/start-stack.sh --restart
    (a full install starts the stack afterward, so no reload is needed then).

  Optional Matrix-SSO gateway add-on: see the commented forward_auth block in
  /etc/caddy/apps/kavita.caddy and docs/APP_AUTH.md (OPDS stays exempt either way).
EOF

ok "apps/kavita.sh done (books.${DOMAIN} once the Cloudflare hostname + Access policy + OPDS exemption are added)"


#!/usr/bin/env bash
#
# apps/dufs.sh — install + supervise DUFS (a tiny stateless Rust file server:
# browser UI + WebDAV) as an OPTIONAL app behind the loopback Caddy edge.
#
# DUFS is a single static musl binary (no DB, no state) that serves a directory
# over a browser file manager AND WebDAV. We run that one binary INSIDE the
# Debian userland at /opt/dufs and front it with the core Caddy on
# ${CADDY_BIND}:${CADDY_PORT}; the public hostname is files.${DOMAIN}.
#
# What it does (idempotent — safe to re-run):
#   1. downloads + sha256-verifies (fail-closed) the pinned aarch64-musl tarball
#      into ${DATA_DIR}/binaries, then installs the single binary into the
#      userland at /opt/dufs/dufs and verifies it runs,
#   2. generates + persists a per-deployment HTTP Basic credential under
#      ${DATA_DIR}/secrets/dufs.env (chmod 600; reused on re-run); only the
#      $6$ SHA-512 *hash* lands in the config, not the cleartext,
#   3. writes a hardened /opt/dufs/dufs.yaml into the userland (loopback bind,
#      read-only, the served path = the bind-mounted SD content dir, the Basic
#      auth rule), chmod 600, and ASSERTS the loopback bind fail-closed,
#   4. writes a self-contained Caddy vhost to /etc/caddy/apps/dufs.caddy and
#      validates the full Caddyfile fail-closed (it does NOT restart Caddy),
#   5. supervises the binary via the shared lib (respawn + identity-checked pid),
#      with the large-volume content dir bind-mounted in.
#
# AUTH MODEL — read this, it has a sharp edge:
#   By default files.${DOMAIN} is gated at the Cloudflare edge with Cloudflare
#   Access (a policy you add in the Cloudflare dashboard — NOT configured by this
#   script), AND dufs itself requires HTTP Basic login (the per-deploy credential
#   in dufs.env). Two gates, two very different client stories:
#     - BROWSER UI: a browser hits the Cloudflare Access 302 login, completes it,
#       then sees the dufs Basic-auth prompt. Both gates work fine.
#     - WebDAV CLIENTS (rclone, davfs2, Finder/Explorer "map drive"): a WebDAV
#       client CANNOT follow the Cloudflare Access 302-to-login redirect — it just
#       sees an HTML login page where it expected WebDAV, and fails. To use
#       WebDAV you MUST, operator-side in the Cloudflare dashboard, add a
#       SERVICE-TOKEN exemption (a Service Auth policy) for files.${DOMAIN} and
#       use a header-capable client (rclone with CF-Access-Client-Id /
#       CF-Access-Client-Secret headers). The optional Matrix-SSO gateway has NO
#       service-token path at all, so it CANNOT front WebDAV — leave dufs on
#       Cloudflare Access if you want WebDAV. See docs/FILES.md + docs/APP_AUTH.md.
#
# UPLOAD CAP: the Cloudflare Tunnel caps a single request body at ~100MB.
#   Downloads are unaffected (any size). If you enable uploads (off by default),
#   anything >100MB must go through chunked WebDAV PATCH or a different tool
#   (e.g. Syncthing). See docs/FILES.md.
#
# STORAGE SPLIT: the SERVED CONTENT lives on the large volume (the exFAT SD) at
# ${DATA_DIR}/dufs, bind-mounted into the userland at serve time. The CONFIG +
# the generated credential live on ext4 in the userland / ${DATA_DIR}/secrets
# (0600) — never on the perms-less exFAT card.
#
# READ-ONLY BY DEFAULT: allow-upload / allow-delete are OFF. A clearly-marked
# spot below shows how to flip uploads on (with the exFAT write hazards spelled
# out).
#
# Idempotent — review before running.

set -euo pipefail
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"

load_env
require_var DOMAIN   "your public domain, e.g. example.com"
require_var DATA_DIR "folder on your large volume / SD card"
require_cmd proot-distro
require_cmd curl
require_cmd openssl                       # SECURITY: needed for the $6$ password hash

# NOTE: enabling/disabling is handled by install.sh (it only runs this script when
# ENABLE_DUFS=true), so this script does not re-check ENABLE_DUFS.

# ── Mutual-exclusion guard ───────────────────────────────────────────────────
# DUFS and FileBrowser both claim files.${DOMAIN} — only one can own the vhost.
if [ "${ENABLE_FILEBROWSER:-false}" = "true" ]; then
  die "ENABLE_DUFS and ENABLE_FILEBROWSER both set — they share files.${DOMAIN}; enable exactly one."
fi

in_debian() { proot-distro login debian -- bash -lc "$1"; }

# ── Pinned release ───────────────────────────────────────────────────────────
# Pin an EXACT dufs version + sha256 (env-overridable) rather than tracking a
# floating release, so a corrupt or tampered download fails closed. To upgrade:
# bump DUFS_VER and DUFS_SHA256 *together* (get the new hash from the release
# checksums, or by hashing a tarball you already trust:
#   sha256sum dufs-v<ver>-aarch64-unknown-linux-musl.tar.gz
# ), then re-run this script. dufs is stateless — there's no data migration; your
# served content on ${DATA_DIR}/dufs is untouched by an upgrade.
#
# The tarball is a static musl aarch64 build; it runs fine on glibc proot-Debian.
DUFS_VER="${DUFS_VER:-0.46.0}"
DUFS_SHA256="${DUFS_SHA256:-1472123ae3aa07e49404d16b20305c2dec90c59883ebda9308717f7205e6511b}"
DUFS_TARBALL="dufs-v${DUFS_VER}-aarch64-unknown-linux-musl.tar.gz"
DUFS_URL="${DUFS_URL:-https://github.com/sigoden/dufs/releases/download/v${DUFS_VER}/${DUFS_TARBALL}}"

# ── Service coordinates ──────────────────────────────────────────────────────
DUFS_PORT=9117                           # loopback bind; only Caddy reaches it
DUFS_HOST="files.${DOMAIN}"              # public hostname (via the CF Tunnel)
INSTALL_DIR=/opt/dufs                     # in userland — the binary + config
BIN="${INSTALL_DIR}/dufs"                # in userland — /opt/dufs/dufs
CONFIG="${INSTALL_DIR}/dufs.yaml"        # in userland (ext4) — chmod 600
DATA_MOUNT=/opt/dufs-data                # in userland — bind-mount target (served content)
DATA_BACKING="${DATA_DIR}/dufs"          # on the large volume (exFAT SD) — bulk content
CACHE_DIR="${DATA_DIR}/binaries"
DUFS_LOCAL="${CACHE_DIR}/${DUFS_TARBALL}"
SECRETS_FILE="${DATA_DIR}/secrets/dufs.env"

mkdir -p "${CACHE_DIR}" "${DATA_DIR}/secrets" "${DATA_BACKING}"

# ── Preflight: the userland must exist ───────────────────────────────────────
in_debian 'true' >/dev/null 2>&1 || die "proot-distro debian not reachable — install the userland first (run scripts/install.sh)"

# ── 1. Download the release tarball, sha256-verified fail-closed ─────────────
# fetch_verified (from common.sh) reuses a cached copy that already matches the
# pin, and deletes + aborts on any mismatch.
fetch_verified "${DUFS_URL}" "${DUFS_LOCAL}" "${DUFS_SHA256}"
ok "dufs v${DUFS_VER} tarball ready at ${DUFS_LOCAL} ($(wc -c < "${DUFS_LOCAL}") bytes)"

# ── 2. Extract the binary into the userland + verify it runs ─────────────────
# proot-distro manages the rootfs path, so go through `proot-distro login` and
# stream the tarball in over stdin (no hardcoded rootfs location). The release
# tarball contains a single `dufs` binary at its top level.
say "extracting dufs into the userland (${BIN})"
in_debian "mkdir -p ${INSTALL_DIR}"
proot-distro login debian -- bash -lc "tar -xzf - -C ${INSTALL_DIR} && chmod +x ${BIN}" \
  < "${DUFS_LOCAL}" || die "failed to extract the dufs binary into the userland"
in_debian "[ -x ${BIN} ]" || die "dufs binary missing after extract at ${BIN}"
ver="$(in_debian "${BIN} --version 2>&1 | head -1" || true)"
[ -n "${ver}" ] && ok "dufs: ${ver}" || die "dufs binary did not run inside the userland"

# ── 3. Served-content dir on the large volume (exFAT SD) ─────────────────────
# dufs serves ONE directory tree. We keep that bulk content on ${DATA_DIR} (the
# big volume) and bind-mount it into the userland at run time (see step 7),
# mirroring how memos/vikunja bind their data. We create both the backing dir on
# the volume AND the in-userland mountpoint.
say "creating the dufs served-content dir on the large volume (${DATA_BACKING})"
mkdir -p "${DATA_BACKING}" || die "cannot create ${DATA_BACKING} on the data volume"
chmod 700 "${DATA_BACKING}" 2>/dev/null || true   # best-effort; exFAT has no unix perms
in_debian "mkdir -p ${DATA_MOUNT}" || die "failed to create the ${DATA_MOUNT} mountpoint in the userland"
ok "dufs content backing dir ready: ${DATA_BACKING} (bind-mounted at ${DATA_MOUNT} at start time)"

# ── 4. Generate + persist the per-deployment Basic-auth credential ───────────
# ┌── SECURITY-LOAD-BEARING ───────────────────────────────────────────────────
# │ dufs has no user DB; access is a list of "user:password@/path:perm" rules in
# │ the config. We generate ONE per-deployment credential (username ${ADMIN_USER},
# │ a random password) and store the $6$ SHA-512 *hash* in dufs.yaml so the
# │ cleartext is never persisted in the served-config file. The cleartext is kept
# │ ONLY in the 0600 ${SECRETS_FILE} so the operator can hand it to a WebDAV
# │ client; reused on re-run so the password is stable across redeploys.
# │
# │ AUTH-METHOD NOTE (verified against dufs v0.46.0 docs): dufs has no flag to
# │ pick Basic vs Digest. A client that sends Basic credentials is authenticated
# │ with Basic; Digest auth "does not function properly with hashed passwords",
# │ so by using a $6$ hash we are effectively Basic-only — which is exactly what
# │ browsers and rclone/davfs send. The human reviewing this should confirm the
# │ exact rule syntax ("user:$6$...@/:ro") against the dufs README for the pinned
# │ version.
# └────────────────────────────────────────────────────────────────────────────
ADMIN_USER="${ADMIN_USER:-admin}"
if [ -f "${SECRETS_FILE}" ]; then
  # shellcheck disable=SC1090
  . "${SECRETS_FILE}"
  say "reusing dufs Basic-auth credential from ${SECRETS_FILE}"
else
  DUFS_USER="${ADMIN_USER}"
  DUFS_PASSWORD="$(openssl rand -base64 18 | tr -d '/+=' | cut -c1-24)"
  # $6$ = SHA-512 crypt. Note: this hash legitimately contains '$' — keep it
  # SINGLE-QUOTED everywhere it is written so the shell never expands it.
  DUFS_PASS_HASH="$(openssl passwd -6 "${DUFS_PASSWORD}")"
  [ -n "${DUFS_PASS_HASH}" ] || die "openssl passwd -6 produced no hash — cannot set up dufs auth"
  umask 077
  # Persist BOTH the cleartext (for WebDAV clients) and the hash (for the config).
  # Heredoc is QUOTED ('SECRETS') so the $6$ hash + password are written verbatim.
  cat > "${SECRETS_FILE}" <<'SECRETS'
# Per-deployment dufs HTTP Basic credential — generated by apps/dufs.sh. PRIVATE.
# DUFS_USER / DUFS_PASSWORD are what you give a browser or a WebDAV client.
# DUFS_PASS_HASH is the $6$ SHA-512 hash that goes into /opt/dufs/dufs.yaml.
# Deleting this file regenerates a new password on the next run.
SECRETS
  {
    printf 'DUFS_USER=%s\n' "${DUFS_USER}"
    # POCKET_DUFS_QUOTE_FIX: single-quote both values. The hash contains
    # literal '$' (it is a $6$ crypt string) and this file is SOURCED, so an
    # unquoted value makes bash expand $6 and die under `set -u`.
    printf "DUFS_PASSWORD='%s'\n" "${DUFS_PASSWORD}"
    printf "DUFS_PASS_HASH='%s'\n" "${DUFS_PASS_HASH}"
  } >> "${SECRETS_FILE}"
  chmod 600 "${SECRETS_FILE}"
  ok "generated dufs Basic-auth credential → ${SECRETS_FILE} (chmod 600, user '${DUFS_USER}')"
fi
DUFS_USER="${DUFS_USER:-${ADMIN_USER}}"
DUFS_PASS_HASH="${DUFS_PASS_HASH:-}"
[ -n "${DUFS_PASS_HASH}" ] || die "dufs password hash is empty — check ${SECRETS_FILE} (delete it to regenerate)"

# ── 5. Hardened dufs.yaml (loopback bind, read-only, Basic auth) ─────────────
# Written into the userland on ext4, chmod 600. The YAML keys are the dufs
# v0.46.0 config keys (serve-path / bind / port / auth / allow-*). The served
# tree is the bind-mounted SD content dir (${DATA_MOUNT}).
#
# This heredoc is UNQUOTED so the shell expands ${DATA_MOUNT}, ${DUFS_PORT},
# ${DUFS_USER}, and ${DUFS_PASS_HASH}. The auth value is wrapped in SINGLE quotes
# inside the YAML so dufs (not the shell — the shell already expanded our vars)
# treats the literal '$6$...' hash correctly.
# POCKET_DUFS_WRITABLE: upstream is read-only by design — ':ro' plus
# allow-upload/allow-delete false — so even the admin credential gets 403 on
# MKCOL/PUT and a mounted network drive looks broken to its owner. Make it a
# flag so the choice survives a reinstall, instead of a hand edit that
# `install.sh --force` silently reverts.
if [ "${DUFS_WRITABLE:-false}" = "true" ]; then
  DUFS_PERM="rw"; DUFS_WRITABLE_YN="true"
  warn "DUFS_WRITABLE=true — ${DUFS_USER} can upload AND DELETE over WebDAV"
else
  DUFS_PERM="ro"; DUFS_WRITABLE_YN="false"
fi
say "writing hardened ${CONFIG}"
# POCKET_DUFS_HEREDOC_FIX: escaped $<digit> inside the heredoc below.
proot-distro login debian -- bash -lc "umask 077; cat > ${CONFIG}" <<EOF
# Generated by apps/dufs.sh — hardened, single-tenant, READ-ONLY file server.
# dufs v${DUFS_VER} config. Bound to loopback only; Caddy fronts the edge.

# The directory tree dufs serves = the SD content dir, bind-mounted here.
serve-path: '${DATA_MOUNT}'

# ┌── SECURITY-LOAD-BEARING: loopback bind ────────────────────────────────────
# │ dufs DEFAULTS TO 0.0.0.0:5000 (DUFS_BIND=0.0.0.0). We FORCE 127.0.0.1 so the
# │ only path in is through Caddy + the Cloudflare Tunnel. Step 6 greps this file
# │ to assert the bind is loopback and aborts otherwise. Do NOT change this.
# └────────────────────────────────────────────────────────────────────────────
bind: 127.0.0.1
port: ${DUFS_PORT}

# ┌── SECURITY-LOAD-BEARING: auth (HTTP Basic, \$6$ SHA-512 hashed) ─────────────
# │ One rule, no anonymous '@/' rule → the WHOLE server requires login. ':ro' =
# │ read-only (no upload/delete via the credential either). The password is the
# │ \$6$ hash from ${SECRETS_FILE}; cleartext is NOT stored here. Because dufs
# │ Digest auth is broken with hashed passwords, clients authenticate with Basic.
# └────────────────────────────────────────────────────────────────────────────
auth:
  - '${DUFS_USER}:${DUFS_PASS_HASH}@/:${DUFS_PERM}'

# READ-ONLY BY DEFAULT — uploads + deletes are OFF.
allow-upload: ${DUFS_WRITABLE_YN}
allow-delete: ${DUFS_WRITABLE_YN}
# Browsing conveniences (read-only; safe to leave on).
allow-search: true
allow-archive: true

# ┌── To ENABLE UPLOADS (off by default — understand the hazards first) ────────
# │ Flip the rule perm to ':rw' AND set allow-upload: true (and allow-delete:
# │ true only if you also want deletes):
# │     auth:
# │       - '${DUFS_USER}:${DUFS_PASS_HASH}@/:rw'
# │     allow-upload: true
# │ exFAT/FUSE write hazards on the SD card (${DATA_BACKING}):
# │   - NO atomic rename-over-existing → no safe "finalize" of a partial upload;
# │     an interrupted upload can leave a truncated/garbage file.
# │   - NO fsync semantics → a power loss can lose recently-written data.
# │   - filenames may NOT contain ':' (and other exFAT-illegal chars) — such
# │     uploads will fail.
# │ Plus the Cloudflare Tunnel caps a single request body at ~100MB: larger
# │ uploads need chunked WebDAV PATCH or a different tool (Syncthing). Downloads
# │ are unaffected. See docs/FILES.md.
# └────────────────────────────────────────────────────────────────────────────

log-format: '\$remote_addr "\$request" \$status \$http_user_agent'
EOF
in_debian "chmod 600 ${CONFIG}" || true
ok "wrote ${CONFIG} (chmod 600)"

# ── 6. FAIL-CLOSED loopback assert ───────────────────────────────────────────
# ┌── SECURITY-LOAD-BEARING ───────────────────────────────────────────────────
# │ Hard guarantee against the 0.0.0.0 default: re-read the rendered config and
# │ confirm the bind line is exactly loopback. If anything other than 127.0.0.1
# │ is bound (or the line is missing), abort rather than expose dufs on the LAN.
# │ (pingvin-style post-render assertion.)
# └────────────────────────────────────────────────────────────────────────────
say "asserting the dufs bind is loopback (guards against the 0.0.0.0 default)"
in_debian "grep -Eq '^[[:space:]]*bind:[[:space:]]*127\.0\.0\.1[[:space:]]*\$' ${CONFIG}" \
  || die "dufs.yaml bind is NOT 127.0.0.1 — refusing to start a LAN-exposed file server (check ${CONFIG})"
in_debian "grep -Eq '^[[:space:]]*bind:[[:space:]]*0\.0\.0\.0' ${CONFIG}" \
  && die "dufs.yaml still binds 0.0.0.0 — refusing to start (check ${CONFIG})" || true
ok "dufs bind confirmed loopback (127.0.0.1)"

# ── 7. Caddy vhost → /etc/caddy/apps/dufs.caddy (validate fail-closed) ───────
# A self-contained site block so enabling dufs never requires hand-editing the
# core Caddyfile (it imports /etc/caddy/apps/*.caddy). The listener style MUST
# match the other vhosts: explicit `http://<host>:${CADDY_PORT}` + `bind
# ${CADDY_BIND}` (plain HTTP on the shared high loopback port; the Cloudflare
# Tunnel terminates public TLS).
#
# Extra for a FILE SERVER: inside reverse_proxy we disable response buffering
# (flush_interval -1) so large file downloads stream straight through, and we set
# generous transport timeouts so a slow large-file transfer is not cut off.
#
# This heredoc is UNQUOTED so the shell expands ${DOMAIN}, ${CADDY_BIND},
# ${CADDY_PORT}, and ${DUFS_PORT}.
say "writing the dufs vhost → /etc/caddy/apps/dufs.caddy"
proot-distro login debian -- bash -lc 'mkdir -p /etc/caddy/apps && cat > /etc/caddy/apps/dufs.caddy' <<EOF
# files.${DOMAIN} — DUFS (file server: browser UI + WebDAV).
# Written by scripts/apps/dufs.sh. Loopback-only; the Cloudflare Tunnel forwards
# public traffic here and (by default) Cloudflare Access gates the hostname at the
# edge. dufs ALSO requires its own HTTP Basic login. WebDAV clients cannot follow
# the Cloudflare Access 302 — give them a CF Access service-token exemption + a
# header-capable client (rclone). See docs/FILES.md + docs/APP_AUTH.md.
http://files.${DOMAIN}:${CADDY_PORT} {
	bind ${CADDY_BIND}

	header {
		Strict-Transport-Security "max-age=31536000; includeSubDomains"
		X-Content-Type-Options nosniff
		X-Frame-Options SAMEORIGIN
		Referrer-Policy no-referrer
		-Server
	}

	# OPTIONAL Matrix-SSO gateway add-on (advanced; see docs/APP_AUTH.md).
	# Disabled by default — the default front door is Cloudflare Access at the
	# edge plus dufs' own Basic auth. NOTE: the Matrix-SSO gateway has NO
	# service-token path, so fronting dufs with it BREAKS WebDAV entirely (only
	# the browser UI would work). If you enable it, the three parts MUST precede
	# the reverse_proxy below: the /authgw/* handler keeps the login form
	# reachable (else the 302-to-login loops), the request_header strips any
	# client-forged Remote-User before the gate, and forward_auth gates the rest.
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

	# Everything → the dufs backend on loopback. flush_interval -1 streams large
	# downloads without buffering; the generous transport timeouts keep big
	# transfers alive.
	reverse_proxy 127.0.0.1:${DUFS_PORT} {
		flush_interval -1
		transport http {
			dial_timeout 10s
			response_header_timeout 5m
			read_timeout 0
			write_timeout 0
		}
	}
}
EOF
ok "wrote /etc/caddy/apps/dufs.caddy"

# Validate the WHOLE Caddyfile (which imports our new app block) fail-closed, so
# we never leave a broken edge config in place. We do NOT restart Caddy here.
say "validating the Caddyfile inside the userland"
in_debian 'caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile' \
  || die "caddy validate FAILED — refusing to leave a broken vhost in /etc/caddy/apps/dufs.caddy"
ok "dufs vhost written + Caddyfile validates"

# NOTE: we do NOT restart Caddy here. During a full install the stack is started
# afterward (scripts/start-stack.sh). If the stack is ALREADY running, the new
# vhost is not live until Caddy reloads — see the closing notes.

# ── 8. Supervise dufs on loopback ────────────────────────────────────────────
# The shared supervisor (respawn loop + identity-checked pidfile) runs the static
# binary inside the userland, with the large-volume content dir bind-mounted in at
# ${DATA_MOUNT} (the serve-path in dufs.yaml). --config points at the 0600 YAML so
# the credential + bind never appear on the process argv.
say "supervising dufs (static Rust binary in the userland, bind 127.0.0.1:${DUFS_PORT})"
supervise dufs -- \
  proot-distro login debian \
  --bind "${DATA_BACKING}:${DATA_MOUNT}" \
  -- /opt/dufs/dufs --config /opt/dufs/dufs.yaml

# ── 8b. FAIL-CLOSED post-start loopback backstop (ss wildcard check) ─────────
# dufs defaults to 0.0.0.0; the dufs.yaml bind grep-assert above is backed by an
# empirical socket audit — refuse to leave a wildcard listener for :${DUFS_PORT}
# running (this file server exposes the SD content). See lib/common.sh.
assert_loopback_listener dufs "${DUFS_PORT}"

# ── 9. Best-effort health check ──────────────────────────────────────────────
# dufs requires auth, so an unauthenticated GET returns 401 — which still proves
# the server is up and listening. We treat ANY HTTP response (incl. 401) as
# healthy; only a connection failure is unhealthy. Non-fatal — the supervisor
# keeps retrying.
say "waiting for dufs to answer on 127.0.0.1:${DUFS_PORT}"
healthy=0
for _ in $(seq 1 30); do
  if curl -fsS -o /dev/null -m 3 "http://127.0.0.1:${DUFS_PORT}/" 2>/dev/null \
     || curl -s -o /dev/null -m 3 "http://127.0.0.1:${DUFS_PORT}/" 2>/dev/null; then
    healthy=1; break
  fi
  sleep 1
done
if [ "${healthy}" -eq 1 ]; then
  ok "dufs answering on 127.0.0.1:${DUFS_PORT} (401 without credentials is expected)"
else
  warn "dufs not yet answering on :${DUFS_PORT} — check ${POCKET_LOG_DIR}/dufs.log (the supervisor keeps retrying)"
fi

# ── 10. Closing notes (manual Cloudflare + the WebDAV/upload caveats) ─────────
cat >&2 <<EOF

$(ok "DUFS installed + supervised on 127.0.0.1:${DUFS_PORT} (read-only; content on ${DATA_BACKING})" 2>&1)

  Manual steps to finish (in the Cloudflare dashboard — NOT done by this script):
    1. Public hostname: add a Public Hostname in your Cloudflare Tunnel:
         ${DUFS_HOST}  ->  http://localhost:${CADDY_PORT}
       (the tunnel's local service is this phone's loopback Caddy edge; plain
        HTTP — the tunnel terminates public TLS).
    2. Cloudflare Access: add an Access application/policy covering
         ${DUFS_HOST}
       so only people you allow can reach it. dufs ALSO has its own Basic login.

  WebDAV (rclone / davfs2 / "map network drive"):
    WebDAV clients CANNOT complete the Cloudflare Access 302 browser login. To use
    WebDAV you must, in the Cloudflare dashboard, add a SERVICE-TOKEN (Service
    Auth) exemption for ${DUFS_HOST}, then use a header-capable client (rclone
    with CF-Access-Client-Id / CF-Access-Client-Secret) plus the dufs Basic
    credential below. The Matrix-SSO gateway has no service-token path and cannot
    front WebDAV — keep dufs on Cloudflare Access if you need WebDAV.

  Upload cap: the Cloudflare Tunnel caps one request body at ~100MB. Downloads
    are unaffected. Uploads are OFF by default; if you enable them (see the
    commented block in ${CONFIG}), anything >100MB needs chunked WebDAV PATCH or
    a different tool (Syncthing). Mind the exFAT SD write hazards noted there.

  Your generated dufs Basic credential lives at:
         ${SECRETS_FILE}   (chmod 600; user '${DUFS_USER}')
    Read DUFS_USER / DUFS_PASSWORD from there to log in (browser or WebDAV).

  If the stack is ALREADY running, reload Caddy so the new vhost goes live:
         bash ${POCKET_ROOT}/scripts/start-stack.sh --restart
    (a full install starts the stack afterward, so no reload is needed then;
     brief ingress outage while cloudflared cycles).

  More detail: docs/FILES.md (incl. "why not Nextcloud/SMB") + docs/APP_AUTH.md.
EOF

ok "apps/dufs.sh done (files.${DOMAIN} once the Cloudflare hostname + Access policy are added)"

# Generalized from a working deployment; review before running.

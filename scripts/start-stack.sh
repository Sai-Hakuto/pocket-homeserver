#!/usr/bin/env bash
#
# start-stack.sh — bring the WHOLE stack up (or restart it).
#
# Core, started first in dependency order:
#   1. matrix       — the Matrix homeserver (continuwuity); everything depends on it
#   2. caddy        — the loopback HTTP edge on ${CADDY_BIND}:${CADDY_PORT}
#                     (the Cloudflare Tunnel terminates public TLS)
#   3. cloudflared  — the Cloudflare Tunnel that forwards public traffic to Caddy
#
# Then every installed app / extra service (the auth gateway, the admin panel, and
# each enabled app) is brought up too, re-supervised from the launch command its
# install step recorded in ${POCKET_STATE_DIR}/<name>.cmd. That makes this the ONE
# command that restores the entire stack — after a reboot, or just on a re-run —
# without duplicating any launch lines (it shares the recorded command with
# scripts/ops/restart.sh, so it never drifts from the install scripts).
#
# Each service runs INSIDE the Debian userland via `proot-distro login` (the admin
# panel runs Termux-native) and is kept alive by the lib's supervisor (respawns on
# crash, identity-checked pidfile).
#
# Idempotent: `supervise` no-ops if a service is already running. Pass --restart to
# stop then re-start every service (a brief ingress outage while cloudflared cycles).
#
# The Cloudflare Tunnel token is passed to cloudflared via the TUNNEL_TOKEN
# environment variable — NEVER on argv (it would otherwise show in /proc/*/cmdline).
#
# Generalized from a working deployment; review before running on a fresh phone.

set -euo pipefail
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"

load_env
require_var DATA_DIR        "folder on your large volume / SD card"
require_var CF_TUNNEL_TOKEN  "the Cloudflare Tunnel token"
require_cmd proot-distro

RESTART=0
case "${1:-}" in
  --restart) RESTART=1 ;;
  "") ;;
  *) die "usage: start-stack.sh [--restart]" ;;
esac

# Acquire a wake-lock so Android doesn't doze the long-running stack (best effort).
command -v termux-wake-lock >/dev/null 2>&1 && { termux-wake-lock 2>/dev/null || true; }

# ── Launch commands (each runs inside the userland) ──────────────────────────
# Matrix: bind the large-volume media dir into the userland so uploads land on
# ${DATA_DIR} (the in-userland DB stays small). CONDUIT_CONFIG points at the
# deployed conduwuit.toml.
matrix_cmd=(
  proot-distro login debian
  --bind "${DATA_DIR}/media:/var/lib/conduwuit/media"
  -- env CONDUIT_CONFIG=/etc/conduwuit/conduwuit.toml /opt/conduwuit/conduwuit
)

# Caddy: serve the deployed Caddyfile (loopback HTTP edge; the tunnel does TLS).
# Bind the host log dir in at /var/log/pocket so Caddy's JSON access log lands on
# the large volume (and the optional native honeypot watcher can tail it).
mkdir -p "${POCKET_LOG_DIR}"
caddy_cmd=(
  proot-distro login debian
  --bind "${POCKET_LOG_DIR}:/var/log/pocket"
  -- caddy run --config /etc/caddy/Caddyfile --adapter caddyfile
)

# cloudflared: keep the tunnel token OFF every argv (/proc/*/cmdline). Stage it
# in a 0600 file inside the userland and read it via a small launcher, so neither
# the supervisor, proot-distro, nor cloudflared expose it on the command line.
# (The token still lives in the launcher's ENVIRON, readable only by the same
# user.) This mirrors the reference deployment's file-based token handling.
stage_cloudflared() {
  proot-distro login debian -- bash -lc '
    mkdir -p /etc/cloudflared && chmod 700 /etc/cloudflared
    cat > /etc/cloudflared/token && chmod 600 /etc/cloudflared/token
    cat > /usr/local/bin/pocket-cloudflared.sh <<"LAUNCH"
#!/bin/bash
export TUNNEL_TOKEN="$(cat /etc/cloudflared/token)"
exec /usr/local/bin/cloudflared tunnel --no-autoupdate --protocol http2 run
LAUNCH
    chmod 700 /usr/local/bin/pocket-cloudflared.sh
  ' <<<"${CF_TUNNEL_TOKEN}"
}
cloudflared_cmd=( proot-distro login debian -- /usr/local/bin/pocket-cloudflared.sh )

# ── --restart: stop everything first (reverse dependency order) ──────────────
if [ "${RESTART}" -eq 1 ]; then
  say "== restarting core stack =="
  unsupervise cloudflared
  unsupervise caddy
  unsupervise matrix
  unsupervise backup-daemon
fi

# ── Start in dependency order (supervise no-ops if already running) ──────────
# Stage the cloudflared token + launcher first (idempotent; picks up token changes).
# POCKET_INGRESS_MODE: exactly one connector runs, chosen by INGRESS_MODE.
INGRESS_MODE="${INGRESS_MODE:-cloudflare}"
if [ "${INGRESS_MODE}" = "cloudflare" ]; then
  say "staging cloudflared token (0600, kept off argv)"
  stage_cloudflared || die "failed to stage the cloudflared token in the userland"
fi

say "== starting core stack =="
supervise matrix      -- "${matrix_cmd[@]}"
supervise caddy       -- "${caddy_cmd[@]}"
# The connector for the selected mode. vps-tunnel is registered by
# apps/vps-tunnel.sh, which records its own .cmd — the loop further down
# re-supervises it, so nothing extra is needed here.
if [ "${INGRESS_MODE}" = "cloudflare" ]; then
  supervise cloudflared -- "${cloudflared_cmd[@]}"
fi

# ── Scheduled backup daemon (opt-in; flag-gated, NOT .cmd-driven) ─────────────
# Controlled by ENABLE_BACKUP_DAEMON, not by a lingering .cmd, so it is supervised
# here explicitly and skipped by the *.cmd glob below. Started after core (a
# snapshot stops/starts the homeserver, so core should be up first).
if [ "${ENABLE_BACKUP_DAEMON:-false}" = "true" ]; then
  say "== starting scheduled backup daemon =="
  supervise backup-daemon -- bash "${POCKET_ROOT}/scripts/ops/backup-daemon.sh"
fi

# ── Bring up every installed app / extra service ─────────────────────────────
# Re-supervise anything that recorded a launch command at install time
# (${POCKET_STATE_DIR}/<name>.cmd — written by `supervise` in lib/common.sh),
# skipping the core services we just handled. supervise() is idempotent, so this
# is a no-op for anything already running and a respawn for anything that's down
# (e.g. after a reboot). New installs add their .cmd, so they get picked up here
# on the next bring-up automatically.
say "== bringing up installed apps =="
extras=0
shopt -s nullglob
for cmdfile in "${POCKET_STATE_DIR}"/*.cmd; do
  name="$(basename "${cmdfile}" .cmd)"
  # Skip core (handled above) AND exobot-ui: the heavy Gradio UI is lazily
  # started + idle-stopped by exobot-waker, so pinning it up here on every
  # bring-up would defeat its on-demand design. The waker itself stays .cmd-driven.
  case " matrix caddy cloudflared backup-daemon exobot-ui " in *" ${name} "*) continue ;; esac
  mapfile -t _cmd < "${cmdfile}"
  [ "${#_cmd[@]}" -gt 0 ] || { warn "empty launch command for '${name}' (${cmdfile}) — skipping"; continue; }
  [ "${RESTART}" -eq 1 ] && unsupervise "${name}"
  supervise "${name}" -- "${_cmd[@]}"
  extras=1
done
shopt -u nullglob
[ "${extras}" -eq 0 ] && say "(no apps installed yet — enable some in .env and run scripts/install.sh)"

# ── Final status ─────────────────────────────────────────────────────────────
echo
say "== stack status =="
shopt -s nullglob
for pidfile in "${POCKET_STATE_DIR}"/*.pid; do
  name="$(basename "${pidfile}" .pid)"
  pid="$(cat "${pidfile}" 2>/dev/null || true)"
  if [ -n "${pid}" ] && kill -0 "${pid}" 2>/dev/null; then
    printf '  %-16s : RUNNING (pid %s)\n' "${name}" "${pid}"
  else
    printf '  %-16s : DOWN\n' "${name}"
  fi
done
shopt -u nullglob

echo
ok "stack start complete (logs under ${POCKET_LOG_DIR})"

#!/data/data/com.termux/files/usr/bin/bash
# harness-web.sh — a browser UI for the `pi` agent, over the SSH tunnel you
# already have. NOT published to the internet, deliberately.
#
# WHY NOT A PUBLIC SUBDOMAIN
# The agent has shell, read, write and edit tools and runs as the same uid as
# every service on this box. Publishing it on agent.${DOMAIN} would put arbitrary
# command execution behind a single login form. The value of a browser UI is
# convenience, not exposure, so this binds LOOPBACK ONLY and you reach it the
# same way Syncthing's GUI is reached:
#
#     ssh -p 8022 -i <key> -L 7681:127.0.0.1:7681 <phone>
#     open http://localhost:7681
#
# Your SSH key is the gate. Basic auth is layered on top so that a future
# mistake — someone binding this to 0.0.0.0 — is not instantly fatal.
#
# Works from a phone too: any SSH client that can port-forward (Termux,
# Termius, JuiceSSH), then the browser on the same device.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "${HERE}/../lib/common.sh"
load_env

[ "${ENABLE_HARNESS_WEB:-false}" = "true" ] || { ok "harness-web disabled — skipping"; exit 0; }
[ "${ENABLE_HARNESS:-false}" = "true" ] || die "ENABLE_HARNESS_WEB needs ENABLE_HARNESS=true (there is no agent to serve)"

PORT="${HARNESS_WEB_PORT:-7681}"
SECRETS_FILE="${DATA_DIR}/secrets/harness-web.env"

# ── 1. ttyd ─────────────────────────────────────────────────────────────────
if ! command -v ttyd >/dev/null 2>&1; then
  say "installing ttyd"
  pkg install -y ttyd >/dev/null 2>&1 || die "failed to install ttyd"
fi
ok "ttyd $(ttyd --version 2>&1 | head -1)"

# ── 2. Credential ───────────────────────────────────────────────────────────
# Generated once, kept 0600, never echoed by the installer and never on argv
# (ttyd reads it from a credential file via -c, which we feed from the env).
if [ ! -f "${SECRETS_FILE}" ]; then
  umask 077
  WEB_USER="${ADMIN_USER:-admin}"
  # POCKET_NO_SIGPIPE: do NOT use `tr < /dev/urandom | head -c N`. head closes
  # the pipe, tr dies of SIGPIPE, and under `set -o pipefail` that kills the
  # whole script with 141 — which looks like a mysterious crash. openssl reads a
  # bounded amount and exits cleanly, which is why the rest of this repo uses it.
  WEB_PASS="$(openssl rand -base64 24 | tr -d '/+=' | cut -c1-24)"
  {
    printf '# pocket-homeserver harness web UI. PRIVATE — 0600.\n'
    printf '# Single-quoted: this file is SOURCED by bash.\n'
    printf "HARNESS_WEB_USER='%s'\n" "${WEB_USER}"
    printf "HARNESS_WEB_PASS='%s'\n" "${WEB_PASS}"
  } > "${SECRETS_FILE}"
  chmod 600 "${SECRETS_FILE}"
  ok "generated the web credential -> ${SECRETS_FILE} (0600)"
else
  ok "web credential already present"
fi
# shellcheck disable=SC1090
. "${SECRETS_FILE}"
[ -n "${HARNESS_WEB_PASS:-}" ] || die "HARNESS_WEB_PASS is empty in ${SECRETS_FILE}"

# ── 3. Launcher ─────────────────────────────────────────────────────────────
# POCKET_ARGV_HONEST — read this before "improving" the wrapper.
# ttyd has NO credential-file option. `-c user:pass` is the only way, and it
# therefore lands on argv, where /proc/<pid>/cmdline exposes it (mode 0444) to
# anything running as this uid. The wrapper below keeps the credential out of
# the SUPERVISOR's argv and out of shell history, but it CANNOT keep it off
# ttyd's own. An earlier version of this comment claimed otherwise; it was wrong.
#
# Why that is tolerable here and not a reason to skip the layer: Termux gives one
# app one uid, so every process that could read that cmdline already runs as the
# same user as the agent, the secrets and the tunnel key. The basic auth exists
# to catch a misconfiguration (someone binding this to 0.0.0.0), not to defend
# against local processes — that boundary does not exist on this device.
#
# To publish this properly, do NOT expose -c to the internet. Use
# `-H/--auth-header` and let the auth gateway authenticate, then pass the
# verified identity in a header. Then no password sits on argv at all.
LAUNCHER="${HOME}/.pocket/harness-web-launcher.sh"
mkdir -p "$(dirname "${LAUNCHER}")"
cat > "${LAUNCHER}" <<'LAUNCH'
#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail
. "$(dirname "$0")/harness-web.conf"
# shellcheck disable=SC1090
. "${SECRETS_FILE}"
exec ttyd \
  --interface 127.0.0.1 \
  --port "${PORT}" \
  --credential "${HARNESS_WEB_USER}:${HARNESS_WEB_PASS}" \
  --writable \
  --title-format "pocket agent" \
  bash "${POCKET_ROOT}/scripts/ops/harness.sh"
LAUNCH
chmod 700 "${LAUNCHER}"

cat > "$(dirname "${LAUNCHER}")/harness-web.conf" <<CONF
SECRETS_FILE="${SECRETS_FILE}"
POCKET_ROOT="${POCKET_ROOT}"
PORT="${PORT}"
CONF
chmod 600 "$(dirname "${LAUNCHER}")/harness-web.conf"

# ── 4. Supervise ────────────────────────────────────────────────────────────
# Unlike the CLI itself, the web front IS a daemon, so it belongs under the
# supervisor — and therefore comes back after a reboot via Termux:Boot.
unsupervise harness-web 2>/dev/null || true
supervise harness-web -- bash "${LAUNCHER}"

# ── 5. Assert it is loopback-only ───────────────────────────────────────────
# Fail closed rather than leaving a shell-capable UI listening on the LAN.
sleep 3
HEX_PORT="$(printf '%04X' "${PORT}")"
if cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | awk '{print $2}' | grep -qiE "^(00000000|0+):${HEX_PORT}$"; then
  unsupervise harness-web 2>/dev/null || true
  die "ttyd bound to ALL interfaces — refusing to leave a shell UI on the LAN"
fi
if ! curl -fsS -o /dev/null -m 5 -u "${HARNESS_WEB_USER}:${HARNESS_WEB_PASS}" "http://127.0.0.1:${PORT}/" 2>/dev/null; then
  warn "ttyd is supervised but did not answer yet — check ${POCKET_LOG_DIR}/harness-web.log"
else
  ok "harness web UI listening on 127.0.0.1:${PORT} (loopback only)"
fi

echo
say "reach it with:"
say "  ssh -p 8022 -i <key> -L ${PORT}:127.0.0.1:${PORT} <phone>"
say "  then open http://localhost:${PORT}"
say "credentials are in ${SECRETS_FILE}"

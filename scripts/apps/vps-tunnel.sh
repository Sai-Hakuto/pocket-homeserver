#!/data/data/com.termux/files/usr/bin/bash
# vps-tunnel.sh — outbound reverse-SSH ingress (INGRESS_MODE=vps-tunnel).
#
# The alternative to a Cloudflare Tunnel: the phone dials OUT to a box you own
# and hands it a reverse forward. That box terminates TLS and proxies into this
# forward. Consequences, all deliberate:
#   - no inbound ports on the phone, so CGNAT / mobile networks are irrelevant
#   - no third party in the data path
#   - the VPS needs no credentials for the phone; the phone drives the link
#
# Caddy on the phone already serves plain HTTP on CADDY_BIND:CADDY_PORT because
# upstream expects TLS to terminate upstream of it. That is exactly the shape a
# reverse forward wants, so nothing about the phone's edge config changes.
#
# Prepare the far end first:  scripts/ops/vps-setup.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "${HERE}/../lib/common.sh"
load_env

[ "${INGRESS_MODE:-cloudflare}" = "vps-tunnel" ] || { ok "INGRESS_MODE is not vps-tunnel — skipping"; exit 0; }

require_var VPS_HOST "the VPS that terminates TLS"
VPS_USER="${VPS_USER:-tunnel}"
VPS_SSH_PORT="${VPS_SSH_PORT:-22}"
KEY="${VPS_TUNNEL_KEY:-${HOME}/.ssh/pocket-tunnel_ed25519}"
PORT="${CADDY_PORT:-8443}"

# ── 1. Key ──────────────────────────────────────────────────────────────────
mkdir -p "$(dirname "${KEY}")"
chmod 700 "$(dirname "${KEY}")"
if [ ! -f "${KEY}" ]; then
  say "generating the tunnel keypair (${KEY})"
  ssh-keygen -t ed25519 -N "" -C "pocket-tunnel@${DOMAIN}" -f "${KEY}" >/dev/null
  ok "keypair created"
fi
chmod 600 "${KEY}"

# ── 2. Host key, up front ───────────────────────────────────────────────────
# StrictHostKeyChecking=yes under a supervisor with no tty would simply fail
# forever on an unknown host. Learn it now, loudly, instead of at 03:00.
touch "${HOME}/.ssh/known_hosts"; chmod 600 "${HOME}/.ssh/known_hosts"
if ! ssh-keygen -F "[${VPS_HOST}]:${VPS_SSH_PORT}" -f "${HOME}/.ssh/known_hosts" >/dev/null 2>&1 \
   && ! ssh-keygen -F "${VPS_HOST}" -f "${HOME}/.ssh/known_hosts" >/dev/null 2>&1; then
  say "learning the VPS host key"
  ssh-keyscan -T 10 -p "${VPS_SSH_PORT}" "${VPS_HOST}" >> "${HOME}/.ssh/known_hosts" 2>/dev/null \
    || die "ssh-keyscan could not reach ${VPS_HOST}:${VPS_SSH_PORT}"
  sort -u -o "${HOME}/.ssh/known_hosts" "${HOME}/.ssh/known_hosts"
  ok "host key recorded"
fi

# ── 3. Can we actually authenticate AND bind the forward? ──────────────────
# POCKET_AUTHPROBE_FIX: probe exactly the way the tunnel connects — with -N and
# the real -R. Do NOT probe with `ssh ... true`: the tunnel account has a
# nologin shell on purpose, so requesting a command returns "This account is
# currently not available" and looks like an auth failure when nothing is wrong.
#
# timeout kills a HEALTHY session, so 124 is success. 255 is ssh failing for
# real: unauthorised key, refused forward, or unreachable host.
# POCKET_PROBE_PORT0: remote port 0 -> the server picks a free one. Probing the
# REAL port collides with the tunnel we may already be running and fails with
# 'remote port forwarding failed' — condemning a setup for already working.
say "probing the tunnel (auth + remote bind)"
set +e
timeout 15 ssh -i "${KEY}" -p "${VPS_SSH_PORT}" \
  -o BatchMode=yes -o StrictHostKeyChecking=yes \
  -o ExitOnForwardFailure=yes -o ConnectTimeout=10 \
  -N -R "127.0.0.1:0:127.0.0.1:${PORT}" \
  "${VPS_USER}@${VPS_HOST}" 2>"${POCKET_LOG_DIR}/vps-tunnel-probe.err"
RC=$?
set -e
if [ "${RC}" -ne 124 ]; then
  echo
  warn "the tunnel probe failed (ssh rc=${RC})"
  sed -n '1,6p' "${POCKET_LOG_DIR}/vps-tunnel-probe.err" 2>/dev/null || true
  echo
  echo "If the key is simply not authorised yet, run this ON THE VPS:"
  echo
  echo "  install -d -m 700 -o ${VPS_USER} -g ${VPS_USER} /home/${VPS_USER}/.ssh"
  echo "  echo 'restrict,port-forwarding $(cat "${KEY}.pub")' \\"
  echo "    >> /home/${VPS_USER}/.ssh/authorized_keys"
  echo "  chown ${VPS_USER}:${VPS_USER} /home/${VPS_USER}/.ssh/authorized_keys"
  echo "  chmod 600 /home/${VPS_USER}/.ssh/authorized_keys"
  echo
  echo "Or provision the whole far end from here:"
  echo "  bash ${POCKET_ROOT}/scripts/ops/vps-setup.sh root@${VPS_HOST}"
  echo
  echo "If it says 'remote port forwarding failed', a stale session still holds"
  echo "127.0.0.1:${PORT} on the VPS. ClientAliveInterval reaps it in ~90s;"
  echo "vps-setup.sh configures that."
  die "tunnel probe failed against ${VPS_HOST}"
fi
ok "authenticated to ${VPS_USER}@${VPS_HOST} and the remote bind succeeded"

# ── 4. Supervise it ─────────────────────────────────────────────────────────
# NEVER `nohup ... &`: Android reaps untracked children, which has already killed
# sshd on this device. supervise() records a .cmd that start-stack.sh re-arms, so
# this also survives a reboot via Termux:Boot.
#
# ExitOnForwardFailure makes ssh die instead of sitting there with no forward —
# the supervisor then backs off and retries, which is what you want when a stale
# session on the VPS is still holding the port.
unsupervise vps-tunnel 2>/dev/null || true
unsupervise tunnel 2>/dev/null || true   # retire the ad-hoc name, if present
supervise vps-tunnel -- ssh \
  -i "${KEY}" -p "${VPS_SSH_PORT}" \
  -o BatchMode=yes \
  -o StrictHostKeyChecking=yes \
  -o ExitOnForwardFailure=yes \
  -o ServerAliveInterval=30 \
  -o ServerAliveCountMax=3 \
  -o TCPKeepAlive=yes \
  -N -R "127.0.0.1:${PORT}:127.0.0.1:${PORT}" \
  "${VPS_USER}@${VPS_HOST}"

# ── 5. Prove the forward came up ────────────────────────────────────────────
say "verifying the reverse forward"
UP=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
  sleep 3
  if ssh -i "${KEY}" -p "${VPS_SSH_PORT}" -o BatchMode=yes -o ConnectTimeout=10 \
         "${VPS_USER}@${VPS_HOST}" true 2>/dev/null; then :; fi
  if pgrep -f -- "-N -R 127.0.0.1:${PORT}" >/dev/null 2>&1; then UP=1; break; fi
done
[ "${UP}" -eq 1 ] || die "the tunnel did not stay up — see ${POCKET_LOG_DIR}/vps-tunnel.log"

ok "vps-tunnel supervised: ${VPS_USER}@${VPS_HOST} <- 127.0.0.1:${PORT}"
say "the VPS must proxy its own 127.0.0.1:${PORT} for each public hostname"

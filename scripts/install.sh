#!/usr/bin/env bash
#
# install.sh — bring up pocket-homeserver from .env (resumable + idempotent).
#
# Usage:
#   scripts/install.sh            # run the install/bring-up plan (resumes)
#   scripts/install.sh --status   # show what's installed + what's running
#   scripts/install.sh --check    # validate config + print the plan, run nothing
#   scripts/install.sh --force     # redo every step, ignoring "done" markers
#   scripts/install.sh --reset     # clear the "done" markers (next run is fresh)
#
# Persistence: each step that finishes successfully is recorded with a marker file
# under ${POCKET_STATE_DIR}. On the next run a recorded step is SKIPPED, so re-runs
# are fast and an interrupted install resumes exactly where it stopped — you can
# run this again and again from Termux. Two steps always run regardless (they are
# cheap and idempotent): `render-config` (regenerates configs from .env) and
# `start` (brings the whole stack up). If you change .env — a new domain, ports, or
# an app's settings — re-run with --force so the install steps pick the change up.
#
# App steps run only when their ENABLE_<APP> flag is true. A step that isn't
# present yet is reported and skipped, so the framework can land incrementally.

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/lib/common.sh"

CHECK=0 STATUS=0 FORCE=0 RESET=0
case "${1:-}" in
  --check)  CHECK=1 ;;
  --status) STATUS=1 ;;
  --force)  FORCE=1 ;;
  --reset)  RESET=1 ;;
  "") ;;
  *) die "usage: install.sh [--status | --check | --force | --reset]" ;;
esac

load_env

# ── Step plan ─────────────────────────────────────────────────────────────────
# Ordered core PROVISION plan: "label:relative-script-path". These install and
# configure components but do NOT start the long-running stack — that happens
# last (start-stack.sh below), AFTER every enabled app has dropped its Caddy
# vhost, so the edge comes up already aware of all the apps.
core_steps=(
  "prereqs:steps/00-prereqs.sh"
  "userland:steps/10-install-userland.sh"
  "cloudflared:steps/20-install-cloudflared.sh"
  "caddy:steps/30-install-caddy.sh"
  "render-config:render-config.sh"
  "matrix:steps/40-install-matrix.sh"
  "element:steps/50-install-element.sh"
  "auth-gateway:steps/60-install-auth-gw.sh"
  "admin:steps/70-install-admin.sh"
  "boot:steps/75-install-boot.sh"
  "honeypot:steps/77-install-honeypot.sh"
  "filters:steps/78-install-filters.sh"
  "cloud-bots:steps/80-install-cloud-bots.sh"
  "exobot:steps/81-install-exobot.sh"
  "stickers:steps/82-install-stickers.sh"
  "adminbot:steps/83-install-adminbot.sh"
  "landing:steps/84-install-landing.sh"
  "email:steps/85-install-email.sh"
  "webmail:steps/86-install-webmail.sh"
  "mcp:steps/87-install-mcp.sh"
  "metrics:steps/88-install-metrics.sh"
  "syncthing:steps/89-install-syncthing.sh"
  "tailscale:steps/90-install-tailscale.sh"
)

# Optional apps, in install order, each gated by ENABLE_<APP>.
# DUFS and FILEBROWSER both serve files.${DOMAIN} and are MUTUALLY EXCLUSIVE —
# each script dies fail-closed if the other is also enabled.
app_order=(LINKDING PINGVIN FRESHRSS MEMOS VIKUNJA SEARXNG ITTOOLS GATUS SITES DUFS FILEBROWSER WALLABAG RADICALE TRILIUM VAULTWARDEN NAVIDROME KAVITA AUDIOBOOKSHELF FORGEJO ADGUARD HARNESS PROXY_ROUTES)
declare -A app_step=(
  [LINKDING]="apps/linkding.sh"
  [PINGVIN]="apps/pingvin.sh"
  [FRESHRSS]="apps/freshrss.sh"
  [MEMOS]="apps/memos.sh"
  [VIKUNJA]="apps/vikunja.sh"
  [SEARXNG]="apps/searxng.sh"
  [ITTOOLS]="apps/ittools.sh"
  [GATUS]="apps/gatus.sh"
  [SITES]="apps/sites.sh"
  [DUFS]="apps/dufs.sh"
  [FILEBROWSER]="apps/filebrowser.sh"
  [WALLABAG]="apps/wallabag.sh"
  [RADICALE]="apps/radicale.sh"
  [TRILIUM]="apps/trilium.sh"
  [VAULTWARDEN]="apps/vaultwarden.sh"
  [NAVIDROME]="apps/navidrome.sh"
  [KAVITA]="apps/kavita.sh"
  [AUDIOBOOKSHELF]="apps/audiobookshelf.sh"
  [FORGEJO]="apps/forgejo.sh"
  [ADGUARD]="apps/adguard.sh"
  [HARNESS]="apps/harness.sh"
  [PROXY_ROUTES]="apps/proxy-routes.sh"
)

# ── Persistence helpers ───────────────────────────────────────────────────────
# A marker key derived from the step label, sanitized to characters that are
# legal in a filename on every filesystem we run on — the SD card is often exFAT,
# which forbids ':' and '/', and labels like "app:linkding" contain a colon.
step_key() { printf 'step-%s' "${1//[^A-Za-z0-9_.-]/-}"; }
# Steps that must run on EVERY invocation (cheap + idempotent): config rendering
# (so .env changes to the core config take effect) and the stack bring-up.
is_always() { case "$1" in render-config|start) return 0 ;; *) return 1 ;; esac; }

# ── --reset: forget what's done ───────────────────────────────────────────────
if [ "$RESET" -eq 1 ]; then
  n=0
  shopt -s nullglob
  for f in "$POCKET_STATE_DIR"/step-*.done; do rm -f "$f"; n=$((n + 1)); done
  shopt -u nullglob
  ok "cleared $n step marker(s) under $POCKET_STATE_DIR — the next install will run every step"
  exit 0
fi

# ── --status: what's installed + what's running ───────────────────────────────
if [ "$STATUS" -eq 1 ]; then
  echo "pocket-homeserver — status for ${DOMAIN:-<no domain set>}"
  echo
  echo "  install steps:"
  status_step() {  # status_step label relpath
    local label="$1" rel="$2" path="$HERE/$2" key state
    key="$(step_key "$label")"
    if [ ! -f "$path" ]; then state="absent "
    elif is_always "$label"; then state="always "
    elif is_done "$key"; then state="done   "
    else state="pending"; fi
    printf '    [%s] %-14s %s\n' "$state" "$label" "$rel"
  }
  for entry in "${core_steps[@]}"; do status_step "${entry%%:*}" "${entry#*:}"; done
  for app in "${app_order[@]}"; do
    flag="ENABLE_${app}"
    [ "${!flag:-false}" = "true" ] && status_step "app:${app,,}" "${app_step[$app]}"
  done
  status_step "start" "start-stack.sh"
  echo
  echo "  services (supervisor pidfiles in ${POCKET_STATE_DIR}):"
  shopt -s nullglob
  any=0
  for pidfile in "${POCKET_STATE_DIR}"/*.pid; do
    any=1
    name="$(basename "${pidfile}" .pid)"
    pid="$(cat "${pidfile}" 2>/dev/null || true)"
    if [ -n "${pid}" ] && kill -0 "${pid}" 2>/dev/null; then
      printf '    %-16s RUNNING (pid %s)\n' "${name}" "${pid}"
    else
      printf '    %-16s DOWN\n' "${name}"
    fi
  done
  shopt -u nullglob
  [ "${any}" -eq 0 ] && echo "    (nothing supervised yet — run scripts/install.sh)"
  echo
  exit 0
fi

# Required before anything runs.
require_var DOMAIN          "your apex domain (DNS on Cloudflare)"
require_var DATA_DIR        "folder on your large volume / SD card"
require_var CF_TUNNEL_TOKEN "the Cloudflare Tunnel token"
require_var ADMIN_PASSWORD  "the admin panel password"

run_step() {   # run_step label relpath
  local label="$1" rel="$2" path="$HERE/$2" key
  key="$(step_key "$label")"
  if [ ! -f "$path" ]; then
    warn "step not present yet: $label ($rel) — skipping"
    return 0
  fi
  if [ "$CHECK" -eq 1 ]; then
    if is_always "$label"; then say "would run (always): $label ($rel)"
    elif [ "$FORCE" -eq 0 ] && is_done "$key"; then say "would skip (already done): $label ($rel)"
    else say "would run: $label ($rel)"; fi
    return 0
  fi
  if [ "$FORCE" -eq 0 ] && ! is_always "$label" && is_done "$key"; then
    ok "skip (already done): $label  —  re-run with --force to redo it"
    return 0
  fi
  say "=== $label ==="
  bash "$path"
  is_always "$label" || mark_done "$key"   # only reached if the step succeeded (set -e)
}

say "pocket-homeserver install plan for ${DOMAIN}  (check=$CHECK force=$FORCE)"
for entry in "${core_steps[@]}"; do
  run_step "${entry%%:*}" "${entry#*:}"
done
for app in "${app_order[@]}"; do
  flag="ENABLE_${app}"
  if [ "${!flag:-false}" = "true" ]; then
    run_step "app:${app,,}" "${app_step[$app]}"
  fi
done

# Start the stack LAST: by now every enabled app has installed its backend and
# written its vhost into /etc/caddy/apps, so Caddy loads them all on first start.
# start-stack.sh re-supervises core + every installed app, so this also restores
# the whole stack on a plain re-run (e.g. after a reboot).
run_step "start" "start-stack.sh"

# Optional Matrix bootstrap — runs AFTER the stack is up, because it needs the
# homeserver reachable AND registration opened (scripts/ops/rotate-registration-token.sh).
# Deliberately NOT a core_step: it self-gates on ENABLE_BOOTSTRAP, is idempotent,
# and is fail-soft here so an unprepared run (e.g. registration still closed) just
# warns instead of aborting the install. See docs/BOOTSTRAP.md.
if [ "$CHECK" -eq 0 ] && [ "${ENABLE_BOOTSTRAP:-false}" = "true" ] && [ -f "$HERE/steps/79-install-bootstrap.sh" ]; then
  say "=== bootstrap (optional) ==="
  bash "$HERE/steps/79-install-bootstrap.sh" \
    || warn "Matrix bootstrap did not complete — the rest of the stack is up. Open registration (scripts/ops/rotate-registration-token.sh) then re-run, or run scripts/steps/79-install-bootstrap.sh by hand. See docs/BOOTSTRAP.md."
fi

ok "install plan complete (check=$CHECK force=$FORCE)"
# Note: keep this as an `if` (not `cond && cmd`) so the script always exits 0 on a
# successful run — `--check` must return success for CI's smoke gate.
if [ "$CHECK" -eq 0 ]; then
  say "tip: 'scripts/install.sh --status' shows what's installed and running."
fi

# Advisory: a read-only health + preflight pass at the end of a real run. Never
# fatal — it only reports; address any FAIL items it prints. Skipped for --check.
if [ "$CHECK" -eq 0 ] && [ -f "$HERE/ops/doctor.sh" ]; then
  echo
  say "running doctor (read-only health check)…"
  bash "$HERE/ops/doctor.sh" || true
fi

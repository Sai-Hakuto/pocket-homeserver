#!/usr/bin/env bash
#
# doctor.sh — read-only preflight + self-test for pocket-homeserver.
#
# Surfaces the phone-specific gotchas the rest of the codebase already knows about
# (exFAT can't safely hold an app database, the Termux:Boot/API addons must be
# present, a wake-lock must be held, duplicate ports, a service stuck crash-looping)
# as one pass / warn / FAIL report with the exact fix. It NEVER changes anything,
# and it never prints secret values — only "set" / "MISSING" / "placeholder".
#
# Usage:
#   scripts/ops/doctor.sh            # run all checks, advisory (always exit 0)
#   scripts/ops/doctor.sh --strict   # exit non-zero if any check FAILED (CI/hooks)
#
# It runs advisory at the end of install.sh (fail-soft), from ./pocket.sh, or any
# time you want a health snapshot.

set -uo pipefail
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"

STRICT=0
case "${1:-}" in
  "")        ;;
  --strict)  STRICT=1 ;;
  *) die "usage: doctor.sh [--strict]" ;;
esac

pass_n=0 warn_n=0 fail_n=0
_p() { printf '  %s[ ok ]%s %s\n' "$_c_grn" "$_c_rst" "$*"; pass_n=$((pass_n + 1)); }
_w() { printf '  %s[warn]%s %s\n' "$_c_ylw" "$_c_rst" "$*"; warn_n=$((warn_n + 1)); }
_f() { printf '  %s[FAIL]%s %s\n' "$_c_red" "$_c_rst" "$*"; fail_n=$((fail_n + 1)); }
_section() { printf '\n%s== %s ==%s\n' "$_c_blu" "$*" "$_c_rst"; }

on_termux() { [ -n "${TERMUX_VERSION:-}" ] || [ -d /data/data/com.termux ]; }

echo "pocket-homeserver doctor — read-only diagnostics"

# ── Configuration (.env) ─────────────────────────────────────────────────────
_section "Configuration"
envf="${POCKET_ENV:-$POCKET_ROOT/.env}"
if [ -f "$envf" ]; then
  _p ".env present ($envf)"
  set -a
  # shellcheck disable=SC1090
  . "$envf"
  [ -f "$POCKET_ROOT/config/versions.env" ] && . "$POCKET_ROOT/config/versions.env"
  set +a
  _apply_env_defaults
  # Required vars — report presence only, NEVER the value.
  # POCKET_NO_CLOUDFLARE: CF_TUNNEL_TOKEN is a placeholder here (ssh -R tunnel instead).
  for v in DOMAIN DATA_DIR ADMIN_PASSWORD; do
    val="${!v:-}"
    case "$val" in
      "")                                  _f "$v is MISSING — set it in .env" ;;
      example.com|*XXXX-XXXX*|changeme|CHANGEME) _f "$v still holds a placeholder — set a real value" ;;
      *)                                   _p "$v is set" ;;
    esac
  done
else
  _f ".env not found at $envf — copy .env.example to .env and edit it (see docs/SETUP.md)"
fi

if [ -f "$POCKET_ROOT/config/versions.env" ]; then
  _p "config/versions.env present (central pin manifest)"
else
  _w "config/versions.env missing — steps fall back to inline pins (see docs/UPDATING.md)"
fi

# ── Storage tiers ────────────────────────────────────────────────────────────
_section "Storage"
if [ -n "${DATA_DIR:-}" ]; then
  if [ -d "$DATA_DIR" ]; then
    _p "DATA_DIR exists ($DATA_DIR)"
    [ -w "$DATA_DIR" ] && _p "DATA_DIR is writable" || _f "DATA_DIR is not writable"
    free="$(df -h "$DATA_DIR" 2>/dev/null | awk 'NR==2{print $4}')"
    [ -n "$free" ] && _p "DATA_DIR free space: $free"
    fstype="$(stat -f -c '%T' "$DATA_DIR" 2>/dev/null || true)"
    case "$fstype" in
      exfat|msdos|vfat|fuseblk)
        _w "DATA_DIR filesystem is '$fstype' — fine for bulk files + backups, but an app DATABASE (SQLite/WAL) must NOT live here. Keep DB-backed apps on ext4 inside the userland (storage-tier rule)." ;;
      "") _w "could not determine DATA_DIR filesystem type" ;;
      *)  _p "DATA_DIR filesystem: $fstype" ;;
    esac
  else
    _f "DATA_DIR does not exist: $DATA_DIR"
  fi
else
  _w "DATA_DIR not set — skipping storage checks"
fi

# ── Debian userland (proot) ──────────────────────────────────────────────────
_section "Debian userland (proot)"
if command -v proot-distro >/dev/null 2>&1; then
  _p "proot-distro installed"
  if proot-distro list 2>/dev/null | grep -qiE 'debian.*installed' || proot-distro login debian -- true 2>/dev/null; then
    _p "debian userland reachable"
  else
    _w "debian userland not installed yet — run scripts/install.sh (step: userland)"
  fi
elif on_termux; then
  _f "proot-distro not installed — pkg install proot-distro (see docs/SETUP.md)"
else
  _w "proot-distro absent (expected when not on the phone)"
fi

# ── Termux integration (only meaningful on the phone) ────────────────────────
_section "Termux integration"
if on_termux; then
  [ -d "$HOME/.termux/boot" ] \
    && _p "Termux:Boot dir present (~/.termux/boot)" \
    || _w "no ~/.termux/boot — install the Termux:Boot addon for reboot survival (docs/SETUP.md)"
  command -v termux-wake-lock >/dev/null 2>&1 \
    && _p "termux-wake-lock available" \
    || _w "termux-wake-lock missing — install Termux:API so the server holds a wake-lock"
  command -v termux-job-scheduler >/dev/null 2>&1 \
    && _p "termux-job-scheduler available (watchdog)" \
    || _w "termux-job-scheduler missing — the watchdog can't be registered (needs Termux:API)"
else
  _w "not running under Termux — skipping phone-integration checks"
fi

# ── Services & ports ─────────────────────────────────────────────────────────
_section "Services & ports"
if [ -f "$envf" ]; then
  dups="$(grep -oE '^[A-Z0-9_]*PORT=[0-9]+' "$envf" 2>/dev/null | sed 's/.*=//' | sort | uniq -d)"
  if [ -n "$dups" ]; then
    _f "duplicate port(s) configured in .env: $(echo "$dups" | tr '\n' ' ')"
  else
    _p "no duplicate *_PORT values in .env"
  fi
fi
# POCKET_NO_CLOUDFLARE: cloudflared is not part of this deployment.
for proc in caddy conduwuit; do
  if pgrep -f "$proc" >/dev/null 2>&1; then
    _p "$proc process running"
  else
    _w "$proc not running (fine if it isn't installed/started yet)"
  fi
done
if [ -n "${CADDY_PORT:-}" ] && command -v curl >/dev/null 2>&1; then
  if curl -fsS -m 4 -o /dev/null "http://${CADDY_BIND:-127.0.0.1}:${CADDY_PORT}/" 2>/dev/null; then
    _p "Caddy edge reachable on ${CADDY_BIND:-127.0.0.1}:${CADDY_PORT}"
  else
    _w "Caddy edge not reachable on ${CADDY_BIND:-127.0.0.1}:${CADDY_PORT} (fine if the stack isn't up)"
  fi
fi

# ── Health (crash-loop / DEGRADED markers) ───────────────────────────────────
_section "Health"
deg=0
if [ -n "${POCKET_STATE_DIR:-}" ] && [ -d "$POCKET_STATE_DIR" ]; then
  shopt -s nullglob
  for m in "$POCKET_STATE_DIR"/*.degraded; do
    deg=1
    _f "DEGRADED: $(basename "$m" .degraded) is crash-looping — $(tr '\t' ' ' < "$m" 2>/dev/null) (see docs/RESILIENCE.md)"
  done
  shopt -u nullglob
fi
[ "$deg" -eq 0 ] && _p "no DEGRADED / crash-loop markers"

# ── Summary ──────────────────────────────────────────────────────────────────
_section "Summary"
printf '  %d ok, %s%d warn%s, %s%d FAIL%s\n' \
  "$pass_n" "$_c_ylw" "$warn_n" "$_c_rst" "$_c_red" "$fail_n" "$_c_rst"
if [ "$fail_n" -gt 0 ]; then
  printf '  %s-> address the FAIL item(s) above.%s\n' "$_c_red" "$_c_rst"
  [ "$STRICT" -eq 1 ] && exit 1
fi
exit 0

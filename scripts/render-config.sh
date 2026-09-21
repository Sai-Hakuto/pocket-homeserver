#!/usr/bin/env bash
#
# render-config.sh — render the config templates in config/*.tmpl into
# config/rendered/ by substituting the values from .env.
#
# Usage: scripts/render-config.sh [OUT_DIR]   (default: config/rendered)
#
# Substitutes only a fixed, known set of ${VARS}, so Caddy's own `{...}`
# placeholders are left untouched. Values must not contain a literal `|`.

set -euo pipefail
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"

load_env
require_var DOMAIN "your apex domain (DNS on Cloudflare)"
: "${MATRIX_SERVER_NAME:=$DOMAIN}"

out="${1:-$POCKET_ROOT/config/rendered}"
mkdir -p "$out"

render() {   # render SRC DST
  local src="$1" dst="$2"
  [ -f "$src" ] || die "template not found: $src"
  sed \
    -e "s|\${DOMAIN}|${DOMAIN}|g" \
    -e "s|\${MATRIX_SERVER_NAME}|${MATRIX_SERVER_NAME}|g" \
    -e "s|\${CADDY_BIND}|${CADDY_BIND}|g" \
    -e "s|\${CADDY_PORT}|${CADDY_PORT}|g" \
    -e "s|\${DATA_DIR}|${DATA_DIR:-}|g" \
    "$src" > "$dst"
  ok "rendered $(basename "$dst") -> $dst"
}

render "$POCKET_ROOT/config/Caddyfile.tmpl"      "$out/Caddyfile"
render "$POCKET_ROOT/config/conduwuit.toml.tmpl" "$out/conduwuit.toml"

# ── Optional privacy/media filter routes (woven into the chat vhost) ──────────
# The filters (scripts/filters/*) intercept SPECIFIC Matrix routes on the chat
# vhost — they can't use the /etc/caddy/apps/*.caddy drop-in (Caddy refuses a
# duplicate site address). Inject their reverse_proxy blocks into the rendered
# Caddyfile ONLY when the filter is enabled: a disabled filter must never be
# routed to a dead loopback port (that would 502 search/media for everyone). The
# `# POCKET_FILTER_ROUTES` marker in Caddyfile.tmpl is where they go.
filter_routes=""
if [ "${ENABLE_USER_FILTER:-false}" = "true" ]; then
  filter_routes+=$'\t# user-filter: route only user-directory search through the proxy.\n'
  filter_routes+=$'\thandle /_matrix/client/*/user_directory/search {\n'
  filter_routes+=$'\t\treverse_proxy 127.0.0.1:'"${USER_FILTER_PORT:-8449}"$'\n'
  filter_routes+=$'\t}\n'
fi
if [ "${ENABLE_MEDIA_FILTER:-false}" = "true" ]; then
  _mp="${MEDIA_FILTER_PORT:-8450}"
  filter_routes+=$'\t# media-filter: route only media download/thumbnail/preview through the proxy.\n'
  filter_routes+=$'\thandle /_matrix/media/v3/download/*   { reverse_proxy 127.0.0.1:'"${_mp}"$' }\n'
  filter_routes+=$'\thandle /_matrix/media/v3/thumbnail/*  { reverse_proxy 127.0.0.1:'"${_mp}"$' }\n'
  filter_routes+=$'\thandle /_matrix/media/v3/preview_url* { reverse_proxy 127.0.0.1:'"${_mp}"$' }\n'
  filter_routes+=$'\thandle /_matrix/client/v1/media/*     { reverse_proxy 127.0.0.1:'"${_mp}"$' }\n'
fi
# Replace the marker line with the routes (or just drop it when none enabled).
awk -v repl="$filter_routes" '
  /# POCKET_FILTER_ROUTES/ { if (repl != "") printf "%s", repl; next }
  { print }
' "$out/Caddyfile" > "$out/Caddyfile.tmp" && mv -f "$out/Caddyfile.tmp" "$out/Caddyfile"
if [ -n "$filter_routes" ]; then ok "wove privacy/media filter routes into the chat vhost"; fi

# POCKET_DEPLOY_ON_RENDER: deploying used to live only in the `caddy` install
# step, which is skipped once marked done — so a .env change re-rendered a file
# that nothing read and the running service kept the old config. Deploy here,
# where it runs every time. Validate first; never install a config Caddy rejects.
if command -v proot-distro >/dev/null 2>&1 && [ -f "$out/Caddyfile" ]; then
  if proot-distro login debian -- bash -lc "test -x /usr/bin/caddy || command -v caddy >/dev/null 2>&1" 2>/dev/null; then
    if proot-distro login debian -- bash -lc "cat > /tmp/Caddyfile.new && caddy validate --config /tmp/Caddyfile.new --adapter caddyfile" \
         < "$out/Caddyfile" >/dev/null 2>&1; then
      proot-distro login debian -- bash -lc "install -m 644 /tmp/Caddyfile.new /etc/caddy/Caddyfile" 2>/dev/null \
        && ok "deployed Caddyfile into the userland (restart caddy to apply)"
    else
      warn "rendered Caddyfile failed validation — NOT deployed"
    fi
  fi
fi
say "config rendered into $out"

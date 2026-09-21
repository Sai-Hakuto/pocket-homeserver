#!/data/data/com.termux/files/usr/bin/bash
# ops/harness.sh — launch the `pi` coding agent on this box.
#
# Deliberately an ops script, not a supervised service: pi is an interactive CLI.
# Supervising it would crash-loop and leave a permanent .degraded marker.
#
# Credentials come from ${DATA_DIR}/secrets/harness.env (0600) and are exported
# into pi's environment — never passed on argv, which /proc/*/cmdline exposes.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "${HERE}/../lib/common.sh"
load_env

SECRETS_FILE="${DATA_DIR}/secrets/harness.env"
WORKSPACE="${HARNESS_WORKSPACE:-${HOME}/.pocket/harness/workspace}"
PROVIDER="${HARNESS_PROVIDER:-openrouter}"
# POCKET_MODEL_DEFAULTS: model IDs are provider-specific — OpenRouter namespaces
# them ("deepseek/deepseek-v4.1-flash"), the direct DeepSeek API does not
# ("deepseek-flash") and 404s on the slashed form. Leave HARNESS_MODEL blank and
# the right default is chosen, so changing provider cannot silently misconfigure.
MODEL="${HARNESS_MODEL:-}"
if [ -z "${MODEL}" ]; then
  case "${PROVIDER}" in
    deepseek)   MODEL="deepseek-flash" ;;
    openrouter) MODEL="deepseek/deepseek-v4.1-flash" ;;
    anthropic)  MODEL="claude-sonnet-5" ;;
    openai)     MODEL="gpt-5.4" ;;
    google)     MODEL="gemini-3-flash" ;;
  esac
fi

STATUS=0
if [ "${1:-}" = "--status" ]; then STATUS=1; shift; fi

command -v pi >/dev/null 2>&1 || die "pi is not installed — set ENABLE_HARNESS=true and run scripts/install.sh"

[ -f "${SECRETS_FILE}" ] || die "missing ${SECRETS_FILE} — run scripts/install.sh to create the template"
# shellcheck disable=SC1090
. "${SECRETS_FILE}"

case "${PROVIDER}" in
  openrouter) KEY="${OPENROUTER_API_KEY:-}" ;;
  anthropic)  KEY="${ANTHROPIC_API_KEY:-}"  ;;
  openai)     KEY="${OPENAI_API_KEY:-}"     ;;
  google)     KEY="${GEMINI_API_KEY:-}"     ;;
  deepseek)   KEY="${DEEPSEEK_API_KEY:-}"   ;;
  *)          die "unknown HARNESS_PROVIDER='${PROVIDER}'" ;;
esac

if [ "${STATUS}" -eq 1 ]; then
  echo "harness   : installed"
  echo "pi        : $(pi --version 2>/dev/null || echo '?')"
  echo "node      : $(node -v 2>/dev/null || echo '?')"
  echo "provider  : ${PROVIDER}"
  echo "model     : ${MODEL}"
  echo "workspace : ${WORKSPACE}"
  echo "key       : $([ -n "${KEY}" ] && echo present || echo MISSING)"
  printf "tools     :"
  for c in rg fd tree git jq; do command -v "$c" >/dev/null 2>&1 && printf " %s" "$c"; done
  echo
  [ -n "${KEY}" ] || exit 1
  exit 0
fi

[ -n "${KEY}" ] || die "no API key for provider '${PROVIDER}' in ${SECRETS_FILE} — fill it in (single-quoted)"

# Export under every name pi may look for, so it never needs --api-key on argv.
export OPENROUTER_API_KEY ANTHROPIC_API_KEY OPENAI_API_KEY GEMINI_API_KEY DEEPSEEK_API_KEY

mkdir -p "${WORKSPACE}"
cd "${WORKSPACE}"

# Keep the CPU awake: Doze will otherwise freeze a long agent run mid-thought.
command -v termux-wake-lock >/dev/null 2>&1 && termux-wake-lock 2>/dev/null || true

exec pi --provider "${PROVIDER}" --model "${MODEL}" "$@"

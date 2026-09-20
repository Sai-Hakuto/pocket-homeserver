#!/data/data/com.termux/files/usr/bin/bash
# harness.sh — install the `pi` coding agent, NATIVELY in Termux.
#
# WHY TERMUX AND NOT THE USERLAND
# Four harnesses were tested on-device. Only this one runs natively:
#   Claude Code  -> needs @anthropic-ai/claude-code-linux-arm64-android, unpublished
#   OpenCode     -> its binary wants /lib/ld-musl-aarch64.so.1; Termux has no musl/glibc
#   Hermes Agent -> requires_python <3.14; Termux ships only 3.14.6
#   pi           -> plain JS bundle, NO optionalDependencies -> nothing to be missing
# Running native matters: PRoot intercepts syscalls via ptrace, and a coding agent
# is syscall-bound. Measured on this device: stat x3000 = 52 ms native vs 1310 ms
# under PRoot; grep across scripts/ = 26 ms vs 480 ms. ~20x, on the operations an
# agent performs constantly.
#
# NOT SUPERVISED, DELIBERATELY
# Every other module is a daemon; this is an interactive CLI. A `supervise` entry
# would exit immediately, crash-loop, and leave a permanent .degraded marker —
# the exact noise that masked a real Matrix outage earlier in this deployment.
# ENABLE_HARNESS is install-only. Nothing is added to start-stack.sh.
#
# NO ISOLATION — READ THIS
# Termux gives one app one uid. The agent runs as the same user as Caddy,
# conduwuit, the admin panel, the tunnel key and every secret under
# ${DATA_DIR}/secrets. It can read and rewrite all of it. There is no service
# account to drop to and PRoot is not a security boundary. This is acceptable
# only because the box is single-tenant. Do not expose this over the network.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "${HERE}/../lib/common.sh"
load_env

[ "${ENABLE_HARNESS:-false}" = "true" ] || { ok "harness disabled (ENABLE_HARNESS=false) — skipping"; exit 0; }

PI_PKG="@earendil-works/pi-coding-agent"
PI_VER="${PI_VER:-0.86.1}"
WORKSPACE="${HOME}/.pocket/harness/workspace"
SECRETS_FILE="${DATA_DIR}/secrets/harness.env"

# ── 1. Runtime: Node from Termux, not the userland ──────────────────────────
# pi declares engines: node >=22.19.0. Termux packages nodejs-lts 24.x, which
# satisfies it. Debian 13 in the userland ships Node 20 and would NOT.
say "ensuring Node (Termux-native) is installed"
if ! command -v node >/dev/null 2>&1; then
  pkg install -y nodejs-lts >/dev/null 2>&1 || die "failed to install nodejs-lts"
fi
NODE_MAJOR="$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)"
[ "${NODE_MAJOR}" -ge 22 ] || die "node ${NODE_MAJOR}.x is too old — pi needs >=22.19.0"
ok "node $(node -v)"

# ── 2. The tools the agent actually reaches for ─────────────────────────────
# pi ships read/bash/edit/write and shells out for everything else. Without these
# it greps with plain grep over a 200+ file tree on a phone. ripgrep and fd are
# the difference between usable and painful.
say "installing the search tooling pi shells out to (ripgrep, fd, tree)"
MISSING=()
command -v rg   >/dev/null 2>&1 || MISSING+=(ripgrep)
command -v fd   >/dev/null 2>&1 || MISSING+=(fd)
command -v tree >/dev/null 2>&1 || MISSING+=(tree)
if [ "${#MISSING[@]}" -gt 0 ]; then
  pkg install -y "${MISSING[@]}" >/dev/null 2>&1 || warn "could not install: ${MISSING[*]}"
fi
for c in rg fd tree git jq; do
  command -v "$c" >/dev/null 2>&1 && ok "  $c $( "$c" --version 2>/dev/null | head -1 )" || warn "  $c missing"
done

# ── 3. pi itself ────────────────────────────────────────────────────────────
# Pinned. npm exits 0 even when a package's binary never landed (this bit us with
# Claude Code), so NEVER trust the npm exit code — assert the CLI runs.
say "installing ${PI_PKG}@${PI_VER}"
if [ "$(pi --version 2>/dev/null || echo none)" = "${PI_VER}" ]; then
  ok "pi ${PI_VER} already installed"
else
  npm install -g "${PI_PKG}@${PI_VER}" 2>&1 | tail -5
fi
GOT="$(pi --version 2>/dev/null || true)"
[ -n "${GOT}" ] || die "pi did not install — 'pi --version' produced nothing (npm exit code is NOT proof)"
ok "pi ${GOT}"

# ── 4. Workspace on ext4 ────────────────────────────────────────────────────
# NOT under /sdcard: that is FUSE, with no POSIX locks and no real fsync — the
# same reason the repo keeps every database off the SD card.
mkdir -p "${WORKSPACE}"
chmod 700 "${WORKSPACE}"
ok "workspace ${WORKSPACE}"

# ── 5. Credentials ──────────────────────────────────────────────────────────
# Deliberately NOT in .env. .env is sourced by every script in this repo, and
# this deployment has twice been broken by bash expanding '$' inside a sourced
# file (the dufs $6$ hash, twice). Own file, 0600, single-quoted, off argv.
mkdir -p "$(dirname "${SECRETS_FILE}")"
if [ ! -f "${SECRETS_FILE}" ]; then
  umask 077
  cat > "${SECRETS_FILE}" <<'SECRETS'
# pocket-homeserver harness credentials. PRIVATE — 0600, never commit.
# Single-quote every value: this file is SOURCED by bash.
# Fill in the provider you intend to use; the others may stay empty.
OPENROUTER_API_KEY=''
ANTHROPIC_API_KEY=''
OPENAI_API_KEY=''
GEMINI_API_KEY=''
DEEPSEEK_API_KEY=''
SECRETS
  chmod 600 "${SECRETS_FILE}"
  ok "wrote credential template ${SECRETS_FILE} (0600) — fill in a key before use"
else
  ok "credentials already present at ${SECRETS_FILE}"
fi

# ── 6. AGENTS.md — what makes it not-bare ───────────────────────────────────
# pi auto-discovers AGENTS.md. Without it the agent knows nothing about this
# machine and will confidently suggest Docker, systemd and nohup — all three of
# which are wrong here. Regenerated every install so it cannot go stale.
say "writing the workspace AGENTS.md (pi discovers this automatically)"
cat > "${WORKSPACE}/AGENTS.md" <<AGENTS
# This machine

You are running on an Android phone (OnePlus 8 Pro) that serves as an always-on
home server. You are inside **Termux**, natively — not in a container, not in a VM.

Stack root: \`${POCKET_ROOT}\`
Data + secrets: \`${DATA_DIR}\`
Public entry: https://chat.${DOMAIN} (TLS terminates on a VPS; the phone dials out
over \`ssh -R\`, there are no inbound ports here)

## Hard constraints — do not suggest otherwise

- **No Docker. Ever.** The kernel lacks \`CONFIG_PID_NS\` and \`CONFIG_USER_NS\`
  (verified in /proc/config.gz) and the bootloader is locked. Root would not help.
- **No systemd.** Services run under this repo's own supervisor.
- **Never background anything with \`nohup ... &\`.** Android reaps orphaned
  processes; that has already killed sshd here. Use \`supervise <name> -- <cmd>\`
  from \`scripts/lib/common.sh\`, which records a .cmd that start-stack.sh re-arms.
- **Never run package installs from an interactive SSH session.** An install
  triggered Android's low-memory killer and took down all services at once. Run
  detached, log to a file, poll the log.

## Layout gotchas that have already caused outages here

- The admin panel runs from a **deployed copy**: gunicorn uses
  \`--chdir ~/pocket-admin\`. Editing \`admin/app.py\` in the repo changes nothing
  until you copy it over and restart \`adminweb\`.
- Caddy is the same: \`install.sh\` re-renders \`config/rendered/Caddyfile\`, but only
  *deploys* it inside the \`caddy\` step — which is skipped once its marker exists.
  Editing \`.env\` alone does not change a running service.
- Restarting \`adminweb\` fails on the first attempt (port 9000 still held). The
  supervisor's retry succeeds ~20s later. This is normal.

## Useful commands

\`\`\`bash
cd ${POCKET_ROOT}
./scripts/install.sh --status        # what is running
./scripts/install.sh --check         # dry run, changes nothing
bash scripts/ops/doctor.sh           # health
bash scripts/ops/restart.sh <svc>    # matrix | caddy | adminweb | tunnel | dufs | ...
proot-distro login debian            # the Debian userland, where the services live
\`\`\`

## Filesystem tiers

- \`\$HOME\` and \`\$HOME/.pocket\` are **ext4** — databases and anything needing real
  fsync or POSIX locks belong here.
- \`/sdcard\` is **FUSE** — fine for bulk media, wrong for a database.
AGENTS

chmod 600 "${WORKSPACE}/AGENTS.md"
ok "AGENTS.md written"

echo
ok "harness ready — run it with: bash ${POCKET_ROOT}/scripts/ops/harness.sh"
say "NOTE: this module is intentionally NOT supervised; it is an interactive CLI."

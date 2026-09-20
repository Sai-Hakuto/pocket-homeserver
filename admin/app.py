#!/usr/bin/env python3
"""pocket-homeserver — web admin panel.

A small, single-file Flask app that gives you a phone-friendly control panel for
the stack: live health + device stats, a log viewer, service restarts, backups,
the registration token, and a guarded "danger zone" for break-glass actions
(rotations + panic kill-switches). It runs Termux-native (NOT inside the proot
userland) because its whole job is to orchestrate the host — it shells out to the
service scripts, reads the supervisor pidfiles, and pgrep's the host processes.

SECURITY INVARIANTS:
  - Binds 127.0.0.1 ONLY; reached via Caddy (public, behind Cloudflare Access) or
    a loopback `ssh -L` tunnel.
  - Auth: scrypt password + signed session cookie + idle timeout.
  - CSRF on every POST (double-submit token).
  - Per-IP brute-force lockout (in-memory + persisted) — REQUIRES a single worker.
  - Optional Cloudflare Access JWT validation (RS256, pure stdlib) on every request
    that carries the header.
  - Scripts: allowlist only, no shell=True, no user input reaches a shell.
  - Filesystem delete: strict basename + bucket validation + realpath containment.
  - Audit log: every action.

Generalized from a working deployment; review before running on a fresh phone.
"""
import base64
import calendar
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import subprocess
import sys
import threading
import time
import urllib.request
from functools import wraps

# Force this process (incl. Werkzeug's request logger) to stamp times in UTC,
# regardless of the device timezone, so logs/audits are consistent and comparable.
os.environ["TZ"] = "UTC"
try:
    time.tzset()
except Exception:
    pass

from flask import Flask, request, session, redirect, url_for, abort, make_response
from werkzeug.middleware.proxy_fix import ProxyFix


# ---------- config (all from the environment; set by steps/70-install-admin.sh) ----------
def _env(name, default=""):
    return os.environ.get(name, default)

def _flag(name):
    return _env(name, "false").strip().lower() == "true"

DATA_DIR    = _env("DATA_DIR")                       # large volume (required)
POCKET_ROOT = _env("POCKET_ROOT")                    # repo root — where scripts/ lives (required)
SCRIPTS     = os.path.join(POCKET_ROOT, "scripts")
SECRETS     = os.path.join(DATA_DIR, "secrets")
STATE       = _env("POCKET_STATE_DIR") or os.path.join(DATA_DIR, "state")
LOGS        = _env("POCKET_LOG_DIR")   or os.path.join(DATA_DIR, "logs")
BACKUP_DIR  = _env("BACKUP_DIR")       or os.path.join(DATA_DIR, "backups")
# Metrics ring written by scripts/ops/metrics-sampler.py. It lives on ext4 (Termux
# $HOME), NOT under DATA_DIR (often exFAT); the sampler's launcher pins the SAME
# default, so the panel finds it without threading the path through .env.
METRICS_LOG = _env("POCKET_METRICS_LOG") or os.path.join(
    os.path.expanduser("~"), ".pocket", "metrics", "metrics.jsonl")

# Pocket Pages (Sites) — Termux-native host-side view of SITES_ROOT inside the
# proot userland (SPEC-SITES-PANEL AD-1); the exact PD_BASE pattern already used by
# ops/backup-all.sh:33 and ops/restore.sh:43. POCKET_SITES_ROOT is the same
# test-fixture override seam scripts/sites/lib-sites.sh's own SITES_ROOT supports
# (unset in production, so this falls back to the real userland path) — keeps the
# panel's registry/staging reads from ever drifting from what the pipeline sees.
PD_BASE        = os.path.join(_env("PREFIX", "/data/data/com.termux/files/usr"),
                               "var/lib/proot-distro/installed-rootfs")
SITES_ROOT     = _env("POCKET_SITES_ROOT") or os.path.join(PD_BASE, "debian/var/www/sites")
SITES_STAGING  = os.path.join(SITES_ROOT, ".staging")
SITES_REGISTRY = os.path.join(SITES_ROOT, ".registry.json")
SITES_MAX_UPLOAD_MB = int(_env("SITES_MAX_UPLOAD_MB", "200") or "200")
# Git-push-to-deploy (Forgejo webhooks, SPEC-DIFFERENTIATORS §6). Per-site
# secrets live on ext4 under POCKET_STATE_DIR (AD-4), never DATA_DIR.
SITES_WEBHOOK_SECRET_DIR    = os.path.join(STATE, "sites-webhook")
SITES_WEBHOOK_BRANCH        = _env("SITES_WEBHOOK_BRANCH", "main") or "main"
SITES_WEBHOOK_COOLDOWN_S    = int(_env("SITES_WEBHOOK_COOLDOWN_S", "10") or "10")
SITES_WEBHOOK_STAGE_TIMEOUT = int(_env("SITES_WEBHOOK_STAGE_TIMEOUT", "60") or "60")
# Forms (Netlify-Forms clone, SPEC-DIFFERENTIATORS §8 + corrections C-2/C-3).
# All derived state on ext4 under POCKET_STATE_DIR (AD-4). The gate file is
# written by apps/sites.sh at render time (C-2) — the panel only READS it.
SITES_FORMS_DB        = os.path.join(STATE, "sites-forms.db")
SITES_FORMS_GATE_FILE = os.path.join(STATE, "sites-forms.gate")
SITES_FORMS_GC_STAMP  = os.path.join(STATE, "sites-forms.gc-stamp")
SITES_FORMS_MAX_BODY_KB   = int(_env("SITES_FORMS_MAX_BODY_KB", "64") or "64")
SITES_FORMS_MAX_FIELDS    = int(_env("SITES_FORMS_MAX_FIELDS", "50") or "50")
SITES_FORMS_MAX_FIELD_LEN = int(_env("SITES_FORMS_MAX_FIELD_LEN", "4000") or "4000")
SITES_FORMS_RATE_LIMIT_PER_HOUR = int(_env("SITES_FORMS_RATE_LIMIT_PER_HOUR", "20") or "20")
SITES_FORMS_RETENTION_DAYS = int(_env("SITES_FORMS_RETENTION_DAYS", "180") or "180")
SITES_FORMS_EMAIL_TO  = _env("SITES_FORMS_EMAIL_TO", "") or ""
MAIL_SUBMISSION_PORT  = int(_env("MAIL_SUBMISSION_PORT", "9587") or "9587")
# Analytics-lite (SPEC-DIFFERENTIATORS §9, AD-10/11/12): on-demand parse of
# the shared sites-access.log, TTL-cached like gather_stats_cached() — no
# daemon, no derived store, nothing IP-shaped persisted.
SITES_ANALYTICS_RETENTION_DAYS = int(_env("SITES_ANALYTICS_RETENTION_DAYS", "30") or "30")
SITES_ANALYTICS_MAX_LINES      = int(_env("SITES_ANALYTICS_MAX_LINES", "200000") or "200000")
SITES_ANALYTICS_CACHE_TTL_S    = int(_env("SITES_ANALYTICS_CACHE_TTL_S", "300") or "300")

PASSWORD_FILE       = os.path.join(SECRETS, "adminweb-password.hash")
SESSION_SECRET_FILE = os.path.join(SECRETS, "adminweb-session.bin")
AUDIT_LOG           = os.path.join(LOGS, "admin-audit.log")
# Optional admin-bot quick-command widget (the /bot/send route). admin-credentials.env
# holds the operator's ADMIN_TOKEN (written by bootstrap/create-admin.sh); adminbot.env
# holds the bot's ADMIN_ROOM (the private admin-ops room).
ADMIN_CRED_FILE     = os.path.join(SECRETS, "admin-credentials.env")
ADMINBOT_CRED_FILE  = os.path.join(SECRETS, "adminbot.env")
MATRIX_HS_API       = "http://127.0.0.1:8448"   # same loopback homeserver as gather_health()

BIND_HOST   = "127.0.0.1"
BIND_PORT   = int(_env("ADMINWEB_PORT", "9000") or "9000")

DOMAIN      = _env("DOMAIN", "localhost")
ADMIN_HOST  = _env("ADMIN_HOST") or f"admin.{DOMAIN}"
ADMIN_USER  = _env("ADMIN_USER", "admin")
BRAND       = _env("ADMIN_BRAND") or "pocket-homeserver"
CADDY_BIND  = _env("CADDY_BIND", "127.0.0.1")
CADDY_PORT  = _env("CADDY_PORT", "8443")
AUTHGW_PORT = _env("AUTHGW_PORT", "9095")
# The canonical .env (same path load_env uses: $POCKET_ENV or $POCKET_ROOT/.env). The
# app-catalog writes ENABLE_* flags here (atomic, 0600) via env_set(); nothing else
# the panel does mutates it.
ENV_FILE    = _env("POCKET_ENV") or os.path.join(POCKET_ROOT, ".env")
IDLE_SECONDS = int(_env("ADMIN_IDLE_MINUTES", "30") or "30") * 60

# Which optional apps are enabled (drives the health checks + restart buttons so a
# disabled app is never shown as a false DOWN).
ENABLE = {
    "auth-gw":  _flag("ENABLE_AUTH_GATEWAY"),
    "linkding": _flag("ENABLE_LINKDING"),
    "pingvin":  _flag("ENABLE_PINGVIN"),
    "freshrss": _flag("ENABLE_FRESHRSS"),
    "memos":    _flag("ENABLE_MEMOS"),
    "vikunja":  _flag("ENABLE_VIKUNJA"),
    "searxng":  _flag("ENABLE_SEARXNG"),
    "ittools":  _flag("ENABLE_ITTOOLS"),
    "gatus":    _flag("ENABLE_GATUS"),
    "sites":    _flag("ENABLE_SITES"),
    "sites-webhooks": _flag("ENABLE_SITES_WEBHOOKS"),
    "sites-forms": _flag("ENABLE_SITES_FORMS"),
    "sites-forms-email": _flag("ENABLE_SITES_FORMS_EMAIL"),
    "sites-analytics": _flag("ENABLE_SITES_ANALYTICS"),
    "wallabag":   _flag("ENABLE_WALLABAG"),
    "radicale":   _flag("ENABLE_RADICALE"),
    "trilium":    _flag("ENABLE_TRILIUM"),
    "vaultwarden":_flag("ENABLE_VAULTWARDEN"),
    "dufs":          _flag("ENABLE_DUFS"),
    "filebrowser":   _flag("ENABLE_FILEBROWSER"),
    "syncthing":     _flag("ENABLE_SYNCTHING"),
    "navidrome":     _flag("ENABLE_NAVIDROME"),
    "kavita":        _flag("ENABLE_KAVITA"),
    "audiobookshelf":_flag("ENABLE_AUDIOBOOKSHELF"),
    "forgejo":       _flag("ENABLE_FORGEJO"),
    "adguard":       _flag("ENABLE_ADGUARD"),
    "tailscale":     _flag("ENABLE_TAILSCALE"),
    "proxy-routes":  _flag("ENABLE_PROXY_ROUTES"),
    "app-catalog":   _flag("ENABLE_APP_CATALOG"),
    "backup-daemon": _flag("ENABLE_BACKUP_DAEMON"),
    "honeypot": _flag("ENABLE_HONEYPOT"),
    "user-filter":  _flag("ENABLE_USER_FILTER"),
    "media-filter": _flag("ENABLE_MEDIA_FILTER"),
    "cloud-bots":   _flag("ENABLE_CLOUD_BOTS"),
    "exobot":       _flag("ENABLE_EXOBOT"),
    "exobot-ui":    _flag("EXOBOT_UI"),
    "stickers":     _flag("ENABLE_STICKERS"),
    "adminbot":     _flag("ENABLE_ADMINBOT"),
    "email":        _flag("ENABLE_EMAIL"),
    "mcp":          _flag("ENABLE_MCP"),
    "metrics":      _flag("ENABLE_METRICS"),
    "user-admin":   _flag("ENABLE_USER_ADMIN"),
    "offsite":      _flag("ENABLE_OFFSITE_BACKUP"),
}

# Script allowlist — the ONLY scripts a click can run, relative to scripts/. No
# shell=True; no user input ever reaches a shell (run_script joins fixed argv).
SCRIPTS_OK = {
    "status":            {"argv": ["ops/status.sh"],                   "kind": "info"},
    "run-doctor":        {"argv": ["ops/doctor.sh"],                   "kind": "info"},
    "backup-now":        {"argv": ["ops/backup-db.sh"],                "kind": "mutate"},
    "full-backup":       {"argv": ["ops/backup-all.sh"],              "kind": "async"},
    "rotate-backups":    {"argv": ["ops/rotate-backups.sh"],          "kind": "mutate"},
    "offsite-push":      {"argv": ["ops/offsite-push.sh"],            "kind": "async"},
    "restart-stack":     {"argv": ["start-stack.sh", "--restart"],    "kind": "restart"},
    # per-service restarts → ops/restart.sh <name> (re-supervises from the recorded cmd)
    "restart-matrix":      {"argv": ["ops/restart.sh", "matrix"],          "kind": "restart"},
    "restart-caddy":       {"argv": ["ops/restart.sh", "caddy"],           "kind": "restart"},
    "restart-cloudflared": {"argv": ["ops/restart.sh", "cloudflared"],     "kind": "restart"},
    "restart-auth-gw":     {"argv": ["ops/restart.sh", "auth-gw"],         "kind": "restart"},
    # restarting the panel kills the worker handling THIS request → run detached.
    "restart-adminweb":    {"argv": ["ops/restart.sh", "adminweb"],        "kind": "async"},
    "restart-linkding":      {"argv": ["ops/restart.sh", "linkding"],       "kind": "restart"},
    "restart-linkding-tasks":{"argv": ["ops/restart.sh", "linkding-tasks"], "kind": "restart"},
    "restart-pingvin":     {"argv": ["ops/restart.sh", "pingvin"],         "kind": "restart"},
    "restart-freshrss":    {"argv": ["ops/restart.sh", "freshrss"],        "kind": "restart"},
    "restart-freshrss-refresh":{"argv": ["ops/restart.sh", "freshrss-refresh"], "kind": "restart"},
    "restart-searxng":     {"argv": ["ops/restart.sh", "searxng"],         "kind": "restart"},
    "restart-memos":       {"argv": ["ops/restart.sh", "memos"],           "kind": "restart"},
    "restart-vikunja":     {"argv": ["ops/restart.sh", "vikunja"],         "kind": "restart"},
    "restart-gatus":       {"argv": ["ops/restart.sh", "gatus"],           "kind": "restart"},
    "restart-wallabag":    {"argv": ["ops/restart.sh", "wallabag"],        "kind": "restart"},
    "restart-radicale":    {"argv": ["ops/restart.sh", "radicale"],        "kind": "restart"},
    "restart-trilium":     {"argv": ["ops/restart.sh", "trilium"],         "kind": "restart"},
    "restart-vaultwarden": {"argv": ["ops/restart.sh", "vaultwarden"],     "kind": "restart"},
    "restart-dufs":        {"argv": ["ops/restart.sh", "dufs"],            "kind": "restart"},
    "restart-filebrowser": {"argv": ["ops/restart.sh", "filebrowser"],    "kind": "restart"},
    "restart-syncthing":   {"argv": ["ops/restart.sh", "syncthing"],      "kind": "restart"},
    "restart-navidrome":     {"argv": ["ops/restart.sh", "navidrome"],      "kind": "restart"},
    "restart-kavita":        {"argv": ["ops/restart.sh", "kavita"],         "kind": "restart"},
    "restart-audiobookshelf":{"argv": ["ops/restart.sh", "audiobookshelf"], "kind": "restart"},
    "restart-forgejo":       {"argv": ["ops/restart.sh", "forgejo"],        "kind": "restart"},
    "restart-adguard":       {"argv": ["ops/restart.sh", "adguard"],        "kind": "restart"},
    # key matches the supervised name "tailscaled" so _restart_for("tailscaled")
    # (built as f"restart-{procname}") resolves to this action.
    "restart-tailscaled":    {"argv": ["ops/restart.sh", "tailscaled"],     "kind": "restart"},
    "apply-proxy-routes":    {"argv": ["apps/proxy-routes.sh"],             "kind": "async"},
    # Sites (Pocket Pages) — dispatched from dedicated /sites/rebuild-registry
    # and /sites/apply-vhost routes (SPEC-SITES-PANEL §5), not the generic
    # /action endpoint, so each can carry its own ENABLE.get("sites") gate.
    "sites-rebuild-registry": {"argv": ["sites/site-list.sh", "--rebuild"], "kind": "mutate"},
    "sites-apply-vhost":      {"argv": ["apps/sites.sh"],                   "kind": "async"},
    "restart-backup-daemon": {"argv": ["ops/restart.sh", "backup-daemon"], "kind": "restart"},
    "restart-honeypot-watcher": {"argv": ["ops/restart.sh", "honeypot-watcher"], "kind": "restart"},
    "restart-metrics-sampler": {"argv": ["ops/restart.sh", "metrics-sampler"], "kind": "restart"},
    "restart-user-filter":  {"argv": ["ops/restart.sh", "user-filter"],  "kind": "restart"},
    "restart-media-filter": {"argv": ["ops/restart.sh", "media-filter"], "kind": "restart"},
    # danger-tier (go through the two-page typed confirmation)
    "rotate-reg-token":  {"argv": ["ops/rotate-registration-token.sh"], "kind": "danger"},
    "rotate-admin-pass": {"argv": ["ops/rotate-admin-password.sh"],      "kind": "danger"},
    "panic-soft":        {"argv": ["ops/panic-soft.sh"],                "kind": "danger"},
    "panic-hard":        {"argv": ["ops/panic-hard.sh"],                "kind": "danger"},
}

# ── App catalog (in-panel module manager) ────────────────────────────────────
# The FIXED set of optional modules the catalog page can enable + install. This dict
# is the allowlist: a module key from a request is only ever VALIDATED against it (it
# never flows into argv). Each value = (label, ENABLE_ var, installer script relative
# to scripts/). Below, a derived "install-<key>" SCRIPTS_OK entry is registered for
# each, so the install action runs ONLY through run_script_detached(allowlisted key) —
# there is no path from request input to a command line. Install/Enable only; disable
# + data-deletion stay CLI-only (out of the web blast radius).
APP_CATALOG = {
    "dufs":          ("Dufs — files + WebDAV",          "ENABLE_DUFS",          "apps/dufs.sh"),
    "filebrowser":   ("FileBrowser — files + shares",   "ENABLE_FILEBROWSER",   "apps/filebrowser.sh"),
    "syncthing":     ("Syncthing — P2P file sync",      "ENABLE_SYNCTHING",     "steps/89-install-syncthing.sh"),
    "wallabag":      ("Wallabag — read-later",          "ENABLE_WALLABAG",      "apps/wallabag.sh"),
    "radicale":      ("Radicale — CalDAV/CardDAV",      "ENABLE_RADICALE",      "apps/radicale.sh"),
    "trilium":       ("Trilium — notes / wiki",         "ENABLE_TRILIUM",       "apps/trilium.sh"),
    "vaultwarden":   ("Vaultwarden — passwords",        "ENABLE_VAULTWARDEN",   "apps/vaultwarden.sh"),
    "navidrome":     ("Navidrome — music",              "ENABLE_NAVIDROME",     "apps/navidrome.sh"),
    "kavita":        ("Kavita — comics / ebooks",       "ENABLE_KAVITA",        "apps/kavita.sh"),
    "audiobookshelf":("Audiobookshelf — audiobooks",    "ENABLE_AUDIOBOOKSHELF","apps/audiobookshelf.sh"),
    "forgejo":       ("Forgejo — git forge",            "ENABLE_FORGEJO",       "apps/forgejo.sh"),
    "adguard":       ("AdGuard Home — DoH resolver",    "ENABLE_ADGUARD",       "apps/adguard.sh"),
    "proxy-routes":  ("BYO reverse-proxy",              "ENABLE_PROXY_ROUTES",  "apps/proxy-routes.sh"),
    "tailscale":     ("Tailscale — mesh VPN",           "ENABLE_TAILSCALE",     "steps/90-install-tailscale.sh"),
    "sites":         ("Pocket Pages — static sites",    "ENABLE_SITES",         "apps/sites.sh"),
}
for _ck, _cv in APP_CATALOG.items():
    # async = run detached + logged (a source build can take 15–40 min); the panel
    # worker is never blocked and the install survives the worker timeout.
    SCRIPTS_OK[f"install-{_ck}"] = {"argv": [_cv[2]], "kind": "async"}

# Danger metadata: impact + reversibility + a per-action confirmation phrase
# (deliberately varied to defeat muscle-memory).
DANGER_META = {
    "rotate-reg-token": {
        "title": "Rotate registration token",
        "phrase": "rotate token",
        "impact": [
            "The homeserver restarts → a brief (tens of seconds) chat interruption.",
            "The current shared invite token becomes INVALID immediately.",
            "Token-gated registration is (re)enabled with the new token.",
            "Anyone still mid-signup must be given the new token; already-registered users are unaffected.",
        ],
        "reversible": False,
    },
    "rotate-admin-pass": {
        "title": "Rotate admin password",
        "phrase": "change admin password",
        "impact": [
            "The web admin panel login password is replaced with a fresh random one.",
            "No server downtime; your CURRENT session stays signed in.",
            "The new password is shown ONCE on the result page — save it then.",
            "New logins require the new password.",
        ],
        "reversible": False,
    },
    "panic-soft": {
        "title": "Soft panic (cut public access)",
        "phrase": "soft panic",
        "impact": [
            "Stops the Cloudflare Tunnel — the box is no longer reachable from the internet.",
            "All local/loopback services keep running; you can still administer locally.",
            "Fully reversible: restart the stack to restore public access.",
        ],
        "reversible": True,
    },
    "panic-hard": {
        "title": "Hard panic (whole stack offline)",
        "phrase": "hard panic",
        "impact": [
            "Stops cloudflared, Caddy, the homeserver, the auth gateway, and all apps.",
            "The admin panel itself is preserved so you can recover from loopback.",
            "Reversible: restart the stack, then your app scripts.",
        ],
        "reversible": True,
    },
    "restart-stack": {
        "title": "Restart the core stack",
        "phrase": "restart stack",
        "impact": [
            "Restarts matrix + Caddy + cloudflared in order.",
            "Brief ingress outage while the tunnel reconnects (tens of seconds).",
            "Apps are not touched.",
        ],
        "reversible": True,
    },
    "delete-backup": {
        "title": "Delete backup",
        "phrase": "delete backup",
        "impact": [
            "Permanently removes the selected backup archive and its checksum sidecar.",
            "If this is your only copy of that snapshot, it cannot be recovered.",
        ],
        "reversible": False,
    },
    # Pocket Pages (Sites) — parameterized danger action; mirrors delete-backup's
    # shape (SPEC-SITES-PANEL AD-6). Impact text is generic boilerplate shared by
    # every site (same convention as every other DANGER_META entry here) — the
    # specific site name/URL is shown separately on the confirm page itself.
    "site-delete": {
        "title": "Delete site",
        "phrase": "delete site",
        "impact": [
            "Permanently removes ALL releases for this site — not just the live one.",
            f"The site's <name>.{DOMAIN} URL starts 404ing immediately.",
            "If this is the only copy of the source outside your own backup, it cannot be recovered.",
        ],
        "reversible": False,
    },
}


# ---------- flask ----------
def _load_session_secret():
    os.makedirs(SECRETS, exist_ok=True)
    if not os.path.exists(SESSION_SECRET_FILE):
        with open(SESSION_SECRET_FILE, "wb") as f:
            f.write(secrets.token_bytes(32))
        try: os.chmod(SESSION_SECRET_FILE, 0o600)
        except Exception: pass
    with open(SESSION_SECRET_FILE, "rb") as f:
        return f.read()


app = Flask(__name__)
app.secret_key = _load_session_secret()
# SESSION_COOKIE_SECURE defaults OFF so the panel also works as a phone-local PWA
# on http://127.0.0.1 (Secure cookies never travel over plain-HTTP loopback). The
# public path is protected by: the Cloudflare Tunnel (TLS to the edge), Cloudflare
# Access in front of origin, HSTS from Caddy, and HttpOnly + SameSite=Lax + idle
# timeout. Set ADMINWEB_SECURE_COOKIE=1 to forbid loopback (HTTP) access.
#
# SameSite=Lax (not Strict): when the panel sits behind a Cloudflare Access gate
# the operator arrives via a cross-site redirect, and Strict would withhold the
# session cookie on that first navigation (breaking the first CSRF check). Lax
# sends it on top-level navigations while still withholding it on cross-site
# POSTs — and CSRF is independently enforced by the double-submit token.
_SECURE_COOKIE = _env("ADMINWEB_SECURE_COOKIE", "0") in ("1", "true", "yes")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=_SECURE_COOKIE,
    PERMANENT_SESSION_LIFETIME=IDLE_SECONDS,
)
# DoS bugfix independent of Sites (SPEC-SITES-PANEL §9): no route had ANY
# body-size ceiling before this — Werkzeug buffers a form-encoded body into
# memory before a view function ever runs, so an unauthenticated multi-gigabyte
# POST to /login used to force a full buffer before credential checking even
# ran. Sized off SITES_MAX_UPLOAD_MB (the largest legitimate body any route
# expects) with headroom; POST /sites/upload's own `length > cap` check is the
# PRECISE enforcement point for that route — this is the blanket backstop for
# every other POST (login, catalog/install, confirm/<key>, backups/delete, ...).
app.config["MAX_CONTENT_LENGTH"] = (SITES_MAX_UPLOAD_MB + 16) * 1024 * 1024
# Trust X-Forwarded-* from Caddy (one hop only) so rate-limit + audit see the real
# client IP, not 127.0.0.1.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)


# App-level CSP + security headers (defense in depth; Caddy also sets a CSP, but
# the loopback ssh -L path bypasses Caddy). 'unsafe-inline' covers the inline
# style attrs + the SSE <script>; connect-src 'self' allows the /events stream.
_CSP = ("default-src 'none'; script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "connect-src 'self'; manifest-src 'self'; base-uri 'none'; "
        "form-action 'self'; frame-ancestors 'none'")


@app.after_request
def _security_headers(resp):
    resp.headers.setdefault("Content-Security-Policy", _CSP)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    return resp


def _load_env(path):
    d = {}
    try:
        with open(path) as f:
            for line in f:
                if "=" in line and not line.startswith("#"):
                    k, v = line.strip().split("=", 1)
                    d[k] = v
    except Exception:
        pass
    return d


# ---------- helpers ----------
def e(s):
    return html.escape(str(s), quote=True)


def log_audit(action, **extra):
    ua = ""
    try:
        ua = request.user_agent.string[:200] if request else ""
    except Exception:
        pass
    line = {
        "ts": time.strftime("%FT%TZ", time.gmtime()),
        "user": session.get("user", "<anon>"),
        "ip": request.remote_addr if request else None,
        "ua": ua,
        "action": action,
        **extra,
    }
    try:
        os.makedirs(LOGS, exist_ok=True)
        with open(AUDIT_LOG, "a") as f:
            f.write(json.dumps(line) + "\n")
    except Exception:
        pass


def scrypt_hash(pw, salt):
    return hashlib.scrypt(pw.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)


def verify_password(pw):
    try:
        with open(PASSWORD_FILE) as f:
            stored = f.read().strip()
        salt_hex, hash_hex = stored.split(":", 1)
        salt = bytes.fromhex(salt_hex)
        return hmac.compare_digest(scrypt_hash(pw, salt).hex(), hash_hex)
    except Exception:
        return False


def new_csrf():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def csrf_ok():
    return (request.form.get("_csrf") and
            request.form.get("_csrf") == session.get("csrf"))


_FAILS = {}            # ip -> (count, last_ts); thread-safe via _FAILS_LOCK
_FAILS_LIFETIME = {}   # ip -> lifetime fail count (exponential backoff)
_FAILS_LOCK = threading.Lock()

# Persist _FAILS to disk so an adminweb restart doesn't reset the brute-force
# counter. Rewritten on every record_fail / clear_fail; trivially small.
_FAILS_FILE = os.path.join(STATE, "adminweb-fails.json")

def _save_fails_unlocked():
    """Persist current _FAILS / _FAILS_LIFETIME state. Caller holds _FAILS_LOCK.
    Best-effort: failures are logged, never raised."""
    try:
        os.makedirs(os.path.dirname(_FAILS_FILE), exist_ok=True)
        tmp = _FAILS_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump({
                "fails":    {k: list(v) for k, v in _FAILS.items()},
                "lifetime": _FAILS_LIFETIME,
            }, f)
        os.replace(tmp, _FAILS_FILE)
    except Exception as ex:
        print(f"[adminweb] _FAILS persist failed: {ex}", file=sys.stderr)

def _load_fails():
    """Restore _FAILS / _FAILS_LIFETIME from disk on boot. Best-effort."""
    try:
        if not os.path.exists(_FAILS_FILE):
            return
        with open(_FAILS_FILE) as f:
            d = json.load(f)
        with _FAILS_LOCK:
            _FAILS.update({k: tuple(v) for k, v in (d.get("fails") or {}).items()})
            _FAILS_LIFETIME.update(d.get("lifetime") or {})
    except Exception as ex:
        print(f"[adminweb] _FAILS load failed: {ex}", file=sys.stderr)

# Regenerate this nonce on every adminweb boot so any session minted by a prior
# process is invalidated immediately (the cookie still decrypts with the same
# SECRET_KEY, but won't carry the current BOOT_NONCE → redirect to /login).
BOOT_NONCE = secrets.token_hex(16)

# Up to 5 fails / 15 min, then exponential backoff per-IP on lifetime fails:
# 6th fail = 30 min lockout, 7th = 60 min, ... capped at 24h.
_BASE_LOCKOUT_S = 15 * 60
_MAX_LOCKOUT_S = 24 * 3600

# The only legitimate path to the panel is Caddy on loopback, or a header-less
# `ssh -L` tunnel which is ALSO loopback. ProxyFix(x_for=1) trusts the FIRST
# X-Forwarded-For hop by COUNT, not by proxy address, so anything that could reach
# the bind port WITHOUT traversing Caddy could supply a forged XFF to evade the
# per-IP lockout or frame a victim IP. ProxyFix stashes the real pre-rewrite socket
# peer in environ['werkzeug.proxy_fix.orig_remote_addr']; if that is not loopback,
# the request did NOT come through Caddy and its XFF is untrustworthy.
def _socket_peer_trusted():
    env = request.environ
    peer = env.get("werkzeug.proxy_fix.orig_remote_addr") or env.get("REMOTE_ADDR")
    return peer in ("127.0.0.1", "::1")


def _lockout_ip():
    """The IP to key the brute-force lockout on. When the socket peer is loopback
    (the legit Caddy path) use the ProxyFix-resolved client IP. When it is NOT
    loopback (a direct-to-origin request with an attacker-controlled XFF), ignore
    the spoofable XFF and key on the real socket peer instead."""
    if _socket_peer_trusted():
        return request.remote_addr or "?"
    peer = request.environ.get("werkzeug.proxy_fix.orig_remote_addr") \
        or request.environ.get("REMOTE_ADDR") or "?"
    return f"untrusted:{peer}"


def rate_limit_login(ip):
    with _FAILS_LOCK:
        c, t = _FAILS.get(ip, (0, 0))
        lifetime = _FAILS_LIFETIME.get(ip, 0)
    if time.time() - t > _BASE_LOCKOUT_S:
        return True
    if c < 5:
        return True
    if lifetime > 5:
        extra = min(_MAX_LOCKOUT_S, _BASE_LOCKOUT_S * (2 ** (lifetime - 5)))
        if time.time() - t < extra:
            return False
    return False

def record_fail(ip):
    with _FAILS_LOCK:
        c, _ = _FAILS.get(ip, (0, 0))
        _FAILS[ip] = (c + 1, time.time())
        _FAILS_LIFETIME[ip] = _FAILS_LIFETIME.get(ip, 0) + 1
        _save_fails_unlocked()

def clear_fail(ip):
    with _FAILS_LOCK:
        _FAILS.pop(ip, None)
        _save_fails_unlocked()


def login_required(f):
    @wraps(f)
    def inner(*a, **kw):
        if not session.get("auth"):
            return redirect(url_for("login"))
        if session.get("boot_nonce") != BOOT_NONCE:
            session.clear()
            return redirect(url_for("login"))
        return f(*a, **kw)
    return inner


def run_script(key, timeout=600):
    spec = SCRIPTS_OK.get(key)
    if not spec: return -1, "not allowed"
    cmd = ["bash", os.path.join(SCRIPTS, spec["argv"][0])] + spec["argv"][1:]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout + p.stderr
    except subprocess.TimeoutExpired:
        return -1, f"timed out after {timeout}s"
    except Exception as ex:
        return -2, str(ex)


def run_script_detached(key):
    """Launch a long-running ("async") script detached from this gunicorn worker,
    so it survives the worker timeout (and, for restart-adminweb, the worker being
    killed). Output goes to logs/adminweb-async.log. Returns (ok, logname)."""
    spec = SCRIPTS_OK.get(key)
    if not spec:
        return False, ""
    argv0 = spec["argv"][0]
    logname = os.path.basename(argv0)
    logname = logname[:-3] + ".log" if logname.endswith(".sh") else logname + ".log"
    cmd = ["bash", os.path.join(SCRIPTS, argv0)] + spec["argv"][1:]
    sink = os.path.join(LOGS, "adminweb-async.log")
    try:
        os.makedirs(LOGS, exist_ok=True)
        with open(sink, "ab", buffering=0) as lf:
            subprocess.Popen(
                cmd, stdin=subprocess.DEVNULL, stdout=lf, stderr=lf,
                start_new_session=True, close_fds=True,
            )
        return True, logname
    except Exception:
        return False, logname


def read_file(path, default=""):
    try:
        with open(path) as f: return f.read()
    except Exception: return default


# ---------- secret redaction (served-log defense-in-depth) ----------
# The app-catalog runs install scripts detached; their combined stdout/stderr lands in
# the SHARED logs/adminweb-async.log, and those scripts load_env the FULL .env — so a
# script that echoes a secret (or errors with one in the message) could otherwise leak
# it through /logs. redact_secrets() is applied to EVERY served log (single chokepoint):
# it exact-matches the secret VALUES the panel can see (its own env + the .env file),
# then pattern-redacts common token shapes. Over-redaction is preferred to a leak.
_SECRET_NAME_RE = re.compile(
    r"(?i)(token|secret|password|passwd|api[_-]?key|access[_-]?key|authkey|"
    r"priv(?:ate)?[_-]?key|credential|tunnel)")
_REDACT_ASSIGN_RE = re.compile(
    r"(?i)([A-Za-z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API[_-]?KEY|ACCESS[_-]?KEY|"
    r"AUTHKEY|PRIVATE[_-]?KEY|CREDENTIAL))"
    r"(\s*[=:]\s*)(\S+)")
_REDACT_LITERAL_RES = [
    re.compile(r"tskey-[A-Za-z0-9_-]{6,}"),                 # Tailscale auth keys
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}"),   # bearer tokens
]


def _scan_env_file(path, vals, name_filtered):
    """Add secret-looking values from a KEY=VALUE file to `vals`. When name_filtered is
    True only values whose KEY matches _SECRET_NAME_RE are added (the file mixes secret
    and non-secret config); when False EVERY value len>=6 is added (a dedicated 0600
    secrets file holds nothing but secrets, so over-redact)."""
    try:
        with open(path, errors="replace") as f:
            for ln in f:
                ln = ln.strip()
                if not ln or ln.startswith("#") or "=" not in ln:
                    continue
                k, v = ln.split("=", 1)
                v = v.strip().strip('"').strip("'")
                if v and len(v) >= 6 and (not name_filtered or _SECRET_NAME_RE.search(k)):
                    vals.add(v)
    except OSError:
        pass


def _secret_values():
    """Literal secret VALUES the panel can see, returned longest-first for clean
    substring replacement. Sources, in order:
      1. the panel's own environment + the main .env (the detached install scripts
         load_env it, so its values are exactly what could leak into the shared async
         log) — filtered by secret-ish KEY name, as both hold non-secret config too;
      2. the 0600 sibling secret files under SECRETS/ (offsite.env, mail-relay.env,
         mail-r2.env, alert-matrix.env, admin-credentials.env, dufs.env, …). These hold
         the S3/R2/SMTP/Matrix creds the backup + install scripts source but that never
         reach the panel's env NOR the main .env, so a value match was previously
         impossible — every value in them is a secret, so redact unconditionally."""
    vals = set()
    for k, v in os.environ.items():
        if v and len(v) >= 6 and _SECRET_NAME_RE.search(k):
            vals.add(v)
    _scan_env_file(ENV_FILE, vals, name_filtered=True)
    try:
        for fn in sorted(os.listdir(SECRETS)):
            if fn.endswith(".env"):
                _scan_env_file(os.path.join(SECRETS, fn), vals, name_filtered=False)
    except OSError:
        pass
    return sorted(vals, key=len, reverse=True)


def redact_secrets(text):
    """Scrub secret values from `text` before it is served. Never raises."""
    if not text:
        return text
    try:
        for v in _secret_values():
            if v in text:
                text = text.replace(v, "***REDACTED***")
        text = _REDACT_ASSIGN_RE.sub(lambda m: m.group(1) + m.group(2) + "***REDACTED***", text)
        for rx in _REDACT_LITERAL_RES:
            text = rx.sub("***REDACTED***", text)
    except Exception:
        return "[redaction error — log withheld]"
    return text


def env_set(key, value):
    """Set KEY=value in the canonical .env, atomically, 0600. KEY is restricted to the
    ENABLE_* flag namespace (defense: the only thing the catalog ever writes) and VALUE
    is forced to a literal true/false — so nothing operator/request-derived reaches the
    file as a key or an arbitrary value. Returns True on success."""
    if not re.fullmatch(r"ENABLE_[A-Z0-9_]+", key or ""):
        return False
    value = "true" if str(value).lower() in ("1", "true", "yes", "on") else "false"
    try:
        try:
            with open(ENV_FILE, errors="replace") as f:
                lines = f.readlines()
        except OSError:
            lines = []
        out, found = [], False
        for ln in lines:
            stripped = ln.lstrip()
            if stripped.split("=", 1)[0].strip() == key and "=" in stripped:
                out.append(f"{key}={value}\n")
                found = True
            else:
                out.append(ln if ln.endswith("\n") else ln + "\n")
        if not found:
            out.append(f"{key}={value}\n")
        fd = os.open(ENV_FILE + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.writelines(out)
        os.replace(ENV_FILE + ".tmp", ENV_FILE)
        try: os.chmod(ENV_FILE, 0o600)
        except OSError: pass
        return True
    except Exception as ex:
        app.logger.warning("env_set failed: %s", ex)
        return False


def human_bytes(n):
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024: return f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} PB"


def human_seconds(s):
    s = int(s)
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m, _ = divmod(s, 60)
    parts = []
    if d: parts.append(f"{d}d")
    if h: parts.append(f"{h}h")
    parts.append(f"{m}m")
    return " ".join(parts)


# ---------- sysinfo ----------
# Android (SELinux) denies the app domain several /proc & /sys files. The
# sysinfo(2) syscall gives uptime + load without /proc; everything else here
# degrades gracefully to "?" / None when a file is unreadable.
def _sysinfo():
    """(uptime_seconds, (load1, load5, load15)) via the sysinfo(2) syscall. None on
    failure."""
    try:
        import ctypes, struct
        buf = ctypes.create_string_buffer(128)
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.sysinfo(buf) != 0:
            return None
        up, l1, l2, l3 = struct.unpack_from("=q3Q", buf.raw, 0)
        return up, (l1 / 65536.0, l2 / 65536.0, l3 / 65536.0)
    except Exception:
        return None

# ---------- optional privileged shell via Shizuku (rish) ----------
# Android (SELinux) denies the app domain (Termux) some /proc & /sys files —
# notably /proc/net/dev. If you run Shizuku and install its `rish` shell-uid
# bridge at ~/.shizuku/rish, the panel can read those files as shell uid (2000).
# This is OPTIONAL and entirely best-effort: without Shizuku (the default) every
# call here returns None and the panel falls back / shows an honest note. The
# Shizuku service also stops on reboot, so callers MUST handle None. See docs/ADMIN.md.
RISH = os.path.expanduser("~/.shizuku/rish")
_RISH_PRESENT = os.path.exists(RISH)

def rish(cmd, timeout=8):
    """Run cmd as shell uid (2000) via the Shizuku rish bridge. Returns stdout, or
    None when rish is missing / the Shizuku service is down / on any error."""
    if not _RISH_PRESENT:
        return None
    try:
        p = subprocess.run(["sh", RISH], input=cmd + "\n",
                            capture_output=True, text=True, timeout=timeout)
        if "Server is not running" in (p.stdout + p.stderr):
            return None
        return p.stdout or None
    except Exception:
        return None

_NET_PREV = {}      # iface -> (rx_bytes, tx_bytes, monotonic_ts) — for throughput rate
_NET_SOURCE = None  # "proc" | "rish" | None — how the last _gather_net() read net/dev

def _read_net_dev():
    """Return (raw /proc/net/dev text, source) where source is 'proc' or 'rish', or
    (None, None). Tries a direct read first (works where the OS allows it), then
    falls back to the OPTIONAL Shizuku rish bridge (shell uid) when the app domain
    is denied. Without Shizuku the fallback is a no-op and this returns (None, None)."""
    try:
        with open("/proc/net/dev") as f:
            raw = f.read()
        if raw:
            return raw, "proc"
    except Exception:
        pass
    raw = rish("cat /proc/net/dev", timeout=5)   # optional; None without Shizuku
    if raw:
        return raw, "rish"
    return None, None

def _gather_net():
    """Per-iface RX/TX bytes + live throughput from /proc/net/dev — read directly, or
    via the optional Shizuku (rish) bridge when the OS blocks it for the app domain.
    Returns None when neither works (the UI then shows an honest 'restricted' note);
    the source ('proc'/'rish'/None) is recorded in _NET_SOURCE for a status pill."""
    global _NET_SOURCE
    raw, _NET_SOURCE = _read_net_dev()
    if not raw:
        return None
    now = time.monotonic()
    out = []
    for line in raw.splitlines()[2:]:
        if ":" not in line:
            continue
        iface, rest = line.split(":", 1)
        iface = iface.strip()
        parts = rest.split()
        if iface == "lo" or len(parts) < 9:
            continue
        try:
            rx, tx = int(parts[0]), int(parts[8])
        except ValueError:
            continue
        if rx == 0 and tx == 0:
            continue
        rrx = rtx = None
        prev = _NET_PREV.get(iface)
        if prev and now - prev[2] > 0.5:
            dt = now - prev[2]
            rrx = max(0.0, (rx - prev[0]) / dt)
            rtx = max(0.0, (tx - prev[1]) / dt)
        _NET_PREV[iface] = (rx, tx, now)
        out.append({"iface": iface, "rx": rx, "tx": tx, "rate_rx": rrx, "rate_tx": rtx})
    out.sort(key=lambda n: -(n["rx"] + n["tx"]))
    return out[:5]


# ---------- health probing ----------
# Loopback HTTP probes hit Caddy on ${CADDY_BIND}:${CADDY_PORT} (plain HTTP — TLS
# terminates at the Cloudflare edge) with an explicit Host header. This exercises
# Caddy + the upstream while bypassing the public edge. Built from the enabled
# apps so a disabled app is never a false failure.
def _build_http_probes():
    probes = [
        {"name": "conduwuit (local)", "host": "127.0.0.1:8448",
         "path": "/_matrix/client/versions", "expect": 200, "scheme": "http"},
        {"name": "matrix via caddy", "host": f"chat.{DOMAIN}",
         "path": "/_matrix/client/versions", "expect": 200, "scheme": "loopback"},
        {"name": "admin panel", "host": f"127.0.0.1:{BIND_PORT}",
         "path": "/login", "expect": 200, "scheme": "http"},
    ]
    if ENABLE["auth-gw"]:
        probes.append({"name": "auth-gw", "host": f"127.0.0.1:{AUTHGW_PORT}",
                       "path": "/authgw/health", "expect": 200, "scheme": "http"})
    if ENABLE["linkding"]:
        probes.append({"name": "linkding /health", "host": f"links.{DOMAIN}",
                       "path": "/health", "expect": 200, "scheme": "loopback"})
    if ENABLE["pingvin"]:
        probes.append({"name": "pingvin /api/health", "host": f"share.{DOMAIN}",
                       "path": "/api/health", "expect": 200, "scheme": "loopback"})
    if ENABLE["vaultwarden"]:
        # /alive is an unauthenticated liveness endpoint (returns a timestamp).
        probes.append({"name": "vaultwarden /alive", "host": f"vault.{DOMAIN}",
                       "path": "/alive", "expect": 200, "scheme": "loopback"})
    if ENABLE["navidrome"]:
        # /ping is an unauthenticated heartbeat (chi middleware.Heartbeat) → 200.
        probes.append({"name": "navidrome /ping", "host": f"music.{DOMAIN}",
                       "path": "/ping", "expect": 200, "scheme": "loopback"})
    if ENABLE["kavita"]:
        # /api/health is [AllowAnonymous] → 200 "Ok".
        probes.append({"name": "kavita /api/health", "host": f"books.{DOMAIN}",
                       "path": "/api/health", "expect": 200, "scheme": "loopback"})
    if ENABLE["audiobookshelf"]:
        # /healthcheck is an unauthenticated 200 liveness endpoint.
        probes.append({"name": "audiobookshelf /healthcheck", "host": f"audiobooks.{DOMAIN}",
                       "path": "/healthcheck", "expect": 200, "scheme": "loopback"})
    if ENABLE["forgejo"]:
        # /api/healthz is an unauthenticated 200 liveness endpoint (Forgejo 15.x).
        probes.append({"name": "forgejo /api/healthz", "host": f"git.{DOMAIN}",
                       "path": "/api/healthz", "expect": 200, "scheme": "loopback"})
    if ENABLE["adguard"]:
        # /control/status is an unauthenticated 200 liveness endpoint.
        probes.append({"name": "adguard /control/status", "host": f"dns.{DOMAIN}",
                       "path": "/control/status", "expect": 200, "scheme": "loopback"})
    # NB: Tailscale + proxy-routes are intentionally NOT HTTP-probed — Tailscale has no
    # public hostname (tailnet only; its liveness is the tailscaled process-check), and
    # proxy-routes runs no process at all (it only generates Caddy vhosts).
    # NB: Radicale is intentionally NOT HTTP-probed here — GET / returns a 302
    # (root → /.well-known/caldav) and the probe opener follows redirects, so there
    # is no single stable status to assert. Its liveness is covered by the process
    # check in _build_health_procs (same approach as memos/vikunja).
    return probes

HEALTH_HTTP_PROBES = _build_http_probes()

# Process aliveness — pgrep -f patterns. Built from the enabled apps. Patterns
# match each service's real process argv (cross-checked against the install
# scripts' supervise/exec lines).
def _build_health_procs():
    procs = [
        {"name": "matrix",      "pattern": "/opt/conduwuit/conduwuit"},
        {"name": "caddy",       "pattern": "caddy run"},
        # POCKET_NO_CLOUDFLARE: no Cloudflare Tunnel in this deployment.
        {"name": "adminweb",    "pattern": "gunicorn.*app:app"},
    ]
    if ENABLE["auth-gw"]:
        procs.append({"name": "auth-gw", "pattern": "matrix-auth-gw\\.py"})
    if ENABLE["linkding"]:
        procs.append({"name": "linkding",       "pattern": "gunicorn.*bookmarks\\.wsgi"})
        procs.append({"name": "linkding-tasks", "pattern": "run_huey"})
    if ENABLE["pingvin"]:
        procs.append({"name": "pingvin", "pattern": "dist/src/main"})
    if ENABLE["freshrss"]:
        procs.append({"name": "freshrss", "pattern": "freshrss/php-fpm.conf"})
        procs.append({"name": "freshrss-refresh", "pattern": "run-refresh\\.sh"})
    if ENABLE["searxng"]:
        procs.append({"name": "searxng", "pattern": "searxng/uwsgi.ini"})
    if ENABLE["memos"]:
        procs.append({"name": "memos", "pattern": "/opt/memos/memos"})
    if ENABLE["vikunja"]:
        procs.append({"name": "vikunja", "pattern": "/opt/vikunja/run.sh"})
    if ENABLE["gatus"]:
        procs.append({"name": "gatus", "pattern": "/opt/gatus"})
    if ENABLE["wallabag"]:
        procs.append({"name": "wallabag", "pattern": "wallabag/php-fpm.conf"})
    if ENABLE["radicale"]:
        procs.append({"name": "radicale", "pattern": "/opt/radicale/venv/bin/radicale"})
    if ENABLE["trilium"]:
        procs.append({"name": "trilium", "pattern": "/opt/trilium/main.cjs"})
    if ENABLE["vaultwarden"]:
        procs.append({"name": "vaultwarden", "pattern": "vaultwarden/run.sh"})
    if ENABLE["dufs"]:
        procs.append({"name": "dufs", "pattern": "/opt/dufs/dufs"})
    if ENABLE["filebrowser"]:
        procs.append({"name": "filebrowser", "pattern": "/opt/filebrowser/filebrowser"})
    if ENABLE["syncthing"]:
        # supervised as `proot-distro … -- /usr/local/bin/syncthing serve …`; pgrep -f
        # matches the in-userland binary path (GUI is loopback-only, so no HTTP probe).
        procs.append({"name": "syncthing", "pattern": "/usr/local/bin/syncthing serve"})
    if ENABLE["navidrome"]:
        procs.append({"name": "navidrome", "pattern": "/opt/navidrome/navidrome"})
    if ENABLE["kavita"]:
        procs.append({"name": "kavita", "pattern": "/opt/Kavita/run.sh"})
    if ENABLE["audiobookshelf"]:
        # matches the proot-distro launcher argv (`bash …/run.sh`), as pgrep -f sees it
        procs.append({"name": "audiobookshelf", "pattern": "audiobookshelf/run.sh"})
    if ENABLE["forgejo"]:
        procs.append({"name": "forgejo", "pattern": "/opt/forgejo/run.sh"})
    if ENABLE["adguard"]:
        procs.append({"name": "adguard", "pattern": "/opt/adguard/AdGuardHome"})
    if ENABLE["tailscale"]:
        procs.append({"name": "tailscaled", "pattern": "/opt/tailscale/tailscaled"})
    if ENABLE["backup-daemon"]:
        procs.append({"name": "backup-daemon", "pattern": "ops/backup-daemon.sh"})
    if ENABLE["honeypot"]:
        procs.append({"name": "honeypot-watcher", "pattern": "honeypot-watcher\\.py"})
    if ENABLE["user-filter"]:
        procs.append({"name": "user-filter", "pattern": "user-filter\\.py"})
    if ENABLE["media-filter"]:
        procs.append({"name": "media-filter", "pattern": "media-filter\\.py"})
    if ENABLE["cloud-bots"]:
        # One collective row for all cloud bots: per-bot identity lives only in the
        # sourced 0600 env (off-argv), so the python child cmdline carries only the
        # module path. Restart individual bots from the shell (ops/restart.sh
        # cloud-bot-<name>) — their names are dynamic, so there is no static button.
        procs.append({"name": "cloud-bots", "pattern": "cloud_chatbot\\.py"})
    if ENABLE["exobot"]:
        # The bot launcher exec's `python3 .../exobot.py` (host-native). The
        # optional UI is supervised as `proot-distro ... bash .../run-ui.sh` and
        # its lazy-start waker as `python3 .../exobot-waker.py`. Restart from the
        # shell (ops/restart.sh exobot|exobot-ui|exobot-waker).
        procs.append({"name": "exobot", "pattern": "exobot\\.py"})
        if ENABLE["exobot-ui"]:
            procs.append({"name": "exobot-ui", "pattern": "run-ui\\.sh"})
            procs.append({"name": "exobot-waker", "pattern": "exobot-waker\\.py"})
    if ENABLE["stickers"]:
        procs.append({"name": "sticker-backend", "pattern": "sticker-backend\\.py"})
        # The DM-import bot only runs when its creds are set, so only health-check
        # it then (else it would always read DOWN).
        if os.environ.get("STICKER_BOT_TOKEN", "").strip():
            procs.append({"name": "sticker-importer", "pattern": "importer-bot\\.py"})
    if ENABLE["adminbot"]:
        procs.append({"name": "adminbot", "pattern": "adminbot/bot\\.py"})
    if ENABLE["email"]:
        # Maddy (run-maddy.sh exec's `./maddy run` in proot), the native R2 drain
        # (run-drain.sh exec's python3 mail-drain.py), and the SnappyMail php-fpm
        # pool. Restart from the shell (ops/restart.sh maddy|mail-drain|snappymail-fpm).
        procs.append({"name": "maddy", "pattern": "maddy run"})
        procs.append({"name": "mail-drain", "pattern": "mail-drain\\.py"})
        procs.append({"name": "snappymail-fpm", "pattern": "snappymail/php-fpm.conf"})
    if ENABLE["metrics"]:
        procs.append({"name": "metrics-sampler", "pattern": "metrics-sampler\\.py"})
    if ENABLE["mcp"] and _env("MCP_TRANSPORT", "stdio") in ("http", "both"):
        # Only the HTTP transport is a supervised long-running service; stdio mode
        # is spawned on demand by the client over SSH (nothing to supervise). The
        # HTTP launcher (run-mcp-http.sh, from steps/87-install-mcp.sh) is
        # supervised as `bash run-mcp-http.sh`, which exec's the venv python on the
        # server script — so the child cmdline carries `pocket-mcp.py`. Restart
        # from the shell (ops/restart.sh mcp).
        procs.append({"name": "mcp", "pattern": "pocket-mcp\\.py"})
    return procs

HEALTH_PROCS = _build_health_procs()


def _probe_http(probe, timeout=5):
    """Returns dict with code, latency_ms, ok bool, error str."""
    import urllib.request, urllib.error
    if probe["scheme"] == "loopback":
        # Caddy is plain HTTP on loopback (TLS terminates at the CF edge); send
        # http:// with the public hostname in the Host header.
        url = f"http://{CADDY_BIND}:{CADDY_PORT}{probe['path']}"
        host_header = probe["host"]
    else:
        url = f"http://{probe['host']}{probe['path']}"
        host_header = probe["host"]
    req = urllib.request.Request(
        url, method="GET",
        headers={"Host": host_header, "User-Agent": "pocket-homeserver-admin-health/1"})
    # A 30x to a login page proves the vhost AND its gate are live; urlopen would
    # FOLLOW it and report the login page's 200. A no-follow opener surfaces the
    # 30x as an HTTPError whose code we read as-is.
    opener = getattr(_probe_http, "_opener", None)
    if opener is None:
        class _NoFollow(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                return None
        opener = urllib.request.build_opener(_NoFollow)
        _probe_http._opener = opener
    t0 = time.time()
    try:
        with opener.open(req, timeout=timeout) as r:
            code = r.status
    except urllib.error.HTTPError as ex:
        code = ex.code
    except Exception as ex:
        return {"code": 0, "latency_ms": int((time.time()-t0)*1000),
                "ok": False, "error": str(ex)[:80]}
    latency = int((time.time() - t0) * 1000)
    ok = (code == probe["expect"])
    return {"code": code, "latency_ms": latency, "ok": ok, "error": ""}


def _proc_alive(pattern):
    """Returns (alive_bool, pid_int_or_0)."""
    try:
        p = subprocess.run(["pgrep", "-f", pattern],
                           capture_output=True, text=True, timeout=3)
        if p.returncode == 0 and p.stdout.strip():
            pid = int(p.stdout.strip().splitlines()[0])
            return (True, pid)
    except Exception:
        pass
    return (False, 0)


def _degraded_marker(name):
    """If the supervisor has flagged this service as crash-looping, return the
    marker text (service/rc/fails/since); else None. Written by supervise() in
    scripts/lib/common.sh after POCKET_CRASHLOOP_FAILS rapid restarts. A service
    can pgrep-alive momentarily while crash-looping, so this marker — not the
    instantaneous proc/port check — is the reliable 'stuck' signal."""
    try:
        with open(os.path.join(STATE, f"{name}.degraded"), encoding="utf-8") as fh:
            return fh.read().strip() or None
    except Exception:
        return None


def _degraded_names():
    """Service names currently flagged DEGRADED (crash-looping) by the supervisor.
    Cheap — just lists *.degraded markers in STATE, no subprocess — so it is safe
    to call on every page render (drives the nav 'problems' badge)."""
    try:
        return sorted(f[: -len(".degraded")] for f in os.listdir(STATE)
                      if f.endswith(".degraded"))
    except OSError:
        return []


def gather_health():
    """Run all probes and process checks. Returns structured report."""
    out = {"ts": time.strftime("%FT%TZ", time.gmtime()),
           "http": [], "procs": [], "summary": {}}
    http_ok = http_total = 0
    for probe in HEALTH_HTTP_PROBES:
        r = _probe_http(probe)
        out["http"].append({**probe, **r})
        http_total += 1
        if r["ok"]: http_ok += 1
    proc_ok = proc_total = 0
    for proc in HEALTH_PROCS:
        alive, pid = _proc_alive(proc["pattern"])
        degraded = _degraded_marker(proc["name"])
        out["procs"].append({**proc, "alive": alive, "pid": pid, "degraded": degraded})
        proc_total += 1
        # A crash-looping service is NOT healthy even if pgrep caught it mid-respawn.
        if alive and not degraded: proc_ok += 1
    out["summary"] = {
        "http_ok": http_ok, "http_total": http_total,
        "proc_ok": proc_ok, "proc_total": proc_total,
        "all_green": http_ok == http_total and proc_ok == proc_total,
    }
    return out


# ---------- stat gathering ----------
def gather_stats():
    """Collect device + stack stats. Best-effort — never raises."""
    s = {}

    si = _sysinfo()
    if si:
        s["uptime"] = human_seconds(si[0])
        s["load"] = " / ".join(f"{x:.2f}" for x in si[1])
    else:
        s["uptime"] = s["load"] = "?"

    # CPU model + cores + per-core freq
    try:
        cpuinfo = read_file("/proc/cpuinfo")
        cores = cpuinfo.count("processor\t:")
        model = "?"
        for line in cpuinfo.splitlines():
            if line.startswith("Hardware") or line.startswith("model name"):
                model = line.split(":", 1)[1].strip(); break
        s["cpu_model"] = model
        s["cpu_cores"] = cores

        freqs = []
        for i in range(cores):
            f = read_file(f"/sys/devices/system/cpu/cpu{i}/cpufreq/scaling_cur_freq").strip()
            if f.isdigit():
                freqs.append(int(f) // 1000)  # kHz → MHz
        if freqs:
            s["cpu_freq"] = f"{min(freqs)}-{max(freqs)} MHz (avg {sum(freqs)//len(freqs)})"
        else:
            s["cpu_freq"] = "?"
    except Exception:
        s["cpu_model"] = s["cpu_cores"] = s["cpu_freq"] = "?"

    s["gpu_note"] = "GPU utilisation needs root (vendor sysfs is restricted)"

    # memory
    try:
        meminfo = {}
        for line in read_file("/proc/meminfo").splitlines():
            parts = line.split(":")
            if len(parts) == 2:
                meminfo[parts[0].strip()] = int(parts[1].strip().split()[0]) * 1024
        total = meminfo.get("MemTotal", 0)
        avail = meminfo.get("MemAvailable", meminfo.get("MemFree", 0))
        used = total - avail
        s["mem_used"] = used
        s["mem_total"] = total
        s["mem_pct"] = int(100 * used / total) if total else 0
        stotal = meminfo.get("SwapTotal", 0)
        sfree = meminfo.get("SwapFree", 0)
        s["swap_used"] = stotal - sfree
        s["swap_total"] = stotal
    except Exception:
        s["mem_used"] = s["mem_total"] = s["mem_pct"] = 0
        s["swap_used"] = s["swap_total"] = 0

    # Storage (via os.statvfs — toybox df can't do -B1). Probe the large data
    # volume and home; both are derived from config, no hardcoded mounts.
    s["storage"] = []
    seen = set()
    for mount, label in ((DATA_DIR or os.path.expanduser("~"), "data volume"),
                         (os.path.expanduser("~"), "home")):
        if not mount or mount in seen:
            continue
        seen.add(mount)
        try:
            st = os.statvfs(mount)
            total = st.f_blocks * st.f_frsize
            avail = st.f_bavail * st.f_frsize
            used = total - avail
            s["storage"].append({
                "label": label, "mount": mount,
                "used": used, "total": total, "avail": avail,
                "pct": int(100 * used / total) if total else 0,
            })
        except Exception:
            pass

    # battery
    try:
        p = subprocess.run(["termux-battery-status"], capture_output=True, text=True, timeout=5)
        b = json.loads(p.stdout)
        s["battery"] = {
            "pct": b.get("percentage", "?"),
            "temp": b.get("temperature", "?"),
            "status": b.get("status", "?").lower(),
            "plugged": b.get("plugged", "?").lower().replace("plugged_", "").replace("unplugged", "on battery"),
        }
    except Exception:
        s["battery"] = None

    # thermal zones
    try:
        temps = []
        for i in range(20):
            t = read_file(f"/sys/class/thermal/thermal_zone{i}/temp").strip()
            tp = read_file(f"/sys/class/thermal/thermal_zone{i}/type").strip()
            if t and t.isdigit():
                c = int(t) / 1000.0
                if 10 < c < 150 and tp:
                    temps.append({"zone": tp, "temp": c})
        s["thermal"] = temps[:8]
        s["max_temp"] = max((z["temp"] for z in temps), default=0)
    except Exception:
        s["thermal"] = []; s["max_temp"] = 0

    # network — /proc/net/dev, read directly or via the optional Shizuku (rish)
    # bridge; None when blocked and Shizuku is unavailable. net_source drives a pill.
    s["net"] = _gather_net()
    s["net_source"] = _NET_SOURCE

    # device
    try:
        p = subprocess.run(["getprop", "ro.product.model"], capture_output=True, text=True, timeout=3)
        s["device"] = p.stdout.strip() or "?"
        p2 = subprocess.run(["getprop", "ro.build.version.release"], capture_output=True, text=True, timeout=3)
        s["android"] = p2.stdout.strip() or "?"
    except Exception:
        s["device"] = s["android"] = "?"

    # kernel
    try:
        s["kernel"] = read_file("/proc/version").split()[2] if read_file("/proc/version") else "?"
    except Exception:
        s["kernel"] = "?"

    # Service health (loopback port probes)
    s["services"] = []
    port_checks = [("matrix", 8448), ("caddy", int(CADDY_PORT) if str(CADDY_PORT).isdigit() else 8443),
                   ("adminweb", BIND_PORT)]
    if ENABLE["auth-gw"]:
        port_checks.append(("auth-gw", int(AUTHGW_PORT) if str(AUTHGW_PORT).isdigit() else 9095))
    for name, port in port_checks:
        up = False
        try:
            import socket as _s
            sock = _s.socket(_s.AF_INET, _s.SOCK_STREAM)
            sock.settimeout(1.0)
            sock.connect(("127.0.0.1", port))
            sock.close(); up = True
        except Exception:
            pass
        s["services"].append({"name": name, "port": port, "up": up,
                               "degraded": _degraded_marker(name)})

    # POCKET_NO_CLOUDFLARE: ingress is an `ssh -R` forward to our own VPS, not a Cloudflare
    # Tunnel, so report the tunnel's health from ITS supervisor state instead.
    try:
        s["services"].append({
            "name": "vps-tunnel",
            "port": None,
            # Deliberately specific: a loose pattern like "cloudflared" also
            # matches any shell command line mentioning it, which is exactly how
            # the old check reported a stopped service as running.
            "up": _proc_alive("-N -R 127.0.0.1:8443"),
            "note": "ssh -R to VPS",
            "degraded": _degraded_marker("tunnel"),
        })
    except Exception:
        pass

    return s


# ---------- CSS + templates ----------
# Inline brand mark — the pocket-homeserver logo (a teal phone + server-rack +
# signal-wave glyph on a dark rounded tile). Kept verbatim so the admin header
# chip matches the site favicon / app icon exactly.
LOGO_MARK_SVG = r'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 500 500" width="100%" height="100%" aria-hidden="true">
<defs>
<filter id="neon-glow" x="-20%" y="-20%" width="140%" height="140%">
<feDropShadow dx="0" dy="0" stdDeviation="8" flood-color="#3de09c" flood-opacity="0.7"/>
</filter>
<mask id="logo-mask">
<rect x="150" y="80" width="200" height="380" rx="30" fill="white"/>
<rect x="175" y="140" width="150" height="260" rx="10" fill="black"/>
<rect x="310" y="210" width="50" height="128" fill="black"/>
<rect x="230" y="105" width="40" height="8" rx="4" fill="black"/>
<rect x="230" y="430" width="40" height="12" rx="6" fill="black"/>
<rect x="260" y="215" width="155" height="32" rx="8" fill="white"/>
<rect x="260" y="258" width="155" height="32" rx="8" fill="white"/>
<rect x="260" y="301" width="155" height="32" rx="8" fill="white"/>
<rect x="275" y="226" width="30" height="10" rx="3" fill="black"/>
<circle cx="369" cy="231" r="3.5" fill="black"/><circle cx="382" cy="231" r="3.5" fill="black"/><circle cx="395" cy="231" r="3.5" fill="black"/>
<rect x="275" y="269" width="30" height="10" rx="3" fill="black"/>
<circle cx="369" cy="274" r="3.5" fill="black"/><circle cx="382" cy="274" r="3.5" fill="black"/><circle cx="395" cy="274" r="3.5" fill="black"/>
<rect x="275" y="312" width="30" height="10" rx="3" fill="black"/>
<circle cx="369" cy="317" r="3.5" fill="black"/><circle cx="382" cy="317" r="3.5" fill="black"/><circle cx="395" cy="317" r="3.5" fill="black"/>
</mask>
</defs>
<rect width="500" height="500" fill="#131615"/>
<g stroke="#2c8e72" stroke-width="14" stroke-linecap="round" fill="none" opacity="0.85">
<path d="M 180,40 A 70,70 0 0,0 90,110"/>
<path d="M 150,15 A 110,110 0 0,0 50,120"/>
<path d="M 320,40 A 70,70 0 0,1 410,110"/>
<path d="M 350,15 A 110,110 0 0,1 450,120"/>
</g>
<g filter="url(#neon-glow)">
<rect x="0" y="0" width="500" height="500" fill="#3de09c" mask="url(#logo-mask)"/>
</g>
</svg>'''

CSS = """
/* ===== design tokens (indigo/blue/teal) ===== */
:root {
  --bg:#f4f7f6; --fg:#16201b; --muted:#566b63; --border:#dde7e2; --panel:#ffffff;
  --card1:#ffffff; --card2:#f2f8f5;
  --pre-bg:#0e1320; --pre-fg:#d4dbe8; --link:#0c8466; --brand:#0c8466;
  --accent:#0f9b76; --accent2:#13b487; --teal:#0f9b76; --pink:#d6498f; --amber:#b9791a;
  --btn-bg:#e6efeb; --btn-hover:#d8e7e1; --btn-fg:#214036;
  --btn-primary:#40c8a0; --btn-primary-hover:#2c8e72; --btn-primary-fg:#04130e;
  --danger:#d23b54; --danger-hover:#b32942;
  --err-bg:#fde8ee; --err-fg:#9a1b3a; --err-border:#f0b9c7;
  --ok-bg:#e4f7ef; --ok-fg:#0a6b4d; --ok-border:#a9e3cf;
  --warn-bg:#fff4d6; --warn-fg:#7a5200; --warn-border:#e6cf8f;
  --code-bg:#eef3f0; --danger-bg:#fdeaee; --danger-border:#e7a9b6;
  --dot-up:#1faf6b; --dot-down:#d23b54;
  --shadow:0 4px 18px rgba(20,60,45,.08); --shadow-sm:0 1px 3px rgba(20,60,45,.06);
  --ring:rgba(15,155,118,.30); --grad:linear-gradient(100deg,#0c8466,#0f9b76 45%,#13b487);
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg:#0a0c12; --fg:#e7ebf3; --muted:#aab2c5; --border:#262c3d; --panel:#141826;
    --card1:#181d2b; --card2:#0e1320;
    --pre-bg:#070a10; --pre-fg:#d4dbe8; --link:#5fe0bb; --brand:#5fe0bb;
    --accent:#40c8a0; --accent2:#5fe0bb; --teal:#40c8a0; --pink:#ec6ead; --amber:#f5b945;
    --btn-bg:#1b2230; --btn-hover:#252d3d; --btn-fg:#d7deea;
    --btn-primary:#40c8a0; --btn-primary-hover:#5fe0bb; --btn-primary-fg:#04130e;
    --danger:#e0556b; --danger-hover:#f3667c;
    --err-bg:#2a1622; --err-fg:#ffb3c4; --err-border:#5b2740;
    --ok-bg:#0f2a22; --ok-fg:#7ff0c8; --ok-border:#1f5a47;
    --warn-bg:#2c2410; --warn-fg:#ffd58a; --warn-border:#6b5520;
    --code-bg:#161c2a; --danger-bg:#251320; --danger-border:#7a2740;
    --dot-up:#42d392; --dot-down:#ff5c7c;
    --shadow:0 8px 28px rgba(0,0,0,.40); --shadow-sm:0 1px 3px rgba(0,0,0,.30);
    --ring:rgba(64,200,160,.40); --grad:linear-gradient(100deg,#2c8e72,#40c8a0 45%,#5fe0bb);
  }
}
body[data-theme=dark] {
  --bg:#0a0c12; --fg:#e7ebf3; --muted:#aab2c5; --border:#262c3d; --panel:#141826;
  --card1:#181d2b; --card2:#0e1320;
  --pre-bg:#070a10; --pre-fg:#d4dbe8; --link:#5fe0bb; --brand:#5fe0bb;
  --accent:#40c8a0; --accent2:#5fe0bb; --teal:#40c8a0; --pink:#ec6ead; --amber:#f5b945;
  --btn-bg:#1b2230; --btn-hover:#252d3d; --btn-fg:#d7deea;
  --btn-primary:#40c8a0; --btn-primary-hover:#5fe0bb; --btn-primary-fg:#04130e;
  --danger:#e0556b; --danger-hover:#f3667c;
  --err-bg:#2a1622; --err-fg:#ffb3c4; --err-border:#5b2740;
  --ok-bg:#0f2a22; --ok-fg:#7ff0c8; --ok-border:#1f5a47;
  --warn-bg:#2c2410; --warn-fg:#ffd58a; --warn-border:#6b5520;
  --code-bg:#161c2a; --danger-bg:#251320; --danger-border:#7a2740;
  --dot-up:#42d392; --dot-down:#ff5c7c;
  --shadow:0 8px 28px rgba(0,0,0,.40); --shadow-sm:0 1px 3px rgba(0,0,0,.30);
  --ring:rgba(64,200,160,.40); --grad:linear-gradient(100deg,#2c8e72,#40c8a0 45%,#5fe0bb);
}
body[data-theme=light] {
  --bg:#f4f7f6; --fg:#16201b; --muted:#566b63; --border:#dde7e2; --panel:#ffffff;
  --card1:#ffffff; --card2:#f2f8f5;
  --pre-bg:#0e1320; --pre-fg:#d4dbe8; --link:#0c8466; --brand:#0c8466;
  --accent:#0f9b76; --accent2:#13b487; --teal:#0f9b76; --pink:#d6498f; --amber:#b9791a;
  --btn-bg:#e6efeb; --btn-hover:#d8e7e1; --btn-fg:#214036;
  --btn-primary:#40c8a0; --btn-primary-hover:#2c8e72; --btn-primary-fg:#04130e;
  --danger:#d23b54; --danger-hover:#b32942;
  --err-bg:#fde8ee; --err-fg:#9a1b3a; --err-border:#f0b9c7;
  --ok-bg:#e4f7ef; --ok-fg:#0a6b4d; --ok-border:#a9e3cf;
  --warn-bg:#fff4d6; --warn-fg:#7a5200; --warn-border:#e6cf8f;
  --code-bg:#eef3f0; --danger-bg:#fdeaee; --danger-border:#e7a9b6;
  --dot-up:#1faf6b; --dot-down:#d23b54;
  --shadow:0 4px 18px rgba(20,60,45,.08); --shadow-sm:0 1px 3px rgba(20,60,45,.06);
  --ring:rgba(15,155,118,.30); --grad:linear-gradient(100deg,#0c8466,#0f9b76 45%,#13b487);
}

/* ===== base — fluid full width ===== */
* { box-sizing: border-box }
html, body { background: var(--bg); color: var(--fg) }
body {
  font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,system-ui,sans-serif;
  width:100%; max-width:1900px; margin:0 auto; padding:0 clamp(1rem,2.2vw,2.6rem) 2.5rem; line-height:1.5;
  background:
    radial-gradient(1100px 420px at 108% -10%, color-mix(in srgb,var(--accent2) 13%,transparent), transparent 70%),
    radial-gradient(900px 380px at -8% -6%, color-mix(in srgb,var(--accent) 11%,transparent), transparent 70%),
    var(--bg);
  background-attachment:fixed;
}
a { color: var(--link); text-decoration: none } a:hover { text-decoration: underline }
h1,h2,h3 { margin:0 }

/* ===== top bar ===== */
header {
  position:sticky; top:0; z-index:20; display:flex; align-items:center; gap:.9rem; flex-wrap:wrap;
  padding:.7rem 0; margin-bottom:1.2rem; border-bottom:1px solid var(--border);
  background:color-mix(in srgb,var(--bg) 82%,transparent); backdrop-filter:saturate(140%) blur(10px);
}
.brand { display:flex; align-items:center; gap:.5rem; font-weight:700; font-size:1.12rem }
.brand .mark { width:1.6rem; height:1.6rem; display:grid; place-items:center; border-radius:8px;
  overflow:hidden; box-shadow:var(--shadow-sm) }
.brand .mark svg { width:100%; height:100%; display:block }
.brand .word { background:var(--grad); -webkit-background-clip:text; background-clip:text; color:transparent }
.brand .sub { color:var(--muted); font-weight:600; font-size:.78rem; letter-spacing:.12em; text-transform:uppercase; margin-left:.1rem }
nav { display:flex; gap:.3rem; flex-wrap:wrap; flex-grow:1 }
nav a { color:var(--muted); font-size:.86rem; font-weight:600; padding:.34rem .68rem; border-radius:999px;
  border:1px solid transparent; transition:background .15s,color .15s,border-color .15s }
nav a:hover { background:var(--btn-bg); color:var(--fg); text-decoration:none }
nav a.active { color:var(--accent); background:color-mix(in srgb,var(--accent) 14%,transparent);
  border-color:color-mix(in srgb,var(--accent) 35%,transparent) }
.theme-toggle,.logout-btn { border:1px solid var(--border); border-radius:999px; cursor:pointer;
  font-size:.8rem; font-weight:600; padding:.34rem .7rem; background:var(--btn-bg); color:var(--btn-fg); transition:background .15s }
.theme-toggle:hover,.logout-btn:hover { background:var(--btn-hover) }

/* ===== cards ===== */
.box { background:linear-gradient(180deg,var(--card1),var(--card2)); border:1px solid var(--border);
  border-radius:16px; padding:1.1rem 1.25rem; margin:.85rem 0; box-shadow:var(--shadow) }
.box h2 { font-size:1.02rem; display:flex; align-items:center; gap:.5rem; flex-wrap:wrap }
.box h2 .ico { font-size:1rem; opacity:.85 }
.box h3 { font-size:.82rem; color:var(--muted); text-transform:uppercase; letter-spacing:.06em; margin:.95rem 0 .4rem }
.grid2 { display:grid; grid-template-columns:1fr 1fr; gap:1rem; align-items:stretch }
.grid2 > .box, .grid2 > .col { margin:0 }
.col { display:flex; flex-direction:column; gap:1rem } .col .box { margin:0 }
.col .box:last-child { flex:1 1 auto }
.cardgrid { display:grid; grid-template-columns:repeat(auto-fit,minmax(290px,1fr)); gap:1rem } .cardgrid .box { margin:0 }
hr { border:0; border-top:1px solid var(--border); margin:.8rem 0 }
.box.danger-zone { border-color:var(--danger-border);
  background:linear-gradient(180deg,color-mix(in srgb,var(--danger) 9%,var(--card1)),var(--card2)) }

/* ===== stat chips ===== */
.statgrid { display:grid; grid-template-columns:repeat(4,1fr); gap:1rem; margin:.2rem 0 1rem }
.stat { position:relative; background:linear-gradient(180deg,var(--card1),var(--card2)); border:1px solid var(--border);
  border-radius:14px; padding:.8rem .95rem; box-shadow:var(--shadow-sm); overflow:hidden }
.stat .lbl { color:var(--muted); font-size:.7rem; font-weight:700; letter-spacing:.08em; text-transform:uppercase }
.stat .val { font-size:1.4rem; font-weight:700; margin-top:.18rem; line-height:1.15; font-variant-numeric:tabular-nums }
.stat .val small { font-size:.78rem; font-weight:600; color:var(--muted) }
.stat .spark { position:absolute; right:.6rem; bottom:.55rem; opacity:.9 }
.stat.accent { border-color:color-mix(in srgb,var(--accent) 40%,var(--border)) }

/* ===== metrics list ===== */
.metrics { display:grid; grid-template-columns:max-content 1fr; gap:.5rem .9rem; font-size:.9rem; align-items:baseline }
.metrics dt { color:var(--muted); font-weight:600 } .metrics dd { margin:0; font-variant-numeric:tabular-nums }

.dot { display:inline-block; width:.6rem; height:.6rem; border-radius:50%; vertical-align:middle; margin-right:.45rem }
.dot.up { background:var(--dot-up); box-shadow:0 0 0 3px color-mix(in srgb,var(--dot-up) 22%,transparent) }
.dot.down { background:var(--dot-down); box-shadow:0 0 0 3px color-mix(in srgb,var(--dot-down) 22%,transparent) }
.dot.degraded { background:var(--amber); box-shadow:0 0 0 3px color-mix(in srgb,var(--amber) 26%,transparent); animation:dotpulse 1.4s ease-in-out infinite }
@keyframes dotpulse { 0%,100%{opacity:1} 50%{opacity:.45} }

/* ===== pills / badges / status ===== */
.pill { display:inline-flex; align-items:center; gap:.35rem; font-size:.74rem; font-weight:700;
  padding:.16rem .55rem; border-radius:999px; border:1px solid var(--border); background:var(--code-bg); color:var(--fg) }
.pill.ok { background:var(--ok-bg); color:var(--ok-fg); border-color:var(--ok-border) }
.pill.warn { background:var(--warn-bg); color:var(--warn-fg); border-color:var(--warn-border) }
.pill.down { background:var(--danger-bg); color:var(--danger); border-color:var(--danger-border) }
.badge { background:var(--code-bg); color:var(--muted); font-size:.72rem; font-weight:600;
  padding:.12rem .45rem; border-radius:6px; margin-left:.4rem }
.ok { color:var(--ok-fg); font-weight:600 } .err { color:var(--danger); font-weight:600 }

/* ===== progress bars ===== */
.bar { position:relative; height:7px; background:var(--border); border-radius:999px; overflow:hidden; width:100%; margin-top:.3rem }
.bar > span { display:block; height:100%; background:linear-gradient(90deg,var(--accent),var(--accent2)); border-radius:999px; transition:width .5s ease }
.bar.warn > span { background:linear-gradient(90deg,#e0a82e,#f5b945) }
.bar.danger > span { background:linear-gradient(90deg,#e0556b,#ff7a7a) }

/* ===== sparkline ===== */
svg.spark { display:block }
svg.spark .ln { fill:none; stroke:var(--accent); stroke-width:1.6; stroke-linejoin:round; stroke-linecap:round }
svg.spark .ar { fill:var(--accent); opacity:.13 }

/* ===== buttons / forms ===== */
button,a.btn { font:inherit; font-size:.86rem; font-weight:600; cursor:pointer; background:var(--btn-bg); color:var(--btn-fg);
  border:1px solid var(--border); border-radius:9px; padding:.42rem .8rem; margin:.18rem .18rem 0 0;
  display:inline-block; text-decoration:none; transition:background .15s,transform .05s }
button:hover,a.btn:hover { background:var(--btn-hover); text-decoration:none }
button:active,a.btn:active { transform:translateY(1px) }
button.primary { background:var(--btn-primary); color:var(--btn-primary-fg); border-color:transparent }
button.primary:hover { background:var(--btn-primary-hover) }
button.danger,a.btn.danger { background:var(--danger); color:#fff; border-color:transparent }
button.danger:hover,a.btn.danger:hover { background:var(--danger-hover) }
button.small,a.btn.small { font-size:.78rem; padding:.3rem .55rem; border-radius:8px }
form { margin:0; display:inline-block } form.block { display:block; margin-top:.8rem }
input[type=password],input[type=text] { font:inherit; padding:.5rem .65rem; border:1px solid var(--border);
  border-radius:9px; background:var(--panel); color:var(--fg); min-width:240px; margin:.15rem .2rem .15rem 0 }
input:focus { outline:2px solid var(--ring); outline-offset:1px; border-color:var(--accent) }

/* ===== tables ===== */
.tablewrap { overflow-x:auto; border:1px solid var(--border); border-radius:12px; margin-top:.5rem }
table { width:100%; border-collapse:collapse; font-size:.86rem }
.tablewrap table { min-width:640px }
th,td { padding:.5rem .7rem; text-align:left; border-bottom:1px solid var(--border); vertical-align:middle; white-space:nowrap }
thead th { position:sticky; top:0; background:var(--card2); color:var(--muted); font-size:.72rem;
  text-transform:uppercase; letter-spacing:.05em; font-weight:700; z-index:1 }
tbody tr:last-child td { border-bottom:0 }
tbody tr:hover { background:color-mix(in srgb,var(--accent) 6%,transparent) }
td.mono,.mono { font-family:ui-monospace,Menlo,Consolas,monospace; font-size:.82rem }
td.path { max-width:340px; overflow:hidden; text-overflow:ellipsis }

/* ===== misc ===== */
pre { background:var(--pre-bg); color:var(--pre-fg); padding:.8rem 1rem; border-radius:10px; overflow-x:auto;
  font-size:.82rem; line-height:1.4; white-space:pre-wrap }
code { background:var(--code-bg); padding:0 .3rem; border-radius:5px; font-size:.9rem; color:var(--fg) }
.small { font-size:.84rem; color:var(--muted) }
.botbar { display:flex; align-items:center; justify-content:space-between; gap:1rem; flex-wrap:wrap;
  margin:1rem 0 .3rem; padding:.6rem 1.15rem; border:1px solid var(--border); border-radius:12px;
  background:linear-gradient(180deg,var(--card1),var(--card2)); box-shadow:var(--shadow-sm);
  color:var(--muted); font-size:.83rem }
.botbar .bb-live { display:inline-flex; align-items:center; gap:.45rem }
.botbar a { color:var(--muted); text-decoration:none } .botbar a:hover { color:var(--accent) }
#live-dot { color:var(--dot-up); transition:opacity .25s }
.flash { padding:.65rem 1rem; border-radius:10px; margin:.6rem 0; border:1px solid var(--border) }
.flash.err { background:var(--err-bg); color:var(--err-fg); border-color:var(--err-border) }
.flash.ok { background:var(--ok-bg); color:var(--ok-fg); border-color:var(--ok-border) }
.flash.warn { background:var(--warn-bg); color:var(--warn-fg); border-color:var(--warn-border) }
.warn-box { background:var(--warn-bg); color:var(--warn-fg); border:1px solid var(--warn-border);
  padding:.75rem 1rem; border-radius:10px; margin:.7rem 0 }
.warn-box ul { margin:.4rem 0; padding-left:1.4rem } .warn-box li { margin:.2rem 0 }
.health-banner { display:inline-flex; align-items:center; gap:.35rem; font-size:.74rem; font-weight:700;
  padding:.16rem .55rem; border-radius:999px; border:1px solid var(--border); vertical-align:middle; margin-left:.4rem }
.health-banner.health-ok { background:var(--ok-bg); color:var(--ok-fg); border-color:var(--ok-border) }
.health-banner.health-warn { background:var(--warn-bg); color:var(--warn-fg); border-color:var(--warn-border) }
.health-banner.health-err { background:var(--danger-bg); color:var(--danger); border-color:var(--danger-border) }
tr.health-ok td:first-child::before { content:"\\25CF "; color:var(--dot-up) }
tr.health-err td:first-child::before { content:"\\25CF "; color:var(--dot-down) }

/* ===== sites: upload dropzone ===== */
.dropzone{border:2px dashed var(--border);border-radius:12px;padding:1.4rem;text-align:center;
  cursor:pointer;color:var(--muted);transition:border-color .15s,background .15s}
.dropzone.drag{border-color:var(--accent);background:var(--btn-bg)}
.progress{height:.5rem;border-radius:999px;background:var(--btn-bg);overflow:hidden;margin-top:.6rem}
#upload-bar{height:100%;background:var(--accent);width:0;transition:width .2s}

/* ===== responsive ===== */
@media (max-width:900px) { .statgrid { grid-template-columns:repeat(2,1fr) } .grid2 { grid-template-columns:1fr } }
@media (max-width:560px) {
  .statgrid { grid-template-columns:1fr } nav { order:3; width:100% }
  button,a.btn,.theme-toggle,.logout-btn { min-height:2.5rem }
  input[type=password],input[type=text] { min-height:2.5rem; width:100% } td.path { max-width:160px }
}
@media (prefers-reduced-motion:reduce) { * { transition:none!important; animation:none!important } }
"""

# Serve the CSS from a cached, content-hashed route (smaller pages + browser
# caching). ?v=<hash> changes only when the CSS changes, so it caches hard.
_CSS_VER = hashlib.sha256(CSS.encode("utf-8")).hexdigest()[:12]


def render(title, body_html, hide_nav=False):
    theme = request.cookies.get("theme", "auto")
    theme_attr = f' data-theme="{e(theme)}"' if theme in ("dark", "light") else ""
    theme_btn_label = {"auto": "\U0001F313", "light": "☀", "dark": "☾"}.get(theme, "\U0001F313")

    nav = ""
    actions = ""
    if not hide_nav and session.get("auth"):
        cur = request.path
        items = [
            ("/", "dashboard"), ("/health", "health"), ("/stats", "stats"),
            ("/backups", "backups"), ("/tokens", "tokens"), ("/logs", "logs"),
            ("/danger", "danger"),
        ]
        if ENABLE.get("metrics"):
            items.append(("/metrics", "metrics"))
        if ENABLE.get("user-admin"):
            items.append(("/users", "users"))
        if ENABLE.get("radicale"):
            items.append(("/dav", "calendar"))
        if ENABLE["honeypot"]:
            items.append(("/honeypot", "security"))
        if ENABLE.get("app-catalog"):
            items.append(("/catalog", "catalog"))
        if ENABLE.get("sites"):
            items.append(("/sites", "sites"))
        # Surface a loud 'problems' tab only when something is crash-looping, so the
        # nav stays clean normally but a DEGRADED service is impossible to miss.
        _degr = _degraded_names()
        if _degr:
            items.append(("/problems", f"problems ({len(_degr)})"))
        links = ""
        for href, label in items:
            on = " class=active" if (cur == href if href == "/" else cur.startswith(href)) else ""
            links += f'<a href="{href}"{on}>{label}</a>'
        nav = f"<nav>{links}</nav>"
        actions = (
            '<form method=post action=/theme><input type=hidden name=_csrf value="'
            + e(new_csrf()) + f'"><button class=theme-toggle>{theme_btn_label} theme</button></form>'
            '<form method=post action=/logout><input type=hidden name=_csrf value="'
            + e(new_csrf()) + '"><button class=logout-btn type=submit>logout</button></form>'
        )
    flashes = ""
    for cat, msg in session.pop("_flashes", []):
        flashes += f'<div class="flash {e(cat)}">{e(msg)}</div>'
    pwa_head = (
        '<link rel="manifest" href="/manifest.json">'
        '<meta name="theme-color" content="#0a0c12">'
        '<meta name="apple-mobile-web-app-capable" content="yes">'
        f'<meta name="apple-mobile-web-app-title" content="{e(BRAND)}">'
        '<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">'
        '<link rel="icon" type="image/svg+xml" href="/icon.svg">'
        '<link rel="apple-touch-icon" href="/icon.svg">'
    )
    brand = ('<div class=brand><span class=mark>' + LOGO_MARK_SVG + '</span>'
             f'<span class=word>{e(BRAND)}</span><span class=sub>admin</span></div>')
    return (
        "<!doctype html>"
        '<html lang=en><head><meta charset=utf-8>'
        '<meta name=viewport content="width=device-width,initial-scale=1">'
        + pwa_head +
        f"<title>{e(title)}</title>"
        f'<link rel="stylesheet" href="/admin.css?v={_CSS_VER}"></head>'
        f"<body{theme_attr}>"
        f"<header>{brand}{nav}{actions}</header>"
        f"{flashes}{body_html}</body></html>"
    )


def flash_msg(msg, cat="ok"):
    session.setdefault("_flashes", []).append((cat, msg))


def action_btn(cmd, label, cls=""):
    klass = f' class="{cls}"' if cls else ""
    return (
        '<form method=post action=/action style="display:inline">'
        f'<input type=hidden name=_csrf value="{e(new_csrf())}">'
        f'<input type=hidden name=cmd value="{e(cmd)}">'
        f"<button type=submit{klass}>{e(label)}</button></form>"
    )


# ---------- Cloudflare Access JWT validation (optional, RS256, pure stdlib) ----------
# When the panel's public hostname is protected by Cloudflare Access, requests
# arrive with a `Cf-Access-Jwt-Assertion` header. This validates that JWT against
# Cloudflare's published JWKS (RSASSA-PKCS1-v1.5: pow(sig,e,n) + PKCS#1 v1.5 unpad
# + SHA-256 DigestInfo), with a matching issuer/audience and an unexpired window —
# else 403 in enforce mode. Requests WITHOUT the header are loopback-only (Caddy
# blocks header-less public requests before they reach us), so they pass through to
# the normal login. This gate is purely ADDITIVE and the loopback escape hatch
# means a bug here cannot lock the operator out.
#
# Config (env vars, or ${DATA_DIR}/secrets/cf-access.env; all optional):
#   CF_ACCESS_MODE=log|enforce              (default log — observe before blocking)
#   CF_ACCESS_TEAM_DOMAIN=<team>.cloudflareaccess.com   (gate is inert if unset)
#   CF_ACCESS_AUD=<application audience tag> (aud enforced only when set)
_CFA = _load_env(os.path.join(SECRETS, "cf-access.env"))
def _cfa_cfg(key, default=""):
    return (os.environ.get(key) or _CFA.get(key) or default).strip()
CF_ACCESS_MODE = (_cfa_cfg("CF_ACCESS_MODE", "log")).lower()
CF_ACCESS_TEAM_DOMAIN = _cfa_cfg("CF_ACCESS_TEAM_DOMAIN", "")
CF_ACCESS_AUD = _cfa_cfg("CF_ACCESS_AUD", "")
CF_ACCESS_ISSUER = f"https://{CF_ACCESS_TEAM_DOMAIN}" if CF_ACCESS_TEAM_DOMAIN else ""
CF_ACCESS_CERTS_URL = f"{CF_ACCESS_ISSUER}/cdn-cgi/access/certs" if CF_ACCESS_ISSUER else ""
_CFA_LEEWAY = 60
_CFA_JWKS_TTL = 3600
_CFA_JWKS = {"keys": {}, "ts": 0.0}
_CFA_JWKS_LOCK = threading.Lock()
# ASN.1 DigestInfo prefix for SHA-256 (RFC 8017 §9.2, EMSA-PKCS1-v1_5).
_CFA_SHA256_DI = bytes.fromhex("3031300d060960864801650304020105000420")


def _cfa_b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _cfa_b64uint(s):
    return int.from_bytes(_cfa_b64d(s), "big")


def _cfa_jwks(force=False):
    """{kid: (n, e)} from Cloudflare Access, cached for _CFA_JWKS_TTL. Keeps the
    last good set if a refresh fails so a transient fetch error can't lock out
    every request."""
    now = time.time()
    with _CFA_JWKS_LOCK:
        if not force and _CFA_JWKS["keys"] and (now - _CFA_JWKS["ts"]) < _CFA_JWKS_TTL:
            return _CFA_JWKS["keys"]
        try:
            req = urllib.request.Request(
                CF_ACCESS_CERTS_URL, headers={"User-Agent": "pocket-homeserver-admin/1.0"})
            with urllib.request.urlopen(req, timeout=10) as r:
                doc = json.loads(r.read())
            keys = {}
            for k in doc.get("keys", []):
                if k.get("kty") == "RSA" and k.get("n") and k.get("e"):
                    keys[k.get("kid", "")] = (_cfa_b64uint(k["n"]), _cfa_b64uint(k["e"]))
            if keys:
                _CFA_JWKS["keys"], _CFA_JWKS["ts"] = keys, now
        except Exception as ex:
            log_audit("cf-access-jwks-fetch-failed", err=str(ex)[:120])
        return _CFA_JWKS["keys"]


def _cfa_verify_rs256(signing_input, sig, n, e):
    """RSASSA-PKCS1-v1.5 verify (pure stdlib). True iff sig is valid for n,e."""
    k = (n.bit_length() + 7) // 8
    if len(sig) != k:
        return False
    em = pow(int.from_bytes(sig, "big"), e, n).to_bytes(k, "big")
    t = _CFA_SHA256_DI + hashlib.sha256(signing_input).digest()
    ps = k - len(t) - 3
    if ps < 8:
        return False
    expected = b"\x00\x01" + b"\xff" * ps + b"\x00" + t
    return hmac.compare_digest(em, expected)


def _cfa_validate(token):
    """Validate a Cloudflare Access JWT; return claims dict or raise ValueError."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("not a compact JWS")
    h_b64, p_b64, s_b64 = parts
    header = json.loads(_cfa_b64d(h_b64))
    if header.get("alg") != "RS256":
        raise ValueError(f"alg {header.get('alg')!r} != RS256")
    kid = header.get("kid", "")
    ke = _cfa_jwks().get(kid) or _cfa_jwks(force=True).get(kid)  # refetch once on rotation
    if not ke:
        raise ValueError(f"unknown kid {kid!r}")
    if not _cfa_verify_rs256((h_b64 + "." + p_b64).encode(), _cfa_b64d(s_b64), *ke):
        raise ValueError("bad signature")
    claims = json.loads(_cfa_b64d(p_b64))
    now = time.time()
    if claims.get("iss") != CF_ACCESS_ISSUER:
        raise ValueError(f"iss {claims.get('iss')!r}")
    exp = claims.get("exp")
    if not isinstance(exp, (int, float)) or now > exp + _CFA_LEEWAY:
        raise ValueError("expired")
    nbf = claims.get("nbf")
    if isinstance(nbf, (int, float)) and now + _CFA_LEEWAY < nbf:
        raise ValueError("not yet valid")
    if CF_ACCESS_AUD:
        aud = claims.get("aud")
        if CF_ACCESS_AUD not in (aud if isinstance(aud, list) else [aud]):
            raise ValueError("aud mismatch")
    return claims


# ---------- routes ----------
@app.before_request
def _cf_access_gate():
    """Validate the Cloudflare Access JWT on every request that carries one.
    Inert unless a team domain is configured. log mode = observe only; enforce
    mode = 403 on any invalid token."""
    if not CF_ACCESS_TEAM_DOMAIN or CF_ACCESS_MODE not in ("log", "enforce"):
        return None
    tok = request.headers.get("Cf-Access-Jwt-Assertion")
    if not tok:
        return None      # loopback-only path — allow
    try:
        claims = _cfa_validate(tok)
    except Exception as ex:
        log_audit("cf-access-reject", ip=request.remote_addr or "?",
                  mode=CF_ACCESS_MODE, err=str(ex)[:120])
        if CF_ACCESS_MODE == "enforce":
            abort(403)
        return None
    if CF_ACCESS_MODE == "log":
        log_audit("cf-access-ok", ip=request.remote_addr or "?",
                  email=(claims.get("email") or claims.get("sub") or "")[:80],
                  aud=claims.get("aud"), iss=claims.get("iss"))
    request.environ["cf_access_email"] = claims.get("email") or claims.get("sub") or ""
    return None


@app.before_request
def _permanent():
    session.permanent = True


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("auth"):
        return redirect(url_for("dashboard"))
    error = None
    if request.method == "POST":
        ip = _lockout_ip()
        if not rate_limit_login(ip):
            error = "too many failed attempts; try again in 15 min"
            log_audit("login-blocked-ratelimit", ip=ip)
        elif not csrf_ok():
            error = "CSRF mismatch"
        else:
            pw = request.form.get("password", "")
            if verify_password(pw):
                session["auth"] = True; session["user"] = ADMIN_USER
                session["boot_nonce"] = BOOT_NONCE
                session.pop("csrf", None); new_csrf(); clear_fail(ip)
                log_audit("login", ok=True)
                return redirect(url_for("dashboard"))
            record_fail(ip); log_audit("login", ok=False)
            error = "wrong password"
    err_html = f'<div class="flash err">{e(error)}</div>' if error else ''
    body = f"""
<div class=box>
<h2>sign in</h2>{err_html}
<form method=post>
<input type=hidden name=_csrf value="{e(new_csrf())}">
<input name=password type=password placeholder=password autofocus required>
<button type=submit>sign in</button>
</form>
</div>"""
    return render(f"login — {BRAND} admin", body, hide_nav=True)


@app.route("/logout", methods=["POST"])
def logout():
    if not csrf_ok(): abort(403)
    log_audit("logout")
    session.clear()
    return redirect(url_for("login"))


@app.route("/theme", methods=["POST"])
def theme_toggle():
    if not csrf_ok(): abort(403)
    cur = request.cookies.get("theme", "auto")
    nxt = {"auto": "dark", "dark": "light", "light": "auto"}[cur]
    resp = make_response(redirect(request.referrer or url_for("dashboard")))
    resp.set_cookie("theme", nxt, max_age=60*60*24*365, samesite="Strict", httponly=False)
    return resp


# ---------- dashboard ----------
def _service_row(svc):
    port_s = f":{svc['port']}" if svc.get("port") else ""
    note = f' <span class=small>({e(svc["note"])})</span>' if svc.get("note") else ""
    # A DEGRADED marker (crash-looping) takes precedence over the up/down probe:
    # the service may flap green for a moment between respawns.
    if svc.get("degraded"):
        hint = ("crash-looping — DB may be corrupt; run scripts/ops/restore.sh"
                if svc["name"] == "matrix" else "crash-looping — see logs")
        return (f'<span class="dot degraded"></span>{e(svc["name"])}{port_s} '
                f'<span class=small style="color:var(--warn-fg)">⚠ {hint}</span>')
    dot_cls = "up" if svc["up"] else "down"
    return f'<span class="dot {dot_cls}"></span>{e(svc["name"])}{port_s}{note}'


def _bar(pct, threshold_warn=70, threshold_danger=90):
    cls = ""
    if pct >= threshold_danger: cls = "danger"
    elif pct >= threshold_warn: cls = "warn"
    return f'<div class="bar {cls}"><span style="width:{pct}%"></span></div>'


def _restart_buttons():
    btns = [("restart-matrix", "matrix"), ("restart-caddy", "caddy"),
            ("restart-cloudflared", "cloudflared")]
    if ENABLE["auth-gw"]:  btns.append(("restart-auth-gw", "auth-gw"))
    if ENABLE["linkding"]: btns += [("restart-linkding", "linkding"),
                                    ("restart-linkding-tasks", "linkding-tasks")]
    if ENABLE["pingvin"]:  btns.append(("restart-pingvin", "pingvin"))
    if ENABLE["freshrss"]: btns += [("restart-freshrss", "freshrss"),
                                     ("restart-freshrss-refresh", "freshrss-refresh")]
    if ENABLE["searxng"]:  btns.append(("restart-searxng", "searxng"))
    if ENABLE["memos"]:    btns.append(("restart-memos", "memos"))
    if ENABLE["vikunja"]:  btns.append(("restart-vikunja", "vikunja"))
    if ENABLE["gatus"]:    btns.append(("restart-gatus", "gatus"))
    if ENABLE["user-filter"]:  btns.append(("restart-user-filter", "user-filter"))
    if ENABLE["media-filter"]: btns.append(("restart-media-filter", "media-filter"))
    # files & sync (v0.6)
    if ENABLE["dufs"]:         btns.append(("restart-dufs", "dufs"))
    if ENABLE["filebrowser"]:  btns.append(("restart-filebrowser", "filebrowser"))
    if ENABLE["syncthing"]:    btns.append(("restart-syncthing", "syncthing"))
    # productivity & security (v0.7)
    if ENABLE["wallabag"]:     btns.append(("restart-wallabag", "wallabag"))
    if ENABLE["radicale"]:     btns.append(("restart-radicale", "radicale"))
    if ENABLE["trilium"]:      btns.append(("restart-trilium", "trilium"))
    if ENABLE["vaultwarden"]:  btns.append(("restart-vaultwarden", "vaultwarden"))
    # media (v0.8)
    if ENABLE["navidrome"]:      btns.append(("restart-navidrome", "navidrome"))
    if ENABLE["kavita"]:         btns.append(("restart-kavita", "kavita"))
    if ENABLE["audiobookshelf"]: btns.append(("restart-audiobookshelf", "audiobookshelf"))
    # platform & networking (v0.9) — proxy-routes has no process (apply on the catalog page)
    if ENABLE["forgejo"]:      btns.append(("restart-forgejo", "forgejo"))
    if ENABLE["adguard"]:      btns.append(("restart-adguard", "adguard"))
    if ENABLE["tailscale"]:    btns.append(("restart-tailscaled", "tailscale"))
    out = "".join(action_btn(k, l, "small") for k, l in btns)
    out += ' <a href="/danger" class="btn danger small">full-stack restart…</a>'
    return out


@app.route("/")
@login_required
def dashboard():
    s = gather_stats()
    svc_html = "<br>".join(_service_row(x) for x in s["services"])
    restart_buttons = _restart_buttons()

    # Loud problems banner (cheap): crash-loop markers + any down core service.
    _dnames = _degraded_names()
    _down = [x["name"] for x in s.get("services", [])
             if not x.get("up") and not x.get("degraded")]
    problems_banner = ""
    if _dnames or _down:
        _bits = []
        if _dnames:
            _bits.append(f"{len(_dnames)} crash-looping ({e(', '.join(_dnames))})")
        if _down:
            _bits.append(f"{len(_down)} down ({e(', '.join(_down))})")
        problems_banner = (
            '<div class="flash err">⚠ ' + " · ".join(_bits)
            + ' &nbsp;<a href="/problems">open problems →</a></div>'
        )

    # Optional admin-bot quick-command widget — each button POSTs one allowlisted
    # read-only !command to the admin-ops room (the bot replies in Element).
    bot_widget = ""
    if ENABLE.get("adminbot"):
        _bbtns = "".join(
            '<form method=post action="/bot/send" style="display:inline">'
            f'<input type=hidden name=_csrf value="{e(new_csrf())}">'
            f'<input type=hidden name=cmd value="!{c}">'
            f'<button class="small" type=submit>!{c}</button></form> '
            for c in ("status", "users", "private-list", "invite-token", "whoami")
        )
        bot_widget = (
            "<hr><h3>admin bot</h3>"
            f"<p>{_bbtns}</p>"
            "<p class=small>Sends a read-only command to the admin-ops room; "
            "open Element to see the bot's reply. Destructive ops run in Element.</p>"
        )

    mem_pct = s.get("mem_pct", 0)
    mem_line = (
        f'{human_bytes(s.get("mem_used",0))} / {human_bytes(s.get("mem_total",0))} '
        f'({mem_pct}%)<br>{_bar(mem_pct)}'
    )

    storage_lines = []
    for d in s.get("storage", []):
        storage_lines.append(
            f"<dt>{e(d['label'])}</dt>"
            f"<dd>{human_bytes(d['used'])} / {human_bytes(d['total'])} "
            f"({d['pct']}%)<br>{_bar(d['pct'])}</dd>"
        )

    b = s.get("battery")
    if b:
        batt_line = f"{b['pct']}%, {b['temp']}°C, {e(b['status'])}, {e(b['plugged'])}"
    else:
        batt_line = "(termux-api unreachable)"

    thermal = s.get("thermal", [])
    if thermal:
        top = sorted(thermal, key=lambda z: -z["temp"])[:3]
        thermal_line = " · ".join(f"{e(z['zone'])}:{z['temp']:.0f}°C" for z in top)
    else:
        thermal_line = "?"

    net = s.get("net")
    if net is None:
        net_line = ('<span class=small>restricted — the OS blocks /proc/net/dev for this app. '
                    'Install Shizuku + its rish bridge to read it (optional; see docs/ADMIN.md).</span>')
    elif net:
        def _nrate(n):
            if n.get("rate_rx") is None:
                return ""
            return f' <span class=small>({human_bytes(n["rate_rx"])}/s↓ {human_bytes(n["rate_tx"])}/s↑)</span>'
        _src = ' <span class=small>(via Shizuku)</span>' if s.get("net_source") == "rish" else ''
        net_line = "<br>".join(
            f"{e(n['iface'])}: ↓{human_bytes(n['rx'])} ↑{human_bytes(n['tx'])}{_nrate(n)}"
            for n in net[:3]
        ) + _src
    else:
        net_line = '<span class=small>no active interfaces</span>'

    load_full = s.get('load', '?')
    _lp = load_full.split(' / ')
    load1 = _lp[0] if _lp else '?'
    load_rest = ' / '.join(_lp[1:]) if len(_lp) > 1 else ''
    mem_used_gb = s.get('mem_used', 0) / 1073741824
    mem_total_gb = s.get('mem_total', 0) / 1073741824
    batt_pct = b['pct'] if b else '?'

    body = f"""
{problems_banner}
<div class=statgrid>
  <div class=stat><div class=lbl>uptime</div><div class=val>{e(s.get('uptime','?'))}</div></div>
  <div class="stat accent"><div class=lbl>load · 1/5/15m</div><div class=val><span id=k-load>{e(load1)}</span> <small>/ {e(load_rest)}</small></div>
    <svg class=spark width=70 height=24 viewBox="0 0 70 24" preserveAspectRatio=none><path id=k-load-ar class=ar d=""></path><path id=k-load-ln class=ln d=""></path></svg></div>
  <div class="stat accent"><div class=lbl>RAM</div><div class=val><span id=k-ram>{mem_used_gb:.1f}</span> <small>/ {mem_total_gb:.1f} GB · <span id=k-ram-pct>{mem_pct}</span>%</small></div>
    <div class=bar><span id=k-ram-bar style="width:{mem_pct}%"></span></div></div>
  <div class=stat><div class=lbl>battery · thermal</div><div class=val>{e(str(batt_pct))}% <small>· {s.get('max_temp',0):.0f}°C</small></div></div>
</div>

<div class=grid2>

<div class=box>
<h2><span class=ico>\U0001FA7A</span> stack health</h2>
<p id=svc-block style="margin-top:.5rem">{svc_html}</p>
<hr>
<h3>quick restart</h3>
<p>{restart_buttons}</p>
<p class=small>Each service auto-restarts on crash; buttons are for manual intervention.</p>
<p>{action_btn("run-doctor", "run doctor", "small")}<span class=small> &nbsp;read-only preflight + health check (scripts/ops/doctor.sh)</span></p>
{bot_widget}
</div>

<div class=col>
<div class=box>
<h2><span class=ico>\U0001F4CA</span> glance metrics</h2>
<dl class=metrics style="margin-top:.5rem">
<dt>device</dt><dd>{e(s.get('device','?'))} · Android {e(s.get('android','?'))}</dd>
<dt>uptime</dt><dd>{e(s.get('uptime','?'))}</dd>
<dt>load 1/5/15m</dt><dd id=load-line>{e(s.get('load','?'))}</dd>
<dt>CPU</dt><dd>{s.get('cpu_cores','?')} cores — {e(s.get('cpu_freq','?'))}<br><span class=small>{e(s.get('cpu_model','?'))}</span></dd>
<dt>GPU</dt><dd><span class=small>{e(s.get('gpu_note','?'))}</span></dd>
<dt>RAM</dt><dd id=mem-line>{mem_line}</dd>
{''.join(storage_lines)}
<dt>battery</dt><dd>{e(batt_line)}</dd>
<dt>thermal</dt><dd>{thermal_line} <span class=small>(max {s.get('max_temp',0):.0f}°C)</span></dd>
<dt>network</dt><dd>{net_line}</dd>
</dl>
</div>
</div>

</div>

<div class=botbar>
  <span class=bb-live><span id=live-dot title="live">●</span> live · updates every second</span>
  <a href="/stats">full stats →</a>
</div>
{_SSE_SCRIPT}
"""
    return render(f"dashboard — {BRAND} admin", body)


@app.route("/health")
@login_required
def health_page():
    h = gather_health()
    s = h["summary"]
    overall_class = "ok" if s["all_green"] else ("warn" if s["http_ok"] == s["http_total"] else "err")
    overall_label = "ALL GREEN" if s["all_green"] else (
        "DEGRADED" if s["http_ok"] == s["http_total"] else "FAIL")

    http_rows = ""
    for r in h["http"]:
        cls = "ok" if r["ok"] else "err"
        code_disp = r["code"] if r["code"] else "—"
        err = e(r["error"]) if r["error"] else ""
        scheme_disp = "loop" if r["scheme"] == "loopback" else "http"
        http_rows += (
            f'<tr class="health-{cls}"><td>{e(r["name"])}</td>'
            f'<td>{e(r["host"])}{e(r["path"])}</td>'
            f'<td>{scheme_disp}</td>'
            f'<td>{code_disp} <span class=small>(want {r["expect"]})</span></td>'
            f'<td>{r["latency_ms"]} ms</td>'
            f'<td>{err}</td></tr>'
        )

    proc_rows = ""
    for r in h["procs"]:
        if r.get("degraded"):
            cls = "err"
            status = "CRASH-LOOPING ⚠ (see logs)"
        elif r["alive"]:
            cls = "ok"; status = f"alive (pid {r['pid']})"
        else:
            cls = "err"; status = "DOWN"
        proc_rows += (
            f'<tr class="health-{cls}"><td>{e(r["name"])}</td>'
            f'<td><code class=small>{e(r["pattern"])}</code></td>'
            f'<td>{status}</td></tr>'
        )

    body = f"""
<div class=box>
<h2><span class=ico>\U0001FA7A</span> health <span class="health-banner health-{overall_class}">{overall_label}</span></h2>
<p class=small>probed {e(h['ts'])} · auto-refresh every 30s</p>
<dl class=metrics style="margin-top:.4rem">
<dt>HTTP probes</dt><dd>{s['http_ok']} / {s['http_total']} ok</dd>
<dt>processes</dt><dd>{s['proc_ok']} / {s['proc_total']} alive</dd>
</dl>
</div>
<div class=box>
<h2><span class=ico>\U0001F310</span> HTTP endpoints</h2>
<p class=small>loopback probes hit <code>http://{e(CADDY_BIND)}:{e(CADDY_PORT)}</code> (Caddy is plain HTTP on-device; TLS terminates at the Cloudflare edge) with the public hostname in the Host header. A direct conduwuit probe verifies the upstream regardless of Caddy.</p>
<div class=tablewrap><table>
<thead><tr><th>name</th><th>endpoint</th><th>via</th><th>status</th><th>latency</th><th>error</th></tr></thead>
<tbody>{http_rows}</tbody>
</table></div>
</div>
<div class=box>
<h2><span class=ico>⚙️</span> processes</h2>
<div class=tablewrap><table>
<thead><tr><th>service</th><th>pgrep pattern</th><th>state</th></tr></thead>
<tbody>{proc_rows}</tbody>
</table></div>
</div>
<meta http-equiv="refresh" content="30">
"""
    return render(f"health — {BRAND} admin", body)


@app.route("/stats")
@login_required
def stats_page():
    s = gather_stats()
    body = f"""
<div class=cardgrid>
<div class=box>
<h2><span class=ico>\U0001F4F1</span> device</h2>
<dl class=metrics style="margin-top:.4rem">
<dt>model</dt><dd>{e(s.get('device','?'))}</dd>
<dt>Android</dt><dd>{e(s.get('android','?'))}</dd>
<dt>kernel</dt><dd>{e(s.get('kernel','?'))}</dd>
<dt>uptime</dt><dd>{e(s.get('uptime','?'))}</dd>
</dl>
</div>
<div class=box>
<h2><span class=ico>\U0001F9E0</span> CPU</h2>
<dl class=metrics style="margin-top:.4rem">
<dt>model</dt><dd>{e(s.get('cpu_model','?'))}</dd>
<dt>cores</dt><dd>{s.get('cpu_cores','?')}</dd>
<dt>freq</dt><dd>{e(s.get('cpu_freq','?'))}</dd>
<dt>load 1/5/15m</dt><dd>{e(s.get('load','?'))}</dd>
</dl>
</div>
<div class=box>
<h2><span class=ico>\U0001F3AE</span> GPU</h2>
<p style="margin-top:.4rem">{e(s.get('gpu_note','?'))}</p>
</div>
<div class=box>
<h2><span class=ico>\U0001F4BE</span> memory</h2>
<dl class=metrics style="margin-top:.4rem">
<dt>RAM</dt><dd>{human_bytes(s.get('mem_used',0))} / {human_bytes(s.get('mem_total',0))} ({s.get('mem_pct',0)}%){_bar(s.get('mem_pct',0))}</dd>
<dt>swap</dt><dd>{human_bytes(s.get('swap_used',0))} / {human_bytes(s.get('swap_total',0))}</dd>
</dl>
</div>
</div>
<div class=box>
<h2><span class=ico>\U0001F321️</span> thermal zones</h2>
<div class=tablewrap><table><thead><tr><th>zone</th><th>temp</th></tr></thead>
<tbody>{''.join(f'<tr><td>{e(z["zone"])}</td><td>{z["temp"]:.1f}°C</td></tr>' for z in s.get('thermal', []))}</tbody>
</table></div>
</div>
<div class=box>
<h2><span class=ico>\U0001F4E1</span> network interfaces{' <span class=small>(via Shizuku)</span>' if s.get('net_source') == 'rish' else ''}</h2>
<div class=tablewrap><table><thead><tr><th>interface</th><th>rx</th><th>tx</th><th>rate</th></tr></thead>
<tbody>{('<tr><td colspan=4 class=small>restricted — the OS blocks /proc/net/dev for this app. Install Shizuku + its rish bridge to read it as shell uid (optional; see docs/ADMIN.md).</td></tr>' if s.get('net') is None else ''.join(f'<tr><td class=mono>{e(n["iface"])}</td><td>{human_bytes(n["rx"])}</td><td>{human_bytes(n["tx"])}</td><td class=small>{(human_bytes(n["rate_rx"])+"/s↓ "+human_bytes(n["rate_tx"])+"/s↑") if n.get("rate_rx") is not None else "—"}</td></tr>' for n in (s.get('net') or [])))}</tbody>
</table></div>
</div>
"""
    return render(f"stats — {BRAND} admin", body)


# ---------- admin-bot quick-command widget ----------
# Posts a SAFE, read-only `!command` to the private admin-ops room as the operator
# (their ADMIN_TOKEN from admin-credentials.env) so the supervised adminbot — whose
# handle() gate only obeys ADMIN_MXID — picks it up and replies in Element. The
# panel never shows the reply; it just queues the command. Destructive commands are
# DELIBERATELY excluded from the allowlist (issue those in Element so the bot's
# in-band confirm gate + audit trail apply).
_BOT_SEND_ALLOWLIST = {
    "status",        # ops/status.sh output (read-only)
    "users",         # list users sharing a room with the operator (read-only)
    "private-list",  # list hidden users (read-only)
    "invite-token",  # reveal current registration token (operator-only room; audited)
    "whoami",        # bot identity (read-only)
    "help",          # command list (read-only)
}


@app.route("/bot/send", methods=["POST"])
@login_required
def bot_send():
    if not csrf_ok():
        abort(403)
    cmd = (request.form.get("cmd") or "").strip()
    # Shape gate: a single short `!word`-ish command, no shell metacharacters. The
    # strict allowlist below is the real authority; this just rejects garbage early.
    if not cmd.startswith("!") or len(cmd) > 120 or not re.fullmatch(r"![\w\-:@. ]+", cmd):
        log_audit("bot-send", cmd=cmd, ok=False, reason="malformed")
        flash_msg("malformed command", "err")
        return redirect(url_for("dashboard"))
    # Only SAFE (read-only / trivially undoable) commands. Anything else must be
    # issued from Element directly (audit trail + the bot's confirm gate).
    cmd_root = cmd[1:].split()[0] if len(cmd) > 1 else ""
    if cmd_root not in _BOT_SEND_ALLOWLIST:
        log_audit("bot-send", cmd=cmd, ok=False, reason="not-in-allowlist")
        flash_msg(f"command !{cmd_root} not allowed via the panel — use Element + the bot directly", "err")
        return redirect(url_for("dashboard"))
    # Send as the OPERATOR (their ADMIN_TOKEN) into the admin-ops room so the bot's
    # ADMIN_MXID gate accepts it. Both come from 0600 secrets files; the token is
    # used only in the Authorization header (never logged / flashed).
    admin = _load_env(ADMIN_CRED_FILE)
    bot   = _load_env(ADMINBOT_CRED_FILE)
    tok  = admin.get("ADMIN_TOKEN")
    room = bot.get("ADMIN_ROOM")
    if not tok or not room:
        log_audit("bot-send", cmd=cmd, ok=False, reason="creds-missing")
        flash_msg("can't send — operator token or admin-ops room missing", "err")
        return redirect(url_for("dashboard"))
    import urllib.parse as up, urllib.request as ur
    txn = str(time.time_ns())
    body = json.dumps({"msgtype": "m.text", "body": cmd}).encode()
    url = (f"{MATRIX_HS_API}/_matrix/client/v3/rooms/{up.quote(room)}"
           f"/send/m.room.message/{txn}")
    req = ur.Request(url, method="PUT", data=body,
                     headers={"Authorization": f"Bearer {tok}",
                              "Content-Type": "application/json"})
    try:
        ur.urlopen(req, timeout=10).read()
        log_audit("bot-send", cmd=cmd, ok=True)
        flash_msg(f"sent {cmd} to the admin-ops room — open Element to see the bot reply", "ok")
    except Exception as ex:
        log_audit("bot-send", cmd=cmd, ok=False, reason=str(ex))
        flash_msg(f"send failed: {ex}", "err")
    return redirect(url_for("dashboard"))


# ---------- simple action dispatch (quick-click) ----------
@app.route("/action", methods=["POST"])
@login_required
def action():
    if not csrf_ok(): abort(403)
    cmd = request.form.get("cmd", "")
    spec = SCRIPTS_OK.get(cmd)
    if spec is None:
        abort(400, description="unknown command")
    if spec["kind"] == "danger":
        log_audit("action", cmd=cmd, ok=False, reason="danger-needs-explicit-confirm")
        flash_msg("that command is danger-tier — use the danger page", "err")
        return redirect(url_for("danger_page"))
    if cmd == "restart-stack":
        return redirect(url_for("confirm_action", action_key="restart-stack"))
    if spec["kind"] == "async":
        ok, logname = run_script_detached(cmd)
        log_audit("action-async", cmd=cmd, ok=ok, log=logname)
        icon = "\U0001F7E2" if ok else "❌"
        verb = "started in the background" if ok else "FAILED to launch"
        body = f"""
<div class=box>
<h2>{icon} {e(cmd)} {verb}</h2>
<p>This runs detached from the web worker, so this page does not block on it.</p>
<p class=small>Watch progress in <code>logs/{e(logname)}</code>. New archives appear
on the <a href="/backups">backups page</a> as they finish.</p>
<a href="/backups">← backups</a> &nbsp; <a href="/">dashboard</a>
</div>"""
        return render(f"{cmd} — {BRAND} admin", body)
    log_audit("action-start", cmd=cmd, kind=spec["kind"])
    rc, out = run_script(cmd)
    log_audit("action-end", cmd=cmd, rc=rc)
    icon = "✅" if rc == 0 else "❌"
    body = f"""
<div class=box>
<h2>{icon} {e(cmd)} → exit={rc}</h2>
<pre>{e(redact_secrets(out))}</pre>
<a href="/">← dashboard</a>
</div>"""
    return render(f"{cmd} — {BRAND} admin", body)


# ---------- confirm-action page ----------
@app.route("/confirm/<action_key>", methods=["GET", "POST"])
@login_required
def confirm_action(action_key):
    """Two-page confirmation flow for any DANGER_META action:
      GET stage 1: show impact + Continue button.
      GET stage 2 (?stage=2): typed phrase + literal 'yes' + password.
      POST: validate all three, then dispatch.
    """
    meta = DANGER_META.get(action_key)
    if not meta or action_key not in SCRIPTS_OK:
        abort(404)

    if request.method == "POST":
        if not csrf_ok(): abort(403)
        typed_phrase = request.form.get("phrase", "").strip().lower()
        typed_yes    = request.form.get("yes", "").strip().lower()
        pw           = request.form.get("password", "")

        if typed_phrase != meta["phrase"]:
            log_audit("confirm", action=action_key, ok=False, reason="phrase-mismatch")
            flash_msg(f"confirmation phrase mismatch — type exactly: {meta['phrase']}", "err")
            return redirect(url_for("confirm_action", action_key=action_key, stage=2))
        if typed_yes != "yes":
            log_audit("confirm", action=action_key, ok=False, reason="yes-not-typed")
            flash_msg("you must literally type 'yes' to confirm", "err")
            return redirect(url_for("confirm_action", action_key=action_key, stage=2))
        if not pw or not verify_password(pw):
            log_audit("confirm", action=action_key, ok=False, reason="bad-password")
            flash_msg("password incorrect — re-auth required", "err")
            return redirect(url_for("confirm_action", action_key=action_key, stage=2))

        log_audit("confirm-go", action=action_key)
        rc, out = run_script(action_key)
        log_audit("action-end", cmd=action_key, rc=rc)
        icon = "✅" if rc == 0 else "❌"
        body = f"""
<div class=box>
<h2>{icon} {e(meta['title'])} → exit={rc}</h2>
<pre>{e(redact_secrets(out))}</pre>
<a href="/">← dashboard</a>
</div>"""
        return render(f"{action_key} — {BRAND} admin", body)

    impact_html = "\n".join(f"<li>{e(x)}</li>" for x in meta["impact"])
    rev = "reversible" if meta.get("reversible") else "NOT reversible"
    stage = request.args.get("stage", "1")

    if stage == "1":
        body = f"""
<div class="box danger-zone">
<h2>⚠ {e(meta['title'])} — review</h2>
<div class=warn-box>
<strong>What this does:</strong>
<ul>{impact_html}</ul>
<p><strong>Reversibility:</strong> {rev}</p>
</div>
<p class=small style="margin-top:1rem">If you really want to proceed, click Continue. The next page asks for typed confirmation, the literal word <code>yes</code>, and your password — three independent inputs, designed to stop accidental clicks.</p>
<form method=get action="{url_for('confirm_action', action_key=action_key)}">
<input type=hidden name=stage value="2">
<button type=submit class=danger>Continue →</button>
<a href="/danger" class="btn small">cancel</a>
</form>
</div>"""
        return render(f"confirm step 1 — {meta['title']}", body)

    body = f"""
<div class="box danger-zone">
<h2>⚠ {e(meta['title'])} — final confirm</h2>
<div class=warn-box>
<p class=small><a href="{url_for('confirm_action', action_key=action_key)}">← back to impact summary</a></p>
<p>Three inputs. All required. None can be auto-completed.</p>
</div>
<form method=post>
<input type=hidden name=_csrf value="{e(new_csrf())}">
<p>1. Type exactly <code>{e(meta['phrase'])}</code>:</p>
<input name=phrase type=text autocomplete=off required placeholder="{e(meta['phrase'])}">
<p>2. Type literally <code>yes</code>:</p>
<input name=yes type=text autocomplete=off required placeholder="yes" pattern="[Yy][Ee][Ss]" maxlength=3>
<p>3. Re-enter your admin password:</p>
<input name=password type=password autocomplete=current-password required>
<button type=submit class=danger>confirm {e(meta['title'].lower())}</button>
<a href="/danger" class="btn small">cancel</a>
</form>
</div>"""
    return render(f"confirm step 2 — {meta['title']}", body)


# ---------- backups ----------
_SAFE_BKP_NAME = re.compile(r"^[\w.:\-+]+\.tar\.zst(\.age)?$")
_SAFE_BUCKET = re.compile(r"^(db|rootfs)$")


@app.route("/backups")
@login_required
def backups():
    rows_html = []
    for bucket in ("db", "rootfs"):
        d = os.path.join(BACKUP_DIR, bucket)
        if os.path.isdir(d):
            files = sorted(
                (f for f in os.listdir(d) if _SAFE_BKP_NAME.fullmatch(f)),
                key=lambda f: os.path.getmtime(os.path.join(d, f)),
                reverse=True,
            )
            for fn in files[:30]:
                path = os.path.join(d, fn)
                age_h = (time.time() - os.path.getmtime(path)) / 3600
                del_form = (
                    '<form method=get action="/backups/delete" style="display:inline">'
                    f'<input type=hidden name=bucket value="{e(bucket)}">'
                    f'<input type=hidden name=file value="{e(fn)}">'
                    '<button class="danger small" type=submit>delete…</button></form>'
                )
                rows_html.append(
                    f'<tr><td>{e(bucket)}</td><td>{e(fn)}</td>'
                    f'<td>{os.path.getsize(path)/1024/1024:.1f} MB</td>'
                    f'<td>{age_h:.1f} h</td><td>{del_form}</td></tr>'
                )
    table = "\n".join(rows_html) or '<tr><td colspan=5>no backups yet</td></tr>'
    body = f"""
<div class=box>
<h2><span class=ico>\U0001F5C4️</span> backups</h2>
<div class=tablewrap><table>
<thead><tr><th>bucket</th><th>file</th><th>size</th><th>age</th><th>actions</th></tr></thead>
<tbody>{table}</tbody>
</table></div>
<p class=small>Stored under <code>{e(BACKUP_DIR)}</code>. Copy them off-device for real durability. Retention keeps the newest few per bucket when <em>prune old</em> runs (see docs/BACKUPS.md).</p>
</div>
<div class=box>
<h2><span class=ico>▶️</span> trigger backup</h2>
{action_btn("full-backup", "FULL backup (whole userland rootfs)", "primary")}
<p class=small><strong>full-backup</strong> tars the entire Debian rootfs (~1 GB) and runs in the background — new files appear above as it finishes. The homeserver stops briefly during the tar.</p>
<hr>
{action_btn("backup-now", "backup the homeserver DB")}
{action_btn("rotate-backups", "prune old (apply retention)")}
<p class=small><strong>backup-now</strong> stops the homeserver for tens of seconds for a consistent DB snapshot. App data lives on the large volume (back that up by copying the volume).</p>
{('<hr>' + action_btn("offsite-push", "push encrypted backups off-device", "primary") + '<p class=small><strong>offsite push</strong> uploads the age-encrypted archives to your S3 bucket and runs in the background. Configure <code>' + e(os.path.join(SECRETS, "offsite.env")) + '</code> (0600). See docs/BACKUPS.md.</p>') if ENABLE.get("offsite") else ''}
</div>"""
    return render(f"backups — {BRAND} admin", body)


@app.route("/backups/delete", methods=["GET", "POST"])
@login_required
def backups_delete():
    bucket = request.values.get("bucket", "")
    fn = request.values.get("file", "")
    if not _SAFE_BUCKET.fullmatch(bucket) or not _SAFE_BKP_NAME.fullmatch(fn):
        abort(400, description="invalid bucket or filename")
    path = os.path.join(BACKUP_DIR, bucket, fn)
    real = os.path.realpath(path)
    expected_prefix = os.path.realpath(os.path.join(BACKUP_DIR, bucket))
    if not real.startswith(expected_prefix + os.sep):
        abort(400, description="path traversal rejected")
    if not os.path.isfile(real):
        flash_msg(f"file not found: {fn}", "err")
        return redirect(url_for("backups"))

    meta = DANGER_META["delete-backup"]

    if request.method == "POST":
        if not csrf_ok(): abort(403)
        typed_phrase = request.form.get("phrase", "").strip().lower()
        typed_yes    = request.form.get("yes", "").strip().lower()
        pw           = request.form.get("password", "")
        if typed_phrase != meta["phrase"]:
            flash_msg(f"phrase mismatch — type exactly: {meta['phrase']}", "err")
            return redirect(url_for("backups_delete", bucket=bucket, file=fn, stage=2))
        if typed_yes != "yes":
            flash_msg("you must literally type 'yes' to confirm", "err")
            return redirect(url_for("backups_delete", bucket=bucket, file=fn, stage=2))
        if not pw or not verify_password(pw):
            log_audit("backup-delete", bucket=bucket, file=fn, ok=False, reason="bad-password")
            flash_msg("password incorrect — re-auth required", "err")
            return redirect(url_for("backups_delete", bucket=bucket, file=fn, stage=2))
        try:
            os.unlink(real)
            for side in (real + ".sha256", real + ".age.sha256"):
                if os.path.isfile(side):
                    os.unlink(side)
            log_audit("backup-delete", bucket=bucket, file=fn, ok=True)
            flash_msg(f"deleted {fn}", "ok")
        except Exception as ex:
            log_audit("backup-delete", bucket=bucket, file=fn, ok=False, reason=str(ex))
            flash_msg(f"delete failed: {ex}", "err")
        return redirect(url_for("backups"))

    size_mb = os.path.getsize(real) / 1024 / 1024
    age_h = (time.time() - os.path.getmtime(real)) / 3600
    impact_html = "\n".join(f"<li>{e(x)}</li>" for x in meta["impact"])
    stage = request.args.get("stage", "1")

    if stage == "1":
        body = f"""
<div class="box danger-zone">
<h2>⚠ Delete backup — review</h2>
<div class=warn-box>
<p><strong>File:</strong> <code>{e(bucket)}/{e(fn)}</code> — {size_mb:.1f} MB, {age_h:.1f} h old</p>
<strong>Impact:</strong>
<ul>{impact_html}</ul>
<p><strong>Reversibility:</strong> NOT reversible — keep another copy off-device.</p>
</div>
<p class=small style="margin-top:1rem">If you really want to delete this file, click Continue. The next page asks for the typed phrase, the literal word <code>yes</code>, and your password.</p>
<form method=get action="{url_for('backups_delete')}">
<input type=hidden name=stage value="2">
<input type=hidden name=bucket value="{e(bucket)}">
<input type=hidden name=file value="{e(fn)}">
<button type=submit class=danger>Continue →</button>
<a href="/backups" class="btn small">cancel</a>
</form>
</div>"""
        return render("review delete backup", body)

    body = f"""
<div class="box danger-zone">
<h2>⚠ Delete backup — final confirm</h2>
<div class=warn-box>
<p><strong>File:</strong> <code>{e(bucket)}/{e(fn)}</code> — {size_mb:.1f} MB, {age_h:.1f} h old</p>
<p class=small><a href="{url_for('backups_delete', bucket=bucket, file=fn)}">← back to impact summary</a></p>
</div>
<form method=post>
<input type=hidden name=_csrf value="{e(new_csrf())}">
<input type=hidden name=bucket value="{e(bucket)}">
<input type=hidden name=file value="{e(fn)}">
<p>1. Type exactly <code>{e(meta['phrase'])}</code>:</p>
<input name=phrase type=text autocomplete=off required placeholder="{e(meta['phrase'])}">
<p>2. Type literally <code>yes</code>:</p>
<input name=yes type=text autocomplete=off required placeholder="yes" pattern="[Yy][Ee][Ss]" maxlength=3>
<p>3. Re-enter your admin password:</p>
<input name=password type=password autocomplete=current-password required>
<button type=submit class=danger>delete backup</button>
<a href="/backups" class="btn small">cancel</a>
</form>
</div>"""
    return render("confirm delete backup", body)


# ---------- tokens / logs ----------
@app.route("/tokens", methods=["GET", "POST"])
@login_required
def tokens_page():
    """The registration token is masked by default. Reveal requires re-entering
    the admin password (POST), rate-limited via the same backoff as /login."""
    reg_full = ""
    try:
        with open(os.path.join(SECRETS, "registration-token.txt")) as f:
            reg_full = f.read().strip()
    except Exception:
        pass

    if len(reg_full) >= 12:
        reg_display = f"{reg_full[:4]}…{reg_full[-4:]}"
    elif reg_full:
        reg_display = "•" * len(reg_full)
    else:
        reg_display = "(no token set yet — rotate one from the danger zone)"

    revealed = False
    msg_html = ""
    if request.method == "POST":
        if not csrf_ok(): abort(403)
        ip = request.remote_addr or "?"
        if not rate_limit_login(ip):
            log_audit("tokens-reveal", ok=False, reason="ratelimit", ip=ip)
            msg_html = '<div class="flash err">too many recent failed reveals — try again later.</div>'
        else:
            pw = request.form.get("password", "")
            if verify_password(pw):
                revealed = True
                reg_display = reg_full or "(no token set yet)"
                clear_fail(ip)
                log_audit("tokens-reveal", ok=True, ip=ip)
            else:
                record_fail(ip)
                log_audit("tokens-reveal", ok=False, reason="bad-password", ip=ip)
                msg_html = '<div class="flash err">password incorrect — token still masked.</div>'

    if revealed:
        action_html = '<p class=small>Token revealed for this view only — refresh hides it.</p>'
    else:
        action_html = f"""
<form method=post>
<input type=hidden name=_csrf value="{e(new_csrf())}">
<p class=small>Token is masked. Re-enter your password to reveal.</p>
<input name=password type=password autocomplete=current-password required>
<button type=submit>reveal token</button>
</form>
"""
    body = f"""
<div class=box>
<h2>registration token (shared invite code)</h2>
<pre>{e(reg_display)}</pre>
{msg_html}
{action_html}
<p class=small>Distribute privately to invited users; never post it publicly. Rotate it from the <a href="/danger">danger zone</a> if it leaks.</p>
</div>
<div class=box>
<h2>admin user</h2>
<ul>
<li>Panel login user: <code>{e(ADMIN_USER)}</code></li>
<li>Rotate the panel password from the <a href="/danger">danger zone</a>.</li>
</ul>
</div>"""
    return render(f"tokens — {BRAND} admin", body)


@app.route("/logs")
@login_required
def logs_index():
    rows = []
    if os.path.isdir(LOGS):
        for fn in sorted(os.listdir(LOGS)):
            if fn.endswith(".log"):
                p = os.path.join(LOGS, fn)
                rows.append(
                    f'<tr><td><a href="/logs/{e(fn[:-4])}">{e(fn[:-4])}</a></td>'
                    f"<td>{os.path.getsize(p)/1024:.1f} KB</td></tr>"
                )
    table = "\n".join(rows) or '<tr><td colspan=2>no logs</td></tr>'
    body = f"""
<div class=box>
<h2>service logs</h2>
<table><tr><th>service</th><th>size</th></tr>{table}</table>
<p class=small>view shows the last 200 lines. Logs live under <code>{e(LOGS)}</code>.</p>
</div>"""
    return render(f"logs — {BRAND} admin", body)


@app.route("/logs/<name>")
@login_required
def logs_view(name):
    if "/" in name or ".." in name or not name.replace("-", "").replace("_", "").isalnum():
        abort(400)
    path = os.path.join(LOGS, name + ".log")
    if not os.path.isfile(path):
        abort(404)
    try:
        n = int(request.args.get("n", "200"))
    except (TypeError, ValueError):
        n = 200
    n = max(20, min(n, 2000))
    # grep is a plain CASE-INSENSITIVE SUBSTRING filter, not a regex — there is no
    # pattern to compile and no shell, so no injection or ReDoS surface.
    grep = (request.args.get("grep", "") or "").strip()
    total = matched = 0
    try:
        with open(path, errors="replace") as f:
            lines = f.readlines()
        total = len(lines)
        if grep:
            gl = grep.lower()
            lines = [ln for ln in lines if gl in ln.lower()]
            matched = len(lines)
        content = "".join(lines[-n:])
    except Exception as ex:
        content = f"[read error] {ex}"
    filt = (f' · matched <strong>{matched}</strong> of {total} lines for '
            f'<code>{e(grep)}</code>' if grep else f' · {total} lines')
    body = f"""
<div class=box>
<h2>log: {e(name)}</h2>
<form method=get action="/logs/{e(name)}" class=block>
  <input type=text name=grep value="{e(grep)}" placeholder="filter (substring, case-insensitive)" autocomplete=off>
  <input type=text name=n value="{n}" inputmode=numeric pattern="[0-9]*" style="min-width:5rem" title="lines to show (20–2000)">
  <button type=submit class=small>filter</button>
  {('<a href="/logs/' + e(name) + '" class="btn small">clear</a>') if grep else ''}
</form>
<p class=small>showing last {n} lines{filt}.</p>
<pre>{e(redact_secrets(content)) or '(no matching lines)'}</pre>
<a href="/logs">← logs</a>
</div>"""
    return render(f"log {name} — {BRAND} admin", body)


# ---------- app catalog (in-panel module manager) ----------
def _enabled_in_envfile(var):
    """True if `var` is set truthy in the .env FILE (the live, just-written value —
    distinct from the panel's import-time env, which only refreshes on a restart)."""
    try:
        with open(ENV_FILE, errors="replace") as f:
            for ln in f:
                s = ln.strip()
                if s.startswith(var + "=") or s.startswith(var + " "):
                    v = s.split("=", 1)[1].strip().strip('"').strip("'").lower() if "=" in s else ""
                    return v in ("1", "true", "yes", "on")
    except OSError:
        pass
    return False


@app.route("/catalog")
@login_required
def catalog():
    if not ENABLE.get("app-catalog"):
        abort(404)
    rows = ""
    for key, (label, var, script) in APP_CATALOG.items():
        on = _enabled_in_envfile(var)
        state = ('<span class="pill ok">enabled</span>' if on
                 else '<span class="pill">off</span>')
        rows += f"""
<tr>
  <td>{e(label)}</td>
  <td>{state}</td>
  <td><code class=small>{e(var)}</code></td>
  <td>
    <form method=post action=/catalog/install class=block>
      <input type=hidden name=_csrf value="{e(new_csrf())}">
      <input type=hidden name=module value="{e(key)}">
      <input type=password name=password placeholder="admin password" autocomplete=current-password required style="max-width:11rem">
      <button class="small primary" type=submit>{"re-install" if on else "enable &amp; install"}</button>
    </form>
  </td>
</tr>"""
    body = f"""
<div class=box>
<h2>app catalog</h2>
<p class=small>Enable &amp; install an optional module from here. The installer runs
<strong>detached</strong> (a source build — Audiobookshelf, Pingvin — can take 15–40 min);
watch <a href="/logs/adminweb-async">the install log</a> (secrets are redacted there).
Re-enter your admin password to confirm each install. The installers are idempotent, so
&ldquo;re-install&rdquo; is safe. A newly-installed module gets its own health row after the
next panel restart (Dashboard → restart adminweb). <strong>Disabling</strong> a module and
deleting its data are deliberately kept command-line only (out of the web blast radius).</p>
<table class=grid>
<tr><th>module</th><th>state (.env)</th><th>flag</th><th>action</th></tr>
{rows}
</table>
</div>"""
    return render(f"catalog — {BRAND} admin", body)


@app.route("/catalog/install", methods=["POST"])
@login_required
def catalog_install():
    if not ENABLE.get("app-catalog"):
        abort(404)
    if not csrf_ok():
        abort(403)
    # The module key is ONLY ever validated against the fixed in-code allowlist
    # (APP_CATALOG) — it never reaches a command line. An unknown key is a hard 400.
    module = (request.form.get("module") or "").strip()
    if module not in APP_CATALOG:
        abort(400, description="unknown module")
    # Password re-auth (danger-confirm): a catalog install runs a script + edits .env,
    # so require the admin password again even within an authenticated session.
    pw = request.form.get("password", "")
    if not pw or not verify_password(pw):
        log_audit("catalog-install", module=module, ok=False, reason="bad-password")
        flash_msg("admin password incorrect — install not started", "err")
        return redirect(url_for("catalog"))
    label, var, _script = APP_CATALOG[module]
    # 1) persist the ENABLE_ flag (atomic, 0600; env_set restricts the key to ENABLE_*).
    wrote = env_set(var, True)
    # 2) run the installer DETACHED via the derived, allowlisted SCRIPTS_OK key
    #    (install-<module>) — run_script_detached only ever runs an allowlisted key.
    ok2, _logname = run_script_detached(f"install-{module}")
    log_audit("catalog-install", module=module, enable_written=wrote, started=ok2)
    if ok2:
        flash_msg(
            f"installing {label} (detached) — watch the install log at "
            f"/logs/adminweb-async (secrets redacted). "
            f"{'Enabled in .env. ' if wrote else 'WARNING: could not write the .env flag — set it manually. '}"
            f"Its health row appears after a panel restart.",
            "ok" if wrote else "warn")
    else:
        flash_msg(f"could not start the {label} installer (see /logs/adminweb-async)", "err")
    return redirect(url_for("catalog"))


# ---------- Pocket Pages (Sites) — deploy/rollback/delete/QR/health ----------
# SPEC-SITES-PANEL.md is the authoritative design; this comment only orients
# you. Every route below opens with the same ENABLE.get("sites") gate /dav
# uses for radicale. The pipeline itself (scripts/sites/*.sh + lib-sites.sh)
# is SPEC-SITES-PIPELINE.md's M1 — already shipped, unmodified by this panel.

# §7/AD-2 — name validation MUST equal scripts/sites/lib-sites.sh's SUB_RE and
# scripts/sites/reserved-subs.sh's RESERVED_SUBS (duplication contract; tests/
# asserts parity — SPEC-SITES-PANEL §17: change one, change both).
SITE_SUB_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
SITE_RESERVED = frozenset(
    "chat admin files music books audiobooks read dav wiki vault links share rss notes "
    "tasks search tools status stickers webmail ai mcp git dns "
    "www mail mta smtp imap pop autoconfig autodiscover matrix sites api cdn ns1 ns2 preview".split()
)
# Same shape as the pipeline's RELEASE_ID_RE (lib-sites.sh:49): {4,6} tolerates
# both HHMM and the HHMMSS form new_job_id()/new_release_id() actually mint —
# the panel must accept pipeline-minted ids everywhere a job/release id appears.
_SITE_JOB_RE = re.compile(r"^[0-9]{8}T[0-9]{4,6}Z-[0-9a-f]{4}$")

# Git-push-to-deploy payload validation (SPEC-DIFFERENTIATORS §6.4) — mirrors
# webhook-stage.sh's OWNER_REPO_RE/SHA_RE exactly. This route only regex-gates
# repository.full_name; webhook-stage.sh is what re-validates it with
# realpath-containment + existence under the Forgejo repos root — a second,
# independent layer, same three-layer discipline as validate_release_id().
_WEBHOOK_OWNER_REPO_RE = re.compile(
    # The lookaheads reject an all-dots segment ("." / ".." / "...") on either
    # side — "../.." is inside the plain char class and would otherwise pass
    # this first layer and lean entirely on webhook-stage.sh's realpath
    # containment (which does catch it; this just refuses it one layer sooner,
    # and no real Forgejo owner/repo is ever named only-dots).
    r"^(?!\.+/)[A-Za-z0-9._-]{1,100}/(?!\.+$)[A-Za-z0-9._-]{1,100}$")
_WEBHOOK_SHA_RE = re.compile(r"^[0-9a-f]{40}$")

# AD-4 — hardcoded, NEVER taken from request data. The two Sites scripts the
# panel launches with a dynamic argv tail: SITES_DEPLOY_SCRIPT via
# run_script_detached_argv (deploy, §8), SITES_ROLLBACK_SCRIPT via
# run_script_argv (rollback, §11). SITES_DELETE_SCRIPT is a third, used ONLY by
# run_script_argv — delete is fast (unlink a dir tree + rewrite the registry,
# no build), so it runs synchronously, never through the detached helper
# (§12/AD-6).
SITES_DEPLOY_SCRIPT   = "sites/site-deploy.sh"
SITES_ROLLBACK_SCRIPT = "sites/site-rollback.sh"
SITES_DELETE_SCRIPT   = "sites/site-delete.sh"
# Git-push-to-deploy (SPEC-DIFFERENTIATORS §6.4) — used ONLY by
# run_script_argv, both synchronously: staging is a bounded, quick
# subprocess (git archive under a timeout) and secret mint/rotate is a
# handful of filesystem ops, neither warrants the detached-launch machinery.
SITES_WEBHOOK_STAGE_SCRIPT  = "sites/webhook-stage.sh"
SITES_WEBHOOK_SECRET_SCRIPT = "sites/site-webhook-secret.sh"


def csrf_ok_header():
    """Double-submit CSRF check for the one route that can't carry a form field —
    POST /sites/upload's body IS the raw zip stream, so CSRF rides a header
    instead (AD-3). Every other Sites POST uses the standard csrf_ok() field."""
    tok = request.headers.get("X-CSRF-Token", "")
    return bool(tok) and hmac.compare_digest(tok, session.get("csrf", ""))


def json_response(obj, status=200):
    r = make_response(json.dumps(obj), status)
    r.headers["Content-Type"] = "application/json"
    return r


def run_script_argv(base_script, extra_argv, timeout=60):
    """run_script(), but takes an explicit script path + a server-validated argv
    tail instead of a SCRIPTS_OK key — used by rollback (§11), delete (§12),
    and the git-push-to-deploy webhook receiver's synchronous staging step +
    its secret mint/rotate action (SPEC-DIFFERENTIATORS §6.4), all with argv
    the caller already validated (name regex + existence checked against the
    registry, or webhook-stage.sh's own regex/containment/existence checks).
    Same (rc, out) shape as run_script(); always synchronous — AD-4's detached
    counterpart is run_script_detached_argv, below, for the one caller
    (deploy) that must survive past the request."""
    cmd = ["bash", os.path.join(SCRIPTS, base_script)] + list(extra_argv)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout + p.stderr
    except subprocess.TimeoutExpired:
        return -1, f"timed out after {timeout}s"
    except Exception as ex:
        return -2, str(ex)


def run_script_detached_argv(base_script, extra_argv, logname):
    """run_script_detached(), but appends a caller-supplied argv tail instead of
    a fixed SCRIPTS_OK entry (AD-4) — deploy needs a per-request staged path +
    job id, which SCRIPTS_OK's fixed-argv contract can't carry. Every element of
    extra_argv MUST already be server-validated/allocated by the CALLER (name
    regex + reserved-list checked; staged path/job id are ours) — this helper
    interprets nothing, it just launches. base_script is always one of the
    module-level constants above, never request.* directly."""
    cmd = ["bash", os.path.join(SCRIPTS, base_script)] + list(extra_argv)
    sink = os.path.join(LOGS, "adminweb-async.log")
    try:
        os.makedirs(LOGS, exist_ok=True)
        with open(sink, "ab", buffering=0) as lf:
            subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=lf, stderr=lf,
                              start_new_session=True, close_fds=True)
        return True, logname
    except Exception:
        return False, logname


def _read_sites_registry():
    """Direct file read of .registry.json (AD-2) — no subprocess, no proot
    round-trip. A missing/corrupt registry degrades to an empty site list
    rather than raising; the 'rebuild registry' button (site-list.sh
    --rebuild) is the self-healing escape hatch when the panel and the tree
    disagree."""
    try:
        with open(SITES_REGISTRY) as f:
            return json.load(f)
    except Exception:
        return {"version": 1, "sites": {}}


def _route_collision(name):
    """True if <name> is already claimed by a BYO proxy route — mirrors
    lib-sites.sh's validate_site_name() §7 check. byo-<name>.caddy is the
    filename proxy-routes.sh:206 actually writes; route-<name>.caddy never
    existed but stays checked as a belt against a future rename. Skipped
    (False) when the userland doesn't exist at all — never a false pass on a
    real phone, only inapplicable off-phone."""
    if not os.path.isdir(os.path.join(PD_BASE, "debian")):
        return False
    apps_dir = os.path.join(PD_BASE, "debian/etc/caddy/apps")
    return (os.path.exists(os.path.join(apps_dir, f"byo-{name}.caddy")) or
            os.path.exists(os.path.join(apps_dir, f"route-{name}.caddy")))


def _site_updated_ago(ts_iso):
    """A registry 'updated' timestamp (%Y-%m-%dT%H:%M:%SZ) -> a human 'N ago'
    string. calendar.timegm (not time.mktime) reads the parsed fields as UTC
    regardless of the process TZ setting. Never raises — falls back to the raw
    string on any parse failure, since a page render must survive a
    hand-edited or half-written registry value."""
    try:
        t = calendar.timegm(time.strptime(ts_iso, "%Y-%m-%dT%H:%M:%SZ"))
        secs = max(0, int(time.time() - t))
        return f"{human_seconds(secs)} ago" if secs >= 60 else "just now"
    except Exception:
        return ts_iso or "?"


def _site_release_created(release_id):
    """Parse the UTC timestamp out of a self-describing release id
    (<UTC-ts>-<4hex>, e.g. '20260717T120003Z-a1b2') into a readable string —
    SPEC-SITES-PANEL §6: 'no extra registry field needed'. Falls back to the
    raw id on any parse failure."""
    try:
        ts = release_id.split("-", 1)[0]
        return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.strptime(ts, "%Y%m%dT%H%M%SZ"))
    except Exception:
        return release_id


def _site_card_html(name, site):
    releases = list(reversed(site.get("releases") or []))
    active = site.get("active_release") or ""
    url = site.get("url") or f"https://{name}.{DOMAIN}"
    n_rel = len(releases)

    if n_rel > 1:
        opts = "".join(
            f'<option value="{e(r)}"{" selected" if r == active else ""}>'
            f'{e(r)}{" — active" if r == active else ""}</option>'
            for r in releases
        )
        rollback_html = f"""
<form method=post action="/sites/{e(name)}/rollback" class=block>
<input type=hidden name=_csrf value="{e(new_csrf())}">
<select name=release style="max-width:100%">{opts}</select>
<button class=small type=submit>rollback</button>
</form>"""
    else:
        rollback_html = '<p class=small>only one release — nothing to roll back to yet.</p>'

    hist_rows = "".join(
        f'<tr{" class=health-ok" if r == active else ""}>'
        f'<td class=mono>{e(r)}</td><td>{e(_site_release_created(r))}</td>'
        f'<td>{"active" if r == active else ""}</td></tr>'
        for r in releases
    ) or '<tr><td colspan=3 class=small>no releases</td></tr>'

    return f"""
<div class=box>
<h2><span class=ico>\U0001F310</span> {e(name)}
<span class=pill data-site-health="{e(name)}">checking…</span></h2>
<p class=small><a href="{e(url)}" target=_blank rel=noopener>{e(url)}</a></p>
<p class=small>release {e(active) or '—'} &middot; {n_rel} release{'s' if n_rel != 1 else ''}
&middot; build: {e(site.get('build') or 'none')}<br>
{human_bytes(site.get('bytes') or 0)} &middot; updated {e(_site_updated_ago(site.get('updated') or ''))}</p>
<details>
<summary class=small>rollback / history</summary>
{rollback_html}
<div class=tablewrap><table>
<thead><tr><th>release</th><th>created</th><th></th></tr></thead>
<tbody>{hist_rows}</tbody>
</table></div>
</details>
<details>
<summary class=small>QR code</summary>
<div style="text-align:center;margin:.6rem 0">
<img src="/sites/{e(name)}/qr.svg" loading=lazy alt="QR for {e(url)}"
     style="width:180px;height:180px;background:#fff;padding:8px;border-radius:10px">
</div>
</details>
{f'<p class=small><a href="/sites/{e(name)}/webhook">git-push-to-deploy &rarr;</a></p>' if ENABLE.get("sites-webhooks") else ''}
{f'<p class=small><a href="/sites/{e(name)}/forms">form submissions &rarr;</a></p>' if ENABLE.get("sites-forms") else ''}
{f'<p class=small><a href="/sites/{e(name)}/analytics">analytics &rarr;</a></p>' if ENABLE.get("sites-analytics") else ''}
<a href="/sites/{e(name)}/delete" class="btn danger small">delete…</a>
</div>"""


# AD-7 — deploy-log SSE gets its OWN session cap, separate from the
# dashboard's _SSE_SESSIONS: gunicorn is 1 worker x 4 gthreads, so sharing the
# dashboard's cap would reject a deploy-log tab the instant the dashboard tab
# is also open. Self-terminating (closes on job done/failed) + duration-capped,
# unlike the open-ended dashboard stream.
_SITE_SSE_SESSIONS = {}
_SITE_SSE_SESSIONS_LOCK = threading.Lock()
_SITE_SSE_MAX_PER_SESSION = 1
_SITE_SSE_MAX_DURATION_S = int(_env("SITES_BUILD_TIMEOUT", "900") or "900") + 120

# AD-8 — lazy, short-TTL, capped-count/per-probe-timeout health, NOT baked into
# the static HEALTH_HTTP_PROBES list: that list is built once at import time,
# but sites are added/removed/redeployed without a panel restart.
_SITE_HEALTH_CACHE = {"data": None, "ts": 0.0}
_SITE_HEALTH_LOCK = threading.Lock()
_SITE_HEALTH_TTL = 10.0
_SITE_HEALTH_MAX = 30        # mirrors the backups page's files[:30] cap
_SITE_HEALTH_TIMEOUT = 2     # vs the 5s default for fixed infra probes


def _site_probes():
    # Holds the lock across the whole recompute — the same coarse-grained shape
    # as gather_stats_cached() above. The worst case (a slow probe run
    # serializing concurrent /sites/health.json callers for a couple seconds)
    # is harmless for an endpoint fetched once per page load.
    now = time.time()
    with _SITE_HEALTH_LOCK:
        if _SITE_HEALTH_CACHE["data"] is not None and (now - _SITE_HEALTH_CACHE["ts"]) < _SITE_HEALTH_TTL:
            return _SITE_HEALTH_CACHE["data"]
        reg = _read_sites_registry()
        out = {}
        for name in sorted(reg.get("sites", {}))[:_SITE_HEALTH_MAX]:
            probe = {"name": name, "host": f"{name}.{DOMAIN}", "path": "/", "expect": 200, "scheme": "loopback"}
            out[name] = _probe_http(probe, timeout=_SITE_HEALTH_TIMEOUT)
        _SITE_HEALTH_CACHE["data"] = out
        _SITE_HEALTH_CACHE["ts"] = time.time()
        return out


# Vanilla JS (no framework, no build step — matches every other inline <script>
# in this file). A plain (non f-) string, like _SSE_SCRIPT below, so its own
# JS `{}` braces need no Python escaping; interpolated whole into sites_page()'s
# body via `{_SITES_UPLOAD_SCRIPT}`.
_SITES_UPLOAD_SCRIPT = """<script>
(function(){
  var zone = document.getElementById('dropzone'), fileInput = document.getElementById('site-file');
  if (!zone) return;
  var nameEl = document.getElementById('site-name'), pwEl = document.getElementById('site-pw');
  var bar = document.getElementById('upload-bar'), wrap = document.getElementById('upload-progress');
  var logEl = document.getElementById('upload-log');
  function pick(){ fileInput.click(); }
  zone.addEventListener('click', pick);
  zone.addEventListener('keydown', function(ev){ if (ev.key==='Enter'||ev.key===' ') pick(); });
  ['dragenter','dragover'].forEach(function(ev){
    zone.addEventListener(ev, function(e){ e.preventDefault(); zone.classList.add('drag'); });
  });
  ['dragleave','drop'].forEach(function(ev){
    zone.addEventListener(ev, function(e){ e.preventDefault(); zone.classList.remove('drag'); });
  });
  zone.addEventListener('drop', function(e){
    var f = e.dataTransfer.files && e.dataTransfer.files[0];
    if (f) upload(f);
  });
  fileInput.addEventListener('change', function(){ if (fileInput.files[0]) upload(fileInput.files[0]); });

  function upload(file){
    var name = nameEl.value.trim(), pw = pwEl.value;
    if (!/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(name)) { alert('enter a valid site name first'); return; }
    if (!pw) { alert('enter your admin password first'); return; }
    if (!/\\.zip$/i.test(file.name)) { alert('only .zip is accepted'); return; }
    // Client-side hints only — the server enforces the real cap independently.
    wrap.hidden = false; bar.style.width = '0%'; logEl.hidden = true;
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '/sites/upload?name=' + encodeURIComponent(name));
    xhr.setRequestHeader('Content-Type', 'application/octet-stream');
    xhr.setRequestHeader('X-CSRF-Token', zone.dataset.csrf);
    xhr.setRequestHeader('X-Admin-Password', pw);
    xhr.upload.onprogress = function(e){
      if (e.lengthComputable) bar.style.width = Math.round(100 * e.loaded / e.total) + '%';
    };
    xhr.onload = function(){
      pwEl.value = '';  // never keep the password in the DOM after the request fires
      var res = {}; try { res = JSON.parse(xhr.responseText); } catch(_) {}
      if (xhr.status === 200 && res.job) { bar.style.width = '100%'; openDeployLog(res.job); }
      else { logEl.hidden = false; logEl.textContent = 'upload failed: ' + (res.error || xhr.status); }
    };
    xhr.onerror = function(){ pwEl.value = ''; logEl.hidden = false; logEl.textContent = 'upload failed: network error'; };
    xhr.send(file);
  }

  function openDeployLog(job){
    logEl.hidden = false; logEl.textContent = 'deploying…\\n';
    if (!window.EventSource) { pollJob(job); return; }
    var es = new EventSource('/sites/deploy-log/' + job);
    es.onmessage = function(e){
      try {
        var d = JSON.parse(e.data);
        if (d.line) logEl.textContent += d.line + '\\n';
        if (d.state === 'done')   { logEl.textContent += '\\n✔ deployed\\n'; es.close(); setTimeout(function(){ location.reload(); }, 1200); }
        if (d.state === 'failed') { logEl.textContent += '\\n✘ failed: ' + (d.error||'') + '\\n'; es.close(); }
      } catch(_) {}
    };
    es.addEventListener('toomany', function(){ es.close(); pollJob(job); });
  }
  function pollJob(job){
    var t = setInterval(function(){
      fetch('/sites/job/' + job, {credentials:'include'}).then(function(r){ return r.json(); }).then(function(d){
        if (d.state === 'done' || d.state === 'failed') {
          clearInterval(t);
          logEl.textContent += (d.state==='done' ? '\\n✔ deployed\\n' : '\\n✘ failed: '+(d.error||'')+'\\n');
          if (d.state === 'done') setTimeout(function(){ location.reload(); }, 1200);
        }
      }).catch(function(){});
    }, 2000);
  }

  // Health pill patch — one fetch after load (AD-8), same DOM-patch idiom
  // _SSE_SCRIPT uses elsewhere in the panel, just via fetch instead of a stream.
  fetch('/sites/health.json', {credentials:'include'}).then(function(r){ return r.json(); }).then(function(d){
    Object.keys(d).forEach(function(name){
      var el = document.querySelector('[data-site-health="' + name + '"]');
      if (!el) return;
      var p = d[name];
      if (p && p.ok) { el.className = 'pill ok'; el.textContent = 'up (' + p.latency_ms + 'ms)'; }
      else { el.className = 'pill down'; el.textContent = 'down'; }
    });
  }).catch(function(){});
})();
</script>
"""


@app.route("/sites")
@login_required
def sites_page():
    if not ENABLE.get("sites"):
        abort(404)
    reg = _read_sites_registry()
    sites = reg.get("sites", {})
    cards = "".join(_site_card_html(name, sites[name]) for name in sorted(sites))
    if not cards:
        cards = '<div class=box><p class=small>no sites deployed yet — drop a .zip below to publish your first one.</p></div>'

    csrf = e(new_csrf())
    body = f"""
<div class=box>
<h2><span class=ico>\U0001F680</span> deploy a new site</h2>
<p class=small>Drop a .zip with <code>index.html</code> at its root (or use the CLI with
<code>--build hugo|node</code> for a source deploy — see docs/SITES.md). Max
{SITES_MAX_UPLOAD_MB} MB. Re-enter your admin password to confirm — the same
re-auth the app catalog uses.</p>
<input id=site-name type=text placeholder="site name (a-z0-9-)"
       pattern="[a-z0-9]([a-z0-9-]{{0,61}}[a-z0-9])?" required style="max-width:16rem">
<input id=site-pw type=password placeholder="admin password" autocomplete=current-password
       required style="max-width:16rem">
<div id=dropzone class=dropzone tabindex=0 data-csrf="{csrf}">
  drop a .zip here, or click to choose
  <input id=site-file type=file accept=".zip" hidden>
</div>
<div id=upload-progress class=progress hidden><div id=upload-bar></div></div>
<pre id=upload-log class=small hidden></pre>
</div>

<div class=cardgrid>{cards}</div>

<div class=box>
<h2>maintenance</h2>
<p class=small>The registry is derived state — if it and the on-disk release tree
ever disagree, rebuild it from the tree. Reapply the wildcard vhost after changing
<code>SITES_SPA_MODE</code> in <code>.env</code>.</p>
<form method=post action="/sites/rebuild-registry">
<input type=hidden name=_csrf value="{csrf}">
<button class=small type=submit>rebuild registry</button>
</form>
<form method=post action="/sites/apply-vhost">
<input type=hidden name=_csrf value="{csrf}">
<button class=small type=submit>reapply sites config</button>
</form>
</div>
{_SITES_UPLOAD_SCRIPT}"""
    return render(f"sites — {BRAND} admin", body)


@app.route("/sites/upload", methods=["POST"])
@login_required
def sites_upload():
    if not ENABLE.get("sites"):
        abort(404)
    if not csrf_ok_header():
        return json_response({"ok": False, "error": "bad csrf"}, 403)
    pw = request.headers.get("X-Admin-Password", "")
    if not pw or not verify_password(pw):
        log_audit("sites-upload", ok=False, reason="bad-password")
        return json_response({"ok": False, "error": "bad password"}, 401)

    name = (request.args.get("name") or "").strip()
    if not SITE_SUB_RE.fullmatch(name) or name in SITE_RESERVED:
        return json_response({"ok": False, "error": "invalid or reserved site name"}, 400)
    if _route_collision(name):
        return json_response({"ok": False, "error": "name already used by a BYO proxy route"}, 400)

    length = request.content_length
    if length is None:
        return json_response({"ok": False, "error": "Content-Length required"}, 411)
    cap = SITES_MAX_UPLOAD_MB * 1024 * 1024
    if length > cap:
        return json_response({"ok": False, "error": f"upload exceeds {SITES_MAX_UPLOAD_MB} MB"}, 413)

    # HHMMSS — identical shape to the pipeline's new_job_id() (lib-sites.sh:141);
    # the panel must never mint an id shape the pipeline itself wouldn't produce.
    job = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + secrets.token_hex(2)
    staged = os.path.join(SITES_STAGING, f"upload-{job}.zip")
    written = 0
    try:
        os.makedirs(SITES_STAGING, exist_ok=True)
        with open(staged, "wb") as f:
            stream = request.stream
            while True:
                chunk = stream.read(1 << 20)          # 1 MiB reads
                if not chunk:
                    break
                written += len(chunk)
                if written > cap:                      # belt-over-suspenders vs a lying Content-Length
                    raise ValueError("cap exceeded mid-stream")
                f.write(chunk)
        if written != length:
            raise ValueError("truncated upload")
    except Exception as ex:
        try:
            os.unlink(staged)
        except OSError:
            pass
        log_audit("sites-upload", name=name, ok=False, reason=str(ex))
        return json_response({"ok": False, "error": "upload incomplete or oversized"}, 400)

    ok2, _logname = run_script_detached_argv(
        SITES_DEPLOY_SCRIPT, [name, staged, "--job", job], f"site-deploy-{job}.log")
    log_audit("sites-upload", name=name, job=job, bytes=written, started=ok2)
    if not ok2:
        return json_response({"ok": False, "error": "could not start the deploy"}, 500)
    return json_response({"ok": True, "job": job}, 200)


# ── Git-push-to-deploy (Forgejo webhooks, SPEC-DIFFERENTIATORS §6) ──────────
# Per-site cooldown: {name: last_dispatch_epoch} + lock — same shape as
# _SITE_HEALTH_CACHE/_STATS_CACHE (module-level dict + lock) — cheap
# back-pressure against a misbehaving CI loop or a replayed delivery,
# independent of the HMAC check (§6.4).
_SITE_WEBHOOK_COOLDOWN = {}
_SITE_WEBHOOK_COOLDOWN_LOCK = threading.Lock()


def _site_webhook_secret_path(name):
    return os.path.join(SITES_WEBHOOK_SECRET_DIR, f"{name}.secret")


def _site_webhook_read_secret(name):
    """The site's webhook secret text (stripped), or None if none has been
    provisioned yet — the panel's "generate webhook secret" action (below) is
    the only thing that ever creates this file. Never raises."""
    try:
        with open(_site_webhook_secret_path(name)) as f:
            secret = f.read().strip()
        return secret or None
    except OSError:
        return None


def _site_webhook_verify_signature(secret, raw_body):
    """hmac.compare_digest over hex HMAC-SHA256(raw_body), checked against
    EITHER X-Forgejo-Signature or its Gitea-compatibility fallback
    X-Gitea-Signature (Forgejo's own docs, §16-EXT-1b) — same
    constant-time-compare idiom as csrf_ok_header() above. True on a match
    against either header."""
    expected = hmac.new(secret.encode(), raw_body, hashlib.sha256).hexdigest()
    for hdr in ("X-Forgejo-Signature", "X-Gitea-Signature"):
        got = request.headers.get(hdr, "")
        if got and hmac.compare_digest(expected, got):
            return True
    return False


@app.route("/sites/<name>/webhook/forgejo", methods=["POST"])
def sites_webhook_forgejo(name):
    """Machine-called receiver for the bundled Forgejo's push-event webhook —
    NO @login_required, NO CSRF (both are browser-session concepts; the
    caller here is Forgejo, not the operator's browser, exactly like
    sites_upload() above is gated by a DIFFERENT mechanism than the rest of
    the panel, admin/app.py:3109-3114 — except this route has no
    session/password concept at all). Authenticated purely by a per-site HMAC
    secret (§6.6 — loopback is not a trust boundary on Android/Termux, the
    exact reasoning maddy.conf.tmpl:54-55 already documents for its own
    loopback-only inject endpoint)."""
    if not (ENABLE.get("sites") and ENABLE.get("sites-webhooks")):
        abort(404)
    if not SITE_SUB_RE.fullmatch(name):
        abort(400)

    raw_body = request.get_data(cache=False)

    secret = _site_webhook_read_secret(name)
    if secret is None:
        # Generic 404 — the SAME shared error page as an unknown-site request
        # anywhere else in the panel (@app.errorhandler(404) below) — no "site
        # exists but has no secret yet" vs "no such site" oracle (§6.6).
        log_audit("sites-webhook", name=name, ok=False, reason="no-secret")
        abort(404)

    if not _site_webhook_verify_signature(secret, raw_body):
        # Generic 401 — a missing header and a wrong signature look identical
        # to the caller (§6.6's "no probing oracle" rule).
        log_audit("sites-webhook", name=name, ok=False, reason="bad-signature")
        abort(401)

    try:
        payload = json.loads(raw_body)
        if not isinstance(payload, dict):
            raise ValueError("payload is not a JSON object")
    except (ValueError, UnicodeDecodeError):
        log_audit("sites-webhook", name=name, ok=False, reason="bad-json")
        abort(400)

    ref = payload.get("ref") or ""
    if ref != f"refs/heads/{SITES_WEBHOOK_BRANCH}":
        # A push to a non-deploy branch (or a tag, or any other ref shape) is
        # NOT a delivery failure — Forgejo must not see this as an error and
        # retry/alert (§6.4/§6.7).
        log_audit("sites-webhook", name=name, ok=True, skipped=True, ref=ref)
        return json_response({"skipped": "not the configured branch"}, 200)

    full_name = (payload.get("repository") or {}).get("full_name") or ""
    after = payload.get("after") or ""
    if not (isinstance(full_name, str) and _WEBHOOK_OWNER_REPO_RE.fullmatch(full_name)
            and isinstance(after, str) and _WEBHOOK_SHA_RE.fullmatch(after)):
        log_audit("sites-webhook", name=name, ok=False, reason="bad-payload")
        return json_response({"ok": False, "error": "invalid repository/after in payload"}, 400)

    now = time.time()
    with _SITE_WEBHOOK_COOLDOWN_LOCK:
        last = _SITE_WEBHOOK_COOLDOWN.get(name, 0.0)
        if now - last < SITES_WEBHOOK_COOLDOWN_S:
            log_audit("sites-webhook", name=name, ok=False, reason="cooldown")
            return json_response({"ok": False, "error": "cooldown — try again shortly"}, 429)
        _SITE_WEBHOOK_COOLDOWN[name] = now

    # HHMMSS — identical shape to sites_upload()'s own job minting (above) so
    # this synchronous stage step and the eventual detached site-deploy.sh
    # launch share ONE job id end to end.
    job = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + secrets.token_hex(2)
    rc, out = run_script_argv(
        SITES_WEBHOOK_STAGE_SCRIPT, [name, full_name, after, "--job", job],
        timeout=SITES_WEBHOOK_STAGE_TIMEOUT + 15)
    if rc != 0:
        log_audit("sites-webhook", name=name, job=job, ok=False, reason="stage-failed", rc=rc)
        return json_response({"ok": False, "error": "staging failed"}, 502)
    # webhook-stage.sh's ONLY stdout output on success is the staged path
    # (nothing on stderr on that path either — see its own header) — so the
    # combined (rc, out) run_script_argv() shape is safe to read as-is here.
    staged = out.strip()

    reg = _read_sites_registry()
    tier = reg.get("sites", {}).get(name, {}).get("build", "none")
    ok2, _logname = run_script_detached_argv(
        SITES_DEPLOY_SCRIPT, [name, staged, "--build", tier, "--job", job],
        f"site-deploy-{job}.log")
    log_audit("sites-webhook", name=name, job=job, ok=ok2, ref=ref, sha=after)
    if not ok2:
        return json_response({"ok": False, "error": "could not start the deploy"}, 500)
    return json_response({"ok": True, "job": job}, 200)


def _site_webhook_setup_html(name, webhook_url, provisioned):
    return f"""
<div class=box>
<p class=small>Paste this into Forgejo's per-repo <strong>Settings &rarr; Webhooks &rarr; Add Webhook &rarr; Forgejo</strong>:</p>
<ul class=small>
<li>Target URL: <code>{e(webhook_url)}</code></li>
<li>HTTP Method: <code>POST</code></li>
<li>POST Content Type: <code>application/json</code></li>
<li>Secret: {'generate/rotate it below, then paste the value shown' if not provisioned else 'the value shown the last time you generated/rotated it (not re-displayed)'}</li>
<li>Trigger On: <code>Push Events</code></li>
<li>Branch filter: pushes to <code>{e(SITES_WEBHOOK_BRANCH)}</code> deploy; any other branch is skipped (not an error)</li>
</ul>
</div>"""


@app.route("/sites/<name>/webhook", methods=["GET", "POST"])
@login_required
def sites_webhook_admin(name):
    if not (ENABLE.get("sites") and ENABLE.get("sites-webhooks")):
        abort(404)
    if not SITE_SUB_RE.fullmatch(name) or name in SITE_RESERVED:
        abort(400)
    webhook_url = f"http://127.0.0.1:{BIND_PORT}/sites/{e(name)}/webhook/forgejo"

    if request.method == "POST":
        if not csrf_ok():
            abort(403)
        rotate = request.form.get("rotate") == "1"
        argv = [name] + (["--rotate"] if rotate else [])
        rc, out = run_script_argv(SITES_WEBHOOK_SECRET_SCRIPT, argv, timeout=30)
        log_audit("sites-webhook-secret", name=name, rotate=rotate, ok=(rc == 0))
        if rc != 0:
            flash_msg(f"could not generate the webhook secret: {redact_secrets(out)[:300]}", "err")
            return redirect(url_for("sites_webhook_admin", name=name))
        secret = out.strip()
        # Shown ONCE on this result page — mirrors rotate-admin-pass
        # (admin/app.py:265, confirm_action()'s POST branch above).
        body = f"""
<div class="box">
<h2>✅ webhook secret {'rotated' if rotate else 'generated'} for {e(name)}</h2>
<div class=warn-box>
<p><strong>Shown ONCE — copy it now, it will not be shown again:</strong></p>
<pre>{e(redact_secrets(secret))}</pre>
</div>
{_site_webhook_setup_html(name, webhook_url, provisioned=True)}
<p class=small><a href="/sites/{e(name)}/webhook">&larr; back</a> &middot; <a href="/sites">sites</a></p>
</div>"""
        return render(f"webhook secret — {name}", body)

    has_secret = _site_webhook_read_secret(name) is not None
    csrf = e(new_csrf())
    body = f"""
<div class=box>
<h2><span class=ico>\U0001F517</span> git-push-to-deploy — {e(name)}</h2>
<p class=small>Webhook secret: {'<strong>configured</strong>' if has_secret else '<em>not configured yet</em>'}.</p>
{_site_webhook_setup_html(name, webhook_url, provisioned=has_secret)}
<form method=post>
<input type=hidden name=_csrf value="{csrf}">
<input type=hidden name=rotate value="{'1' if has_secret else '0'}">
<button class=small type=submit>{'rotate secret (invalidates the old one)' if has_secret else 'generate webhook secret'}</button>
</form>
<p class=small><a href="/sites">&larr; sites</a></p>
</div>"""
    return render(f"webhook — {name} — {BRAND} admin", body)


# ── Forms (Netlify-Forms clone, SPEC-DIFFERENTIATORS §8 + C-2/C-3) ───────────
# The submit route is PUBLIC by design (Netlify's own model: no secret at all
# on the wire from the visitor's side) — the structural mitigations are the
# render-time gate token (C-2: proves the request came through the sites
# wildcard vhost, whose header strip-then-set is the ONLY thing allowed to
# attribute a site), body/field caps, the honeypot field, and the per-
# (site, form, truncated-ip) rate limit. Field VALUES are attacker text and
# only ever become HTML through e() in the inbox below.
_FORM_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_FORMS_HP_FIELD = "_pocket_hp"

_FORMS_RATE = {}
_FORMS_RATE_LOCK = threading.Lock()

_FORMS_DB_MOD = None


def _forms_db():
    """Lazy-load scripts/sites/forms_db.py by absolute path — the panel runs
    as an out-of-tree copy (70-install-admin.sh), so a package import can't
    reach it; SCRIPTS is already how every run_script* call finds the repo."""
    global _FORMS_DB_MOD
    if _FORMS_DB_MOD is None:
        import importlib.util
        p = os.path.join(SCRIPTS, "sites", "forms_db.py")
        spec = importlib.util.spec_from_file_location("pocket_forms_db", p)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _FORMS_DB_MOD = mod
    return _FORMS_DB_MOD


def _forms_gate_token():
    """The render-time-minted gate value apps/sites.sh wrote 0600 into
    POCKET_STATE_DIR (C-2) and baked into the sites vhost's header_up. None
    until the forms feature has actually been rendered into the vhost."""
    try:
        with open(SITES_FORMS_GATE_FILE) as f:
            return f.read().strip() or None
    except OSError:
        return None


def _forms_client_ip():
    """C-3: behind the default CF Tunnel ingress, Caddy's own client address
    for visitor traffic is the LOCAL tunnel daemon — the real visitor is in
    Cf-Connecting-IP (the exact preference chain honeypot-watcher.py's
    parse_line() already proves against this repo's production logs), falling
    back to remote_addr (ProxyFix has already consumed X-Forwarded-For)."""
    return (request.headers.get("Cf-Connecting-IP") or "").strip() \
        or (request.remote_addr or "")


def _forms_rate_ok(site, form, ip_truncated):
    """Fixed-window per (site, form, truncated-ip) — a simpler, non-backoff
    cousin of rate_limit_login()'s dict+lock shape; spam mitigation doesn't
    need the login path's escalating-lockout severity. The dict is pruned
    opportunistically so an attacker rotating keys can't grow it unbounded."""
    now = time.time()
    key = (site, form, ip_truncated)
    with _FORMS_RATE_LOCK:
        if len(_FORMS_RATE) > 4096:
            for stale in [k for k, ts in _FORMS_RATE.items()
                          if not ts or now - ts[-1] > 3600]:
                _FORMS_RATE.pop(stale, None)
        ts = [t for t in _FORMS_RATE.get(key, []) if now - t < 3600]
        if len(ts) >= SITES_FORMS_RATE_LIMIT_PER_HOUR:
            _FORMS_RATE[key] = ts
            return False
        ts.append(now)
        _FORMS_RATE[key] = ts
        return True


def _forms_relay_email(site, form, fields):
    """Best-effort relay through the bundled Maddy's loopback submission
    listener — the exact smtplib pattern mail-drain.py's inject() already
    runs in production (ehlo -> starttls if offered -> login -> send). Creds
    come from the email module's own 0600 mail-admin.env (ADMIN_USER/
    ADMIN_PASS); a missing file just means "email module not installed" and
    the relay quietly reports False. Never raises; never blocks the visitor
    (the caller stores the row FIRST and only flips `emailed` on success)."""
    import smtplib
    from email.message import EmailMessage
    creds = {}
    try:
        with open(os.path.join(SECRETS, "mail-admin.env")) as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, _, v = line.partition("=")
                    creds[k.strip()] = v.strip()
    except OSError:
        return False
    user, pw = creds.get("ADMIN_USER"), creds.get("ADMIN_PASS")
    if not (user and pw):
        return False
    msg = EmailMessage()
    msg["From"] = user
    msg["To"] = SITES_FORMS_EMAIL_TO or user
    msg["Subject"] = f"[{site}] form '{form}' submission"
    msg.set_content(
        "\n".join(f"{k}: {v}" for k, v in fields.items()) or "(no fields)")
    try:
        s = smtplib.SMTP("127.0.0.1", MAIL_SUBMISSION_PORT, timeout=10)
        try:
            s.ehlo()
            if s.has_extn("starttls"):
                s.starttls()
                s.ehlo()
            s.login(user, pw)
            s.send_message(msg)
        finally:
            try:
                s.quit()
            except Exception:
                pass
        return True
    except Exception:
        return False


@app.route("/__pocket-forms__/submit/<form>", methods=["POST"])
def sites_forms_submit(form):
    """Visitor-facing form receiver. Deliberately NO log_audit here (AD-8):
    audit entries carry full operator IPs by design, and a third-party
    visitor's full address must never be persisted anywhere — the only
    address-shaped thing stored is the /24 (v4) / /48 (v6) truncation."""
    if not (ENABLE.get("sites") and ENABLE.get("sites-forms")):
        abort(404)
    gate = _forms_gate_token()
    got = request.headers.get("X-Pocket-Forms-Gate", "")
    if not (gate and got and hmac.compare_digest(gate, got)):
        # C-2: no valid gate value = this did NOT come through the sites
        # vhost (direct loopback POST, or the admin vhost, which strips the
        # header) — generic 404, indistinguishable from the feature being off.
        abort(404)
    site = (request.headers.get("X-Pocket-Site") or "").strip().lower()
    if not SITE_SUB_RE.fullmatch(site):
        abort(404)
    if not _FORM_NAME_RE.fullmatch(form):
        abort(400)
    cl = request.content_length
    if cl is None:
        abort(411)
    if cl > SITES_FORMS_MAX_BODY_KB * 1024:
        abort(413)
    items = list(request.form.items())
    if len(items) > SITES_FORMS_MAX_FIELDS:
        abort(413)
    hp_tripped = False
    fields = {}
    for k, v in items:
        if len(k) > 200 or len(v) > SITES_FORMS_MAX_FIELD_LEN:
            abort(413)
        if k == _FORMS_HP_FIELD:
            # AD-9: the trip is recorded as spam=1, the bait value itself is
            # never stored.
            hp_tripped = bool(v.strip())
            continue
        fields[k] = v
    db = _forms_db()
    ip_truncated = db.truncate_ip(_forms_client_ip())
    if not _forms_rate_ok(site, form, ip_truncated):
        abort(429)
    conn = db.connect(SITES_FORMS_DB)
    try:
        row_id = db.insert(conn, site, form, fields, ip_truncated,
                           request.headers.get("User-Agent", ""), hp_tripped)
        if not hp_tripped and ENABLE.get("sites-forms-email"):
            if _forms_relay_email(site, form, fields):
                db.mark_emailed(conn, row_id)
        if db.gc_due(SITES_FORMS_GC_STAMP):
            # OQ-5: automatic, at most daily — retention is a privacy bound,
            # so it must actually happen without operator memory or a cron.
            db.gc(conn, SITES_FORMS_RETENTION_DAYS, SITES_FORMS_GC_STAMP)
    finally:
        conn.close()
    # A honeypot trip gets the SAME response as success — no signal (AD-9).
    if "application/json" in (request.headers.get("Accept") or ""):
        return json_response({"ok": True}, 200)
    return make_response(
        "<!doctype html><meta charset=utf-8>"
        "<meta name=viewport content='width=device-width,initial-scale=1'>"
        "<title>Thanks</title>"
        "<body style='font-family:system-ui;margin:15vh auto;max-width:28rem;"
        "text-align:center'><h1>Thanks!</h1>"
        "<p>Your submission was received.</p>"
        "<p><a href='javascript:history.back()'>&larr; back</a></p>", 200)


@app.route("/sites/<name>/forms")
@login_required
def sites_forms_inbox(name):
    if not (ENABLE.get("sites") and ENABLE.get("sites-forms")):
        abort(404)
    if not SITE_SUB_RE.fullmatch(name) or name in SITE_RESERVED:
        abort(400)
    include_spam = request.args.get("spam") == "1"
    try:
        page = max(0, int(request.args.get("page", "0")))
    except ValueError:
        page = 0
    per = 50
    db = _forms_db()
    conn = db.connect(SITES_FORMS_DB)
    try:
        rows, total = db.query(conn, name, include_spam=include_spam,
                               limit=per, offset=page * per)
    finally:
        conn.close()
    csrf = e(new_csrf())
    body_rows = []
    for r in rows:
        try:
            fields = json.loads(r["fields_json"])
        except ValueError:
            fields = {}
        field_html = "<br>".join(
            f"<strong>{e(str(k))}</strong>: {e(str(v))}"
            for k, v in fields.items()) or "<em>(no fields)</em>"
        badges = ""
        if r["spam"]:
            badges += " <span class=badge>spam</span>"
        if r["emailed"]:
            badges += " <span class=badge>emailed</span>"
        body_rows.append(
            f"<tr><td><input type=checkbox name=id value=\"{r['id']}\"></td>"
            f"<td class=small>{e(r['ts'])}</td>"
            f"<td class=small>{e(r['form'])}{badges}</td>"
            f"<td>{field_html}</td>"
            f"<td class=small>{e(r['ip_truncated'] or '')}</td></tr>")
    spam_link = (f'<a href="/sites/{e(name)}/forms">hide spam</a>'
                 if include_spam else
                 f'<a href="/sites/{e(name)}/forms?spam=1">show spam</a>')
    nav = ""
    if page > 0:
        nav += f'<a href="?page={page - 1}{"&spam=1" if include_spam else ""}">&larr; newer</a> '
    if (page + 1) * per < total:
        nav += f'<a href="?page={page + 1}{"&spam=1" if include_spam else ""}">older &rarr;</a>'
    body = f"""
<div class=box>
<h2><span class=ico>\U0001F4E8</span> forms — {e(name)}</h2>
<p class=small>{total} submission(s){' incl. spam' if include_spam else ''} &middot; {spam_link} &middot; retention {SITES_FORMS_RETENTION_DAYS}d &middot; stored fields + a /24 (v4) / /48 (v6) truncated IP only — never the full address</p>
<form method=post action="/sites/{e(name)}/forms/delete">
<input type=hidden name=_csrf value="{csrf}">
<table>
<tr><th></th><th>when (UTC)</th><th>form</th><th>fields</th><th>ip (truncated)</th></tr>
{''.join(body_rows) or '<tr><td colspan=5><em>nothing yet</em></td></tr>'}
</table>
<button class="btn danger small" type=submit name=mode value=selected>delete selected</button>
<button class="btn small" type=submit name=mode value=spam>delete ALL spam rows</button>
</form>
<p class=small>{nav}</p>
<p class=small><a href="/sites">&larr; sites</a></p>
</div>"""
    return render(f"forms — {name} — {BRAND} admin", body)


# ── Analytics-lite (SPEC-DIFFERENTIATORS §9, AD-10/11/12) ────────────────────
_ANALYTICS_MOD = None
_SITES_ANALYTICS_CACHE = {"ts": 0.0, "agg": None}
_SITES_ANALYTICS_LOCK = threading.Lock()


def _analytics_mod():
    """Lazy path-load of scripts/sites/analytics.py — same out-of-tree-copy
    reasoning as _forms_db() above."""
    global _ANALYTICS_MOD
    if _ANALYTICS_MOD is None:
        import importlib.util
        p = os.path.join(SCRIPTS, "sites", "analytics.py")
        spec = importlib.util.spec_from_file_location("pocket_sites_analytics", p)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _ANALYTICS_MOD = mod
    return _ANALYTICS_MOD


def _sites_analytics_cached():
    """The whole-registry aggregate, recomputed at most once per TTL — the
    identical module-level dict+lock shape as gather_stats_cached()/
    _site_probes(). One parse serves every site's page (the log is shared;
    per-site slicing is free)."""
    now = time.time()
    with _SITES_ANALYTICS_LOCK:
        if _SITES_ANALYTICS_CACHE["agg"] is not None \
                and now - _SITES_ANALYTICS_CACHE["ts"] < SITES_ANALYTICS_CACHE_TTL_S:
            return _SITES_ANALYTICS_CACHE["agg"]
    mod = _analytics_mod()
    agg = mod.aggregate(
        mod.iter_log_lines(LOGS, SITES_ANALYTICS_RETENTION_DAYS),
        DOMAIN, max_lines=SITES_ANALYTICS_MAX_LINES)
    with _SITES_ANALYTICS_LOCK:
        _SITES_ANALYTICS_CACHE["ts"] = now
        _SITES_ANALYTICS_CACHE["agg"] = agg
    return agg


@app.route("/sites/<name>/analytics")
@login_required
def sites_analytics(name):
    if not (ENABLE.get("sites") and ENABLE.get("sites-analytics")):
        abort(404)
    if not SITE_SUB_RE.fullmatch(name) or name in SITE_RESERVED:
        abort(400)
    try:
        agg = _sites_analytics_cached()
    except Exception:
        # Isolated failure (unreadable log dir, etc.) — the rest of the panel
        # is unaffected, matching _read_sites_registry()'s degrade convention.
        log_audit("sites-analytics", name=name, ok=False, reason="aggregate-failed")
        abort(500)
    s = agg["sites"].get(name)
    if s is None:
        body_stats = "<p><em>No traffic recorded for this site yet (or the access log has rotated past the window).</em></p>"
    else:
        rows = "".join(
            f"<tr><td><code>{e(p)}</code></td><td>{c}</td></tr>"
            for p, c in s["top_paths"])
        mb = s["bytes_hint"] / (1024 * 1024)
        body_stats = f"""
<div class=grid>
<div class=box><h3>{s['requests']}</h3><p class=small>requests</p></div>
<div class=box><h3>{s['approx_unique_visitors']}</h3><p class=small>approx. unique visitors (truncated-IP set, in-memory only)</p></div>
<div class=box><h3>{s['status_2xx']}/{s['status_3xx']}/{s['status_4xx']}/{s['status_5xx']}</h3><p class=small>2xx / 3xx / 4xx / 5xx</p></div>
<div class=box><h3>{mb:.1f} MiB</h3><p class=small>bytes served (best-effort)</p></div>
</div>
<h3>top paths</h3>
<table><tr><th>path (query strings never recorded)</th><th>hits</th></tr>{rows}</table>"""
    trunc_note = ("<p class=small>⚠ line cap hit — figures are a lower bound for the window.</p>"
                  if agg.get("truncated") else "")
    body = f"""
<div class=box>
<h2><span class=ico>\U0001F4C8</span> analytics — {e(name)}</h2>
<p class=small>window: newest rotated logs within {SITES_ANALYTICS_RETENTION_DAYS} days — history depends on
how much log-rotation headroom your traffic has used (rotation is by SIZE, not calendar), so a busy site
may hold less than the full window. No client-side JS, no cookies; unique-visitor counts come from a
truncated-IP set discarded after each pass — nothing per-visitor is ever stored.</p>
{trunc_note}
{body_stats}
<p class=small><a href="/sites">&larr; sites</a></p>
</div>"""
    return render(f"analytics — {name} — {BRAND} admin", body)


@app.route("/sites/<name>/forms/delete", methods=["POST"])
@login_required
def sites_forms_delete(name):
    if not (ENABLE.get("sites") and ENABLE.get("sites-forms")):
        abort(404)
    if not SITE_SUB_RE.fullmatch(name) or name in SITE_RESERVED:
        abort(400)
    if not csrf_ok():
        abort(403)
    mode = request.form.get("mode", "selected")
    db = _forms_db()
    conn = db.connect(SITES_FORMS_DB)
    try:
        if mode == "spam":
            n = db.delete_spam(conn, name)
        else:
            try:
                ids = [int(i) for i in request.form.getlist("id")]
            except ValueError:
                abort(400)
            n = db.delete_ids(conn, name, ids)
    finally:
        conn.close()
    log_audit("sites-forms-delete", name=name, mode=mode, rows=n, ok=True)
    flash_msg(f"deleted {n} submission(s)")
    return redirect(url_for("sites_forms_inbox", name=name))


@app.route("/sites/health.json")
@login_required
def sites_health_json():
    if not ENABLE.get("sites"):
        abort(404)
    return json_response(_site_probes(), 200)


@app.route("/sites/deploy-log/<job_id>")
@login_required
def sites_deploy_log(job_id):
    if not ENABLE.get("sites"):
        abort(404)
    if not _SITE_JOB_RE.fullmatch(job_id):
        abort(400)
    sid = request.cookies.get("session", "") or (request.remote_addr or "?")

    def stream():
        with _SITE_SSE_SESSIONS_LOCK:
            if _SITE_SSE_SESSIONS.get(sid, 0) >= _SITE_SSE_MAX_PER_SESSION:
                yield "event: toomany\ndata: {}\n\n"
                return
            _SITE_SSE_SESSIONS[sid] = _SITE_SSE_SESSIONS.get(sid, 0) + 1
        try:
            log_path = os.path.join(LOGS, f"site-deploy-{job_id}.log")
            state_path = os.path.join(STATE, f"site-job-{job_id}.json")
            pos, t0 = 0, time.time()
            while True:
                if time.time() - t0 > _SITE_SSE_MAX_DURATION_S:
                    yield 'data: {"state":"failed","error":"stream timeout"}\n\n'
                    return
                new_text = None
                try:
                    with open(log_path) as f:
                        f.seek(pos)
                        new_text = f.read()
                        pos = f.tell()
                except OSError:
                    pass
                state, error = "running", None
                try:
                    with open(state_path) as f:
                        j = json.load(f)
                    state, error = j.get("state", "running"), j.get("error")
                except Exception:
                    pass
                yield "data: " + json.dumps({
                    "line": new_text.rstrip("\n") if new_text else None,
                    "state": state, "error": error,
                }) + "\n\n"
                if state in ("done", "failed"):
                    return
                time.sleep(1)
        except GeneratorExit:
            return
        finally:
            with _SITE_SSE_SESSIONS_LOCK:
                n = _SITE_SSE_SESSIONS.get(sid, 1) - 1
                if n <= 0:
                    _SITE_SSE_SESSIONS.pop(sid, None)
                else:
                    _SITE_SSE_SESSIONS[sid] = n
    r = make_response(stream(), 200)
    r.headers["Content-Type"] = "text/event-stream"
    r.headers["Cache-Control"] = "no-cache"
    r.headers["X-Accel-Buffering"] = "no"
    r.headers["Connection"] = "keep-alive"
    return r


@app.route("/sites/job/<job_id>")
@login_required
def sites_job_status(job_id):
    # §10's own sketch omits this gate; added for consistency with §5's "every
    # route" rule (a disabled Sites module should 404 everywhere, not just on
    # the SSE route) — see the deviations note in the implementation report.
    if not ENABLE.get("sites"):
        abort(404)
    if not _SITE_JOB_RE.fullmatch(job_id):
        abort(400)
    try:
        with open(os.path.join(STATE, f"site-job-{job_id}.json")) as f:
            j = json.load(f)
    except Exception:
        j = {"state": "running"}
    return json_response(j, 200)


@app.route("/sites/<name>/rollback", methods=["POST"])
@login_required
def sites_rollback(name):
    if not ENABLE.get("sites"):
        abort(404)
    if not csrf_ok():
        abort(403)
    if not SITE_SUB_RE.fullmatch(name):
        abort(400)
    release = (request.form.get("release") or "").strip()
    reg = _read_sites_registry()
    site = reg.get("sites", {}).get(name)
    if not site:
        flash_msg(f"unknown site: {name}", "err")
        return redirect(url_for("sites_page"))
    if release and release not in site.get("releases", []):
        flash_msg("unknown release id", "err")
        return redirect(url_for("sites_page"))
    argv = [name] + ([release] if release else [])
    rc, out = run_script_argv(SITES_ROLLBACK_SCRIPT, argv, timeout=60)  # fast, synchronous (AD-5)
    log_audit("sites-rollback", name=name, release=release or "previous", rc=rc)
    flash_msg(f"rolled back {name}" if rc == 0 else f"rollback failed: {redact_secrets(out)[:300]}",
              "ok" if rc == 0 else "err")
    return redirect(url_for("sites_page"))


@app.route("/sites/<name>/delete", methods=["GET", "POST"])
@login_required
def sites_delete(name):
    if not ENABLE.get("sites"):
        abort(404)
    if not SITE_SUB_RE.fullmatch(name):
        abort(400)
    reg = _read_sites_registry()
    site = reg.get("sites", {}).get(name)
    if not site:
        abort(404)  # no probing for undeployed names via this route (AD-6)
    url = site.get("url") or f"https://{name}.{DOMAIN}"
    meta = DANGER_META["site-delete"]

    if request.method == "POST":
        if not csrf_ok():
            abort(403)
        typed_phrase = request.form.get("phrase", "").strip().lower()
        typed_yes    = request.form.get("yes", "").strip().lower()
        pw           = request.form.get("password", "")
        if typed_phrase != meta["phrase"]:
            flash_msg(f"phrase mismatch — type exactly: {meta['phrase']}", "err")
            return redirect(url_for("sites_delete", name=name, stage=2))
        if typed_yes != "yes":
            flash_msg("you must literally type 'yes' to confirm", "err")
            return redirect(url_for("sites_delete", name=name, stage=2))
        if not pw or not verify_password(pw):
            log_audit("sites-delete", name=name, ok=False, reason="bad-password")
            flash_msg("password incorrect — re-auth required", "err")
            return redirect(url_for("sites_delete", name=name, stage=2))
        # Synchronous (AD-6): unlink a dir tree + rewrite the registry, no build.
        rc, out = run_script_argv(SITES_DELETE_SCRIPT, [name, "--yes"], timeout=60)
        log_audit("sites-delete", name=name, ok=(rc == 0), rc=rc)
        flash_msg(f"deleted {name}" if rc == 0 else f"delete failed: {redact_secrets(out)[:300]}",
                  "ok" if rc == 0 else "err")
        return redirect(url_for("sites_page"))

    impact_html = "\n".join(f"<li>{e(x)}</li>" for x in meta["impact"])
    stage = request.args.get("stage", "1")

    if stage == "1":
        body = f"""
<div class="box danger-zone">
<h2>⚠ Delete site — review</h2>
<div class=warn-box>
<p><strong>Site:</strong> <code>{e(name)}</code> — <a href="{e(url)}" target=_blank rel=noopener>{e(url)}</a></p>
<strong>Impact:</strong>
<ul>{impact_html}</ul>
<p><strong>Reversibility:</strong> NOT reversible.</p>
</div>
<p class=small style="margin-top:1rem">If you really want to delete this site, click Continue. The next page asks for the typed phrase, the literal word <code>yes</code>, and your password.</p>
<form method=get action="{url_for('sites_delete', name=name)}">
<input type=hidden name=stage value="2">
<button type=submit class=danger>Continue →</button>
<a href="/sites" class="btn small">cancel</a>
</form>
</div>"""
        return render("review delete site", body)

    body = f"""
<div class="box danger-zone">
<h2>⚠ Delete site — final confirm</h2>
<div class=warn-box>
<p><strong>Site:</strong> <code>{e(name)}</code> — {e(url)}</p>
<p class=small><a href="{url_for('sites_delete', name=name)}">← back to impact summary</a></p>
</div>
<form method=post>
<input type=hidden name=_csrf value="{e(new_csrf())}">
<p>1. Type exactly <code>{e(meta['phrase'])}</code>:</p>
<input name=phrase type=text autocomplete=off required placeholder="{e(meta['phrase'])}">
<p>2. Type literally <code>yes</code>:</p>
<input name=yes type=text autocomplete=off required placeholder="yes" pattern="[Yy][Ee][Ss]" maxlength=3>
<p>3. Re-enter your admin password:</p>
<input name=password type=password autocomplete=current-password required>
<button type=submit class=danger>delete site</button>
<a href="/sites" class="btn small">cancel</a>
</form>
</div>"""
    return render("confirm delete site", body)


@app.route("/sites/<name>/qr.svg")
@login_required
def sites_qr(name):
    if not ENABLE.get("sites"):
        abort(404)
    if not SITE_SUB_RE.fullmatch(name):
        abort(400)
    url = f"https://{name}.{DOMAIN}"
    # QR encodes ONLY the public URL (never a secret) — mirrors /dav's segno
    # usage. Unlike /dav (which embeds an <img> via a data: URI inside an HTML
    # page, so svg_inline()'s HTML5-fragment form is fine there), this route
    # SERVES the SVG as its own standalone image/svg+xml resource — that needs
    # a complete, namespaced SVG document, so save(..., kind="svg") is used
    # instead of svg_inline() (which deliberately omits the XML declaration
    # AND the xmlns attribute, and would not render as a standalone <img src>
    # target in most browsers).
    try:
        import io
        import segno  # type: ignore
        buf = io.BytesIO()
        segno.make(url, error="m").save(buf, kind="svg", scale=5, border=2)
        svg = buf.getvalue().decode("utf-8")
    except Exception:
        abort(404)  # the card's <details> just shows a broken-image icon; no extra UX beyond that
    r = make_response(svg, 200)
    r.headers["Content-Type"] = "image/svg+xml"
    r.headers["Cache-Control"] = "public, max-age=300"
    return r


@app.route("/sites/rebuild-registry", methods=["POST"])
@login_required
def sites_rebuild_registry():
    if not ENABLE.get("sites"):
        abort(404)
    if not csrf_ok():
        abort(403)
    rc, out = run_script("sites-rebuild-registry")
    log_audit("sites-rebuild-registry", rc=rc)
    flash_msg("registry rebuilt from the on-disk release tree" if rc == 0
              else f"rebuild failed: {redact_secrets(out)[:300]}", "ok" if rc == 0 else "err")
    return redirect(url_for("sites_page"))


@app.route("/sites/apply-vhost", methods=["POST"])
@login_required
def sites_apply_vhost():
    if not ENABLE.get("sites"):
        abort(404)
    if not csrf_ok():
        abort(403)
    ok2, logname = run_script_detached("sites-apply-vhost")
    log_audit("sites-apply-vhost", started=ok2)
    flash_msg("reapplying the sites vhost (detached) — watch /logs/adminweb-async" if ok2
              else "could not start the vhost reapply (see /logs/adminweb-async)", "ok" if ok2 else "err")
    return redirect(url_for("sites_page"))


# ---------- observability: metrics history + problems view ----------
def _read_metrics(limit=1500):
    """Tail the JSONL metrics ring (newest `limit` samples) as a list of dicts.
    Best-effort: a missing/half-written line is skipped, never raised."""
    try:
        with open(METRICS_LOG, errors="replace") as fh:
            lines = fh.readlines()[-limit:]
    except OSError:
        return []
    out = []
    for ln in lines:
        ln = ln.strip()
        if not ln:
            continue
        try:
            out.append(json.loads(ln))
        except ValueError:
            continue
    return out


def _svg_spark(vals, w=260, h=46, pad=3):
    """Inline SVG sparkline from a series (None entries skipped). Reuses the
    existing svg.spark .ln/.ar CSS so it inherits the theme's accent colour."""
    pts_vals = [v for v in vals if isinstance(v, (int, float))]
    if len(pts_vals) < 2:
        return '<p class=small>not enough data yet</p>'
    mn, mx = min(pts_vals), max(pts_vals)
    rng = (mx - mn) or 1.0
    n = len(pts_vals)
    coords = []
    for i, v in enumerate(pts_vals):
        x = (i / (n - 1)) * (w - 2 * pad) + pad
        y = (h - pad) - ((v - mn) / rng) * (h - 2 * pad)
        coords.append(f"{x:.1f},{y:.1f}")
    d = "M" + " ".join(coords)
    ar = d + f" {w - pad:.1f},{h - pad:.1f} {pad:.1f},{h - pad:.1f}Z"
    return (f'<svg class=spark width="{w}" height="{h}" viewBox="0 0 {w} {h}" '
            f'preserveAspectRatio=none style="width:100%"><path class=ar d="{ar}">'
            f'</path><path class=ln d="{d}"></path></svg>')


def _svg_health_strip(samples, cols=96, w=576, h=22):
    """A 24h health strip: one column per ~15min bucket, green when no service was
    DEGRADED in that window, red when one was, grey when there is no sample."""
    now = int(time.time())
    span = 24 * 3600
    start = now - span
    buckets = [None] * cols  # None=no data, 0=ok, 1=problem
    for s in samples:
        ts = s.get("ts")
        if not isinstance(ts, (int, float)) or ts < start:
            continue
        idx = int((ts - start) / span * cols)
        idx = max(0, min(cols - 1, idx))
        deg = s.get("deg")
        prob = 1 if (isinstance(deg, (int, float)) and deg > 0) else 0
        buckets[idx] = prob if buckets[idx] is None else max(buckets[idx], prob)
    cw = w / cols
    rects = []
    for i, b in enumerate(buckets):
        fill = ("var(--border)" if b is None
                else "var(--dot-down)" if b == 1 else "var(--dot-up)")
        rects.append(f'<rect x="{i * cw:.1f}" y="0" width="{cw + 0.6:.1f}" '
                     f'height="{h}" style="fill:{fill}"></rect>')
    return (f'<svg width="{w}" height="{h}" viewBox="0 0 {w} {h}" '
            f'preserveAspectRatio=none style="width:100%;border-radius:6px;display:block">'
            f'{"".join(rects)}</svg>')


@app.route("/metrics")
@login_required
def metrics_page():
    if not ENABLE.get("metrics"):
        body = """
<div class=box>
<h2>metrics</h2>
<p>The metrics sampler is not enabled. Set <code>ENABLE_METRICS=true</code> in
<code>.env</code> and re-run <code>scripts/install.sh --force</code> (or pick it in
<code>./setup.sh</code>). It records CPU/memory/disk/temperature/load once a minute
into a tiny capped file the panel charts here. See docs/OBSERVABILITY.md.</p>
</div>"""
        return render(f"metrics — {BRAND} admin", body)

    samples = _read_metrics(1500)
    if not samples:
        body = f"""
<div class=box>
<h2>metrics</h2>
<p>No samples yet — the sampler may have just started (it writes one sample every
~minute to <code>{e(METRICS_LOG)}</code>). Refresh shortly.</p>
</div>"""
        return render(f"metrics — {BRAND} admin", body)

    last = samples[-1]

    def card(key, label, unit, fmt="{:.0f}"):
        vals = [s.get(key) for s in samples]
        present = [v for v in vals if isinstance(v, (int, float))]
        cur = last.get(key)
        cur_s = (fmt.format(cur) if isinstance(cur, (int, float)) else "—") + unit
        if present:
            stat = (f"min {min(present):.0f}{unit} · "
                    f"avg {sum(present) / len(present):.0f}{unit} · "
                    f"max {max(present):.0f}{unit}")
        else:
            stat = "no data for this metric"
        return f"""
<div class=box>
<h3>{e(label)}</h3>
<div class=val style="font-size:1.6rem;font-weight:700;line-height:1">{e(cur_s)}</div>
{_svg_spark(vals)}
<p class=small>{e(stat)} · {len(present)} samples</p>
</div>"""

    cards = (card("cpu", "CPU busy", "%") + card("mem", "memory used", "%")
             + card("l1", "load (1m)", "", "{:.2f}") + card("temp", "temperature", "°C")
             + card("disk", "disk used", "%") + card("batt", "battery", "%"))

    health = _svg_health_strip(samples)
    span_h = (last.get("ts", 0) - samples[0].get("ts", 0)) / 3600.0
    body = f"""
<div class=box>
<h2><span class=ico>\U0001F4C8</span> 24h service health</h2>
<p class=small>green = all services healthy · red = a service was crash-looping (DEGRADED) · grey = no sample</p>
{health}
</div>
<div class=cardgrid>{cards}</div>
<p class=small>Sampled by scripts/ops/metrics-sampler.py into <code>{e(METRICS_LOG)}</code>
(~{span_h:.1f}h shown, {len(samples)} samples). See docs/OBSERVABILITY.md.</p>
"""
    return render(f"metrics — {BRAND} admin", body)


# ---------- Radicale "connect device" card (optional — ENABLE_RADICALE) ----------
# A READ-ONLY onboarding helper for the CalDAV/CardDAV server: it renders the
# base URL + a scannable QR so a phone (DAVx5) or desktop (Thunderbird/iOS/Apple)
# can be pointed at dav.<domain> without typing the URL by hand. The PASSWORD is
# NEVER embedded — the QR carries only the public service URL + username; the user
# still types their own password in the client. The QR is built server-side with
# the pure-Python `segno` lib (lazy import → graceful degrade to the plain URL card
# if it is not installed).
_DAV_USER_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


@app.route("/dav")
@login_required
def dav_connect_page():
    if not ENABLE.get("radicale"):
        body = """
<div class=box>
<h2>calendar &amp; contacts</h2>
<p>Radicale (CalDAV/CardDAV) is not enabled. Set <code>ENABLE_RADICALE=true</code>
in <code>.env</code> and re-run <code>scripts/install.sh --force</code> (or pick it
in <code>./setup.sh</code>). See docs/DAV.md.</p>
</div>"""
        return render(f"calendar — {BRAND} admin", body)

    # Username: from ?user= (validated) else the configured admin user. NOT a secret.
    user = request.args.get("user", "").strip() or ADMIN_USER
    if not _DAV_USER_RE.match(user):
        user = ADMIN_USER

    base_url = f"https://dav.{DOMAIN}/{user}/"
    discovery = f"https://dav.{DOMAIN}/"

    # QR encodes ONLY the public base URL (no password). Lazy import so a missing
    # segno never breaks the panel — we just show the URL card instead.
    qr_html = ""
    try:
        import segno  # type: ignore
        src = segno.make(base_url, error="m").svg_data_uri(scale=5, border=2)
        qr_html = (
            f'<div style="text-align:center;margin:.6rem 0">'
            f'<img src="{src}" alt="CalDAV/CardDAV QR for {e(user)}" '
            f'style="width:220px;height:220px;background:#fff;padding:8px;border-radius:10px">'
            f'</div>'
        )
    except Exception:
        qr_html = (
            '<div class=warn-box>QR rendering needs the <code>segno</code> Python '
            'package (it is installed with the admin panel by default). Use the URL '
            'below to set up your client manually.</div>'
        )

    body = f"""
<div class=box>
<h2><span class=ico>\U0001F4C5</span> connect a calendar / contacts client</h2>
<p class=small>For DAVx5 (Android), Thunderbird, iOS/macOS Calendar &amp; Contacts.
The QR and URL carry only the public service address and your username —
<strong>never your password</strong>. You still type your password in the client.</p>
{qr_html}
<table>
<tr><td>Username</td><td><code>{e(user)}</code></td></tr>
<tr><td>CalDAV / CardDAV URL</td><td><code>{e(base_url)}</code></td></tr>
<tr><td>Auto-discovery (DAVx5)</td><td><code>{e(discovery)}</code></td></tr>
</table>
<p class=small><strong>DAVx5 (Android):</strong> Add account → "Login with URL and user
name" → scan this QR (or paste the auto-discovery URL) → enter your password.
<br><strong>iOS / macOS / Thunderbird:</strong> add a CalDAV (and a CardDAV) account
using the CalDAV/CardDAV URL above, username <code>{e(user)}</code>, and your password.</p>
<p class=small>Show the card for another user: <code>/dav?user=&lt;name&gt;</code>.
Reminder: Cloudflare Access must allow native clients on <code>dav.{e(DOMAIN)}</code>
via a SERVICE-TOKEN exemption (DAV clients cannot complete an interactive login).
See docs/DAV.md.</p>
</div>"""
    return render(f"calendar — {BRAND} admin", body)


@app.route("/problems")
@login_required
def problems_page():
    h = gather_health()
    degraded = [p for p in h["procs"] if p.get("degraded")]
    down = [p for p in h["procs"] if not p["alive"] and not p.get("degraded")]
    http_fail = [r for r in h["http"] if not r["ok"]]

    if not (degraded or down or http_fail):
        body = f"""
<div class=box>
<h2>✅ no problems</h2>
<p>All {h['summary']['proc_total']} services are running and all
{h['summary']['http_total']} endpoint probes are green.</p>
<p>{action_btn("run-doctor", "run doctor", "small")}<span class=small> &nbsp;read-only preflight check</span></p>
<a href="/">← dashboard</a> &nbsp; <a href="/health">full health →</a>
</div>"""
        return render(f"problems — {BRAND} admin", body)

    def _restart_for(name):
        key = f"restart-{name}"
        return action_btn(key, f"restart {name}", "small danger") if key in SCRIPTS_OK else ""

    rows = []
    for p in degraded:
        info = e(p["degraded"] or "")
        hint = ("DB may be corrupt — see scripts/ops/restore.sh"
                if p["name"] == "matrix" else "check this service's log")
        rows.append(
            f'<div class=box><h3><span class="dot degraded"></span>{e(p["name"])} '
            f'— crash-looping</h3><pre>{info}</pre>'
            f'<p class=small>{hint}</p>'
            f'<p>{_restart_for(p["name"])} '
            f'<a href="/logs/{e(p["name"])}" class="btn small">view log</a></p></div>')
    for p in down:
        rows.append(
            f'<div class=box><h3><span class="dot down"></span>{e(p["name"])} '
            f'— not running</h3>'
            f'<p>{_restart_for(p["name"])} '
            f'<a href="/logs/{e(p["name"])}" class="btn small">view log</a></p></div>')
    http_html = ""
    if http_fail:
        items = "".join(
            f'<li>{e(r["name"])}: '
            f'{("HTTP " + str(r["code"])) if r["code"] else "unreachable"}'
            f'{(" — " + e(r["error"])) if r.get("error") else ""}</li>'
            for r in http_fail)
        http_html = (f'<div class=box><h3>endpoint probes failing</h3>'
                     f'<ul>{items}</ul>'
                     f'<p class=small>An app behind Cloudflare Access may answer 302 '
                     f'to its login — that is expected, not an outage.</p></div>')

    body = f"""
<div class="flash err">⚠ {len(degraded)} crash-looping · {len(down)} down · {len(http_fail)} probe failure(s)</div>
<p>{action_btn("run-doctor", "run doctor", "small")}
<a href="/danger" class="btn danger small">full-stack restart…</a>
<a href="/health" class="btn small">full health →</a></p>
<div class=cardgrid>{''.join(rows)}</div>
{http_html}
"""
    return render(f"problems — {BRAND} admin", body)


# ---------- Matrix user management (optional — ENABLE_USER_ADMIN) ----------
# These drive continuwuity's admin command room through fixed-argv ops/user-*.sh
# (no shell, validated input). Every write op requires a CSRF token + a password
# re-auth + an audit-log entry; deactivation additionally requires retyping the
# exact user id. continuwuity returns generated passwords in its room reply, so
# those land in the admin room history — see docs/USERS.md.
_VALID_LOCALPART = re.compile(r"^[a-z0-9][a-z0-9._=-]{0,63}$")
_VALID_MXID = re.compile(r"^@[a-z0-9._=/+-]+:[A-Za-z0-9.:-]+$")
# op -> (script, value-kind, needs_typed_confirm)
_USER_OPS = {
    "create":     ("user-create.sh",         "localpart", False),
    "reset":      ("user-reset-password.sh",  "localpart", False),
    "suspend":    ("user-suspend.sh",         "user",      False),
    "unsuspend":  ("user-unsuspend.sh",       "user",      False),
    "deactivate": ("user-deactivate.sh",      "user",      True),
    "invite":     ("user-invite.sh",          "count",     False),
}


def run_user_op(script, *args, timeout=90):
    """Run an ops/user-*.sh with FIXED, pre-validated argv (no shell)."""
    cmd = ["bash", os.path.join(SCRIPTS, "ops", script), *args]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout + p.stderr)
    except subprocess.TimeoutExpired:
        return -1, f"timed out after {timeout}s"
    except Exception as ex:
        return -2, str(ex)


@app.route("/users")
@login_required
def users_page():
    if not ENABLE.get("user-admin"):
        body = """
<div class=box>
<h2>users</h2>
<p>Matrix user management is not enabled. Set <code>ENABLE_USER_ADMIN=true</code>
in <code>.env</code> and re-run <code>scripts/install.sh --force</code> (or pick it
in <code>./setup.sh</code>). It drives the homeserver's admin command room. See
docs/USERS.md.</p>
</div>"""
        return render(f"users — {BRAND} admin", body)

    rc, out = run_user_op("user-list.sh")
    list_block = e(out.strip()) or "(no reply — open the admin room in Element)"
    csrf = e(new_csrf())

    def _form(op, label, placeholder, kind, danger=False, confirm=False):
        cls = "danger" if danger else "primary"
        extra = ""
        if confirm:
            extra = ('<input name=confirm type=text autocomplete=off '
                     'placeholder="retype to confirm" required>')
        return f"""
<form method=post action=/users/op class=block>
<input type=hidden name=_csrf value="{csrf}">
<input type=hidden name=op value="{e(op)}">
<input name=value type=text autocomplete=off placeholder="{e(placeholder)}" required>
{extra}
<input name=password type=password autocomplete=current-password placeholder="admin password" required>
<button type=submit class="{cls} small">{e(label)}</button>
</form>"""

    body = f"""
<div class=box>
<h2><span class=ico>\U0001F465</span> users</h2>
<p class=small>Drives continuwuity's admin command room (<code>#admins:{e(DOMAIN)}</code>).
Generated passwords appear in that room's history — treat it as sensitive (docs/USERS.md).</p>
<pre>{list_block}</pre>
</div>

<div class=cardgrid>
<div class=box><h3>create user</h3>{_form("create", "create", "localpart e.g. alice", "localpart")}
<p class=small>The server generates the password and shows it in its reply.</p></div>
<div class=box><h3>reset password</h3>{_form("reset", "reset password", "localpart e.g. alice", "localpart")}</div>
<div class=box><h3>suspend / unsuspend</h3>
{_form("suspend", "suspend (read-only)", "localpart or @user:server", "user")}
{_form("unsuspend", "unsuspend", "localpart or @user:server", "user")}</div>
<div class=box><h3>invite tokens</h3>{_form("invite", "mint tokens", "count (1–99)", "count")}
<p class=small>Single-use, self-expiring registration tokens to hand out.</p></div>
<div class=box><h3>deactivate (irreversible)</h3>
{_form("deactivate", "deactivate", "localpart or @user:server", "user", danger=True, confirm=True)}
<p class=small>Closes the account; retype the exact id to confirm.</p></div>
</div>
"""
    return render(f"users — {BRAND} admin", body)


@app.route("/users/op", methods=["POST"])
@login_required
def users_op():
    if not ENABLE.get("user-admin"):
        abort(404)
    if not csrf_ok():
        abort(403)
    op = request.form.get("op", "")
    spec = _USER_OPS.get(op)
    if not spec:
        abort(400, description="unknown user op")
    script, kind, needs_confirm = spec
    val = (request.form.get("value", "") or "").strip()
    pw = request.form.get("password", "")

    # Re-auth on every write op (second factor beyond the session).
    if not pw or not verify_password(pw):
        log_audit("user-op", op=op, ok=False, reason="bad-password")
        flash_msg("password incorrect — re-auth required", "err")
        return redirect(url_for("users_page"))

    # Validate the value strictly per kind (this is what reaches the script argv).
    if kind == "localpart":
        if not _VALID_LOCALPART.fullmatch(val):
            flash_msg("invalid localpart (a-z 0-9 . _ = -, up to 64)", "err")
            return redirect(url_for("users_page"))
    elif kind == "user":
        if not (_VALID_LOCALPART.fullmatch(val) or _VALID_MXID.fullmatch(val)):
            flash_msg("invalid user (localpart or @user:server)", "err")
            return redirect(url_for("users_page"))
    elif kind == "count":
        if not re.fullmatch(r"[1-9][0-9]?", val or ""):
            flash_msg("invite count must be 1–99", "err")
            return redirect(url_for("users_page"))
    else:
        abort(400)

    if needs_confirm:
        if (request.form.get("confirm", "") or "").strip() != val:
            log_audit("user-op", op=op, ok=False, reason="confirm-mismatch")
            flash_msg("retype the exact user id to confirm", "err")
            return redirect(url_for("users_page"))

    log_audit("user-op-start", op=op, target=val)
    rc, out = run_user_op(script, val)
    log_audit("user-op-end", op=op, target=val, rc=rc)
    icon = "✅" if rc == 0 else "❌"
    body = f"""
<div class=box>
<h2>{icon} {e(op)} {e(val)} → exit={rc}</h2>
<pre>{e(out)}</pre>
<p class=small>If a password was generated it is shown above (and in the admin room history).</p>
<a href="/users">← users</a>
</div>"""
    return render(f"user {op} — {BRAND} admin", body)


# ---------- danger zone ----------
@app.route("/danger")
@login_required
def danger_page():
    panic_keys = ("panic-soft", "panic-hard")
    other_keys = ("rotate-reg-token", "rotate-admin-pass", "restart-stack")

    def _card(key):
        meta = DANGER_META[key]
        imp_short = meta["impact"][0] if meta["impact"] else ""
        return f"""
<div class=box>
<h3>{e(meta['title'])}</h3>
<p class=small>{e(imp_short)}</p>
<a href="/confirm/{e(key)}" class="btn danger">{e(meta['title'].lower())}…</a>
</div>"""

    panic_html = "".join(_card(k) for k in panic_keys)
    other_html = "".join(_card(k) for k in other_keys)

    _hdr = "color:var(--muted);text-transform:uppercase;letter-spacing:.06em;font-size:.82rem;margin:1.4rem 0 .5rem"
    body = f"""
<div class="box danger-zone">
<h2><span class=ico>⚠️</span> danger zone</h2>
<p>Every action below uses a <strong>two-page confirmation</strong>: an impact-review page first, then a final-confirm page that requires three independent inputs (typed phrase, the literal word <code>yes</code>, and your admin password). Designed to stop accidental clicks.</p>
<p class=small>Every attempt is audit-logged with timestamp + IP + UA to <code>{e(AUDIT_LOG)}</code>.</p>
</div>

<h3 style="{_hdr}">Panic buttons — kill switches</h3>
<p class=small>Soft panic stops only public access (the Cloudflare Tunnel) so you can keep working from loopback. Hard panic stops the whole stack except the admin panel, so you can recover from the loopback PWA at <code>http://127.0.0.1:{e(BIND_PORT)}/</code>.</p>
<div class=cardgrid>{panic_html}</div>

<h3 style="{_hdr}">Rotations + restarts</h3>
<div class=cardgrid>{other_html}</div>
"""
    return render(f"danger zone — {BRAND} admin", body)


# ---------- live updates via SSE ----------
_SSE_SCRIPT = """<script>
(function(){
  var dot = document.getElementById("live-dot");
  if (!window.EventSource) return;
  var hist = [];
  function set(id, t){ var el = document.getElementById(id); if (el) el.textContent = t; }
  function html(id, h){ var el = document.getElementById(id); if (el) el.innerHTML = h; }
  function spark(arr){
    var ln = document.getElementById("k-load-ln"); if (!ln || arr.length < 2) return;
    var w = 70, h = 24, mn = Math.min.apply(null, arr), mx = Math.max.apply(null, arr), rng = (mx - mn) || 1;
    var pts = arr.map(function(v, i){
      var x = (i / (arr.length - 1)) * w, y = h - 2 - ((v - mn) / rng) * (h - 4);
      return x.toFixed(1) + "," + y.toFixed(1);
    });
    ln.setAttribute("d", "M" + pts.join(" "));
    var ar = document.getElementById("k-load-ar");
    if (ar) ar.setAttribute("d", "M" + pts.join(" ") + " " + w + "," + h + " 0," + h + "Z");
  }
  var ev = new EventSource("/events");
  ev.onopen = function(){ if (dot) dot.style.opacity = "1"; };
  ev.onerror = function(){ if (dot) dot.style.opacity = ".3"; };
  ev.onmessage = function(e){
    try {
      var d = JSON.parse(e.data);
      if (d.svc_html) html("svc-block", d.svc_html);
      if (d.load) set("load-line", d.load);
      if (d.mem_html) html("mem-line", d.mem_html);
      if (d.load1 != null) set("k-load", d.load1);
      if (d.mem_used_gb != null) set("k-ram", d.mem_used_gb);
      if (d.mem_pct != null){ set("k-ram-pct", d.mem_pct);
        var bar = document.getElementById("k-ram-bar"); if (bar) bar.style.width = d.mem_pct + "%"; }
      if (d.load1 != null){ hist.push(parseFloat(d.load1)); if (hist.length > 20) hist.shift(); spark(hist); }
      if (dot){ dot.style.opacity = ".35"; setTimeout(function(){ dot.style.opacity = "1"; }, 150); }
    } catch(_) {}
  };
})();
</script>
"""

# A short-TTL global cache so concurrent SSE streams SHARE one probe instead of
# each forking; plus a per-session stream cap so one operator with several tabs
# can't multiply the loops.
_STATS_CACHE = {"data": None, "ts": 0.0}
_STATS_CACHE_LOCK = threading.Lock()
_STATS_TTL = 4.0
_SSE_SESSIONS = {}
_SSE_SESSIONS_LOCK = threading.Lock()
_SSE_MAX_PER_SESSION = 1


def gather_stats_cached(ttl=_STATS_TTL):
    now = time.time()
    with _STATS_CACHE_LOCK:
        if _STATS_CACHE["data"] is not None and (now - _STATS_CACHE["ts"]) < ttl:
            return _STATS_CACHE["data"]
        data = gather_stats()
        _STATS_CACHE["data"] = data
        _STATS_CACHE["ts"] = time.time()
        return data


def _quick_metrics():
    """Cheap stats safe to poll every second: uptime + load (sysinfo syscall) and
    RAM (/proc/meminfo). No subprocess forks — unlike gather_stats()."""
    q = {"uptime": "?", "load": "?", "load1": 0.0,
         "mem_used": 0, "mem_total": 0, "mem_pct": 0}
    si = _sysinfo()
    if si:
        q["uptime"] = human_seconds(si[0])
        q["load"] = " / ".join(f"{x:.2f}" for x in si[1])
        q["load1"] = round(si[1][0], 2)
    try:
        meminfo = {}
        for line in read_file("/proc/meminfo").splitlines():
            parts = line.split(":")
            if len(parts) == 2:
                meminfo[parts[0].strip()] = int(parts[1].strip().split()[0]) * 1024
        total = meminfo.get("MemTotal", 0)
        avail = meminfo.get("MemAvailable", meminfo.get("MemFree", 0))
        used = total - avail
        q["mem_used"] = used
        q["mem_total"] = total
        q["mem_pct"] = int(100 * used / total) if total else 0
    except Exception:
        pass
    return q


# ============================================================================
# Security / honeypot console (optional — shown only when ENABLE['honeypot']).
#
# The watcher (scripts/honeypot/honeypot-watcher.py, supervised by
# steps/77-install-honeypot.sh) tails the core Caddy access log and writes a JSONL
# ledger of high-confidence scanner probes. These routes render that ledger plus a
# per-IP drill-down, passive enrichment, and a confirm-gated, DEFENSIVE write
# console (Cloudflare IP Access Rules on the operator's OWN edge + the local
# safelist). Everything degrades gracefully when the optional modules
# (cf_actions.py / honeypot_db.py) are not deployed, so the panel never breaks.
#
# SAFETY BOUNDARY (designed-in):
#   * Write actions touch ONLY the operator's OWN Cloudflare IP-Access-Rules
#     (challenge/block/unblock a single source IP) and the local safelist — the
#     exact mechanism + blast radius the watcher itself uses. No traffic is ever
#     sent toward the source host.
#   * Enrichment is PASSIVE: registry RDAP (queries the RIR, not the source), a
#     single reverse-DNS PTR, offline geo from our own logs, and outbound *links*
#     to third-party threat-intel sites.
#   * CF edge actions go through the shared cf_actions module (re-asserts the
#     token scope + the 'honeypot-auto' note prefix before any delete) behind the
#     same three-input confirm flow as /danger (typed phrase + 'yes' + password).
# ============================================================================
HP_SCRIPTS_DIR = os.environ.get("HP_SCRIPTS_DIR",
                                os.path.join(POCKET_ROOT, "scripts", "honeypot"))
HP_LEDGER = os.path.join(LOGS, "honeypot.log")
HP_MODE_FILE = os.path.join(SECRETS, "honeypot.mode")
HP_IP_STATE = os.path.join(STATE, "honeypot-ip-state.json")
HP_CF_ENV = os.path.join(SECRETS, "cf-honeypot.env")
HP_SAFELIST = os.path.join(SECRETS, "honeypot-safelist.txt")
HP_GEO_DIR = os.path.join(HP_SCRIPTS_DIR, "geo")

_hp_mods = {}
_hp_lock = threading.Lock()
_hp_last_ingest = [0.0]


def _hp_load(name):
    """Lazily import scripts/honeypot/<name>.py from HP_SCRIPTS_DIR (cached, incl.
    negative cache). Returns the module or None — never raises to the handler."""
    if name in _hp_mods:
        return _hp_mods[name]
    mod = None
    try:
        import importlib.util
        path = os.path.join(HP_SCRIPTS_DIR, f"{name}.py")
        spec = importlib.util.spec_from_file_location(f"hp_{name}", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    except Exception as ex:
        sys.stderr.write(f"adminweb: honeypot module {name} unavailable: {ex}\n")
        mod = None
    _hp_mods[name] = mod
    return mod


def _hp_conn():
    """Open the honeypot DB and incrementally ingest the ledger (throttled across
    the gthread pool). Returns (db_module, connection) or (None, None). The caller
    MUST close the connection. The DB is an OPTIONAL accelerator — the /honeypot
    overview reads the JSONL ledger directly and works without it."""
    hdb = _hp_load("honeypot_db")
    if hdb is None:
        return None, None
    try:
        conn = hdb.connect()
    except Exception as ex:
        sys.stderr.write(f"adminweb: honeypot DB open failed: {ex}\n")
        return None, None
    try:
        with _hp_lock:
            if time.time() - _hp_last_ingest[0] > 2.0:
                hdb.ingest(conn)
                _hp_last_ingest[0] = time.time()
    except Exception as ex:
        sys.stderr.write(f"adminweb: honeypot ingest failed: {ex}\n")
    return hdb, conn


def _hp_unavailable(msg="honeypot DB module not deployed"):
    body = (f'<div class=box><h2><span class=ico>🍯</span> honeypot</h2>'
            f'<p class=small>{e(msg)}. The <a href="/honeypot">ledger view</a> '
            f'still works. Deploy <code>cf_actions.py</code> + '
            f'<code>honeypot_db.py</code> to <code>{e(HP_SCRIPTS_DIR)}</code> and '
            f'reload.</p></div>')
    return render("security — honeypot", body)


def _hp_action_pill(act):
    a = str(act or "").strip().lower()
    if not a or a in ("-", "none"):
        return '<span class=small>—</span>'
    if "block" in a:
        return f'<span class="pill down" title="{e(str(act))}">block</span>'
    if "challenge" in a:
        return f'<span class="pill warn" title="{e(str(act))}">challenge</span>'
    if "alert" in a:
        return '<span class=pill>alerted</span>'
    return f'<span class="pill" title="{e(str(act))}">{e(str(act)[:18])}</span>'


def e2(s):
    """html-escape that also trims very long tokens for inline summaries."""
    return e(str(s)[:120])


@app.route("/honeypot")
@login_required
def honeypot_page():
    """Read-only Security overview: the honeypot ledger tail + counts + facets.
    The watcher tails Caddy access logs and ledgers/(optionally) Matrix-alerts
    high-confidence scanner probes. Alert-only by default."""
    import time as _t
    try:
        mode = open(HP_MODE_FILE).read().strip() or "alert"
    except OSError:
        mode = "alert (default)"
    counts, hosts, ips = {}, {}, {}
    countries, asns = {}, {}
    hosting_hits = geo_known = 0
    buckets = {"24h": 0, "7d": 0, "30d": 0}
    actioned_ledger = {}
    blocked = total = 0
    rows = []
    now = _t.time()
    cut = {k: _t.strftime("%Y-%m-%dT%H:%M:%SZ", _t.gmtime(now - s))
           for k, s in (("24h", 86400), ("7d", 604800), ("30d", 2592000))}
    try:
        with open(HP_LEDGER) as f:
            lines = f.readlines()
        total = len(lines)
        for ln in lines:
            try:
                r = json.loads(ln)
            except Exception:
                continue
            counts[r.get("hit_rule", "?")] = counts.get(r.get("hit_rule", "?"), 0) + 1
            hosts[r.get("host", "?")] = hosts.get(r.get("host", "?"), 0) + 1
            ips[r.get("ip", "?")] = ips.get(r.get("ip", "?"), 0) + 1
            ts = str(r.get("ts", ""))
            for k in buckets:
                if ts >= cut[k]:
                    buckets[k] += 1
            act = str(r.get("action", ""))
            if act.startswith("cf-"):
                blocked += 1
                actioned_ledger[str(r.get("ip", "?"))] = act
            c, a = r.get("country"), r.get("asn")
            if c or a:
                geo_known += 1
                if c:
                    countries[c] = countries.get(c, 0) + 1
                if a:
                    lab = f"{a} {r.get('as_org', '')}".strip()
                    asns[lab] = asns.get(lab, 0) + 1
                if r.get("hosting"):
                    hosting_hits += 1
        for ln in reversed(lines[-150:]):
            try:
                rows.append(json.loads(ln))
            except Exception:
                continue
    except OSError:
        pass

    try:
        st = json.load(open(HP_IP_STATE))
        if not isinstance(st, dict):
            st = {}
    except Exception:
        st = {}
    offenders = sorted(st.items(),
                       key=lambda kv: -int(kv[1].get("total_hits", 0) or 0))[:10]

    proc_up, _ = _proc_alive("honeypot-watcher\\.py")

    def _facet(title, d, n=6):
        items = sorted(d.items(), key=lambda x: -x[1])[:n]
        if not items:
            return ""
        mx = items[0][1] or 1
        rws = ""
        for k, v in items:
            w = round(100 * v / mx)
            rws += (f'<div class=frow><span class=fn>{e(str(k))}</span>'
                    f'<span class=fc>{v}</span>'
                    f'<span class=fb><span style="width:{w}%"></span></span></div>')
        return f'<div class=facet><h3>{e(title)}</h3>{rws}</div>'

    def _action_pill(act):
        a = str(act or "").strip()
        if not a or a in ("-", "none"):
            return '<span class=small>—</span>'
        low = a.lower()
        if "alert" in low:
            return '<span class=pill>alerted</span>'
        if "block" in low:
            return f'<span class="pill down" title="{e(a)}">block</span>'
        if "challenge" in low:
            return f'<span class="pill warn" title="{e(a)}">challenge</span>'
        return f'<span class="pill" title="{e(a)}">{e(a[:18])}</span>'

    if rows:
        trs = ""
        for r in rows:
            geo = ""
            if r.get("country") or r.get("asn"):
                geo = e(str(r.get("country", "")))
                if r.get("hosting"):
                    geo += " ⚠DC"
            trs += (
                "<tr>"
                f"<td class=small>{e(str(r.get('ts','')))}</td>"
                f"<td class=mono>{e(str(r.get('ip','')))}</td>"
                f"<td class=small>{geo}</td>"
                f"<td>{e(str(r.get('host','')))}</td>"
                f"<td class='mono path' title=\"{e(str(r.get('uri','')))}\">{e(str(r.get('uri',''))[:72])}</td>"
                f"<td>{e(str(r.get('hit_rule','')))}</td>"
                f"<td>{e(str(r.get('status','')))}</td>"
                f"<td>{_action_pill(r.get('action',''))}</td>"
                "</tr>"
            )
        table = (
            '<div class=tablewrap><table><thead><tr>'
            "<th>ts (UTC)</th><th>ip</th><th>geo</th><th>host</th><th>path</th>"
            "<th>rule</th><th>code</th><th>action</th></tr></thead>"
            f"<tbody>{trs}</tbody></table></div>"
        )
    else:
        table = "<p class=small>No scanner hits recorded yet — the ledger is empty (Cloudflare's WAF/Bot-Fight filters most probes before they reach the tunnel).</p>"

    if geo_known:
        pct = round(100 * hosting_hits / geo_known) if geo_known else 0
        geo_facets = _facet("top countries", countries) + _facet("top ASNs", asns)
        geo_note = (f'<p class=small style="margin-top:.7rem">{hosting_hits}/{geo_known} '
                    f'geo-known hits (<b>{pct}%</b>) from hosting/datacenter ASNs.</p>')
    else:
        geo_facets = ""
        geo_note = ('<p class=small style="margin-top:.7rem">Geo/ASN enrichment inactive '
                    f'(offline DB-IP dataset not deployed to <code>{e(HP_GEO_DIR)}</code>).</p>')

    facets_html = (_facet("by rule", counts) + _facet("by host", hosts)
                   + _facet("top IPs", ips) + geo_facets)

    act_ips = {ip: ent.get("actioned") for ip, ent in st.items() if ent.get("actioned")}
    for ip, a in actioned_ledger.items():
        act_ips.setdefault(ip, a)
    if act_ips:
        items = list(act_ips.items())
        CAP = 23
        cells = "".join(
            f'<span class=ipchip><a class=ip href="/honeypot/ip/{e(ip)}">{e(ip)}</a> {_action_pill(a)}</span>'
            for ip, a in items[:CAP])
        if len(items) > CAP:
            cells += f'<span class="ipchip more">+{len(items) - CAP} more</span>'
        actioned_html = '<div class=chips>' + cells + '</div>'
    else:
        actioned_html = "<p class=small>No IPs currently challenged/blocked.</p>"

    if offenders:
        orows = ""
        for ip, ent in offenders:
            orows += (
                "<tr>"
                f"<td class=mono><a href=\"/honeypot/ip/{e(ip)}\">{e(ip)}</a></td>"
                f"<td>{e(str(ent.get('total_hits','')))}</td>"
                f"<td class=small>{e(','.join(ent.get('rules', []) or []))}</td>"
                f"<td>{_action_pill(ent.get('actioned',''))}</td>"
                f"<td class=small>{e(str(ent.get('first_seen','')))}</td>"
                "</tr>"
            )
        offenders_html = ('<h3>repeat offenders · top 10 by lifetime hits</h3>'
                          '<div class=tablewrap><table><thead><tr><th>ip</th><th>hits</th>'
                          '<th>rules</th><th>actioned</th><th>first seen</th></tr></thead>'
                          f'<tbody>{orows}</tbody></table></div>')
    else:
        offenders_html = ""

    status_pill = ('<span class="pill ok">● RUNNING</span>' if proc_up
                   else '<span class="pill down">stopped</span>')
    body = f"""
<div class=box>
<h2><span class=ico>🍯</span> honeypot — scanner detection &amp; deception
 {status_pill} <span class="pill warn">mode: {e(mode)}</span></h2>
<div class=statgrid style="margin-top:.7rem">
  <div class="stat accent"><div class=lbl>ledger hits</div><div class=val>{total}</div></div>
  <div class=stat><div class=lbl>CF-actioned</div><div class=val>{blocked}</div></div>
  <div class="stat accent"><div class=lbl>last 24h</div><div class=val>{buckets['24h']}</div></div>
  <div class=stat><div class=lbl>7d · 30d</div><div class=val>{buckets['7d']} <small>· {buckets['30d']}</small></div></div>
</div>
<p class=small style="margin-top:.7rem">Tails the Caddy access log for high-confidence scanner probes using the
real client IP, writes the JSONL ledger <code>{e(HP_LEDGER)}</code>, optionally posts a Matrix
alert, and (challenge/block mode) adds a Cloudflare IP Access Rule with auto-expiry. Loopback + all
Cloudflare ranges + <code>{e(HP_SAFELIST)}</code> are safelisted.
 {action_btn("restart-honeypot-watcher", "restart watcher", "small")}</p>
</div>

<div class=box>
<h2><span class=ico>🔎</span> breakdown</h2>
<div class=facets>{facets_html}</div>
{geo_note}
</div>

<div class=box>
<h2><span class=ico>🛡️</span> currently actioned <span class=badge>{len(act_ips)} IPs</span></h2>
{actioned_html}
{offenders_html}
</div>

<div class=box>
<h2><span class=ico>🛰️</span> recent hits <span class=badge>newest first · last 150</span>
 <a href="/honeypot/hits" style="font-size:.8rem;font-weight:400">browse &amp; filter all →</a></h2>
{table}
<p class=small style="margin-top:.5rem"><b>Tiers</b> via <code>{e(HP_MODE_FILE)}</code>
(alert → challenge → block; hot-reloaded). Edge blocking is triple-gated and off by default.
See docs/HONEYPOT.md.</p>
</div>
"""
    return render("security — honeypot", body)


# ---------- honeypot SQLite cache: browse/filter hits + per-IP drill-down -----
# The /honeypot view above reads the JSONL ledger directly and ALWAYS works. The
# routes below add server-side filter/sort/paginate + per-IP drill-down backed by
# a small SQLite cache (scripts/honeypot/honeypot_db.py) that the panel — the SOLE
# writer (one gunicorn worker) — ingests incrementally from the same ledger.
# Cloudflare reads go through the shared scripts/honeypot/cf_actions.py. Each
# read-only route is a GET (login_required; no state change → no CSRF needed);
# IPs are validated via ipaddress before use and all output is html-escaped. The
# modules load lazily + gracefully so a deploy without them degrades to the legacy
# ledger view instead of breaking the panel.
@app.route("/honeypot/hits")
@login_required
def honeypot_hits():
    from urllib.parse import urlencode
    hdb, conn = _hp_conn()
    if conn is None:
        return _hp_unavailable()
    try:
        args = request.args
        q = (args.get("q") or "").strip()[:120]
        rule = (args.get("rule") or "").strip()[:64]
        host = (args.get("host") or "").strip()[:128]
        country = (args.get("country") or "").strip()[:8]
        action = "actioned" if args.get("action") == "actioned" else None
        sort = args.get("sort") or "ts"
        desc = (args.get("dir") or "desc") != "asc"
        try:
            page = max(1, int(args.get("page") or 1))
        except ValueError:
            page = 1
        PER = 100
        rows, total = hdb.query_hits(conn, q=q or None, rule=rule or None,
                                     host=host or None, country=country or None,
                                     action=action, order=sort, desc=desc,
                                     limit=PER, offset=(page - 1) * PER)
        pages = max(1, (total + PER - 1) // PER)

        def qs(**over):
            cur = {}
            for k in ("q", "rule", "host", "country", "action", "sort", "dir"):
                v = args.get(k)
                if v:
                    cur[k] = v
            for k, v in over.items():
                if v in (None, ""):
                    cur.pop(k, None)
                else:
                    cur[k] = v
            return "?" + urlencode(cur) if cur else ""

        active = []
        for label, key, val in (("search", "q", q), ("rule", "rule", rule),
                                ("host", "host", host), ("country", "country", country)):
            if val:
                active.append(f'{e(label)}=<b>{e(val)}</b> '
                              f'<a href="{qs(**{key: "", "page": ""})}">✕</a>')
        if action:
            active.append(f'<b>cf-actioned only</b> <a href="{qs(action="", page="")}">✕</a>')
        filt = (" · ".join(active)) if active else "no filters"

        def chips(col, key):
            out = ""
            for val, n in hdb.distinct_values(conn, col, 12):
                out += (f'<a class=ipchip href="{qs(**{key: val, "page": ""})}">'
                        f'<span class=ip>{e(str(val))}</span> '
                        f'<span class=badge>{n}</span></a>')
            return out or '<span class=small>none yet</span>'

        trs = ""
        for r in rows:
            geo = e(str(r["country"] or ""))
            if r["hosting"]:
                geo += " ⚠DC"
            ipv = str(r["ip"] or "")
            trs += (
                "<tr>"
                f"<td class=small>{e(str(r['ts'] or ''))}</td>"
                f"<td class=mono><a href=\"/honeypot/ip/{e(ipv)}\">{e(ipv)}</a></td>"
                f"<td class=small>{geo}</td>"
                f"<td>{e(str(r['host'] or ''))}</td>"
                f"<td class='mono path' title=\"{e(str(r['uri'] or ''))}\">{e(str(r['uri'] or '')[:72])}</td>"
                f"<td>{e(str(r['hit_rule'] or ''))}</td>"
                f"<td>{e(str(r['status'] or ''))}</td>"
                f"<td>{_hp_action_pill(r['action'])}</td>"
                "</tr>")
        table = ('<div class=tablewrap><table><thead><tr>'
                 '<th>ts (UTC)</th><th>ip</th><th>geo</th><th>host</th><th>path</th>'
                 '<th>rule</th><th>code</th><th>action</th></tr></thead>'
                 f'<tbody>{trs}</tbody></table></div>') if rows else \
                '<p class=small>No hits match these filters.</p>'

        prev_l = (f'<a href="{qs(page=page-1)}">‹ prev</a>' if page > 1 else
                  '<span class=small>‹ prev</span>')
        next_l = (f'<a href="{qs(page=page+1)}">next ›</a>' if page < pages else
                  '<span class=small>next ›</span>')

        body = f"""
<div class=box>
<h2><span class=ico>🍯</span> honeypot hits <span class=badge>{total} match</span>
 <a href="/honeypot" style="font-size:.8rem;font-weight:400">‹ back to overview</a></h2>
<form method=get action="/honeypot/hits" style="margin:.6rem 0">
  <input name=q value="{e(q)}" placeholder="search ip / path / host / UA / rule"
         style="padding:.4rem .6rem;min-width:18rem">
  <button type=submit>search</button>
  {'<a href="/honeypot/hits" style="margin-left:.6rem;font-size:.85rem">reset</a>' if (active or q) else ''}
</form>
<p class=small>filters: {filt}</p>
<p class=small style="margin-top:.5rem"><b>quick filter · rules</b></p>
<div class=chips>{chips("hit_rule","rule")}</div>
<p class=small style="margin-top:.5rem"><b>quick filter · hosts</b></p>
<div class=chips>{chips("host","host")}</div>
</div>

<div class=box>
{table}
<p class=small style="margin-top:.6rem">{prev_l} &nbsp; page <b>{page}</b> / {pages} &nbsp; {next_l}
 &nbsp;·&nbsp; sort:
 <a href="{qs(sort='ts', dir='desc', page='')}">newest</a> ·
 <a href="{qs(sort='ts', dir='asc', page='')}">oldest</a> ·
 <a href="{qs(sort='ip', dir='asc', page='')}">ip</a> ·
 <a href="{qs(sort='rule', dir='asc', page='')}">rule</a>
 &nbsp;·&nbsp; <a href="{qs(action='actioned', page='')}">cf-actioned only</a></p>
</div>
"""
        return render("honeypot — hits", body)
    finally:
        conn.close()


@app.route("/honeypot/ip/<ip>")
@login_required
def honeypot_ip(ip):
    import ipaddress
    try:
        ipn = str(ipaddress.ip_address(ip))
    except ValueError:
        abort(404)
    hdb, conn = _hp_conn()
    if conn is None:
        return _hp_unavailable()
    try:
        summ = hdb.ip_summary(conn, ipn)
        rows, total = hdb.ip_hits(conn, ipn, limit=300)

        # Overlay the live ip-state JSON for the freshest actioned/action_ts (this is
        # what --reap reads); the DB-derived value is the fallback.
        live_actioned = live_action_ts = ""
        try:
            st = json.load(open(HP_IP_STATE))
            ent = st.get(ipn) if isinstance(st, dict) else None
            if ent:
                live_actioned = ent.get("actioned") or ""
                live_action_ts = ent.get("action_ts") or ""
        except Exception:
            pass
        actioned = live_actioned or (summ.get("actioned") if summ else "") or ""
        action_ts = live_action_ts or (summ.get("action_ts") if summ else "") or ""

        # Optional LIVE Cloudflare rule state (read-only) — opt-in via ?cf=1 so a CF
        # API call isn't made on every page view. Best-effort; never breaks the page.
        cf_html = (f'<a href="/honeypot/ip/{e(ipn)}?cf=1">check live Cloudflare '
                   f'rule state →</a>')
        if request.args.get("cf") == "1":
            cf = _hp_load("cf_actions")
            if cf is None:
                cf_html = '<span class=small>cf_actions module not deployed.</span>'
            else:
                cf.CF_ENV = HP_CF_ENV
                try:
                    cfg = cf._load_cf_env()
                    tok, acct = cfg.get("CF_API_TOKEN"), cfg.get("CF_ACCOUNT_ID")
                    if not (tok and acct):
                        cf_html = ('<span class=small>no cf-honeypot.env — edge '
                                   'blocking not provisioned.</span>')
                    else:
                        mine = [r for r in cf.cf_list_rules(tok, acct)
                                if r.get("ip") == ipn]
                        if mine:
                            cf_html = "".join(
                                f'<span class=ipchip><span class=ip>rule '
                                f'{e(str(r["id"])[:12])}</span> '
                                f'<span class=badge title="{e(r.get("notes",""))}">'
                                f'honeypot-auto</span></span>' for r in mine)
                        else:
                            cf_html = ('<span class=small>no honeypot-auto CF rule '
                                       'currently targets this IP.</span>')
                except Exception as ex:
                    cf_html = f'<span class=small>CF lookup failed: {e(str(ex))}</span>'

        if summ is None and not rows:
            body = (f'<div class=box><h2><span class=ico>🔎</span> '
                    f'<span class=mono>{e(ipn)}</span></h2>'
                    f'<p class=small>No honeypot hits recorded for this IP. '
                    f'<a href="/honeypot/hits">‹ back to hits</a></p></div>')
            return render(f"honeypot — {ipn}", body)

        rules = ", ".join(summ.get("rules", [])) if summ else ""
        geo = ""
        if summ and (summ.get("country") or summ.get("asn")):
            geo = e(str(summ.get("country") or ""))
            if summ.get("asn"):
                geo += f" · {e(str(summ.get('asn')))} {e(str(summ.get('as_org') or ''))}"
            if summ.get("hosting"):
                geo += " · ⚠ hosting/DC"

        trs = ""
        for r in rows:
            trs += ("<tr>"
                    f"<td class=small>{e(str(r['ts'] or ''))}</td>"
                    f"<td>{e(str(r['host'] or ''))}</td>"
                    f"<td class='mono path' title=\"{e(str(r['uri'] or ''))}\">{e(str(r['uri'] or '')[:80])}</td>"
                    f"<td>{e(str(r['method'] or ''))}</td>"
                    f"<td>{e(str(r['hit_rule'] or ''))}</td>"
                    f"<td>{e(str(r['status'] or ''))}</td>"
                    f"<td>{_hp_action_pill(r['action'])}</td>"
                    "</tr>")
        table = ('<div class=tablewrap><table><thead><tr>'
                 '<th>ts (UTC)</th><th>host</th><th>path</th><th>method</th>'
                 '<th>rule</th><th>code</th><th>action</th></tr></thead>'
                 f'<tbody>{trs}</tbody></table></div>')

        total_hits = (summ.get("total_hits", total) if summ else total)
        nrules = (len(summ.get("rules", [])) if summ else 0)
        first_seen = e(str(summ.get("first_seen", "") if summ else ""))
        last_seen = e(str(summ.get("last_seen", "") if summ else ""))

        # ---- operator actions (defensive, confirm-gated) ----
        def _act_btn(act, label, cls):
            klass = f"btn {cls}".strip()
            return (f'<a class="{klass}" href="/honeypot/act/{act}/{e(ipn)}" '
                    f'style="margin:.15rem .4rem .15rem 0">{label}</a>')
        safel = " <span class=pill>safelisted</span>" if (summ and summ.get("safelisted")) else ""
        cur_note = e(str(summ.get("note") or "") if summ else "")
        cur_esc = e(str(summ.get("escalation") or "") if summ else "")
        actions_box = f"""
<div class=box>
<h2><span class=ico>🛡️</span> operator actions
 <span class=small style="font-weight:400">defensive · your own edge{safel}</span></h2>
<p class=small>Each action opens a confirm flow (typed phrase + <code>yes</code> +
password) and is written to the audit log. No traffic is ever sent to this host.</p>
<div style="margin:.5rem 0">
  {_act_btn('challenge', '⚠ challenge', 'warn')}
  {_act_btn('block', '⛔ block', 'danger')}
  {_act_btn('unblock', '✓ unblock', '')}
  {_act_btn('safelist', '★ safelist', '')}
</div>
<form method=post action="/honeypot/annotate/{e(ipn)}" style="margin-top:.6rem">
  <input type=hidden name=_csrf value="{e(new_csrf())}">
  <p class=small style="margin-bottom:.2rem"><b>note</b></p>
  <input name=note value="{cur_note}" placeholder="free-text note"
         style="min-width:22rem;padding:.4rem .6rem" maxlength=500>
  <p class=small style="margin:.4rem 0 .2rem"><b>escalation</b></p>
  <input name=escalation value="{cur_esc}"
         placeholder="e.g. watch / reported / blocked-upstream"
         style="min-width:16rem;padding:.4rem .6rem" maxlength=64>
  <button type=submit style="margin-left:.4rem">save annotation</button>
</form>
</div>"""

        # ---- enrichment (passive identification + threat-intel deep-links) ----
        ti = (
            f'<a class=btn href="https://www.abuseipdb.com/check/{e(ipn)}" target=_blank rel=noopener>AbuseIPDB ↗</a> '
            f'<a class=btn href="https://www.shodan.io/host/{e(ipn)}" target=_blank rel=noopener>Shodan ↗</a> '
            f'<a class=btn href="https://viz.greynoise.io/ip/{e(ipn)}" target=_blank rel=noopener>GreyNoise ↗</a> '
            f'<a class=btn href="https://www.virustotal.com/gui/ip-address/{e(ipn)}" target=_blank rel=noopener>VirusTotal ↗</a>')
        enrich_box = f"""
<div class=box>
<h2><span class=ico>🔬</span> enrichment
 <span class=small style="font-weight:400">passive only</span></h2>
<p class=small><b>registry (RDAP):</b>
 <a href="/honeypot/rdap/{e(ipn)}">look up network owner + abuse contact →</a></p>
<p class=small style="margin-top:.35rem"><b>abuse report:</b>
 <a href="/honeypot/abuse-report/{e(ipn)}">generate a pre-filled draft →</a></p>
<p class=small style="margin-top:.35rem"><b>reverse DNS + geo:</b>
 <a href="/honeypot/lookup/{e(ipn)}">passive lookup →</a></p>
<p class=small style="margin-top:.5rem"><b>threat-intel:</b> {ti}</p>
<p class=small style="margin-top:.4rem">External links open third-party sites in a
new tab. No automated query is sent from this server to those services or to the
source host.</p>
</div>"""
        body = f"""
<div class=box>
<h2><span class=ico>🔎</span> <span class=mono>{e(ipn)}</span> {_hp_action_pill(actioned)}
 <a href="/honeypot/hits" style="font-size:.8rem;font-weight:400">‹ all hits</a></h2>
<div class=statgrid style="margin-top:.7rem">
  <div class="stat accent"><div class=lbl>total hits</div><div class=val>{total_hits}</div></div>
  <div class=stat><div class=lbl>distinct rules</div><div class=val>{nrules}</div></div>
  <div class=stat><div class=lbl>first seen</div><div class=val style="font-size:.8rem">{first_seen or '—'}</div></div>
  <div class=stat><div class=lbl>last seen</div><div class=val style="font-size:.8rem">{last_seen or '—'}</div></div>
</div>
<p class=small style="margin-top:.7rem"><b>rules:</b> {e(rules) or '—'}</p>
<p class=small><b>geo/ASN:</b> {geo or 'not enriched'}</p>
<p class=small><b>edge action:</b> {_hp_action_pill(actioned)} {('since ' + e(action_ts)) if action_ts else ''}
 &nbsp;·&nbsp; <a href="/honeypot/lookup/{e(ipn)}">passive lookup (rDNS + geo) →</a></p>
<p class=small><b>note:</b> {e(str(summ.get('note') or '')) if summ and summ.get('note') else '—'}
 &nbsp;·&nbsp; <b>escalation:</b> {e(str(summ.get('escalation') or '')) if summ and summ.get('escalation') else '—'}</p>
<p class=small><b>Cloudflare:</b> {cf_html}</p>
</div>
{actions_box}
{enrich_box}
<div class=box>
<h2><span class=ico>🛰️</span> hits <span class=badge>{total} · newest first</span></h2>
{table}
</div>
"""
        return render(f"honeypot — {ipn}", body)
    finally:
        conn.close()


@app.route("/honeypot/lookup/<ip>")
@login_required
def honeypot_lookup(ip):
    import ipaddress
    import socket
    import concurrent.futures as _f
    try:
        ipn = str(ipaddress.ip_address(ip))
    except ValueError:
        abort(404)
    # Passive reverse-DNS PTR with a hard 3s cap (a single lookup; NO active probe).
    ptr = ""
    try:
        with _f.ThreadPoolExecutor(max_workers=1) as ex_:
            ptr = ex_.submit(lambda: socket.gethostbyaddr(ipn)[0]).result(timeout=3)
    except Exception:
        ptr = ""
    # Offline geo from the DB (already-collected; no network call).
    geo_line, nhits = "not enriched", 0
    hdb, conn = _hp_conn()
    summ = None
    if conn is not None:
        try:
            summ = hdb.ip_summary(conn, ipn)
        finally:
            conn.close()
    if summ:
        nhits = summ.get("total_hits", 0) or 0
        if summ.get("country") or summ.get("asn"):
            geo_line = e(str(summ.get("country") or ""))
            if summ.get("asn"):
                geo_line += f" · {e(str(summ.get('asn')))} {e(str(summ.get('as_org') or ''))}"
            if summ.get("hosting"):
                geo_line += " · ⚠ hosting/DC"
    body = f"""
<div class=box>
<h2><span class=ico>🛰️</span> passive lookup · <span class=mono>{e(ipn)}</span>
 <a href="/honeypot/ip/{e(ipn)}" style="font-size:.8rem;font-weight:400">‹ back</a></h2>
<p class=small style="margin-top:.5rem">Passive identification only — a single reverse-DNS PTR
and the offline geo already collected in our own logs. No active scanning, probing, or
connect-back to the source.</p>
<p class=small style="margin-top:.6rem"><b>reverse DNS (PTR):</b>
 <span class=mono>{e(ptr) if ptr else 'no PTR record'}</span></p>
<p class=small><b>offline geo / ASN:</b> {geo_line}</p>
<p class=small><b>hits in ledger:</b> {nhits}</p>
</div>
"""
    return render(f"honeypot — lookup {ipn}", body)


# ============================================================================
# Honeypot write-action console + passive enrichment.
#
# SAFETY BOUNDARY (designed-in):
#   * Write actions touch ONLY the operator's OWN Cloudflare IP-Access-Rules
#     (challenge/block/unblock a single source IP) and the local safelist — the
#     exact mechanism + blast radius the watcher already uses to auto-block. No
#     traffic is ever sent toward the source host.
#   * Enrichment is PASSIVE: registry RDAP (queries the RIR, not the source), a
#     single reverse-DNS PTR, offline geo from our own logs, and outbound *links*
#     to third-party threat-intel sites.
#   * CF edge actions go through the shared cf_actions module (re-asserts token
#     scope + the 'honeypot-auto' note prefix before any delete) behind the same
#     three-input confirm flow as /danger (typed phrase + 'yes' + password).
# ============================================================================
_HP_ACTIONS = {
    "challenge": {
        "title": "Challenge IP at Cloudflare", "phrase": "challenge",
        "verb": "apply a managed-challenge to", "reversible": True,
        "impact": [
            "Adds ONE Cloudflare IP Access Rule (mode = managed_challenge) for this "
            "single source IP, on your own account edge.",
            "Requests from this IP get an interstitial challenge — real humans can "
            "still pass, automated scanners fail. CGNAT-safe.",
            "Reversible: use the 'unblock' action to remove the rule.",
            "No traffic is sent to the source — this only changes how YOUR edge "
            "treats requests coming FROM it.",
        ],
    },
    "block": {
        "title": "Block IP at Cloudflare", "phrase": "block this ip",
        "verb": "hard-block", "reversible": True,
        "impact": [
            "Adds ONE Cloudflare IP Access Rule (mode = block) for this single "
            "source IP, on your own account edge.",
            "ALL requests from this IP are refused at the edge — harder than a "
            "challenge; a shared/CGNAT address would take collateral.",
            "Reversible: use the 'unblock' action to remove the rule.",
            "No traffic is sent to the source.",
        ],
    },
    "unblock": {
        "title": "Unblock IP at Cloudflare", "phrase": "unblock",
        "verb": "remove the honeypot edge rule(s) for", "reversible": True,
        "impact": [
            "Deletes every honeypot-auto IP Access Rule that targets this IP "
            "(challenge or block).",
            "Only rules the honeypot itself created (notes prefixed "
            "'honeypot-auto') are touched — your manual Cloudflare rules are never "
            "affected.",
            "Afterwards, requests from this IP are treated normally again.",
        ],
    },
    "safelist": {
        "title": "Safelist IP", "phrase": "safelist",
        "verb": "permanently allow", "reversible": True,
        "impact": [
            "Appends this IP to the honeypot safelist — the watcher will NEVER "
            "alert on or auto-block it again.",
            "Use only for known-good operator / egress addresses. Reversible by "
            "editing honeypot-safelist.txt.",
            "Does NOT remove an existing Cloudflare rule — run 'unblock' separately "
            "if one is currently active for this IP.",
        ],
    },
}


def _hp_cf():
    """Load cf_actions, point it at the honeypot env, and return
    (module, token, account, reason). On any problem → (None, None, None, reason).
    No CF request is made here — only local env parse."""
    cf = _hp_load("cf_actions")
    if cf is None:
        return None, None, None, "cf_actions.py not deployed"
    cf.CF_ENV = HP_CF_ENV
    try:
        cfg = cf._load_cf_env()
    except Exception as ex:
        return None, None, None, f"cf-honeypot.env unreadable ({ex})"
    tok, acct = cfg.get("CF_API_TOKEN"), cfg.get("CF_ACCOUNT_ID")
    if not (tok and acct):
        return None, None, None, ("cf-honeypot.env missing token/account — edge "
                                  "blocking not provisioned")
    return cf, tok, acct, "ok"


def _safelist_add(ip, actor):
    """Idempotently append `ip` to the honeypot safelist (one IP/CIDR per line; the
    watcher strips inline '#' comments). Returns True if newly added, False if it
    was already present."""
    path = HP_SAFELIST
    existing = set()
    try:
        for ln in open(path):
            tok = ln.split("#", 1)[0].strip()
            if tok:
                existing.add(tok)
    except OSError:
        pass
    if ip in existing:
        return False
    ts = time.strftime("%FT%TZ", time.gmtime())
    with open(path, "a") as f:
        f.write(f"{ip}  # safelisted via adminweb {ts} by {actor}\n")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return True


def _hp_execute(action, ip, actor):
    """Perform one confirmed write-action. Returns (ok, summary_text, detail_dict).
    Persists ip_state + an audit row in the DB and never sends traffic to `ip`."""
    detail = {"action": action, "ip": ip}

    if action == "safelist":
        added = _safelist_add(ip, actor)
        hdb, conn = _hp_conn()
        if conn is not None:
            try:
                hdb.update_ip_state(conn, ip, safelisted=1)
                hdb.record_action(conn, actor, "safelist", ip,
                                  detail={"added": added}, result="ok")
            finally:
                conn.close()
        msg = (f"{ip} added to the honeypot safelist — it will no longer be alerted "
               f"on or auto-blocked." if added else
               f"{ip} was already on the safelist (no change).")
        return True, msg, detail

    # ---- Cloudflare edge actions (challenge / block / unblock) ----
    cf, tok, acct, why = _hp_cf()
    if cf is None:
        return False, f"Cloudflare edge unavailable: {why}", detail
    ok_scope, reason = cf.cf_token_scope_ok(tok, acct)
    if not ok_scope:
        detail["scope"] = reason
        return False, f"refusing CF write — token scope self-check failed: {reason}", detail

    if action in ("challenge", "block"):
        tag = cf.cf_block(ip, action)   # 'cf-managed_challenge:<rid>' | 'cf-block:<rid>' | 'cf-<m>:dup' | 'cf-error'
        detail["result_tag"] = tag
        ok = tag.startswith("cf-") and tag != "cf-error"
        cf_mode, rid = "", ""
        if tag.startswith("cf-") and ":" in tag:
            cf_mode, rid = tag[3:].split(":", 1)
        if rid == "dup":
            rid = ""
        if ok:
            hdb, conn = _hp_conn()
            if conn is not None:
                try:
                    hdb.update_ip_state(
                        conn, ip, actioned=action,
                        action_ts=time.strftime("%FT%TZ", time.gmtime()),
                        cf_mode=cf_mode, cf_rule_id=rid, cf_actor=actor)
                    hdb.record_action(conn, actor, action, ip, detail=detail, result=tag)
                finally:
                    conn.close()
            verb = "managed-challenge" if action == "challenge" else "block"
            return True, f"Cloudflare {verb} applied to {ip} ({e2(tag)}).", detail
        return False, f"Cloudflare action failed ({e2(tag)}) — see the admin log.", detail

    if action == "unblock":
        deleted, failed = cf.cf_unblock(tok, acct, ip)
        detail["deleted"], detail["failed"] = deleted, failed
        hdb, conn = _hp_conn()
        if conn is not None:
            try:
                hdb.update_ip_state(conn, ip, actioned="", cf_rule_id="", cf_mode="")
                hdb.record_action(conn, actor, "unblock", ip, detail=detail,
                                  result=f"deleted={deleted} failed={len(failed)}")
            finally:
                conn.close()
        if failed:
            return False, (f"removed {deleted} rule(s) for {ip}, but "
                           f"{len(failed)} delete(s) failed: {', '.join(failed)}"), detail
        if deleted == 0:
            return True, f"no honeypot-auto Cloudflare rule currently targets {ip}.", detail
        return True, f"removed {deleted} honeypot-auto Cloudflare rule(s) for {ip}.", detail

    return False, "unknown action", detail


@app.route("/honeypot/act/<action>/<ip>", methods=["GET", "POST"])
@login_required
def honeypot_act(action, ip):
    import ipaddress
    meta = _HP_ACTIONS.get(action)
    if not meta:
        abort(404)
    try:
        ipn = str(ipaddress.ip_address(ip))
    except ValueError:
        abort(404)

    if request.method == "POST":
        if not csrf_ok():
            abort(403)
        typed_phrase = request.form.get("phrase", "").strip().lower()
        typed_yes = request.form.get("yes", "").strip().lower()
        pw = request.form.get("password", "")
        if typed_phrase != meta["phrase"]:
            log_audit("hp-confirm", act=action, ip=ipn, ok=False, reason="phrase-mismatch")
            flash_msg(f"confirmation phrase mismatch — type exactly: {meta['phrase']}", "err")
            return redirect(url_for("honeypot_act", action=action, ip=ipn, stage=2))
        if typed_yes != "yes":
            log_audit("hp-confirm", act=action, ip=ipn, ok=False, reason="yes-not-typed")
            flash_msg("you must literally type 'yes' to confirm", "err")
            return redirect(url_for("honeypot_act", action=action, ip=ipn, stage=2))
        if not pw or not verify_password(pw):
            log_audit("hp-confirm", act=action, ip=ipn, ok=False, reason="bad-password")
            flash_msg("password incorrect — re-auth required", "err")
            return redirect(url_for("honeypot_act", action=action, ip=ipn, stage=2))
        actor = session.get("user", "admin")
        log_audit("hp-action-go", act=action, ip=ipn)
        ok, summary, detail = _hp_execute(action, ipn, actor)
        log_audit("hp-action-end", act=action, ip=ipn, ok=ok, result=summary[:200])
        icon = "✅" if ok else "❌"
        body = f"""
<div class=box>
<h2>{icon} {e(meta['title'])} · <span class=mono>{e(ipn)}</span></h2>
<p>{e(summary)}</p>
<p class=small style="margin-top:.9rem">
 <a href="/honeypot/ip/{e(ipn)}">‹ back to {e(ipn)}</a> &nbsp;·&nbsp;
 <a href="/honeypot">security overview</a></p>
</div>"""
        return render(f"{action} {ipn} — security", body)

    impact_html = "\n".join(f"<li>{e(x)}</li>" for x in meta["impact"])
    stage = request.args.get("stage", "1")
    if stage == "1":
        body = f"""
<div class="box danger-zone">
<h2>⚠ {e(meta['title'])} — review &nbsp;<span class=mono>{e(ipn)}</span></h2>
<div class=warn-box>
<strong>What this does:</strong>
<ul>{impact_html}</ul>
<p><strong>Safety boundary:</strong> a DEFENSIVE action on your own Cloudflare
edge / safelist. No traffic is ever sent to the source host.</p>
</div>
<p class=small style="margin-top:1rem">To proceed, click Continue. The next page
asks for a typed phrase, the literal word <code>yes</code>, and your admin password.</p>
<form method=get action="{url_for('honeypot_act', action=action, ip=ipn)}">
<input type=hidden name=stage value="2">
<button type=submit class=danger>Continue →</button>
<a href="/honeypot/ip/{e(ipn)}" class="btn small">cancel</a>
</form>
</div>"""
        return render(f"confirm — {meta['title']}", body)

    body = f"""
<div class="box danger-zone">
<h2>⚠ {e(meta['title'])} — final confirm &nbsp;<span class=mono>{e(ipn)}</span></h2>
<div class=warn-box>
<p class=small><a href="{url_for('honeypot_act', action=action, ip=ipn)}">← back to impact summary</a></p>
<p>Three inputs. All required. None can be auto-completed.</p>
</div>
<form method=post>
<input type=hidden name=_csrf value="{e(new_csrf())}">
<p>1. Type exactly <code>{e(meta['phrase'])}</code>:</p>
<input name=phrase type=text autocomplete=off required placeholder="{e(meta['phrase'])}">
<p>2. Type literally <code>yes</code>:</p>
<input name=yes type=text autocomplete=off required placeholder="yes" pattern="[Yy][Ee][Ss]" maxlength=3>
<p>3. Re-enter your admin password:</p>
<input name=password type=password autocomplete=current-password required>
<button type=submit class=danger>{e(meta['verb'])} {e(ipn)}</button>
<a href="/honeypot/ip/{e(ipn)}" class="btn small">cancel</a>
</form>
</div>"""
    return render(f"confirm — {meta['title']}", body)


@app.route("/honeypot/annotate/<ip>", methods=["POST"])
@login_required
def honeypot_annotate(ip):
    import ipaddress
    if not csrf_ok():
        abort(403)
    try:
        ipn = str(ipaddress.ip_address(ip))
    except ValueError:
        abort(404)
    fields = {}
    if "note" in request.form:
        fields["note"] = (request.form.get("note") or "").strip()[:500]
    if "escalation" in request.form:
        fields["escalation"] = (request.form.get("escalation") or "").strip()[:64]
    actor = session.get("user", "admin")
    hdb, conn = _hp_conn()
    if conn is None:
        flash_msg("honeypot DB unavailable — annotation not saved", "err")
        return redirect(url_for("honeypot_ip", ip=ipn))
    try:
        n = hdb.update_ip_state(conn, ipn, **fields)
        hdb.record_action(conn, actor, "annotate", ipn, detail=fields, result=f"cols={n}")
    finally:
        conn.close()
    log_audit("hp-annotate", ip=ipn, fields=list(fields))
    flash_msg(f"annotation saved for {ipn}", "ok")
    return redirect(url_for("honeypot_ip", ip=ipn))


def _rdap_lookup(ip, timeout=8):
    """Passive RDAP query — registry (RIR) data ONLY, never the source host. Returns
    {ok, name, handle, country, range, abuse[], error}. Best-effort; never raises."""
    from urllib.parse import quote
    out = {"ok": False, "name": "", "handle": "", "country": "", "range": "",
           "abuse": [], "error": ""}
    try:
        # ARIN's RDAP server (operated directly by ARIN, NOT Cloudflare-fronted, so
        # the device's outbound isn't tripped by CF Bot Fight Mode) auto-redirects an
        # out-of-region IP to the authoritative RIR (RIPE/APNIC/…); urllib follows it.
        req = urllib.request.Request(
            f"https://rdap.arin.net/registry/ip/{quote(ip)}",
            headers={"User-Agent": "pocket-homeserver-honeypot/1.0 (rdap)",
                     "Accept": "application/rdap+json, application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.load(r)
    except Exception as ex:
        out["error"] = str(ex)[:200]
        return out
    out["ok"] = True
    out["name"] = str(data.get("name") or "")
    out["handle"] = str(data.get("handle") or "")
    out["country"] = str(data.get("country") or "")
    sa, ea = data.get("startAddress"), data.get("endAddress")
    if sa and ea:
        out["range"] = f"{sa} – {ea}"
    elif data.get("cidr0_cidrs"):
        try:
            c = data["cidr0_cidrs"][0]
            out["range"] = f"{c.get('v4prefix') or c.get('v6prefix')}/{c.get('length')}"
        except Exception:
            pass

    pairs = []   # (roles, email)

    def _walk(ent):
        roles = [str(x).lower() for x in (ent.get("roles") or [])]
        va = ent.get("vcardArray")
        if isinstance(va, list) and len(va) > 1 and isinstance(va[1], list):
            for item in va[1]:
                if isinstance(item, list) and len(item) >= 4 and item[0] == "email":
                    pairs.append((roles, str(item[3])))
        for sub in ent.get("entities") or []:
            _walk(sub)

    for ent in data.get("entities") or []:
        _walk(ent)
    abuse = [em for roles, em in pairs if "abuse" in roles]
    if not abuse:
        abuse = [em for _, em in pairs]   # fall back to any contact email
    seen = set()
    out["abuse"] = [x for x in abuse if not (x in seen or seen.add(x))]
    return out


@app.route("/honeypot/rdap/<ip>")
@login_required
def honeypot_rdap(ip):
    import ipaddress
    try:
        ipn = str(ipaddress.ip_address(ip))
    except ValueError:
        abort(404)
    r = _rdap_lookup(ipn)
    log_audit("hp-rdap", ip=ipn, ok=r["ok"])
    if r["ok"]:
        abuse = (", ".join(f'<a href="mailto:{e(a)}">{e(a)}</a>' for a in r["abuse"])
                 or "<span class=small>none published</span>")
        info = f"""
<p class=small><b>network name:</b> {e(r['name']) or '—'}</p>
<p class=small><b>handle:</b> {e(r['handle']) or '—'}</p>
<p class=small><b>range:</b> <span class=mono>{e(r['range']) or '—'}</span></p>
<p class=small><b>country:</b> {e(r['country']) or '—'}</p>
<p class=small><b>abuse contact:</b> {abuse}</p>"""
    else:
        info = (f'<p class=small>RDAP lookup failed: <span class=mono>{e(r["error"])}</span>. '
                f'Registries rate-limit; try again shortly.</p>')
    body = f"""
<div class=box>
<h2><span class=ico>🏛️</span> RDAP · <span class=mono>{e(ipn)}</span>
 <a href="/honeypot/ip/{e(ipn)}" style="font-size:.8rem;font-weight:400">‹ back</a></h2>
<p class=small style="margin-top:.4rem">Passive registry lookup — this queries the
regional internet registry (RIR), NOT the source host. It identifies the network
owner and their published abuse contact.</p>
{info}
<p class=small style="margin-top:.6rem">
 <a href="/honeypot/abuse-report/{e(ipn)}">generate an abuse-report draft →</a></p>
</div>"""
    return render(f"honeypot — rdap {ipn}", body)


@app.route("/honeypot/abuse-report/<ip>")
@login_required
def honeypot_abuse_report(ip):
    import ipaddress
    try:
        ipn = str(ipaddress.ip_address(ip))
    except ValueError:
        abort(404)
    summ, rows = None, []
    hdb, conn = _hp_conn()
    if conn is not None:
        try:
            summ = hdb.ip_summary(conn, ipn)
            rows, _ = hdb.ip_hits(conn, ipn, limit=20)
        finally:
            conn.close()
    rdap = _rdap_lookup(ipn, timeout=6)
    to = (rdap["abuse"][0] if rdap.get("abuse")
          else "(run the RDAP lookup to find the network abuse contact)")
    first = (summ.get("first_seen") if summ else "") or "—"
    last = (summ.get("last_seen") if summ else "") or "—"
    total = (summ.get("total_hits") if summ else 0) or len(rows)
    rules = ", ".join(summ.get("rules", [])) if summ else ""
    geo = ""
    if summ:
        geo = f"{summ.get('country') or '?'} / {summ.get('asn') or '?'} {summ.get('as_org') or ''}".strip()
    sample = "\n".join(
        f"  {r['ts']}  {r['host']}  {r['method']} {str(r['uri'])[:80]}  -> {r['hit_rule']} [{r['status']}]"
        for r in rows) or "  (no sample lines available)"
    report = f"""Subject: Abuse report — automated scanning from {ipn}

To: {to}

Hello,

The IP address {ipn} has been repeatedly probing our infrastructure with automated
vulnerability scans. Details from our logs (all timestamps UTC):

  IP            : {ipn}
  First seen    : {first}
  Last seen     : {last}
  Total hits    : {total}
  Geo / ASN     : {geo or 'not enriched'}
  Matched rules : {rules or '(various scanner signatures)'}

Sample of requests (timestamp  host  method path  -> matched-rule [status]):
{sample}

These requests match known scanner / exploit signatures (probing for paths such as
/.env, /.git, wp-login.php, phpMyAdmin, and shell-upload endpoints). Please
investigate and take appropriate action against this source.

Thank you,
{BRAND} operations
"""
    body = f"""
<div class=box>
<h2><span class=ico>✉️</span> abuse-report draft · <span class=mono>{e(ipn)}</span>
 <a href="/honeypot/ip/{e(ipn)}" style="font-size:.8rem;font-weight:400">‹ back</a></h2>
<p class=small style="margin-top:.4rem">A pre-filled draft built from your own logs
(+ the RDAP abuse contact, if found). Review, then send it yourself to the network's
abuse contact. Nothing is sent automatically.</p>
<textarea readonly rows=22 style="width:100%;font-family:var(--mono,monospace);
 font-size:.82rem;padding:.7rem;margin-top:.5rem" onclick="this.select()">{e(report)}</textarea>
<p class=small style="margin-top:.4rem">Click the text to select all, then copy.</p>
</div>"""
    return render(f"honeypot — abuse report {ipn}", body)


@app.route("/events")
@login_required
def sse_events():
    """Server-sent events for the dashboard — a small JSON payload each second
    with just the bits that change."""
    sid = request.cookies.get("session", "") or (request.remote_addr or "?")

    def stream():
        with _SSE_SESSIONS_LOCK:
            if _SSE_SESSIONS.get(sid, 0) >= _SSE_MAX_PER_SESSION:
                yield "retry: 30000\nevent: toomany\ndata: {}\n\n"
                return
            _SSE_SESSIONS[sid] = _SSE_SESSIONS.get(sid, 0) + 1
        try:
            i = 0
            svc_html = ""
            while True:
                try:
                    q = _quick_metrics()
                    mem_pct = q["mem_pct"]
                    mem_line = (
                        f'{human_bytes(q["mem_used"])} / {human_bytes(q["mem_total"])} '
                        f'({mem_pct}%)<br>{_bar(mem_pct)}'
                    )
                    if i % 5 == 0:
                        s = gather_stats_cached()
                        svc_html = "<br>".join(_service_row(x) for x in s["services"])
                    payload = json.dumps({
                        "ts": int(time.time()),
                        "load": q["load"],
                        "load1": q["load1"],
                        "uptime": q["uptime"],
                        "mem_html": mem_line,
                        "mem_pct": mem_pct,
                        "mem_used_gb": f'{q["mem_used"]/1073741824:.1f}',
                        "svc_html": svc_html,
                    })
                    yield f"data: {payload}\n\n"
                except GeneratorExit:
                    return
                except Exception as ex:
                    yield f": err {ex}\n\n"
                i += 1
                time.sleep(1)
        finally:
            with _SSE_SESSIONS_LOCK:
                n = _SSE_SESSIONS.get(sid, 1) - 1
                if n <= 0:
                    _SSE_SESSIONS.pop(sid, None)
                else:
                    _SSE_SESSIONS[sid] = n
    r = make_response(stream(), 200)
    r.headers["Content-Type"] = "text/event-stream"
    r.headers["Cache-Control"] = "no-cache"
    r.headers["X-Accel-Buffering"] = "no"
    r.headers["Connection"] = "keep-alive"
    return r


# ---------- PWA assets (no auth — these must load to install) ----------
_ICON_LETTER = (BRAND.strip()[:1] or "p").upper()
_ICON_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">'
    '<rect width="512" height="512" rx="80" fill="#0a0c12"/>'
    '<text x="256" y="340" font-family="ui-monospace,Menlo,monospace" '
    f'font-size="280" font-weight="700" text-anchor="middle" fill="#e7e9ee">{html.escape(_ICON_LETTER)}</text>'
    '<rect x="64" y="430" width="384" height="14" rx="4" fill="#40c8a0"/>'
    "</svg>"
)

@app.route("/icon.svg")
def pwa_icon():
    r = make_response(_ICON_SVG)
    r.headers["Content-Type"] = "image/svg+xml"
    r.headers["Cache-Control"] = "public,max-age=86400"
    return r

@app.route("/admin.css")
def admin_css():
    r = make_response(CSS)
    r.headers["Content-Type"] = "text/css; charset=utf-8"
    r.headers["Cache-Control"] = "public,max-age=31536000,immutable"
    return r

@app.route("/manifest.json")
def pwa_manifest():
    m = {
        "name": f"{BRAND} admin",
        "short_name": (BRAND[:12] or "admin"),
        "description": f"Control panel for the {BRAND} server.",
        "start_url": "/",
        "scope": "/",
        "display": "standalone",
        "orientation": "any",
        "background_color": "#0a0c12",
        "theme_color": "#0a0c12",
        "icons": [
            {"src": "/icon.svg", "type": "image/svg+xml", "sizes": "any", "purpose": "any maskable"},
        ],
    }
    r = make_response(json.dumps(m))
    r.headers["Content-Type"] = "application/manifest+json"
    r.headers["Cache-Control"] = "public,max-age=86400"
    return r


# ---------- error handlers ----------
def _err_page(code, title, body_text):
    body = f"""
<div class=box>
<h2>{e(title)}</h2>
<p>{e(body_text)}</p>
<p><a href="/">← dashboard</a> &middot; <a href="/login">login</a></p>
</div>"""
    return render(f"{code} — {BRAND} admin", body), code

@app.errorhandler(403)
def _e403(_):
    return _err_page(403, "403 forbidden", "Action not allowed (CSRF or auth).")
@app.errorhandler(404)
def _e404(_):
    return _err_page(404, "404 not found", "That page does not exist.")
@app.errorhandler(405)
def _e405(_):
    return _err_page(405, "405 method not allowed", "Wrong HTTP method.")
@app.errorhandler(500)
def _e500(_):
    log_audit("error-500")
    return _err_page(500, "500 server error", "Something went wrong; check logs.")


# ---------- main ----------
def _sanity():
    if BIND_HOST != "127.0.0.1":
        raise RuntimeError("BIND_HOST must be 127.0.0.1")
    if not POCKET_ROOT:
        raise RuntimeError("POCKET_ROOT is not set — the launcher must export it")
    if not os.path.exists(PASSWORD_FILE):
        raise RuntimeError(f"password hash missing at {PASSWORD_FILE}; run scripts/steps/70-install-admin.sh")


# --- Startup init (runs on import) -------------------------------------------
# These run at module import so they execute under BOTH gunicorn AND the
# `python3 app.py` dev fallback. They MUST run per-worker and NOT behind
# `gunicorn --preload`: _load_fails() has to re-read the persisted brute-force
# counters on every worker (re)spawn, else the cross-restart fail tracking would
# silently revert to the startup snapshot. With workers=1 there's no --preload
# memory benefit anyway.
_sanity()
_load_fails()

if __name__ == "__main__":
    print(f"[adminweb] binding {BIND_HOST}:{BIND_PORT} boot_nonce={BOOT_NONCE[:8]}...", flush=True)
    app.run(host=BIND_HOST, port=BIND_PORT, debug=False, use_reloader=False)

# Reaching the server over your LAN

With `INGRESS_MODE=vps-tunnel` every request from your own house takes this path:

```
your PC  ──►  VPS (possibly another continent)  ──►  ssh -R  ──►  the phone
```

For a browser that is fine. For copying a 40 GB game-mod folder to a phone
sitting on the desk next to you it is absurd: every byte crosses the ocean
twice, and it is bounded by your home connection's **upload** speed, which is
usually the slowest link you own.

LAN access also keeps the server usable when the VPS is rebooting, in
maintenance, or simply gone.

---

## 1. Let Caddy listen on the LAN

In `.env`:

```
CADDY_BIND=0.0.0.0
```

Then re-run the installer. Caddy on the phone serves **plain HTTP** on
`CADDY_PORT` — that is by design: TLS terminates on the VPS, never on the phone
(an unprivileged proot process cannot bind :443 anyway).

> Everything on your LAN can now reach every service. Each app still has its own
> login, but this is a real change in exposure — deliberate, not accidental.

⚠️ Editing `.env` is not enough on its own if the `caddy` step is already marked
done: upstream renders the config on every run but only *deploys* it inside that
step. This fork moves the deploy into `render-config.sh`, which always runs — so
a `CADDY_BIND` change does reach the running service. If you are on upstream,
you must deploy the rendered file yourself.

## 2. Make the hostnames resolve locally

Caddy routes by `Host`, so the names must stay the same — only the address
changes. Add to your hosts file (`C:\Windows\System32\drivers\etc\hosts`, or
`/etc/hosts`), using the phone's LAN address:

```
192.168.0.69  chat.your-domain
192.168.0.69  admin.your-domain
192.168.0.69  files.your-domain
192.168.0.69  music.your-domain
192.168.0.69  books.your-domain
```

Open them as `http://chat.your-domain:8443` — plain HTTP, so the browser will
warn. That is expected; the certificate lives on the VPS.

**Give the phone a DHCP reservation on your router.** If its address moves, every
line above silently points at the wrong machine.

## 3. Bulk file transfer: use Syncthing, not WebDAV

For moving a large folder, `ENABLE_SYNCTHING=true` is the right tool. It is
peer-to-peer, it finds the phone on the LAN by itself, it resumes, and it has no
size limits or proxies in the way.

Its GUI is loopback-only by design:

```bash
ssh -p 8022 -i <key> -L 8384:127.0.0.1:8384 <phone>
# then open http://localhost:8384
```

## 4. If you do map DUFS as a network drive

Windows' built-in WebDAV client is workable but has sharp edges, and its failure
mode is a **hang at 100%** rather than a message:

- **It refuses Basic auth over plain HTTP.** Over the LAN there is no TLS, so a
  `\\192.168.0.69@8443\` mapping will not authenticate until
  `HKLM\SYSTEM\CurrentControlSet\Services\WebClient\Parameters\BasicAuthLevel`
  is set to `2`. That sends your password unencrypted over the LAN — acceptable
  on a network you control, not on one you do not.
- **Default per-file ceiling is ~50 MB**
  (`...\Parameters\FileSizeLimitInBytes`). Raise it for real files.
- **Restart the `WebClient` service** after either change.

Over the VPS path (HTTPS) neither applies, and mapping just works:
`\\files.your-domain@SSL\DavWWWRoot`.

### The edge must not cap the body size

If the VPS Caddyfile carries a `request_body max_size`, a larger upload is
rejected with **413 — after the client has already streamed the entire file**.
Windows reports that as "There is a problem accessing…" with no size mentioned,
so it reads as a network fault.

`scripts/ops/vps-setup.sh` therefore gives `files.` its own vhost with **no body
cap** and a patient `response_header_timeout`, because a large PUT can spend
minutes being written to the phone's storage before any response is due. Matrix
media has its own limit inside conduwuit; the edge does not need to guess one on
the file server's behalf.

Symptom to recognise, from a real incident in this deployment:

```
PUT  413  dur=31.9s  /buffer/<file>
```

33 uploads died that way before the cap was found.

## 5. Quick check

```bash
# from another machine on the LAN — no VPS involved
curl -s -o /dev/null -w "%{http_code}\n" \
  -H "Host: chat.your-domain" http://192.168.0.69:8443/
```

`200` means the phone is serving your LAN directly. Stop the VPS and it should
still answer.

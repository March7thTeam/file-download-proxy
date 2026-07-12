# Deployment runbook

The examples below install the application at `/opt/file-download-proxy`, run
it as an unprivileged account, and expose it through Nginx.

## Install

```bash
sudo useradd --system --home /opt/file-download-proxy --shell /usr/sbin/nologin fileproxy
sudo install -d -o fileproxy -g fileproxy /opt/file-download-proxy
sudo python3 -m venv /opt/file-download-proxy/venv
sudo /opt/file-download-proxy/venv/bin/pip install -r /opt/file-download-proxy/requirements.txt
```

Create `/etc/file-download-proxy.env` with mode `0600`:

```dotenv
PROXY_TOKEN=replace-with-output-from-openssl-rand
REQUIRE_PROXY_TOKEN=true
MAX_FILE_SIZE=4294967296
CHUNK_SIZE=1048576
MAX_REDIRECTS=5
ALLOWED_HOSTS=
```

Generate the token with `openssl rand -hex 32`. Copy
`deploy/file-proxy.service` to `/etc/systemd/system/`, then run:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now file-proxy
curl -fsS http://127.0.0.1:8794/health
```

## Nginx and TLS

Adapt `deploy/nginx.conf`, enable only that site, and validate before reloading:

```bash
sudo nginx -t
sudo systemctl reload nginx
sudo certbot --nginx -d proxy.example.com
```

`merge_slashes off` is important for the `/https://host/path` compatibility
form. Buffering is disabled so Nginx does not spool downloads to disk.

## Verification

```bash
curl -fsS https://proxy.example.com/health
curl -I -H "x-proxy-token: $PROXY_TOKEN" \
  https://proxy.example.com/https/github.com
curl -I -H "Range: bytes=0-1023" -H "x-proxy-token: $PROXY_TOKEN" \
  https://proxy.example.com/https/github.com/owner/repo/archive/refs/heads/main.zip
curl -i -H "x-proxy-token: $PROXY_TOKEN" \
  https://proxy.example.com/http/127.0.0.1/
curl -i -H "x-proxy-token: $PROXY_TOKEN" \
  https://proxy.example.com/https/example.com/
```

The last two requests must be rejected. Never print the production token in
deployment logs or command transcripts.

For a public direct-link deployment, set `REQUIRE_PROXY_TOKEN=false` only after
accepting the bandwidth risk. In that mode the host allowlist and SSRF controls
remain mandatory, and the token query name is treated as ordinary upstream
query data.

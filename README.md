# File Download Proxy

A small FastAPI service for forwarding large downloads from an explicit host
allowlist. It streams bytes directly from the upstream response, supports
`Range` and `HEAD`, and rejects private or otherwise non-public network targets
after DNS resolution.

This is deliberately not a general-purpose web proxy. The public template
requires a token by default, and every redirect is checked against the same
host and IP policy. Operators can explicitly disable token authentication for
browser-friendly direct links while retaining the narrow allowlist.

## URL forms

The service accepts both compact and full-URL path forms:

```text
https://proxy.example.com/https/github.com/owner/repo/releases/download/v1/file.zip
https://proxy.example.com/https://github.com/owner/repo/releases/download/v1/file.zip
```

The equivalent `http` forms are available for allowlisted hosts that do not
provide HTTPS. The legacy `/proxy?url=...` and `/url?url=...` endpoints return
`410 Gone` by design.

With the default configuration, prefer sending the token in a header so it does
not appear in URLs:

```bash
curl -fL \
  -H "x-proxy-token: $PROXY_TOKEN" \
  "https://proxy.example.com/https/github.com/owner/repo/archive/refs/heads/main.zip" \
  -o project.zip
```

Query authentication is also supported:

```text
https://proxy.example.com/https/github.com/file.zip?token=TOKEN
```

When authentication is enabled, the `token` parameter is consumed by the proxy
and is not forwarded upstream. Other query parameters keep their original
order and encoding.

## What is enforced

- `http` and `https` are the only accepted schemes.
- URL credentials such as `user:password@host` are rejected.
- Hosts must be listed in `ALLOWED_HOSTS` or supplied through the optional
  `ALLOWED_HOSTS` environment variable.
- DNS answers are rejected if any address is private, loopback, link-local,
  multicast, reserved, or unspecified.
- Redirects are followed manually and revalidated, up to five hops.
- Downloads default to a 4 GiB maximum and never use a temporary file.
- Token authentication is enabled by default. A missing server-side
  `PROXY_TOKEN` then fails closed with HTTP 503.

See [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md) for the trust boundaries
and [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for a systemd and Nginx deployment.

## Local development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
export PROXY_TOKEN="$(openssl rand -hex 32)"
export REQUIRE_PROXY_TOKEN=true
uvicorn app:app --host 127.0.0.1 --port 8794
```

On PowerShell, activate with `.venv\Scripts\Activate.ps1` and set the token
with `$env:PROXY_TOKEN = "..."`.

Run the checks with:

```bash
python -m py_compile app.py
pytest -q
```

## License

The source code is available under the [MIT License](LICENSE).

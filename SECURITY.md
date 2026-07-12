# Security Policy

## Reporting a vulnerability

Please open a private GitHub security advisory for vulnerabilities involving
authentication bypass, SSRF, redirect validation, DNS handling, or size-limit
enforcement. Do not include live tokens, private hostnames, or production logs
in a public issue.

## Deployment expectations

The strongest deployment mode uses a non-empty, unpredictable `PROXY_TOKEN`, a
narrow host allowlist, and a Uvicorn listener bound to loopback behind a
configured reverse proxy. Treat the included deployment files as examples and
review them for the target host.

Setting `REQUIRE_PROXY_TOKEN=false` intentionally permits unauthenticated direct
links, but it does not disable the allowlist, DNS/IP checks, redirect checks, or
size limit. Use that compatibility mode only when its public bandwidth and abuse
risk are acceptable.

Rotate the token immediately if it is placed in a URL that may have been logged
or shared. Header authentication is preferred for routine use.

## Supported versions

Only the latest commit on the default branch receives security fixes.

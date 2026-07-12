# Security model

The proxy accepts an untrusted target URL and therefore treats URL parsing,
name resolution, redirects, and response streaming as security boundaries.

## Request gate

1. When `REQUIRE_PROXY_TOKEN` is enabled, the caller presents `PROXY_TOKEN`
   through `x-proxy-token` or the `token` query parameter.
2. The URL parser allows only `http` or `https` and rejects embedded user info.
3. The normalized hostname must match an exact allowlist entry or one of its
   subdomains.
4. Every DNS result is inspected. A single non-public result rejects the
   request instead of selecting another address.
5. Each redirect returns to steps 2 through 4 before the next request is sent.

This blocks common loopback, RFC1918, link-local, metadata, IPv6-local, and
redirect-based rebinding paths. Keep in mind that DNS is resolved once for
validation and again by the HTTP transport. For especially hostile networks,
combine this application policy with host-level egress filtering.

## Data path

The application forwards `Range` and `If-Range`, preserves download-relevant
headers, and yields chunks from the upstream socket. It does not persist the
payload. A known upstream size over `MAX_FILE_SIZE` is rejected before the body
is returned. An upstream that omits all size headers is terminated when the
stream reaches the configured limit.

## Allowlist maintenance

Prefer exact distribution hosts. Avoid broad storage suffixes such as
`*.amazonaws.com`, `*.cloudfront.net`, and `*.storage.googleapis.com`; those can
turn a narrow download helper into a near-public proxy. New environment entries
are additive and still pass the DNS/IP checks.

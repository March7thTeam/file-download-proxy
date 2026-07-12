import ipaddress
import os
import secrets
import socket
from contextlib import asynccontextmanager
from pathlib import PurePosixPath
from typing import AsyncIterator
from urllib.parse import quote, unquote, unquote_plus, urlparse

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse


SERVICE_NAME = "march7th-download-proxy"

# Whitelist lives here so it is easy to edit later.
ALLOWED_HOSTS = {
    "github.com",
    "raw.githubusercontent.com",
    "gist.githubusercontent.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
    "codeload.github.com",
    "gitlab.com",
    "packages.gitlab.com",
    "sourceforge.net",
    "downloads.sourceforge.net",
    "master.dl.sourceforge.net",
    "fosshub.com",
    "download.fosshub.com",
    "downloads.apache.org",
    "archive.apache.org",
    "dlcdn.apache.org",
    "ftp.gnu.org",
    "alpha.gnu.org",
    "kernel.org",
    "cdn.kernel.org",
    "mirrors.edge.kernel.org",
    "downloads.openwrt.org",
    "www.python.org",
    "python.org",
    "pypi.org",
    "files.pythonhosted.org",
    "bootstrap.pypa.io",
    "nodejs.org",
    "registry.npmjs.org",
    "classic.yarnpkg.com",
    "repo.yarnpkg.com",
    "deno.land",
    "dl.deno.land",
    "crates.io",
    "static.crates.io",
    "static.rust-lang.org",
    "index.crates.io",
    "go.dev",
    "proxy.golang.org",
    "sum.golang.org",
    "dl.google.com",
    "repo.maven.apache.org",
    "repo1.maven.org",
    "search.maven.org",
    "plugins.gradle.org",
    "services.gradle.org",
    "downloads.gradle.org",
    "repo.anaconda.com",
    "conda.anaconda.org",
    "anaconda.org",
    "huggingface.co",
    "hf.co",
    "cdn-lfs.huggingface.co",
    "cdn-lfs-us-1.huggingface.co",
    "cdn-lfs-eu-1.huggingface.co",
    "transfer.xethub.hf.co",
    "cas-bridge.xethub.hf.co",
    "cas-server.xethub.hf.co",
    "download.jetbrains.com",
    "download-cdn.jetbrains.com",
    "download.visualstudio.microsoft.com",
    "update.code.visualstudio.com",
    "vscode.download.prss.microsoft.com",
    "download.microsoft.com",
    "go.microsoft.com",
    "aka.ms",
    "download.sysinternals.com",
    "download.docker.com",
    "desktop.docker.com",
    "registry-1.docker.io",
    "auth.docker.io",
    "production.cloudflare.docker.com",
    "pkg.cloudflare.com",
    "download.mozilla.org",
    "archive.mozilla.org",
    "ftp.mozilla.org",
    "edgedl.me.gvt1.com",
    "redirector.gvt1.com",
    "msedge.sf.dl.delivery.mp.microsoft.com",
    "releases.ubuntu.com",
    "cdimage.ubuntu.com",
    "archive.ubuntu.com",
    "security.ubuntu.com",
    "ports.ubuntu.com",
    "deb.debian.org",
    "security.debian.org",
    "cdimage.debian.org",
    "snapshot.debian.org",
    "dl-cdn.alpinelinux.org",
    "geo.mirror.pkgbuild.com",
    "archive.archlinux.org",
    "download.fedoraproject.org",
    "dl.fedoraproject.org",
    "mirror.stream.centos.org",
    "download.rockylinux.org",
    "repo.almalinux.org",
    "us.download.nvidia.com",
    "international.download.nvidia.com",
    "drivers.amd.com",
    "downloadmirror.intel.com",
    "archive.org",
    "ia801009.us.archive.org",
    "ia801509.us.archive.org",
    "ia800905.us.archive.org",
    "march7th.cn",
    "luomo.moe",
}

ALLOWED_HOSTS.update(
    host.strip().rstrip(".").lower()
    for host in os.environ.get("ALLOWED_HOSTS", "").split(",")
    if host.strip()
)

PROXY_TOKEN = os.environ.get("PROXY_TOKEN", "")
REQUIRE_PROXY_TOKEN = os.environ.get("REQUIRE_PROXY_TOKEN", "true").strip().lower() not in {
    "0",
    "false",
    "no",
    "off",
}
MAX_FILE_SIZE = int(os.environ.get("MAX_FILE_SIZE", str(4 * 1024 * 1024 * 1024)))
CHUNK_SIZE = int(os.environ.get("CHUNK_SIZE", str(1024 * 1024)))
MAX_REDIRECTS = min(int(os.environ.get("MAX_REDIRECTS", "5")), 5)

HOP_BY_HOP_HEADERS = {
    "connection",
    "transfer-encoding",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "trailers",
    "upgrade",
}

PASSTHROUGH_RESPONSE_HEADERS = {
    "content-type",
    "content-length",
    "content-range",
    "accept-ranges",
    "etag",
    "last-modified",
    "content-disposition",
    "cache-control",
}


def is_allowed_host(hostname: str) -> bool:
    host = hostname.rstrip(".").lower()
    return any(host == allowed or host.endswith("." + allowed) for allowed in ALLOWED_HOSTS)


def require_proxy_token(request: Request) -> None:
    if not REQUIRE_PROXY_TOKEN:
        return
    if not PROXY_TOKEN:
        raise HTTPException(status_code=503, detail="Proxy token is not configured")

    candidates = (request.query_params.get("token"), request.headers.get("x-proxy-token"))
    if not any(candidate and secrets.compare_digest(candidate, PROXY_TOKEN) for candidate in candidates):
        raise HTTPException(
            status_code=401,
            detail="Missing or invalid proxy token",
            headers={"WWW-Authenticate": "Bearer"},
        )


def is_forbidden_ip(raw_ip: str) -> bool:
    ip = ipaddress.ip_address(raw_ip)
    if getattr(ip, "ipv4_mapped", None):
        return is_forbidden_ip(str(ip.ipv4_mapped))
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def validate_dns_ips(hostname: str) -> None:
    try:
        literal_ip = ipaddress.ip_address(hostname)
    except ValueError:
        literal_ip = None
    if literal_ip is not None and is_forbidden_ip(str(literal_ip)):
        raise HTTPException(status_code=403, detail="Target IP is forbidden")

    try:
        infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise HTTPException(status_code=400, detail="Cannot resolve target hostname")

    ips = {info[4][0] for info in infos}
    if not ips:
        raise HTTPException(status_code=400, detail="Cannot resolve target hostname")
    if any(is_forbidden_ip(ip) for ip in ips):
        raise HTTPException(status_code=403, detail="Target resolves to a forbidden IP")


def validate_target_url(raw_url: str) -> str:
    parsed = urlparse(raw_url)
    if parsed.scheme not in {"http", "https"}:
        raise HTTPException(status_code=400, detail="Only http and https URLs are allowed")
    if not parsed.hostname:
        raise HTTPException(status_code=400, detail="Target URL must include a hostname")
    if parsed.username or parsed.password:
        raise HTTPException(status_code=400, detail="Credentials in URL are not allowed")
    if not is_allowed_host(parsed.hostname):
        raise HTTPException(status_code=403, detail="Target hostname is not in the whitelist")
    validate_dns_ips(parsed.hostname)
    return raw_url


def parse_total_size(headers: httpx.Headers) -> int | None:
    content_range = headers.get("content-range")
    if content_range and "/" in content_range:
        total = content_range.rsplit("/", 1)[1].strip()
        if total.isdigit():
            return int(total)

    content_length = headers.get("content-length")
    if content_length and content_length.isdigit():
        return int(content_length)
    return None


def sanitize_range(value: str | None) -> str | None:
    if not value:
        return None
    value = value.strip()
    if not value.lower().startswith("bytes="):
        raise HTTPException(status_code=400, detail="Only bytes Range requests are supported")
    return value


def build_content_disposition(target_url: str) -> str:
    path = urlparse(target_url).path
    name = PurePosixPath(unquote(path)).name or "download"
    safe_ascii = "".join(c if 32 <= ord(c) < 127 and c not in {'"', "\\"} else "_" for c in name)
    if not safe_ascii or safe_ascii == ".":
        safe_ascii = "download"
    return f'attachment; filename="{safe_ascii}"; filename*=UTF-8\'\'{quote(name)}'


def response_headers_from_upstream(headers: httpx.Headers, target_url: str) -> dict[str, str]:
    out: dict[str, str] = {}
    seen: set[str] = set()
    for name, value in headers.items():
        lower = name.lower()
        if lower in PASSTHROUGH_RESPONSE_HEADERS and lower not in HOP_BY_HOP_HEADERS and lower not in seen:
            out[name] = value
            seen.add(lower)
    if "accept-ranges" not in seen:
        out["Accept-Ranges"] = "bytes"
    if "content-disposition" not in seen:
        out["Content-Disposition"] = build_content_disposition(target_url)
    out["X-Content-Type-Options"] = "nosniff"
    return out


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    app.state.client = httpx.AsyncClient(
        timeout=httpx.Timeout(connect=10.0, read=60.0, write=10.0, pool=10.0),
        follow_redirects=False,
        http2=True,
        headers={"User-Agent": f"{SERVICE_NAME}/2.0"},
    )
    try:
        yield
    finally:
        await app.state.client.aclose()


app = FastAPI(title=SERVICE_NAME, lifespan=lifespan)


@app.get("/")
async def index() -> dict[str, object]:
    return {
        "service": SERVICE_NAME,
        "purpose": "Whitelist-only streaming file download proxy.",
        "new_format": "https://proxy.march7th.cn/https/<host>/<path>",
        "examples": [
            "https://proxy.march7th.cn/https/github.com/owner/repo/releases/download/v1.0/file.zip",
            "https://proxy.march7th.cn/http/example.allowed.host/path/file.zip",
        ],
        "deprecated": ["/proxy?url=<encoded_url>", "/url?url=<encoded_url>"],
    }


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": SERVICE_NAME}


def deprecated_endpoint() -> JSONResponse:
    return JSONResponse(
        status_code=410,
        content={
            "error": "deprecated_endpoint",
            "message": "This endpoint has been deprecated. Use /https/<host>/<path> instead.",
            "example": "https://proxy.march7th.cn/https/github.com/owner/repo/releases/download/v1.0/file.zip",
        },
    )


@app.get("/proxy")
@app.head("/proxy")
@app.get("/url")
@app.head("/url")
async def deprecated_proxy() -> JSONResponse:
    return deprecated_endpoint()


async def request_with_redirects(
    client: httpx.AsyncClient,
    method: str,
    target_url: str,
    headers: dict[str, str],
    *,
    stream: bool,
) -> httpx.Response:
    current_url = validate_target_url(target_url)
    current_method = method
    current_headers = dict(headers)

    for _ in range(MAX_REDIRECTS + 1):
        if stream:
            request = client.build_request(current_method, current_url, headers=current_headers)
            response = await client.send(request, stream=True)
        else:
            response = await client.request(current_method, current_url, headers=current_headers)

        if response.status_code not in {301, 302, 303, 307, 308}:
            return response

        location = response.headers.get("location")
        await response.aclose()
        if not location:
            raise HTTPException(status_code=502, detail="Upstream redirect has no Location header")

        current_url = str(httpx.URL(current_url).join(location))
        current_url = validate_target_url(current_url)
        if response.status_code == 303:
            current_method = "GET"
            current_headers.pop("Range", None)

    raise HTTPException(status_code=508, detail="Too many redirects")


async def proxy_download_url(request: Request, target_url: str, method: str = "GET"):
    require_proxy_token(request)
    target_url = validate_target_url(target_url)
    range_header = sanitize_range(request.headers.get("range"))
    upstream_headers = {"Accept-Encoding": "identity"}
    if range_header:
        upstream_headers["Range"] = range_header
    if if_range := request.headers.get("if-range"):
        upstream_headers["If-Range"] = if_range

    client: httpx.AsyncClient = request.app.state.client

    if method == "HEAD":
        probe_method = "GET" if range_header else "HEAD"
        upstream = await request_with_redirects(client, probe_method, target_url, upstream_headers, stream=bool(range_header))
        try:
            total_size = parse_total_size(upstream.headers)
            if total_size is not None and total_size > MAX_FILE_SIZE:
                raise HTTPException(status_code=413, detail="File exceeds configured maximum size")
            headers = response_headers_from_upstream(upstream.headers, target_url)
            return Response(status_code=upstream.status_code, headers=headers)
        finally:
            await upstream.aclose()

    head = await request_with_redirects(client, "HEAD", target_url, upstream_headers, stream=False)
    try:
        if head.status_code < 400:
            total_size = parse_total_size(head.headers)
            if total_size is not None and total_size > MAX_FILE_SIZE:
                raise HTTPException(status_code=413, detail="File exceeds configured maximum size")
    finally:
        await head.aclose()

    upstream = await request_with_redirects(client, "GET", target_url, upstream_headers, stream=True)
    if upstream.status_code >= 400:
        body = await upstream.aread()
        status = upstream.status_code
        await upstream.aclose()
        detail = body[:512].decode("utf-8", errors="replace") if body else f"Upstream returned HTTP {status}"
        return JSONResponse(status_code=status, content={"detail": detail})

    total_size = parse_total_size(upstream.headers)
    if total_size is not None and total_size > MAX_FILE_SIZE:
        await upstream.aclose()
        raise HTTPException(status_code=413, detail="File exceeds configured maximum size")

    headers = response_headers_from_upstream(upstream.headers, target_url)

    async def body_iter() -> AsyncIterator[bytes]:
        sent = 0
        try:
            async for chunk in upstream.aiter_bytes(CHUNK_SIZE):
                sent += len(chunk)
                if total_size is None and sent > MAX_FILE_SIZE:
                    break
                yield chunk
                if await request.is_disconnected():
                    break
        finally:
            await upstream.aclose()

    return StreamingResponse(
        body_iter(),
        status_code=upstream.status_code,
        headers=headers,
        media_type=upstream.headers.get("content-type") or "application/octet-stream",
    )


def target_query_string(request: Request) -> str:
    raw_query = request.scope.get("query_string", b"").decode("latin-1")
    parts = []
    for part in raw_query.split("&"):
        if not part:
            continue
        raw_key = part.partition("=")[0]
        if not REQUIRE_PROXY_TOKEN or unquote_plus(raw_key) != "token":
            parts.append(part)
    return "&".join(parts)


def target_from_path(request: Request, scheme: str, target_path: str) -> str:
    # A leading slash appears when the client uses /https://host/path.
    target_url = f"{scheme}://{target_path.lstrip('/')}"
    if query := target_query_string(request):
        target_url += "?" + query
    return target_url


@app.get("/https/{target_path:path}")
@app.head("/https/{target_path:path}")
async def https_proxy(request: Request, target_path: str):
    return await proxy_download_url(request, target_from_path(request, "https", target_path), request.method)


@app.get("/http/{target_path:path}")
@app.head("/http/{target_path:path}")
async def http_proxy(request: Request, target_path: str):
    return await proxy_download_url(request, target_from_path(request, "http", target_path), request.method)


def normalize_raw_target(raw_target: str) -> str | None:
    if raw_target.startswith("https://") or raw_target.startswith("http://"):
        return raw_target
    if raw_target.startswith("https:/"):
        return "https://" + raw_target[len("https:/"):].lstrip("/")
    if raw_target.startswith("http:/"):
        return "http://" + raw_target[len("http:/"):].lstrip("/")
    return None


@app.api_route("/{raw_target:path}", methods=["GET", "HEAD"])
async def full_url_proxy(request: Request, raw_target: str):
    target_url = normalize_raw_target(raw_target)
    if target_url is None:
        raise HTTPException(status_code=404, detail="Not found")
    if query := target_query_string(request):
        target_url += "?" + query
    return await proxy_download_url(request, target_url, request.method)

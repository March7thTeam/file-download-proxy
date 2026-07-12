import httpx
from fastapi.testclient import TestClient

import app as proxy


def upstream_response(status_code=200, headers=None):
    return httpx.Response(
        status_code,
        headers=headers or {"Content-Length": "128", "Content-Type": "application/octet-stream"},
        request=httpx.Request("HEAD", "https://github.com/file.zip"),
    )


def test_health_and_deprecated_endpoints():
    with TestClient(proxy.app) as client:
        assert client.get("/health").json() == {
            "status": "ok",
            "service": "march7th-download-proxy",
        }
        assert client.get("/proxy").status_code == 410
        assert client.head("/url").status_code == 410


def test_download_requires_a_configured_valid_token(monkeypatch):
    monkeypatch.setattr(proxy, "REQUIRE_PROXY_TOKEN", True)
    monkeypatch.setattr(proxy, "PROXY_TOKEN", "")
    with TestClient(proxy.app) as client:
        assert client.head("/https/github.com/file.zip").status_code == 503

    monkeypatch.setattr(proxy, "PROXY_TOKEN", "secret")
    with TestClient(proxy.app) as client:
        assert client.head("/https/github.com/file.zip").status_code == 401
        assert client.head(
            "/https/github.com/file.zip", headers={"x-proxy-token": "wrong"}
        ).status_code == 401


def test_both_path_forms_preserve_query_without_forwarding_token(monkeypatch):
    monkeypatch.setattr(proxy, "REQUIRE_PROXY_TOKEN", True)
    monkeypatch.setattr(proxy, "PROXY_TOKEN", "secret")
    monkeypatch.setattr(proxy, "validate_dns_ips", lambda hostname: None)
    seen = []

    async def fake_request(client, method, target_url, headers, *, stream):
        seen.append((method, target_url, headers, stream))
        return upstream_response()

    monkeypatch.setattr(proxy, "request_with_redirects", fake_request)

    with TestClient(proxy.app) as client:
        compact = client.head(
            "/https/github.com/file.zip?download=1&token=secret&name=a%2Fb"
        )
        full = client.head(
            "/https://github.com/file.zip?token=secret&download=2"
        )

    assert compact.status_code == 200
    assert full.status_code == 200
    assert seen[0][1] == "https://github.com/file.zip?download=1&name=a%2Fb"
    assert seen[1][1] == "https://github.com/file.zip?download=2"


def test_header_token_and_range_are_forwarded(monkeypatch):
    monkeypatch.setattr(proxy, "REQUIRE_PROXY_TOKEN", True)
    monkeypatch.setattr(proxy, "PROXY_TOKEN", "secret")
    monkeypatch.setattr(proxy, "validate_dns_ips", lambda hostname: None)
    seen = []

    async def fake_request(client, method, target_url, headers, *, stream):
        seen.append((method, target_url, headers, stream))
        return upstream_response(
            206,
            {
                "Content-Length": "1024",
                "Content-Range": "bytes 0-1023/4096",
                "Accept-Ranges": "bytes",
            },
        )

    monkeypatch.setattr(proxy, "request_with_redirects", fake_request)

    with TestClient(proxy.app) as client:
        response = client.request(
            "HEAD",
            "/https/github.com/file.zip",
            headers={"x-proxy-token": "secret", "Range": "bytes=0-1023"},
        )

    assert response.status_code == 206
    assert seen[0][0] == "GET"
    assert seen[0][2]["Range"] == "bytes=0-1023"
    assert seen[0][3] is True


def test_non_allowlisted_and_private_targets_are_rejected(monkeypatch):
    monkeypatch.setattr(proxy, "REQUIRE_PROXY_TOKEN", True)
    monkeypatch.setattr(proxy, "PROXY_TOKEN", "secret")
    with TestClient(proxy.app) as client:
        assert client.head(
            "/https/example.com/", headers={"x-proxy-token": "secret"}
        ).status_code == 403
        assert client.head(
            "/http/127.0.0.1/", headers={"x-proxy-token": "secret"}
        ).status_code == 403

    assert proxy.is_forbidden_ip("127.0.0.1")
    assert proxy.is_forbidden_ip("169.254.169.254")
    assert proxy.is_forbidden_ip("::1")
    assert not proxy.is_forbidden_ip("1.1.1.1")


def test_default_file_limit_is_four_gibibytes():
    assert proxy.MAX_FILE_SIZE == 4 * 1024 * 1024 * 1024


def test_compatibility_mode_keeps_token_named_upstream_query(monkeypatch):
    monkeypatch.setattr(proxy, "REQUIRE_PROXY_TOKEN", False)
    seen = []

    async def fake_proxy(request, target_url, method="GET"):
        seen.append(target_url)
        return proxy.Response(status_code=204)

    monkeypatch.setattr(proxy, "proxy_download_url", fake_proxy)
    with TestClient(proxy.app) as client:
        response = client.head("/https/github.com/file.zip?token=upstream-value")

    assert response.status_code == 204
    assert seen == ["https://github.com/file.zip?token=upstream-value"]

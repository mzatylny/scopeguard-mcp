import hashlib
import socket

import pytest

from scopeguard_mcp.analyzers import network
from scopeguard_mcp.analyzers.network import ResolvedEndpoint
from scopeguard_mcp.errors import AuthorizationError, NetworkProbeError


class FakeSocket:
    def __init__(self):
        self.sent = b""
        self.closed = False

    def sendall(self, data):
        self.sent += data

    def close(self):
        self.closed = True


def test_resolver_requires_hostname_and_network_allowlists(monkeypatch):
    monkeypatch.setattr(
        network.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.10", 443))],
    )
    endpoint = network.resolve_allowed_endpoint(
        "app.example.com",
        443,
        allowed_hosts=("*.example.com",),
        allowed_networks=("192.0.2.0/24",),
    )
    assert endpoint.selected_address == "192.0.2.10"

    with pytest.raises(AuthorizationError, match="ALLOWED_HOSTS"):
        network.resolve_allowed_endpoint(
            "other.example.net",
            443,
            allowed_hosts=("*.example.com",),
            allowed_networks=("192.0.2.0/24",),
        )
    with pytest.raises(AuthorizationError, match="ALLOWED_NETWORKS"):
        network.resolve_allowed_endpoint(
            "app.example.com",
            443,
            allowed_hosts=("*.example.com",),
            allowed_networks=(),
        )


def test_resolver_rejects_mixed_dns_answers_and_bad_inputs(monkeypatch):
    monkeypatch.setattr(
        network.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.10", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.8", 443)),
        ],
    )
    with pytest.raises(AuthorizationError, match="resolved address"):
        network.resolve_allowed_endpoint(
            "app.example.com",
            443,
            allowed_hosts=("app.example.com",),
            allowed_networks=("192.0.2.0/24",),
        )
    with pytest.raises(NetworkProbeError, match="port"):
        network.resolve_allowed_endpoint(
            "127.0.0.1", 0, allowed_hosts=(), allowed_networks=("127.0.0.0/8",)
        )


def test_resolver_handles_ip_and_resolution_failure(monkeypatch):
    endpoint = network.resolve_allowed_endpoint(
        "127.0.0.1", 80, allowed_hosts=(), allowed_networks=("127.0.0.0/8",)
    )
    assert endpoint.addresses == ("127.0.0.1",)

    def fail(*args, **kwargs):
        raise socket.gaierror

    monkeypatch.setattr(network.socket, "getaddrinfo", fail)
    with pytest.raises(NetworkProbeError, match="resolution failed"):
        network.resolve_allowed_endpoint(
            "localhost.example",
            443,
            allowed_hosts=("localhost.example",),
            allowed_networks=("127.0.0.0/8",),
        )


def test_http_probe_sends_head_and_does_not_follow_redirect(monkeypatch):
    fake_socket = FakeSocket()
    monkeypatch.setattr(network, "_connect", lambda endpoint, timeout: fake_socket)

    class FakeResponse:
        status = 302
        reason = "Found"

        def __init__(self, connection, method):
            assert connection is fake_socket
            assert method == "HEAD"

        def begin(self):
            return None

        def getheaders(self):
            return [
                ("Location", "https://user:secret@elsewhere.example/next?token=secret#part"),
                ("X-Test", "one"),
                ("Set-Cookie", "session=do-not-return; Secure; HttpOnly; SameSite=Lax"),
            ]

    monkeypatch.setattr(network, "HTTPResponse", FakeResponse)
    endpoint = ResolvedEndpoint("example.com", 80, ("192.0.2.10",), "192.0.2.10")
    result = network.probe_http_head("http://example.com/path", endpoint, timeout=1)
    assert fake_socket.sent.startswith(b"HEAD /path HTTP/1.1\r\n")
    assert result["status"] == 302
    assert result["redirect_followed"] is False
    assert result["headers"]["location"] == "https://elsewhere.example/next"
    assert result["headers"]["set-cookie"] == "[redacted]; Secure; HttpOnly; SameSite=Lax"
    assert fake_socket.closed is True


def test_http_probe_rejects_endpoint_mismatch():
    endpoint = ResolvedEndpoint("example.com", 80, ("192.0.2.10",), "192.0.2.10")
    with pytest.raises(NetworkProbeError, match="does not match"):
        network.probe_http_head("http://other.example/", endpoint, timeout=1)


def test_sensitive_response_headers_are_redacted():
    assert network._redact_header("authorization", "Bearer secret") == "[redacted]"
    assert network._redact_header("x-api-key", "secret") == "[redacted]"
    assert network._redact_header("x-session-token", "secret") == "[redacted]"
    cookie = network._redact_header(
        "set-cookie",
        "id=secret; Secure; HttpOnly; SameSite=Strict; Extension-Value=also-secret",
    )
    assert cookie == "[redacted]; Secure; HttpOnly; SameSite=Strict"
    assert "also-secret" not in cookie
    assert network._redact_header("server", "scopeguard-test") == "scopeguard-test"


def test_tls_inspection_returns_bounded_metadata(monkeypatch):
    class FakeTLS(FakeSocket):
        def getpeercert(self, binary_form=False):
            if binary_form:
                return b"certificate"
            return {
                "notBefore": "Jan 1 00:00:00 2026 GMT",
                "notAfter": "Jan 1 00:00:00 2027 GMT",
                "subjectAltName": (("DNS", "example.com"), ("IP Address", "192.0.2.10")),
            }

        def cipher(self):
            return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

        def version(self):
            return "TLSv1.3"

    tls_socket = FakeTLS()
    monkeypatch.setattr(network, "_tls_socket", lambda endpoint, timeout: tls_socket)
    endpoint = ResolvedEndpoint("example.com", 443, ("192.0.2.10",), "192.0.2.10")
    result = network.inspect_tls_endpoint(endpoint, timeout=1)
    assert result["valid"] is True
    assert result["certificate"]["subject_alt_names"] == ["example.com"]
    assert result["certificate"]["sha256"] == hashlib.sha256(b"certificate").hexdigest()
    assert tls_socket.closed is True


def test_tcp_probe_is_bounded_and_collects_no_banners(monkeypatch):
    def connect(address, timeout):
        if address[1] == 443:
            return FakeSocket()
        raise OSError

    monkeypatch.setattr(network.socket, "create_connection", connect)
    endpoint = ResolvedEndpoint("example.com", 80, ("192.0.2.10",), "192.0.2.10")
    result = network.probe_tcp_ports(endpoint, [443, 80, 443], timeout=1, max_ports=2)
    assert result["summary"] == {"requested": 2, "open": 1}
    assert result["banner_grabbing"] is False

    with pytest.raises(NetworkProbeError, match="limited"):
        network.probe_tcp_ports(endpoint, [1, 2, 3], timeout=1, max_ports=2)
    with pytest.raises(NetworkProbeError, match="between"):
        network.probe_tcp_ports(endpoint, [0], timeout=1, max_ports=2)
    with pytest.raises(NetworkProbeError, match="integers"):
        network.probe_tcp_ports(endpoint, [True], timeout=1, max_ports=2)

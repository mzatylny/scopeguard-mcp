"""Bounded, allowlisted network posture probes without arbitrary requests or commands."""

from __future__ import annotations

import hashlib
import ipaddress
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from http.client import HTTPException, HTTPResponse
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from ..errors import AuthorizationError, NetworkProbeError

_SENSITIVE_RESPONSE_HEADERS = frozenset(
    {"authorization", "proxy-authorization", "set-cookie", "set-cookie2", "x-api-key"}
)
_SENSITIVE_HEADER_MARKERS = ("authorization", "cookie", "token", "secret", "api-key", "apikey")


@dataclass(frozen=True, slots=True)
class ResolvedEndpoint:
    host: str
    port: int
    addresses: tuple[str, ...]
    selected_address: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "addresses": list(self.addresses),
            "selected_address": self.selected_address,
        }


def _normalize_host(value: str) -> tuple[str, bool]:
    candidate = value.strip().strip("[]").rstrip(".")
    if not candidate:
        raise NetworkProbeError("network target host is empty")
    try:
        return str(ipaddress.ip_address(candidate)), True
    except ValueError:
        try:
            return candidate.encode("idna").decode("ascii").lower(), False
        except UnicodeError as exc:
            raise NetworkProbeError("network target host is invalid") from exc


def _host_allowed(host: str, patterns: tuple[str, ...]) -> bool:
    for raw_pattern in patterns:
        pattern, is_ip = _normalize_host(raw_pattern.removeprefix("*."))
        if is_ip:
            continue
        if raw_pattern.startswith("*."):
            if host.endswith("." + pattern) and host != pattern:
                return True
        elif host == pattern:
            return True
    return False


def resolve_allowed_endpoint(
    host: str,
    port: int,
    *,
    allowed_hosts: tuple[str, ...],
    allowed_networks: tuple[str, ...],
) -> ResolvedEndpoint:
    """Resolve once, then require every answer to satisfy the operator allowlist."""
    if not 1 <= port <= 65_535:
        raise NetworkProbeError("port must be between 1 and 65535")
    normalized_host, is_ip = _normalize_host(host)
    if not is_ip and not _host_allowed(normalized_host, allowed_hosts):
        raise AuthorizationError("hostname is outside SCOPEGUARD_ALLOWED_HOSTS")
    networks = tuple(ipaddress.ip_network(value) for value in allowed_networks)
    if not networks:
        raise AuthorizationError("SCOPEGUARD_ALLOWED_NETWORKS is empty")
    if is_ip:
        addresses = (normalized_host,)
    else:
        try:
            answers = socket.getaddrinfo(
                normalized_host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
            )
        except socket.gaierror as exc:
            raise NetworkProbeError("hostname resolution failed") from exc
        addresses = tuple(dict.fromkeys(answer[4][0] for answer in answers))
        if not addresses:
            raise NetworkProbeError("hostname resolution returned no addresses")
    if any(
        not any(ipaddress.ip_address(address) in network for network in networks)
        for address in addresses
    ):
        raise AuthorizationError("resolved address is outside SCOPEGUARD_ALLOWED_NETWORKS")
    return ResolvedEndpoint(normalized_host, port, addresses, addresses[0])


def _connect(endpoint: ResolvedEndpoint, timeout: float) -> socket.socket:
    try:
        return socket.create_connection((endpoint.selected_address, endpoint.port), timeout=timeout)
    except (OSError, TimeoutError) as exc:
        raise NetworkProbeError("connection failed or timed out") from exc


def _tls_socket(endpoint: ResolvedEndpoint, timeout: float) -> ssl.SSLSocket:
    raw_socket = _connect(endpoint, timeout)
    try:
        context = ssl.create_default_context()
        return context.wrap_socket(raw_socket, server_hostname=endpoint.host)
    except (OSError, TimeoutError) as exc:
        raw_socket.close()
        raise NetworkProbeError("TLS certificate or handshake validation failed") from exc


def _host_header(host: str, port: int, scheme: str) -> str:
    rendered = f"[{host}]" if ":" in host else host
    default_port = 443 if scheme == "https" else 80
    return rendered if port == default_port else f"{rendered}:{port}"


def _redact_header(name: str, value: str) -> str:
    if name == "location":
        try:
            parsed = urlsplit(value)
            hostname = parsed.hostname or ""
            rendered_host = f"[{hostname}]" if ":" in hostname else hostname
            authority = rendered_host
            if parsed.port is not None:
                authority = f"{rendered_host}:{parsed.port}"
            return urlunsplit((parsed.scheme, authority, parsed.path, "", ""))[:4096]
        except ValueError:
            return "[redacted]"
    sensitive = name in _SENSITIVE_RESPONSE_HEADERS or any(
        marker in name for marker in _SENSITIVE_HEADER_MARKERS
    )
    if not sensitive:
        return value[:4096]
    if name not in {"set-cookie", "set-cookie2"}:
        return "[redacted]"
    # Preserve only attributes needed by the offline hardening analysis. Cookie extension
    # attributes may contain arbitrary values, so every unknown attribute stays redacted.
    safe_attributes: list[str] = []
    for raw_attribute in value.split(";")[1:]:
        attribute = raw_attribute.strip()
        lowered = attribute.lower()
        if lowered == "secure":
            safe_attributes.append("Secure")
        elif lowered == "httponly":
            safe_attributes.append("HttpOnly")
        elif lowered.startswith("samesite="):
            same_site = lowered.partition("=")[2].strip()
            if same_site in {"strict", "lax", "none"}:
                safe_attributes.append(f"SameSite={same_site.title()}")
    return "; ".join(["[redacted]", *dict.fromkeys(safe_attributes)])


def probe_http_head(url: str, endpoint: ResolvedEndpoint, *, timeout: float) -> dict[str, Any]:
    """Perform one HEAD request to the pinned address and never follow redirects."""
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname != endpoint.host:
        raise NetworkProbeError("HTTP target does not match the authorized endpoint")
    connection: socket.socket | ssl.SSLSocket
    connection = (
        _tls_socket(endpoint, timeout) if parsed.scheme == "https" else _connect(endpoint, timeout)
    )
    path = parsed.path or "/"
    request = (
        f"HEAD {path} HTTP/1.1\r\n"
        f"Host: {_host_header(endpoint.host, endpoint.port, parsed.scheme)}\r\n"
        "User-Agent: ScopeGuard-MCP/0.2\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")
    try:
        connection.sendall(request)
        response = HTTPResponse(connection, method="HEAD")
        response.begin()
        grouped: dict[str, list[str]] = {}
        for name, value in response.getheaders():
            normalized_name = name.lower()
            grouped.setdefault(normalized_name, []).append(_redact_header(normalized_name, value))
        headers = {name: ", ".join(values) for name, values in grouped.items()}
        return {
            "method": "HEAD",
            "url": url,
            "status": response.status,
            "reason": response.reason,
            "headers": headers,
            "redirect_followed": False,
            "endpoint": endpoint.as_dict(),
        }
    except (HTTPException, OSError, TimeoutError) as exc:
        raise NetworkProbeError("HTTP response failed or timed out") from exc
    finally:
        connection.close()


def inspect_tls_endpoint(endpoint: ResolvedEndpoint, *, timeout: float) -> dict[str, Any]:
    """Validate one TLS handshake and return bounded certificate metadata."""
    connection = _tls_socket(endpoint, timeout)
    try:
        certificate = connection.getpeercert()
        certificate_der = connection.getpeercert(binary_form=True) or b""
        cipher = connection.cipher()
        return {
            "valid": True,
            "protocol": connection.version(),
            "cipher": cipher[0] if cipher else None,
            "certificate": {
                "not_before": certificate.get("notBefore"),
                "not_after": certificate.get("notAfter"),
                "subject_alt_names": [
                    value for kind, value in certificate.get("subjectAltName", ()) if kind == "DNS"
                ][:20],
                "sha256": hashlib.sha256(certificate_der).hexdigest(),
            },
            "endpoint": endpoint.as_dict(),
        }
    finally:
        connection.close()


def probe_tcp_ports(
    endpoint: ResolvedEndpoint,
    ports: list[int],
    *,
    timeout: float,
    max_ports: int,
) -> dict[str, Any]:
    """Attempt bounded TCP connects only; do not send data or collect banners."""
    if any(not isinstance(port, int) or isinstance(port, bool) for port in ports):
        raise NetworkProbeError("TCP ports must be integers")
    normalized_ports = sorted(set(ports))
    if not normalized_ports:
        raise NetworkProbeError("at least one TCP port is required")
    if len(normalized_ports) > max_ports:
        raise NetworkProbeError(f"TCP probe is limited to {max_ports} unique ports")
    if any(not 1 <= port <= 65_535 for port in normalized_ports):
        raise NetworkProbeError("TCP ports must be between 1 and 65535")

    def check(port: int) -> dict[str, Any]:
        started = time.monotonic()
        try:
            connection = socket.create_connection(
                (endpoint.selected_address, port), timeout=timeout
            )
        except (OSError, TimeoutError):
            state = "closed-or-filtered"
        else:
            connection.close()
            state = "open"
        return {
            "port": port,
            "state": state,
            "latency_ms": round((time.monotonic() - started) * 1000, 2),
        }

    with ThreadPoolExecutor(max_workers=min(8, len(normalized_ports))) as executor:
        results = list(executor.map(check, normalized_ports))
    return {
        "host": endpoint.host,
        "selected_address": endpoint.selected_address,
        "ports": results,
        "summary": {
            "requested": len(results),
            "open": sum(item["state"] == "open" for item in results),
        },
        "banner_grabbing": False,
    }

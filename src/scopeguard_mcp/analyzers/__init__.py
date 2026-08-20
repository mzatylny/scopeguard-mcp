"""Built-in, read-only defensive analyzers."""

from .headers import analyze_security_headers
from .network import (
    inspect_tls_endpoint,
    probe_http_head,
    probe_tcp_ports,
    resolve_allowed_endpoint,
)
from .repository import scan_repository

__all__ = [
    "analyze_security_headers",
    "inspect_tls_endpoint",
    "probe_http_head",
    "probe_tcp_ports",
    "resolve_allowed_endpoint",
    "scan_repository",
]

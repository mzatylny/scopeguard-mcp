"""Target normalization and deterministic scope matching."""

from __future__ import annotations

import ipaddress
import posixpath
import re
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit, urlunsplit

from .errors import InvalidTargetError
from .models import NormalizedTarget

_DOMAIN_RE = re.compile(
    r"^(?:\*\.)?(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    re.IGNORECASE,
)


def _normalize_domain(value: str) -> str:
    wildcard = value.startswith("*.")
    candidate = value[2:] if wildcard else value
    candidate = candidate.rstrip(".").encode("idna").decode("ascii").lower()
    if not _DOMAIN_RE.fullmatch(("*." if wildcard else "") + candidate):
        raise InvalidTargetError(f"invalid domain target: {value}")
    return ("*." if wildcard else "") + candidate


def normalize_target(raw: str, *, base_dir: Path | None = None) -> NormalizedTarget:
    if not isinstance(raw, str) or not raw.strip():
        raise InvalidTargetError("target must be a non-empty string")
    value = raw.strip()

    if value.lower().startswith("file:"):
        path_value = unquote(value[5:])
        if path_value.startswith("//"):
            path_value = path_value[2:]
        path = Path(path_value).expanduser()
        if not path.is_absolute():
            path = (base_dir or Path.cwd()) / path
        resolved = path.resolve(strict=False)
        return NormalizedTarget("file", str(resolved), f"file:{resolved}")

    if "://" in value:
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise InvalidTargetError("only absolute http and https targets are supported")
        if parsed.username or parsed.password:
            raise InvalidTargetError("target URLs must not contain credentials")
        if parsed.hostname.startswith("*."):
            raise InvalidTargetError("wildcards are supported only as domain targets")
        if _is_ip(parsed.hostname):
            address = ipaddress.ip_address(parsed.hostname)
            host = str(address)
            authority_host = f"[{host}]" if address.version == 6 else host
        else:
            host = _normalize_domain(parsed.hostname)
            authority_host = host
        try:
            port = parsed.port
        except ValueError as exc:
            raise InvalidTargetError("target URL contains an invalid port") from exc
        default_port = 80 if parsed.scheme.lower() == "http" else 443
        authority = authority_host if port in {None, default_port} else f"{authority_host}:{port}"
        decoded_path = unquote(parsed.path or "/")
        path = posixpath.normpath("/" + decoded_path.lstrip("/"))
        path = quote(path, safe="/:@-._~!$&'()*+,;=")
        normalized = urlunsplit((parsed.scheme.lower(), authority, path, "", ""))
        return NormalizedTarget("url", normalized, normalized)

    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        domain = _normalize_domain(value)
        return NormalizedTarget("domain", domain, domain)
    if "/" in value:
        canonical = str(network)
        return NormalizedTarget("network", canonical, canonical)
    address = str(network.network_address)
    return NormalizedTarget("ip", address, address)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _host_for(target: NormalizedTarget) -> str | None:
    if target.kind == "url":
        return urlsplit(target.value).hostname
    if target.kind in {"domain", "ip"}:
        return target.value
    return None


def target_in_scope(scope: NormalizedTarget, candidate: NormalizedTarget) -> bool:
    if scope.kind == "file":
        if candidate.kind != "file":
            return False
        return Path(candidate.value).is_relative_to(Path(scope.value))

    if scope.kind == "url":
        if candidate.kind != "url":
            return False
        allowed = urlsplit(scope.value)
        requested = urlsplit(candidate.value)
        allowed_path = allowed.path.rstrip("/") or "/"
        requested_path = requested.path.rstrip("/") or "/"
        path_matches = requested_path == allowed_path or requested_path.startswith(
            allowed_path.rstrip("/") + "/"
        )
        return (
            allowed.scheme == requested.scheme
            and allowed.netloc == requested.netloc
            and path_matches
        )

    if scope.kind == "network":
        host = _host_for(candidate)
        if host is None or not _is_ip(host):
            return False
        return ipaddress.ip_address(host) in ipaddress.ip_network(scope.value)

    host = _host_for(candidate)
    if host is None:
        return False
    if scope.kind == "ip":
        return host == scope.value
    if scope.value.startswith("*."):
        suffix = scope.value[1:]
        return host.endswith(suffix) and host != scope.value[2:]
    return host == scope.value


def any_scope_matches(
    scopes: tuple[str, ...], candidate: str, *, base_dir: Path | None = None
) -> tuple[bool, NormalizedTarget]:
    normalized_candidate = normalize_target(candidate, base_dir=base_dir)
    for raw_scope in scopes:
        if target_in_scope(normalize_target(raw_scope, base_dir=base_dir), normalized_candidate):
            return True, normalized_candidate
    return False, normalized_candidate

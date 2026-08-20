"""Operator-controlled configuration for ScopeGuard."""

from __future__ import annotations

import hashlib
import ipaddress
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from .errors import ConfigurationError

_HOST_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)


def _parse_bool(value: str, name: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ConfigurationError(f"{name} must be true or false")


def _parse_positive_int(value: str, name: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be a positive integer") from exc
    if parsed <= 0:
        raise ConfigurationError(f"{name} must be a positive integer")
    return parsed


def _parse_bounded_int(value: str, name: str, *, maximum: int) -> int:
    parsed = _parse_positive_int(value, name)
    if parsed > maximum:
        raise ConfigurationError(f"{name} must not exceed {maximum}")
    return parsed


def _parse_timeout(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise ConfigurationError("SCOPEGUARD_NETWORK_TIMEOUT_SECONDS must be a number") from exc
    if not 0.1 <= parsed <= 10:
        raise ConfigurationError("SCOPEGUARD_NETWORK_TIMEOUT_SECONDS must be between 0.1 and 10")
    return parsed


def _parse_csv(value: str | None) -> tuple[str, ...]:
    if not value:
        return ()
    return tuple(item.strip() for item in value.split(",") if item.strip())


def _parse_hosts(value: str | None) -> tuple[str, ...]:
    hosts: list[str] = []
    for item in _parse_csv(value):
        wildcard = item.startswith("*.")
        candidate = item[2:] if wildcard else item
        if "*" in candidate:
            raise ConfigurationError(
                f"SCOPEGUARD_ALLOWED_HOSTS contains an invalid wildcard: {item}"
            )
        try:
            candidate = candidate.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ConfigurationError(
                f"SCOPEGUARD_ALLOWED_HOSTS contains an invalid hostname: {item}"
            ) from exc
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            pass
        else:
            raise ConfigurationError(
                "SCOPEGUARD_ALLOWED_HOSTS accepts hostnames only; "
                "authorize direct IP targets with SCOPEGUARD_ALLOWED_NETWORKS"
            )
        labels = candidate.split(".")
        if (
            not candidate
            or len(candidate) > 253
            or any(not _HOST_LABEL_RE.fullmatch(label) for label in labels)
        ):
            raise ConfigurationError(
                f"SCOPEGUARD_ALLOWED_HOSTS contains an invalid hostname: {item}"
            )
        hosts.append(("*." if wildcard else "") + candidate)
    return tuple(dict.fromkeys(hosts))


def _parse_networks(value: str | None) -> tuple[str, ...]:
    networks: list[str] = []
    for item in _parse_csv(value):
        try:
            networks.append(str(ipaddress.ip_network(item, strict=False)))
        except ValueError as exc:
            raise ConfigurationError(
                f"SCOPEGUARD_ALLOWED_NETWORKS contains an invalid CIDR: {item}"
            ) from exc
    return tuple(networks)


def _load_audit_key() -> tuple[bytes | None, str]:
    raw_key = os.getenv("SCOPEGUARD_AUDIT_HMAC_KEY", "")
    if not raw_key:
        return None, "unsealed"
    key = raw_key.encode("utf-8")
    if len(key) < 32:
        raise ConfigurationError("SCOPEGUARD_AUDIT_HMAC_KEY must contain at least 32 bytes")
    configured_id = os.getenv("SCOPEGUARD_AUDIT_KEY_ID", "").strip()
    key_id = configured_id or hashlib.sha256(key).hexdigest()[:12]
    if len(key_id) > 64 or any(
        character not in "-_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        for character in key_id
    ):
        raise ConfigurationError(
            "SCOPEGUARD_AUDIT_KEY_ID must use at most 64 letters, numbers, hyphens, or underscores"
        )
    return key, key_id


@dataclass(frozen=True, slots=True)
class Settings:
    """Runtime settings that cannot be changed through MCP tools."""

    project_root: Path
    state_dir: Path
    database_path: Path
    allowed_roots: tuple[Path, ...]
    execution_enabled: bool = False
    max_files: int = 5_000
    max_file_bytes: int = 1_000_000
    max_total_bytes: int = 50_000_000
    max_findings: int = 2_000
    max_targets: int = 25
    max_headers: int = 100
    max_header_bytes: int = 32_768
    require_sealed_audit: bool = False
    audit_hmac_key: bytes | None = field(default=None, repr=False)
    audit_key_id: str = "unsealed"
    network_enabled: bool = False
    allowed_hosts: tuple[str, ...] = ()
    allowed_networks: tuple[str, ...] = ()
    max_ports: int = 32
    network_timeout_seconds: float = 3.0

    @classmethod
    def from_env(cls, project_root: Path | None = None) -> Settings:
        root = (project_root or Path.cwd()).resolve()
        state_value = os.getenv("SCOPEGUARD_STATE_DIR", "").strip()
        state_dir = Path(state_value).resolve() if state_value else root / ".scopeguard"
        roots_value = os.getenv("SCOPEGUARD_ALLOWED_ROOTS")
        if roots_value:
            roots = tuple(
                Path(value).expanduser().resolve()
                for value in roots_value.split(os.pathsep)
                if value.strip()
            )
        else:
            roots = (root,)
        if not roots:
            raise ConfigurationError("SCOPEGUARD_ALLOWED_ROOTS must contain at least one path")
        execution_enabled = _parse_bool(
            os.getenv("SCOPEGUARD_EXECUTION_ENABLED", "false"),
            "SCOPEGUARD_EXECUTION_ENABLED",
        )
        audit_hmac_key, audit_key_id = _load_audit_key()
        return cls(
            project_root=root,
            state_dir=state_dir,
            database_path=state_dir / "scopeguard.db",
            allowed_roots=roots,
            execution_enabled=execution_enabled,
            max_files=_parse_positive_int(
                os.getenv("SCOPEGUARD_MAX_FILES", "5000"), "SCOPEGUARD_MAX_FILES"
            ),
            max_file_bytes=_parse_positive_int(
                os.getenv("SCOPEGUARD_MAX_FILE_BYTES", "1000000"),
                "SCOPEGUARD_MAX_FILE_BYTES",
            ),
            max_total_bytes=_parse_positive_int(
                os.getenv("SCOPEGUARD_MAX_TOTAL_BYTES", "50000000"),
                "SCOPEGUARD_MAX_TOTAL_BYTES",
            ),
            max_findings=_parse_positive_int(
                os.getenv("SCOPEGUARD_MAX_FINDINGS", "2000"),
                "SCOPEGUARD_MAX_FINDINGS",
            ),
            max_targets=_parse_positive_int(
                os.getenv("SCOPEGUARD_MAX_TARGETS", "25"), "SCOPEGUARD_MAX_TARGETS"
            ),
            max_headers=_parse_positive_int(
                os.getenv("SCOPEGUARD_MAX_HEADERS", "100"), "SCOPEGUARD_MAX_HEADERS"
            ),
            max_header_bytes=_parse_positive_int(
                os.getenv("SCOPEGUARD_MAX_HEADER_BYTES", "32768"),
                "SCOPEGUARD_MAX_HEADER_BYTES",
            ),
            require_sealed_audit=_parse_bool(
                os.getenv(
                    "SCOPEGUARD_REQUIRE_SEALED_AUDIT",
                    "true" if execution_enabled else "false",
                ),
                "SCOPEGUARD_REQUIRE_SEALED_AUDIT",
            ),
            audit_hmac_key=audit_hmac_key,
            audit_key_id=audit_key_id,
            network_enabled=_parse_bool(
                os.getenv("SCOPEGUARD_NETWORK_ENABLED", "false"),
                "SCOPEGUARD_NETWORK_ENABLED",
            ),
            allowed_hosts=_parse_hosts(os.getenv("SCOPEGUARD_ALLOWED_HOSTS")),
            allowed_networks=_parse_networks(os.getenv("SCOPEGUARD_ALLOWED_NETWORKS")),
            max_ports=_parse_bounded_int(
                os.getenv("SCOPEGUARD_MAX_PORTS", "32"),
                "SCOPEGUARD_MAX_PORTS",
                maximum=128,
            ),
            network_timeout_seconds=_parse_timeout(
                os.getenv("SCOPEGUARD_NETWORK_TIMEOUT_SECONDS", "3")
            ),
        )

    def ensure_state_dir(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        try:
            self.state_dir.chmod(0o700)
        except OSError:
            pass

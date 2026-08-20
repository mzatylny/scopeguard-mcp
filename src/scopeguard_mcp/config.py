"""Operator-controlled configuration for ScopeGuard."""

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass
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
        return cls(
            project_root=root,
            state_dir=state_dir,
            database_path=state_dir / "scopeguard.db",
            allowed_roots=roots,
            execution_enabled=_parse_bool(
                os.getenv("SCOPEGUARD_EXECUTION_ENABLED", "false"),
                "SCOPEGUARD_EXECUTION_ENABLED",
            ),
            max_files=_parse_positive_int(
                os.getenv("SCOPEGUARD_MAX_FILES", "5000"), "SCOPEGUARD_MAX_FILES"
            ),
            max_file_bytes=_parse_positive_int(
                os.getenv("SCOPEGUARD_MAX_FILE_BYTES", "1000000"),
                "SCOPEGUARD_MAX_FILE_BYTES",
            ),
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

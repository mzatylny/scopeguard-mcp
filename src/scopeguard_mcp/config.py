"""Operator-controlled configuration for ScopeGuard."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .errors import ConfigurationError


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
        )

    def ensure_state_dir(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        try:
            self.state_dir.chmod(0o700)
        except OSError:
            pass

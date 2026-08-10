import os
from pathlib import Path

import pytest

from scopeguard_mcp.config import Settings
from scopeguard_mcp.errors import ConfigurationError


def test_settings_defaults_are_safe(tmp_path, monkeypatch):
    for name in (
        "SCOPEGUARD_STATE_DIR",
        "SCOPEGUARD_ALLOWED_ROOTS",
        "SCOPEGUARD_EXECUTION_ENABLED",
        "SCOPEGUARD_MAX_FILES",
        "SCOPEGUARD_MAX_FILE_BYTES",
    ):
        monkeypatch.delenv(name, raising=False)
    settings = Settings.from_env(tmp_path)
    assert settings.project_root == tmp_path.resolve()
    assert settings.allowed_roots == (tmp_path.resolve(),)
    assert settings.execution_enabled is False
    settings.ensure_state_dir()
    assert settings.state_dir.is_dir()


def test_settings_read_explicit_environment(tmp_path, monkeypatch):
    root_one = tmp_path / "one"
    root_two = tmp_path / "two"
    monkeypatch.setenv("SCOPEGUARD_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("SCOPEGUARD_ALLOWED_ROOTS", f"{root_one}{os.pathsep}{root_two}")
    monkeypatch.setenv("SCOPEGUARD_EXECUTION_ENABLED", "yes")
    monkeypatch.setenv("SCOPEGUARD_MAX_FILES", "12")
    monkeypatch.setenv("SCOPEGUARD_MAX_FILE_BYTES", "345")
    settings = Settings.from_env(tmp_path)
    assert settings.allowed_roots == (root_one.resolve(), root_two.resolve())
    assert settings.execution_enabled is True
    assert settings.max_files == 12
    assert settings.max_file_bytes == 345


@pytest.mark.parametrize(
    "name,value",
    [
        ("SCOPEGUARD_EXECUTION_ENABLED", "sometimes"),
        ("SCOPEGUARD_MAX_FILES", "0"),
        ("SCOPEGUARD_MAX_FILES", "many"),
        ("SCOPEGUARD_MAX_FILE_BYTES", "-1"),
    ],
)
def test_settings_reject_invalid_environment(tmp_path, monkeypatch, name, value):
    monkeypatch.setenv(name, value)
    with pytest.raises(ConfigurationError):
        Settings.from_env(tmp_path)


def test_settings_empty_state_dir_uses_default(tmp_path, monkeypatch):
    monkeypatch.setenv("SCOPEGUARD_STATE_DIR", "")
    settings = Settings.from_env(tmp_path)
    assert settings.state_dir == Path(tmp_path / ".scopeguard").resolve()


def test_settings_reject_allowed_roots_without_paths(tmp_path, monkeypatch):
    monkeypatch.setenv("SCOPEGUARD_ALLOWED_ROOTS", os.pathsep)
    with pytest.raises(ConfigurationError):
        Settings.from_env(tmp_path)

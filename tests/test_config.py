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
        "SCOPEGUARD_MAX_TOTAL_BYTES",
        "SCOPEGUARD_MAX_FINDINGS",
        "SCOPEGUARD_MAX_TARGETS",
        "SCOPEGUARD_MAX_HEADERS",
        "SCOPEGUARD_MAX_HEADER_BYTES",
        "SCOPEGUARD_REQUIRE_SEALED_AUDIT",
        "SCOPEGUARD_AUDIT_HMAC_KEY",
        "SCOPEGUARD_AUDIT_KEY_ID",
    ):
        monkeypatch.delenv(name, raising=False)
    settings = Settings.from_env(tmp_path)
    assert settings.project_root == tmp_path.resolve()
    assert settings.allowed_roots == (tmp_path.resolve(),)
    assert settings.execution_enabled is False
    assert settings.require_sealed_audit is False
    assert settings.audit_hmac_key is None
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
    assert settings.require_sealed_audit is True


@pytest.mark.parametrize(
    "name,value",
    [
        ("SCOPEGUARD_EXECUTION_ENABLED", "sometimes"),
        ("SCOPEGUARD_MAX_FILES", "0"),
        ("SCOPEGUARD_MAX_FILES", "many"),
        ("SCOPEGUARD_MAX_FILE_BYTES", "-1"),
        ("SCOPEGUARD_AUDIT_HMAC_KEY", "too-short"),
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


def test_audit_key_is_loaded_without_leaking_from_repr(tmp_path, monkeypatch):
    secret = "a" * 32
    monkeypatch.setenv("SCOPEGUARD_AUDIT_HMAC_KEY", secret)
    monkeypatch.setenv("SCOPEGUARD_AUDIT_KEY_ID", "primary-2026")
    settings = Settings.from_env(tmp_path)
    assert settings.audit_hmac_key == secret.encode()
    assert settings.audit_key_id == "primary-2026"
    assert secret not in repr(settings)


def test_audit_key_id_is_validated_when_key_is_configured(tmp_path, monkeypatch):
    monkeypatch.setenv("SCOPEGUARD_AUDIT_HMAC_KEY", "a" * 32)
    monkeypatch.setenv("SCOPEGUARD_AUDIT_KEY_ID", "bad key id!")
    with pytest.raises(ConfigurationError, match="AUDIT_KEY_ID"):
        Settings.from_env(tmp_path)

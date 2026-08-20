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
        "SCOPEGUARD_NETWORK_ENABLED",
        "SCOPEGUARD_ALLOWED_HOSTS",
        "SCOPEGUARD_ALLOWED_NETWORKS",
        "SCOPEGUARD_MAX_PORTS",
        "SCOPEGUARD_NETWORK_TIMEOUT_SECONDS",
    ):
        monkeypatch.delenv(name, raising=False)
    settings = Settings.from_env(tmp_path)
    assert settings.project_root == tmp_path.resolve()
    assert settings.allowed_roots == (tmp_path.resolve(),)
    assert settings.execution_enabled is False
    assert settings.network_enabled is False
    assert settings.allowed_hosts == ()
    assert settings.allowed_networks == ()
    assert settings.max_ports == 32
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
    monkeypatch.setenv("SCOPEGUARD_NETWORK_ENABLED", "on")
    monkeypatch.setenv("SCOPEGUARD_ALLOWED_HOSTS", "EXAMPLE.com., *.example.net,example.com")
    monkeypatch.setenv("SCOPEGUARD_ALLOWED_NETWORKS", "192.0.2.4/24,2001:db8::/32")
    monkeypatch.setenv("SCOPEGUARD_MAX_PORTS", "12")
    monkeypatch.setenv("SCOPEGUARD_NETWORK_TIMEOUT_SECONDS", "1.5")
    settings = Settings.from_env(tmp_path)
    assert settings.allowed_roots == (root_one.resolve(), root_two.resolve())
    assert settings.execution_enabled is True
    assert settings.max_files == 12
    assert settings.max_file_bytes == 345
    assert settings.network_enabled is True
    assert settings.allowed_hosts == ("example.com", "*.example.net")
    assert settings.allowed_networks == ("192.0.2.0/24", "2001:db8::/32")
    assert settings.max_ports == 12
    assert settings.network_timeout_seconds == 1.5


@pytest.mark.parametrize(
    "name,value",
    [
        ("SCOPEGUARD_EXECUTION_ENABLED", "sometimes"),
        ("SCOPEGUARD_MAX_FILES", "0"),
        ("SCOPEGUARD_MAX_FILES", "many"),
        ("SCOPEGUARD_MAX_FILE_BYTES", "-1"),
        ("SCOPEGUARD_NETWORK_ENABLED", "perhaps"),
        ("SCOPEGUARD_ALLOWED_HOSTS", "bad_host.example"),
        ("SCOPEGUARD_ALLOWED_HOSTS", "foo.*.example"),
        ("SCOPEGUARD_ALLOWED_HOSTS", "192.0.2.10"),
        ("SCOPEGUARD_ALLOWED_NETWORKS", "not-a-cidr"),
        ("SCOPEGUARD_MAX_PORTS", "129"),
        ("SCOPEGUARD_NETWORK_TIMEOUT_SECONDS", "0"),
        ("SCOPEGUARD_NETWORK_TIMEOUT_SECONDS", "slow"),
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

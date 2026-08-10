import pytest

from scopeguard_mcp.errors import InvalidTargetError
from scopeguard_mcp.scope import any_scope_matches, normalize_target, target_in_scope


def test_normalize_domain_ip_network_and_file(tmp_path):
    assert normalize_target("Example.COM.").value == "example.com"
    assert normalize_target("192.0.2.4").kind == "ip"
    assert normalize_target("192.0.2.7/24").value == "192.0.2.0/24"
    file_target = normalize_target("file:repo", base_dir=tmp_path)
    assert file_target.value == str((tmp_path / "repo").resolve())


def test_normalize_url_removes_query_and_resolves_path_segments():
    target = normalize_target("HTTPS://Example.COM:443/app/../admin?q=secret#fragment")
    assert target.value == "https://example.com/admin"


def test_normalize_ipv6_url():
    target = normalize_target("https://[2001:0db8::1]:8443/path")
    assert target.value == "https://[2001:db8::1]:8443/path"


@pytest.mark.parametrize(
    "value",
    [
        "",
        "ftp://example.com",
        "https://user:pass@example.com",
        "https://example.com:bad",
        "https://*.example.com",
        "not a domain",
    ],
)
def test_invalid_targets_are_rejected(value):
    with pytest.raises(InvalidTargetError):
        normalize_target(value)


def test_domain_and_wildcard_scope_matching():
    exact = normalize_target("example.com")
    wildcard = normalize_target("*.example.com")
    assert target_in_scope(exact, normalize_target("https://example.com/path"))
    assert not target_in_scope(exact, normalize_target("https://api.example.com"))
    assert target_in_scope(wildcard, normalize_target("api.example.com"))
    assert target_in_scope(wildcard, normalize_target("deep.api.example.com"))
    assert not target_in_scope(wildcard, normalize_target("example.com"))


def test_url_scope_enforces_origin_and_path_prefix():
    scope = normalize_target("https://example.com/app")
    assert target_in_scope(scope, normalize_target("https://example.com/app/users"))
    assert not target_in_scope(scope, normalize_target("http://example.com/app"))
    assert not target_in_scope(scope, normalize_target("https://example.com/application"))


def test_network_and_file_scope_matching(tmp_path):
    network = normalize_target("10.20.0.0/16")
    assert target_in_scope(network, normalize_target("10.20.4.5"))
    assert not target_in_scope(network, normalize_target("10.21.4.5"))

    root = normalize_target(f"file:{tmp_path}")
    child = normalize_target(f"file:{tmp_path / 'repo' / 'src'}")
    outside = normalize_target(f"file:{tmp_path.parent / 'outside'}")
    assert target_in_scope(root, child)
    assert not target_in_scope(root, outside)
    assert not target_in_scope(root, normalize_target("example.com"))


def test_any_scope_matches_returns_normalized_candidate(tmp_path):
    matches, candidate = any_scope_matches(
        ("*.example.com", f"file:{tmp_path}"), "API.EXAMPLE.COM", base_dir=tmp_path
    )
    assert matches is True
    assert candidate.value == "api.example.com"

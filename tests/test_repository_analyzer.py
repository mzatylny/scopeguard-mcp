import json

from scopeguard_mcp.analyzers.repository import scan_repository


def test_repository_scan_detects_risky_python_and_redacts_secrets(tmp_path):
    secret = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcd"
    (tmp_path / "risky.py").write_text(
        """
import os
import pickle
import subprocess
import yaml

password = "this-is-a-long-password"
eval(user_input)
os.system(command)
subprocess.run(command, shell=True)
pickle.loads(payload)
yaml.load(document)
""",
        encoding="utf-8",
    )
    (tmp_path / ".env").write_text(f"GITHUB_TOKEN={secret}\n", encoding="utf-8")
    result = scan_repository(tmp_path, max_files=20, max_file_bytes=20_000)
    rule_ids = {finding["rule_id"] for finding in result["findings"]}
    assert {
        "python.dynamic-execution",
        "python.shell-command",
        "python.subprocess-shell",
        "python.unsafe-deserialization",
        "python.yaml-unsafe-loader",
        "secret.generic-assignment",
        "secret.github-token",
    }.issubset(rule_ids)
    assert secret not in json.dumps(result)
    assert "this-is-a-long-password" not in json.dumps(result)


def test_repository_scan_skips_ignored_binary_and_large_files(tmp_path):
    (tmp_path / "safe.py").write_text("print('safe')\n", encoding="utf-8")
    (tmp_path / "large.py").write_text("x" * 100, encoding="utf-8")
    (tmp_path / "binary.py").write_bytes(b"safe\x00eval(x)")
    ignored = tmp_path / ".venv"
    ignored.mkdir()
    (ignored / "bad.py").write_text("eval(x)\n", encoding="utf-8")
    result = scan_repository(tmp_path, max_files=10, max_file_bytes=50)
    assert result["scanned_files"] == 1
    assert result["skipped_files"] == 2
    assert result["summary"]["findings"] == 0


def test_repository_scan_limit_sets_truncated(tmp_path):
    for index in range(3):
        (tmp_path / f"file_{index}.py").write_text("print('ok')\n", encoding="utf-8")
    result = scan_repository(tmp_path, max_files=1, max_file_bytes=1_000)
    assert result["scanned_files"] == 1
    assert result["truncated"] is True


def test_repository_scan_supports_single_file_and_invalid_python(tmp_path):
    path = tmp_path / "broken.py"
    path.write_text("def broken(:\n", encoding="utf-8")
    result = scan_repository(path, max_files=10, max_file_bytes=1_000)
    assert result["scanned_files"] == 1
    assert result["findings"] == []


def test_repository_scan_emits_deterministic_evidence(tmp_path):
    (tmp_path / "a.py").write_text("print('a')\n", encoding="utf-8")
    (tmp_path / "b.json").write_text('{"safe": true}\n', encoding="utf-8")
    first = scan_repository(
        tmp_path,
        max_files=10,
        max_file_bytes=1_000,
        fingerprint_key=b"f" * 32,
    )
    second = scan_repository(
        tmp_path,
        max_files=10,
        max_file_bytes=1_000,
        fingerprint_key=b"f" * 32,
    )
    assert first["evidence"] == second["evidence"]
    assert len(first["evidence"]["manifest_sha256"]) == 64
    assert len(first["evidence"]["ruleset_sha256"]) == 64


def test_repository_scan_enforces_total_bytes_and_finding_limits(tmp_path):
    (tmp_path / "a.py").write_text("eval(a)\neval(b)\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("print('b')\n", encoding="utf-8")
    findings_limited = scan_repository(
        tmp_path,
        max_files=10,
        max_file_bytes=1_000,
        max_findings=1,
    )
    assert findings_limited["summary"]["findings"] == 1
    assert findings_limited["summary"]["findings_truncated"] is True
    assert "max_findings" in findings_limited["truncation_reasons"]

    bytes_limited = scan_repository(
        tmp_path,
        max_files=10,
        max_file_bytes=1_000,
        max_total_bytes=1,
    )
    assert bytes_limited["scanned_files"] == 0
    assert bytes_limited["truncated"] is True
    assert bytes_limited["truncation_reasons"] == ["max_total_bytes"]


def test_repository_scan_never_follows_symlinked_files(tmp_path):
    outside = tmp_path.parent / "outside-secret.py"
    outside.write_text('password = "not-for-scopeguard"\n', encoding="utf-8")
    (tmp_path / "linked.py").symlink_to(outside)
    result = scan_repository(tmp_path, max_files=10, max_file_bytes=1_000)
    assert result["scanned_files"] == 0
    assert result["findings"] == []

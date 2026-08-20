"""Dependency-free repository checks for risky Python and exposed secrets."""

from __future__ import annotations

import ast
import hashlib
import hmac
import json
import os
import re
import stat
from collections.abc import Iterator
from pathlib import Path
from typing import Any

_IGNORED_DIRECTORIES = {
    ".git",
    ".hg",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".scopeguard",
    ".svn",
    ".venv",
    "build",
    "dist",
    "node_modules",
    "vendor",
}
_TEXT_EXTENSIONS = {
    ".cfg",
    ".conf",
    ".env",
    ".ini",
    ".js",
    ".json",
    ".md",
    ".py",
    ".sh",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".yaml",
    ".yml",
}
_SECRET_PATTERNS = (
    (
        "secret.private-key",
        "high",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ),
    ("secret.aws-access-key", "high", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    (
        "secret.github-token",
        "high",
        re.compile(r"\bgh(?:p|o|u|s|r)_[A-Za-z0-9_]{30,255}\b"),
    ),
    (
        "secret.generic-assignment",
        "medium",
        re.compile(
            r"(?i)\b(?:api[_-]?key|client[_-]?secret|password|secret|token)\b\s*[:=]\s*"
            r"['\"]([^'\"\n]{12,})['\"]"
        ),
    ),
)
_RULESET_VERSION = "2026.08.1"
_RULESET_SHA256 = hashlib.sha256(
    "\n".join(
        sorted(
            {
                "python.dynamic-execution",
                "python.shell-command",
                "python.subprocess-shell",
                "python.unsafe-deserialization",
                "python.yaml-unsafe-loader",
                *(rule_id for rule_id, _, _ in _SECRET_PATTERNS),
            }
        )
    ).encode("utf-8")
).hexdigest()
_EPHEMERAL_FINGERPRINT_KEY = os.urandom(32)


def _fingerprint(value: str, key: bytes) -> str:
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()[:16]


def _relative_path(path: Path, root: Path) -> str:
    return path.name if path == root else str(path.relative_to(root))


def _finding(
    *, rule_id: str, severity: str, path: Path, root: Path, line: int, title: str, fingerprint: str
) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "severity": severity,
        "path": _relative_path(path, root),
        "line": line,
        "title": title,
        "fingerprint": fingerprint,
    }


def _call_name(node: ast.Call) -> str:
    parts: list[str] = []
    current: ast.expr = node.func
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


def _python_findings(
    path: Path, root: Path, text: str, fingerprint_key: bytes
) -> list[dict[str, Any]]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    findings: list[dict[str, Any]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node)
        rule_id = ""
        severity = "medium"
        title = ""
        if name in {"eval", "exec", "builtins.eval", "builtins.exec"}:
            rule_id = "python.dynamic-execution"
            severity = "high"
            title = "Dynamic code execution can run untrusted input"
        elif name in {"os.system", "os.popen"}:
            rule_id = "python.shell-command"
            severity = "high"
            title = "Shell command execution requires strict input control"
        elif name.startswith("subprocess.") and any(
            keyword.arg == "shell"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
            for keyword in node.keywords
        ):
            rule_id = "python.subprocess-shell"
            severity = "high"
            title = "subprocess shell=True increases command-injection risk"
        elif name in {"pickle.load", "pickle.loads"}:
            rule_id = "python.unsafe-deserialization"
            title = "Pickle deserialization can execute attacker-controlled code"
        elif name == "yaml.load" and not any(
            keyword.arg == "Loader"
            and isinstance(keyword.value, ast.Attribute)
            and keyword.value.attr in {"SafeLoader", "CSafeLoader"}
            for keyword in node.keywords
        ):
            rule_id = "python.yaml-unsafe-loader"
            title = "yaml.load should use a safe loader"
        if rule_id:
            findings.append(
                _finding(
                    rule_id=rule_id,
                    severity=severity,
                    path=path,
                    root=root,
                    line=node.lineno,
                    title=title,
                    fingerprint=_fingerprint(
                        f"{rule_id}:{_relative_path(path, root)}:{node.lineno}",
                        fingerprint_key,
                    ),
                )
            )
    return findings


def _secret_findings(
    path: Path, root: Path, text: str, fingerprint_key: bytes
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for rule_id, severity, pattern in _SECRET_PATTERNS:
        for match in pattern.finditer(text):
            matched_value = match.group(1) if match.lastindex else match.group(0)
            line = text.count("\n", 0, match.start()) + 1
            findings.append(
                _finding(
                    rule_id=rule_id,
                    severity=severity,
                    path=path,
                    root=root,
                    line=line,
                    title="Potential secret detected; value redacted",
                    fingerprint=_fingerprint(matched_value, fingerprint_key),
                )
            )
    return findings


def _candidate_files(root: Path) -> Iterator[Path]:
    if root.is_file():
        yield root
        return
    for current_root, directories, files in os.walk(root, followlinks=False):
        directories[:] = sorted(
            directory
            for directory in directories
            if directory not in _IGNORED_DIRECTORIES
            and not (Path(current_root) / directory).is_symlink()
        )
        for name in sorted(files):
            if name == ".DS_Store" or name.startswith("._"):
                continue
            path = Path(current_root) / name
            if not path.is_symlink():
                yield path


def _looks_textual(path: Path) -> bool:
    return path.suffix.lower() in _TEXT_EXTENSIONS or path.name in {
        ".env",
        "Dockerfile",
        "Pipfile",
        "requirements.txt",
    }


def _read_regular_file_beneath(
    path: Path, root: Path, *, max_file_bytes: int
) -> tuple[bytes | None, str | None]:
    """Open a regular file without following path-component symlinks where supported."""
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    close_on_exec = getattr(os, "O_CLOEXEC", 0)
    directory_flag = getattr(os, "O_DIRECTORY", 0)
    file_descriptor: int | None = None
    directory_descriptors: list[int] = []
    try:
        can_open_relative = root.is_dir() and os.open in os.supports_dir_fd and bool(no_follow)
        if can_open_relative:
            relative = path.relative_to(root)
            if not relative.parts:
                return None, "not_regular"
            directory_descriptor = os.open(
                root,
                os.O_RDONLY | close_on_exec | directory_flag | no_follow,
            )
            directory_descriptors.append(directory_descriptor)
            for component in relative.parts[:-1]:
                directory_descriptor = os.open(
                    component,
                    os.O_RDONLY | close_on_exec | directory_flag | no_follow,
                    dir_fd=directory_descriptor,
                )
                directory_descriptors.append(directory_descriptor)
            file_descriptor = os.open(
                relative.parts[-1],
                os.O_RDONLY | close_on_exec | no_follow,
                dir_fd=directory_descriptor,
            )
        else:
            resolved = path.resolve(strict=True)
            if root.is_dir() and not resolved.is_relative_to(root):
                return None, "outside_root"
            if path.is_symlink():
                return None, "symlink"
            file_descriptor = os.open(resolved, os.O_RDONLY | close_on_exec | no_follow)

        metadata = os.fstat(file_descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            return None, "not_regular"
        if metadata.st_size > max_file_bytes:
            return None, "too_large"

        content = bytearray()
        while len(content) <= max_file_bytes:
            chunk = os.read(file_descriptor, min(65_536, max_file_bytes + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
        if len(content) > max_file_bytes:
            return None, "too_large"
        return bytes(content), None
    except OSError:
        return None, "unreadable"
    finally:
        if file_descriptor is not None:
            try:
                os.close(file_descriptor)
            except OSError:
                pass
        for descriptor in reversed(directory_descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass


def scan_repository(
    root: Path,
    *,
    max_files: int,
    max_file_bytes: int,
    max_total_bytes: int = 50_000_000,
    max_findings: int = 2_000,
    fingerprint_key: bytes | None = None,
) -> dict[str, Any]:
    resolved_root = root.resolve(strict=True)
    if not resolved_root.is_file() and not resolved_root.is_dir():
        raise ValueError("repository target must be a regular file or directory")
    fingerprint_key = fingerprint_key or _EPHEMERAL_FINGERPRINT_KEY
    findings: list[dict[str, Any]] = []
    manifest: list[dict[str, Any]] = []
    scanned_files = 0
    skipped_files = 0
    bytes_scanned = 0
    truncated = False
    findings_truncated = False
    truncation_reasons: set[str] = set()

    for path in _candidate_files(resolved_root):
        if not _looks_textual(path):
            continue
        if scanned_files >= max_files:
            truncated = True
            truncation_reasons.add("max_files")
            break
        content, skip_reason = _read_regular_file_beneath(
            path, resolved_root, max_file_bytes=max_file_bytes
        )
        if content is None:
            skipped_files += 1
            if skip_reason == "too_large":
                truncation_reasons.add("max_file_bytes")
            continue
        if bytes_scanned + len(content) > max_total_bytes:
            truncated = True
            truncation_reasons.add("max_total_bytes")
            break
        if b"\x00" in content:
            skipped_files += 1
            continue
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            skipped_files += 1
            continue

        scanned_files += 1
        bytes_scanned += len(content)
        relative_path = _relative_path(path, resolved_root)
        manifest.append(
            {
                "path": relative_path,
                "bytes": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        )
        file_findings = _secret_findings(path, resolved_root, text, fingerprint_key)
        if path.suffix.lower() == ".py":
            file_findings.extend(_python_findings(path, resolved_root, text, fingerprint_key))
        remaining = max_findings - len(findings)
        if len(file_findings) > remaining:
            findings.extend(file_findings[: max(0, remaining)])
            findings_truncated = True
            truncated = True
            truncation_reasons.add("max_findings")
        else:
            findings.extend(file_findings)

    unique = {
        (item["rule_id"], item["path"], item["line"], item["fingerprint"]): item
        for item in findings
    }
    ordered = sorted(
        unique.values(),
        key=lambda item: (
            {"high": 0, "medium": 1, "low": 2}[item["severity"]],
            item["path"],
            item["line"],
        ),
    )
    counts = {
        severity: sum(item["severity"] == severity for item in ordered)
        for severity in ("high", "medium", "low")
    }
    manifest_sha256 = hashlib.sha256(
        json.dumps(manifest, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()
    return {
        "root": str(resolved_root),
        "scanned_files": scanned_files,
        "skipped_files": skipped_files,
        "bytes_scanned": bytes_scanned,
        "truncated": truncated,
        "truncation_reasons": sorted(truncation_reasons),
        "summary": {
            "findings": len(ordered),
            "findings_truncated": findings_truncated,
            **counts,
        },
        "evidence": {
            "manifest_sha256": manifest_sha256,
            "ruleset_sha256": _RULESET_SHA256,
            "ruleset_version": _RULESET_VERSION,
        },
        "findings": ordered,
    }

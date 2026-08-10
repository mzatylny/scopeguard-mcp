"""Dependency-free repository checks for risky Python and exposed secrets."""

from __future__ import annotations

import ast
import hashlib
import os
import re
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


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def _finding(
    *, rule_id: str, severity: str, path: Path, root: Path, line: int, title: str, fingerprint: str
) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "severity": severity,
        "path": str(path.relative_to(root)) if path != root else path.name,
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


def _python_findings(path: Path, root: Path, text: str) -> list[dict[str, Any]]:
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
                    fingerprint=_fingerprint(f"{rule_id}:{path}:{node.lineno}"),
                )
            )
    return findings


def _secret_findings(path: Path, root: Path, text: str) -> list[dict[str, Any]]:
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
                    fingerprint=_fingerprint(matched_value),
                )
            )
    return findings


def _candidate_files(root: Path):
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


def scan_repository(root: Path, *, max_files: int, max_file_bytes: int) -> dict[str, Any]:
    resolved_root = root.resolve(strict=True)
    findings: list[dict[str, Any]] = []
    scanned_files = 0
    skipped_files = 0
    truncated = False

    for path in _candidate_files(resolved_root):
        if not _looks_textual(path):
            continue
        if scanned_files >= max_files:
            truncated = True
            break
        try:
            size = path.stat().st_size
            if size > max_file_bytes:
                skipped_files += 1
                continue
            content = path.read_bytes()
            if b"\x00" in content:
                skipped_files += 1
                continue
            text = content.decode("utf-8")
        except (OSError, UnicodeDecodeError):
            skipped_files += 1
            continue
        scanned_files += 1
        findings.extend(_secret_findings(path, resolved_root, text))
        if path.suffix.lower() == ".py":
            findings.extend(_python_findings(path, resolved_root, text))

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
    return {
        "root": str(resolved_root),
        "scanned_files": scanned_files,
        "skipped_files": skipped_files,
        "truncated": truncated,
        "summary": {"findings": len(ordered), **counts},
        "findings": ordered,
    }

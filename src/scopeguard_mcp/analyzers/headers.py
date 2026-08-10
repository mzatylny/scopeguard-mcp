"""Offline HTTP response-header security analysis."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit


def _finding(rule_id: str, severity: str, title: str, recommendation: str) -> dict[str, str]:
    return {
        "rule_id": rule_id,
        "severity": severity,
        "title": title,
        "recommendation": recommendation,
    }


def analyze_security_headers(target: str, headers: dict[str, str]) -> dict[str, Any]:
    normalized = {str(key).strip().lower(): str(value).strip() for key, value in headers.items()}
    findings: list[dict[str, str]] = []
    scheme = urlsplit(target).scheme.lower()

    if scheme == "https" and "strict-transport-security" not in normalized:
        findings.append(
            _finding(
                "headers.hsts.missing",
                "medium",
                "HTTPS response does not set HSTS",
                "Set Strict-Transport-Security with a reviewed max-age and subdomain policy.",
            )
        )
    if "content-security-policy" not in normalized:
        findings.append(
            _finding(
                "headers.csp.missing",
                "medium",
                "Content Security Policy is missing",
                "Deploy a restrictive Content-Security-Policy and avoid unsafe-inline/unsafe-eval.",
            )
        )
    if normalized.get("x-content-type-options", "").lower() != "nosniff":
        findings.append(
            _finding(
                "headers.nosniff.missing",
                "low",
                "MIME sniffing protection is missing",
                "Set X-Content-Type-Options: nosniff.",
            )
        )
    if "referrer-policy" not in normalized:
        findings.append(
            _finding(
                "headers.referrer-policy.missing",
                "low",
                "Referrer policy is missing",
                "Set a Referrer-Policy appropriate for the application's sharing requirements.",
            )
        )
    if "permissions-policy" not in normalized:
        findings.append(
            _finding(
                "headers.permissions-policy.missing",
                "low",
                "Permissions Policy is missing",
                "Disable browser capabilities the application does not need.",
            )
        )

    allow_origin = normalized.get("access-control-allow-origin", "")
    allow_credentials = normalized.get("access-control-allow-credentials", "").lower()
    if allow_origin == "*" and allow_credentials == "true":
        findings.append(
            _finding(
                "headers.cors.wildcard-credentials",
                "high",
                "CORS combines wildcard origin with credentials",
                "Use an explicit origin allowlist and avoid reflecting untrusted origins.",
            )
        )

    cookie = normalized.get("set-cookie", "")
    if cookie:
        lower_cookie = cookie.lower()
        if scheme == "https" and "secure" not in lower_cookie:
            findings.append(
                _finding(
                    "headers.cookie.secure",
                    "medium",
                    "Cookie lacks the Secure attribute",
                    "Mark session and sensitive cookies Secure.",
                )
            )
        if "httponly" not in lower_cookie:
            findings.append(
                _finding(
                    "headers.cookie.httponly",
                    "medium",
                    "Cookie lacks the HttpOnly attribute",
                    "Mark cookies that do not require JavaScript access as HttpOnly.",
                )
            )
        if "samesite=" not in lower_cookie:
            findings.append(
                _finding(
                    "headers.cookie.samesite",
                    "low",
                    "Cookie lacks an explicit SameSite policy",
                    "Set SameSite=Lax or Strict unless cross-site use is required.",
                )
            )

    severity_penalty = {"high": 25, "medium": 12, "low": 5}
    score = max(0, 100 - sum(severity_penalty[item["severity"]] for item in findings))
    counts = {
        severity: sum(item["severity"] == severity for item in findings)
        for severity in ("high", "medium", "low")
    }
    return {
        "target": target,
        "score": score,
        "summary": {"findings": len(findings), **counts},
        "findings": findings,
        "observed_headers": sorted(normalized),
    }

from scopeguard_mcp.analyzers.headers import analyze_security_headers


def test_secure_header_set_scores_full_marks():
    result = analyze_security_headers(
        "https://example.com",
        {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=()",
            "Set-Cookie": "session=redacted; Secure; HttpOnly; SameSite=Lax",
        },
    )
    assert result["score"] == 100
    assert result["summary"]["findings"] == 0


def test_insecure_headers_report_cors_cookie_and_baseline_findings():
    result = analyze_security_headers(
        "https://example.com",
        {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
            "Set-Cookie": "session=redacted",
            "X-Content-Type-Options": "off",
        },
    )
    rule_ids = {finding["rule_id"] for finding in result["findings"]}
    assert "headers.cors.wildcard-credentials" in rule_ids
    assert "headers.cookie.secure" in rule_ids
    assert "headers.cookie.httponly" in rule_ids
    assert "headers.cookie.samesite" in rule_ids
    assert "headers.hsts.missing" in rule_ids
    assert result["score"] < 50


def test_http_target_does_not_require_hsts():
    result = analyze_security_headers("http://localhost", {})
    rule_ids = {finding["rule_id"] for finding in result["findings"]}
    assert "headers.hsts.missing" not in rule_ids

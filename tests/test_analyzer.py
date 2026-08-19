from headerhunter.analyzer import analyze_headers
def test_missing_header():
    rules = {"rules": [{"name": "Strict-Transport-Security", "severity": "HIGH", "check": "missing"}]}
    assert len(analyze_headers({}, rules)) == 1
def test_present_header():
    rules = {"rules": [{"name": "Server", "severity": "LOW", "check": "present"}]}
    assert analyze_headers({"Server": "Apache"}, rules)[0].current_value == "Apache"
def test_case_insensitivity():
    rules = {"rules": [{"name": "X-Frame-Options", "severity": "MEDIUM", "check": "missing"}]}
    assert len(analyze_headers({"x-frame-options": "DENY"}, rules)) == 0
def test_exact_value():
    rules = {"rules": [{"name": "X-Content-Type-Options", "severity": "HIGH", "check": "value", "expected_value": "nosniff"}]}
    assert "mismatch" in analyze_headers({"X-Content-Type-Options": "sniff"}, rules)[0].issue
def test_hsts_valid_min():
    rules = {"value_checks": [{"name": "Strict-Transport-Security", "pattern": r"max-age\s*=\s*(\d+)", "min_value": 31536000, "severity": "MEDIUM"}]}
    assert len(analyze_headers({"Strict-Transport-Security": "max-age=31536000"}, rules)) == 0
def test_hsts_invalid_min():
    rules = {"value_checks": [{"name": "Strict-Transport-Security", "pattern": r"max-age\s*=\s*(\d+)", "min_value": 31536000, "severity": "MEDIUM"}]}
    assert len(analyze_headers({"Strict-Transport-Security": "max-age=86400"}, rules)) == 1
def test_csp_unsafe_pattern():
    rules = {"value_checks": [{"name": "Content-Security-Policy", "patterns": ["'unsafe-inline'"], "severity": "HIGH"}]}
    assert len(analyze_headers({"Content-Security-Policy": "default-src 'self' 'unsafe-inline'"}, rules)) == 1

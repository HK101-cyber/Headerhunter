from headerhunter.inputs import validate_url
def test_valid_url():
    assert validate_url("https://example.com") and validate_url("http://example.com")
def test_invalid_url_rejection():
    assert not (validate_url("example.com") or validate_url("ftp://example.com") or validate_url("http://"))

import pytest
from headerhunter.rules import validate_rules
def test_invalid_regex_rule():
    with pytest.raises(SystemExit): validate_rules({"value_checks": [{"name": "CSP", "pattern": "[", "severity": "HIGH"}]})
def test_invalid_severity():
    with pytest.raises(SystemExit): validate_rules({"rules": [{"name": "X", "severity": "EXTREME", "check": "missing"}]})
def test_invalid_check_type():
    with pytest.raises(SystemExit): validate_rules({"rules": [{"name": "X", "severity": "HIGH", "check": "exists"}]})

"""Header analysis engine."""
import re
from typing import Any, Dict, List
from headerhunter.models import Finding

def analyze_headers(headers: Dict[str, str], rules: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    headers_lower = {k.lower(): v for k, v in headers.items()}
    for rule in rules.get("rules", []):
        name, sev, check = rule["name"].lower(), rule["severity"].upper(), rule["check"]
        if check == "missing" and name not in headers_lower:
            findings.append(Finding(rule["name"], sev, "Missing security header", rule.get("recommendation", "")))
        elif check == "present" and name in headers_lower:
            findings.append(Finding(rule["name"], sev, f"Header present", rule.get("recommendation", ""), headers_lower[name]))
        elif check == "value" and name in headers_lower:
            exp = rule.get("expected_value")
            if exp and headers_lower[name] != exp:
                findings.append(Finding(rule["name"], sev, f"Exact value mismatch", rule.get("recommendation", ""), headers_lower[name]))
    for vc in rules.get("value_checks", []):
        name = vc["name"].lower()
        if name not in headers_lower: continue
        val, sev = headers_lower[name], vc["severity"].upper()
        if "min_value" in vc and "pattern" in vc:
            m = re.search(vc["pattern"], val, re.IGNORECASE)
            if m:
                try:
                    if int(m.group(1)) < vc["min_value"]:
                        findings.append(Finding(vc["name"], sev, vc.get("description",""), vc.get("recommendation",""), val))
                except (ValueError, IndexError): pass
        elif "patterns" in vc:
            for p in vc["patterns"]:
                if re.search(p, val, re.IGNORECASE):
                    findings.append(Finding(vc["name"], sev, vc.get("description",""), vc.get("recommendation",""), val))
                    break
    return findings

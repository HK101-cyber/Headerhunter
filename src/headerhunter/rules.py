"""Rule loading and validation."""
import os
import re
import sys
import yaml
from typing import Any, Dict, Optional

VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
VALID_CHECKS = {"missing", "present", "value"}

def get_default_rules_path() -> str:
    return os.path.join(os.path.dirname(__file__), "data", "default_rules.yaml")

def generate_default_rules() -> None:
    try:
        with open(get_default_rules_path(), "r", encoding="utf-8") as f:
            print(f.read().strip())
    except Exception as e:
        print(f"[!] Failed to read default rules: {e}", file=sys.stderr)
        sys.exit(1)

def validate_regex(pattern: str, context: str):
    try: return re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        print(f"[!] Invalid regex in {context}: {pattern} ({e})", file=sys.stderr)
        sys.exit(1)

def validate_rules(rules_data: Any) -> Dict[str, Any]:
    if not isinstance(rules_data, dict):
        print("[!] Rules file must be a YAML dictionary.", file=sys.stderr)
        sys.exit(1)
    rules = rules_data.get("rules", [])
    for i, rule in enumerate(rules):
        for key in ("name", "severity", "check"):
            if key not in rule:
                print(f"[!] Rule #{i+1} missing {key}", file=sys.stderr); sys.exit(1)
        if rule["severity"].upper() not in VALID_SEVERITIES:
            print(f"[!] Invalid severity in {rule['name']}", file=sys.stderr); sys.exit(1)
        if rule["check"] not in VALID_CHECKS:
            print(f"[!] Invalid check in {rule['name']}", file=sys.stderr); sys.exit(1)
    for i, vc in enumerate(rules_data.get("value_checks", [])):
        if "name" not in vc or "severity" not in vc:
            print(f"[!] Value check #{i+1} missing name/severity", file=sys.stderr); sys.exit(1)
        if vc["severity"].upper() not in VALID_SEVERITIES:
            print(f"[!] Invalid severity in {vc['name']}", file=sys.stderr); sys.exit(1)
        if "pattern" in vc: validate_regex(vc["pattern"], f"{vc['name']} pattern")
        elif "patterns" in vc:
            for p in vc["patterns"]: validate_regex(p, f"{vc['name']} patterns")
    return rules_data

def load_rules(filepath: Optional[str] = None) -> Dict[str, Any]:
    path = filepath or get_default_rules_path()
    if not os.path.exists(path):
        print(f"[!] Rules file not found: {path}", file=sys.stderr); sys.exit(1)
    try:
        with open(path, "r", encoding="utf-8") as f: data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        print(f"[!] YAML error: {e}", file=sys.stderr); sys.exit(1)
    return validate_rules(data)

"""Typed data models for scan results and findings."""
from dataclasses import dataclass, field
from typing import Optional, List, Dict

@dataclass
class Finding:
    header: str
    severity: str
    issue: str
    recommendation: str
    current_value: str = "N/A"

@dataclass
class ScanResult:
    url: str
    status_code: Optional[int] = None
    final_url: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    error: Optional[str] = None

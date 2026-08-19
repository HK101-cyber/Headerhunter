"""HTML report generation."""
import html
from datetime import datetime
from typing import List
from headerhunter.models import ScanResult

def generate_html_report(results: List[ScanResult], output_file: str, ruleset_label: str) -> None:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for r in results:
        for f in r.findings:
            if f.severity in counts: counts[f.severity] += 1
    esc = html.escape
    out = ['<!DOCTYPE html>\n<html lang="en">\n<head><meta charset="UTF-8">',
           '<title>HTTPHeaderHunter 1.1.0 Report</title>',
           '<style>body{font-family:sans-serif;max-width:1000px;margin:20px auto;padding:0 20px;}'
           'h1{color:#333;}.sev-CRITICAL{color:#dc2626;font-weight:bold;}'
           '.sev-HIGH{color:#f59e0b;font-weight:bold;}.sev-MEDIUM{color:#eab308;font-weight:bold;}'
           '.sev-LOW{color:#84cc16;font-weight:bold;}.sev-INFO{color:#3b82f6;font-weight:bold;}'
           'table{border-collapse:collapse;width:100%;margin-bottom:20px;}'
           'th,td{border:1px solid #ddd;padding:8px;text-align:left;}'
           'th{background:#f4f4f4;}.error{color:#dc2626;font-weight:bold;}</style></head><body>',
           '<h1>HTTPHeaderHunter Audit Report</h1>',
           f'<p><strong>Version:</strong> 1.1.0 | <strong>Timestamp:</strong> {esc(timestamp)} | <strong>Targets:</strong> {len(results)} | <strong>Ruleset:</strong> {esc(ruleset_label)}</p>',
           '<h2>Summary</h2><ul>']
    for sev in counts: out.append(f'<li><span class="sev-{sev}">{sev}</span>: {counts[sev]}</li>')
    out.append('</ul>')
    for r in results:
        out.append(f'<h2>Target</h2><p><strong>Original URL:</strong> {esc(r.url)}</p>')
        if r.final_url and r.final_url != r.url: out.append(f'<p><strong>Final URL:</strong> {esc(r.final_url)}</p>')
        if r.status_code: out.append(f'<p><strong>Status Code:</strong> {r.status_code}</p>')
        if r.error: out.append(f'<p class="error">Error: {esc(r.error)}</p>')
        if r.findings:
            out.append('<table><tr><th>Header</th><th>Severity</th><th>Issue</th><th>Current Value</th><th>Recommendation</th></tr>')
            for f in r.findings:
                out.append(f'<tr><td>{esc(f.header)}</td><td class="sev-{f.severity}">{esc(f.severity)}</td><td>{esc(f.issue)}</td><td>{esc(f.current_value)}</td><td>{esc(f.recommendation)}</td></tr>')
            out.append('</table>')
        elif not r.error: out.append('<p>No findings.</p>')
    out.append('</body></html>')
    with open(output_file, "w", encoding="utf-8") as f: f.write('\n'.join(out))

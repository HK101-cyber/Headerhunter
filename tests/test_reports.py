from headerhunter.reports.html import generate_html_report
from headerhunter.models import ScanResult, Finding
def test_html_escaping(tmp_path):
    results = [ScanResult(url="<script>alert(1)</script>", findings=[Finding(header="><", severity="HIGH", issue="&", recommendation="'", current_value='"')])]
    out = str(tmp_path / "test.html")
    generate_html_report(results, out, "Test")
    with open(out, "r", encoding="utf-8") as f: content = f.read()
    assert "<script>" not in content and "&lt;script&gt;" in content

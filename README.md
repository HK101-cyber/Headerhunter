# HTTPHeaderHunter 🛡️

**Version 1.1.0**

A professional HTTP security-header auditor for identifying missing, weak, or misconfigured response headers.

HTTPHeaderHunter evaluates web applications against configurable security-header rules and produces actionable reports with severity levels, explanations, and remediation guidance.

> ⚠️ **Authorized use only.** Scan only systems you own or have explicit written permission to test.

![Python](https://img.shields.io/badge/Python-3.7%2B-blue.svg)
![Status](https://img.shields.io/badge/Status-Active-brightgreen.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

## Features

- **Modern Architecture:** Fully refactored modular Python package with `pyproject.toml` support.
- **Comprehensive Checks:** Evaluates 11 critical HTTP security headers (CSP, HSTS, X-Frame-Options, etc.).
- **OWASP-Aligned Rules:** Practical web-application hardening based on industry standards.
- **Multiple Input Sources:** Scan individual URLs, text files, or SubSnatch JSON output.
- **High Performance:** Concurrent async scanning with `httpx` and HTTP/2 support.
- **Safe Defaults:** TLS verification enabled by default, with explicit `--insecure` fallback for labs.
- **Interactive Reports:** Color-coded HTML reports with HTML-escaped outputs (prevents XSS in reports).
- **Customizable:** Full support for custom YAML rule definitions.
- **Local Testing:** Includes a built-in localhost test server for safe, offline validation.

## Checks Included

The default ruleset evaluates the following headers:

- `Content-Security-Policy` (including unsafe-inline/eval detection)
- `Strict-Transport-Security` (including min-age validation)
- `X-Content-Type-Options`
- `X-Frame-Options`
- `Referrer-Policy`
- `Permissions-Policy`
- `Cross-Origin-Opener-Policy` (COOP)
- `Cross-Origin-Resource-Policy` (CORP)
- `Cross-Origin-Embedder-Policy` (COEP)
- `Server` (Information Disclosure)
- `X-Powered-By` (Information Disclosure)

## Installation

### Requirements
- Python 3.7 or newer
- Network access to authorized targets

### Setup (Kali / Debian / macOS / Linux)

```bash
git clone https://github.com/HK101-cyber/headerhunter.git
cd headerhunter

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install the package in editable mode with test dependencies
pip install --upgrade pip setuptools wheel
pip install -e ".[test]"

### Setup (Windows PowerShell)
git clone https://github.com/HK101-cyber/headerhunter.git
cd headerhunter

python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install --upgrade pip setuptools wheel
pip install -e ".[test]"

### Usage
Once installed, the headerhunter command is available globally in your virtual environment.
Scan a single URL

headerhunter -u https://example.com --follow-redirects -o report.html

### Scan URLs from a file
Create a text file (urls.txt) containing one URL per line. Blank lines and # comments are ignored.
headerhunter -f urls.txt -o security-report.html

Use SubSnatch JSON output
headerhunter -s subs.json -o header-audit.html

Configure concurrency and timeouts
headerhunter -u https://example.com -t 20 --timeout 10 -o report.html

Use conservative concurrency when scanning production systems or when working under a provider's rate limits.

Custom Rules
Generate the default rules to use as a template:
headerhunter --generate-rules > custom_rules.yaml
# Edit custom_rules.yaml as needed
headerhunter -u https://example.com --rules custom_rules.yaml -o custom-report.html

Local Test Server
Test the tool without making external network requests:
# Terminal 1: Start the mock vulnerable server
python tools/test_server.py

# Terminal 2: Scan the local server
headerhunter -u http://127.0.0.1:8080 -o local-report.html

Understanding Results
Findings are grouped by severity to help prioritize remediation:

    CRITICAL – A serious configuration issue that may significantly increase exposure.
    HIGH – A security weakness requiring prompt attention.
    MEDIUM – A meaningful hardening gap or risky configuration.
    LOW – A lower-impact improvement (e.g., information disclosure).
    INFO – Context or metadata that does not necessarily represent a vulnerability.

Note: A missing header is not automatically exploitable in every application. Review each finding in the context of the application, its content, authentication model, browser behavior, and deployment architecture.
Recommended Workflow

    Confirm that every target is within the authorized scope.
    Run an initial scan using the default rules.
    Review the generated HTML report.
    Validate important findings manually.
    Apply remediation changes in a test environment.
    Re-scan and compare the results.
    Document accepted risks and exceptions.

Testing the Codebase
Run the automated pytest suite to verify the analyzer, rule engine, and scanner logic:

pytest -q

Ethical and Legal Use
HTTPHeaderHunter is intended for authorized security testing, defensive assessment, and education.
Use it only:

    On systems you own.
    On systems for which you have explicit written permission.
    Within the approved scope, rate limits, and testing window.
    In compliance with applicable laws, contracts, and organizational policies.

Unauthorized scanning may violate computer-misuse, privacy, or data-protection laws, including the Computer Fraud and Abuse Act (CFAA), GDPR, and applicable local cybercrime legislation. The authors are not responsible for misuse of this tool.

Limitations
HTTPHeaderHunter is a security-auditing aid, not a complete penetration-testing platform. It does not replace manual security review, application testing, or infrastructure assessment. Results may vary based on redirects, authentication, middleware, proxies, CDNs, and dynamic response configuration.

Contributing
Before submitting a change:

    Create a focused branch.
    Keep changes scoped and documented.
    Test against authorized targets or local fixtures (pytest).
    Update the documentation when behavior changes.
    Submit a pull request describing the change and its security impact.

Please do not include real credentials, private target data, or sensitive scan results in issues or pull requests.

About & Contact
HTTPHeaderHunter was developed and is actively maintained by Hammad Khan to make HTTP security-header auditing more accessible, modular, and actionable for the security community.

    GitHub: HK101-cyber
    LinkedIn: Hammad Khan

License
This project is licensed under the MIT License. See LICENSE
 for details.

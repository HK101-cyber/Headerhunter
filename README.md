# HTTPHeaderHunter 🛡️

A professional HTTP security-header auditor for identifying missing, weak, or misconfigured response headers.

HTTPHeaderHunter evaluates web applications against configurable security-header rules and produces actionable reports with severity levels, explanations, and remediation guidance.

> ⚠️ **Authorized use only.** Scan only systems you own or have explicit written permission to test.

[![Python](https://img.shields.io/badge/Python-3.7%2B-blue.svg)](https://www.python.org/)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen.svg)](#project-status)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Features

- **Comprehensive header checks** for 15+ commonly used HTTP security headers.
- **OWASP-aligned rules** for practical web-application hardening.
- **Multiple input sources**, including individual URLs, URL files, and SubSnatch JSON output.
- **Concurrent scanning** with configurable worker counts.
- **Interactive HTML reports** with color-coded findings.
- **Educational findings** containing descriptions, impact, and remediation advice.
- **Custom rule support** through YAML configuration.
- **HTTP/2 support** through `httpx`.

## Checks Included

Depending on the active ruleset, HTTPHeaderHunter can evaluate headers such as:

- `Content-Security-Policy`
- `Strict-Transport-Security`
- `X-Content-Type-Options`
- `X-Frame-Options`
- `Referrer-Policy`
- `Permissions-Policy`
- `Cross-Origin-Opener-Policy`
- `Cross-Origin-Resource-Policy`
- `Cross-Origin-Embedder-Policy`
- Cookie security attributes
- Server and technology disclosure headers
- Cache-control directives
- Additional configurable response-header policies

The exact checks are controlled by the bundled or custom rules file.

## Installation

### Requirements

- Python 3.7 or newer
- Network access to the authorized targets
- Permission to perform the requested security assessment

### Setup

```bash
git clone https://github.com/HK101-cyber/headerhunter.git
cd headerhunter
python3 -m pip install -r requirements.txt
```

Dependencies include:

- `httpx[http2]`
- `PyYAML`
- `beautifulsoup4`
- `rich`

Using a virtual environment is recommended:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
```

On Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

## Usage

### Scan a single URL

```bash
python3 headerhunter.py \
  -u https://example.com \
  -o report.html
```

### Scan URLs from a file

Create a text file containing one URL per line:

```text
https://example.com
https://app.example.org
https://api.example.net
```

Then run:

```bash
python3 headerhunter.py \
  -f urls.txt \
  -o security-report.html
```

### Use SubSnatch JSON output

```bash
python3 headerhunter.py \
  -s subs.json \
  -o header-audit.html
```

### Configure concurrency

Increase or decrease the number of concurrent workers:

```bash
python3 headerhunter.py \
  -u https://example.com \
  -t 20 \
  -o report.html
```

Use conservative concurrency when scanning production systems or when working under a provider's rate limits.

## Custom Rules

Generate a starter rules file:

```bash
python3 headerhunter.py --generate-rules > custom_rules.yaml
```

Run a scan with custom rules:

```bash
python3 headerhunter.py \
  -u https://example.com \
  --rules custom_rules.yaml \
  -o custom-report.html
```

Custom rules allow teams to adapt the audit to their application architecture, deployment model, and internal security requirements.

## Input Notes

- URLs should include a scheme such as `https://` or `http://`.
- Do not include systems that are outside your authorized scope.
- URL files should contain one target per line.
- Remove test or inactive targets before scanning large lists.
- Review redirect behavior and final response headers when interpreting results.

## Understanding Results

Findings are grouped by severity to help prioritize remediation:

- **Critical** – A serious configuration issue that may significantly increase exposure.
- **High** – A security weakness requiring prompt attention.
- **Medium** – A meaningful hardening gap or risky configuration.
- **Low** – A lower-impact improvement.
- **Informational** – Context or metadata that does not necessarily represent a vulnerability.

A missing header is not automatically exploitable in every application. Review each finding in the context of the application, its content, authentication model, browser behavior, and deployment architecture.

## Recommended Workflow

1. Confirm that every target is within the authorized scope.
2. Run an initial scan using the default rules.
3. Review the generated HTML report.
4. Validate important findings manually.
5. Apply remediation changes in a test environment.
6. Re-scan and compare the results.
7. Document accepted risks and exceptions.

## Ethical and Legal Use

HTTPHeaderHunter is intended for authorized security testing, defensive assessment, and education.

Use it only:

- On systems you own.
- On systems for which you have explicit written permission.
- Within the approved scope, rate limits, and testing window.
- In compliance with applicable laws, contracts, and organizational policies.

Unauthorized scanning may violate computer-misuse, privacy, or data-protection laws, including the Computer Fraud and Abuse Act, GDPR, and applicable local cybercrime legislation.

The authors are not responsible for misuse of this tool.

## Responsible Disclosure

If you discover a security issue in a system you do not own, stop testing and follow the system owner's vulnerability-disclosure process. Do not access, modify, retain, or share data beyond what is necessary to demonstrate the issue.

## Limitations

HTTPHeaderHunter is a security-auditing aid, not a complete penetration-testing platform. It does not replace:

- Manual security review.
- Application and API testing.
- Infrastructure assessment.
- Browser-based validation.
- Threat modeling.
- Review of server-side security controls.

Results may vary based on redirects, authentication, middleware, proxies, CDNs, user-agent behavior, and dynamic response configuration.

## Project Status

HTTPHeaderHunter is actively maintained for the security community. Contributions, improvements to the ruleset, documentation updates, and bug reports are welcome.

## Contributing

Before submitting a change:

1. Create a focused branch.
2. Keep changes scoped and documented.
3. Test against authorized targets or local fixtures.
4. Update the documentation when behavior changes.
5. Submit a pull request describing the change and its security impact.

Please do not include real credentials, private target data, or sensitive scan results in issues or pull requests.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## About

HTTPHeaderHunter was developed by [HK101-cyber](https://github.com/HK101-cyber) to make HTTP security-header auditing more accessible and actionable.

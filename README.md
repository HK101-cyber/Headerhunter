# HTTPHeaderHunter 🛡️
### Professional HTTP Security Header Auditor

HTTPHeaderHunter identifies missing or misconfigured HTTP security headers to help harden web applications against common attacks.

![Python](https://img.shields.io/badge/Python-3.7%2B-blue)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)
![License](https://img.shields.io/badge/License-MIT-yellow)

> ⚠️ **Authorized use only. Never scan domains without explicit permission.**

---

## ⚡ Features

- ✅ **Comprehensive Security Checks** – Analyzes 15+ critical HTTP headers  
- ✅ **OWASP-Based Rules Engine** – Follows industry-standard security policies  
- ✅ **Multiple Input Sources** – Single URL, URL files, or SubSnatch JSON output  
- ✅ **Beautiful HTML Reports** – Interactive, color-coded severity levels  
- ✅ **Async Performance** – Fast concurrent scanning with configurable threads  
- ✅ **Educational Output** – Detailed descriptions and remediation guidance  

---

## 📦 Installation

```bash
git clone https://github.com/HK101-cyber/headerhunter.git
cd headerhunter
pip install -r requirements.txt
```

Requirements: Python 3.7+
Dependencies: httpx[http2],PyYAML, beautifulsoup4, rich

```bash
🔧 Usage
Basic Scanning

Analyze a single URL:
python3 headerhunter.py -u https://example.com -o report.html

Analyze multiple URLs from a file:
python3 headerhunter.py -f urls.txt -o security_report.html

Integrate with SubSnatch results:
python3 headerhunter.py -s subs.json -o header_audit.html
```

Advanced Options
```
Generate default rules template:
python3 headerhunter.py --generate-rules > custom_rules.yaml

Use custom rules file:
python3 headerhunter.py -u https://example.com --rules custom_rules.yaml

Adjust thread count for performance:
python3 headerhunter.py -u https://example.com -t 20
```
⚖️ Ethical Use

HTTPHeaderHunter must only be used:

On systems you own

With explicit written permission from the system owner

In compliance with all applicable laws and regulations

Unauthorized scanning may violate:

Computer Fraud and Abuse Act (CFAA)

General Data Protection Regulation (GDPR)

Local cybercrime laws

📄 License

This project is licensed under the MIT License – see the LICENSE file for details.

💡 About

HTTPHeaderHunter – Making web security accessible and actionable.
Developed with care by HK101-cyber for the security community.



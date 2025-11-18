# HTTPHeaderHunter

![HTTPHeaderHunter Banner](https://img.shields.io/badge/HTTPHeaderHunter-Security_Header_Auditor-blue?logo=python)

A professional HTTP security header auditor that identifies missing or misconfigured security headers to help harden web applications against common attacks.

> **Disclaimer**: This tool is for authorized security testing only. Never scan domains without explicit permission.

## Features

- **Comprehensive Security Checks** - Analyzes 15+ critical security headers
- **OWASP-Based Rules Engine** - Industry-standard security policies
- **Multiple Input Sources** - Single URL, URL files, or SubSnatch JSON output
- **Beautiful HTML Reports** - Interactive, color-coded severity levels
- **Async Performance** - Fast concurrent scanning with configurable threads
- **Educational Output** - Detailed descriptions and remediation guidance

## Installation

```bash
git clone https://github.com/HK101-cyber/headerhunter.git
cd headerhunter
pip install -r requirements.txt


Usage 
Basic scanning:
# Analyze a single URL
python3 headerhunter.py -u https://example.com -o report.html

# Analyze multiple URLs from a file
python3 headerhunter.py -f urls.txt -o security_report.html

# Integrate with SubSnatch results
python3 headerhunter.py -s subs.json -o header_audit.html

Advanced options:
# Generate default rules template
python3 headerhunter.py --generate-rules > custom_rules.yaml

# Use custom rules file
python3 headerhunter.py -u https://example.com --rules custom_rules.yaml

# Adjust thread count for performance
python3 headerhunter.py -u https://example.com -t 20


# Generate default rules template
python3 headerhunter.py --generate-rules > custom_rules.yaml

# Use custom rules file
python3 headerhunter.py -u https://example.com --rules custom_rules.yaml

# Adjust thread count for performance
python3 headerhunter.py -u https://example.com -t 20

Sample Output:
 _   _ _____ _____ _____ _____ _____ 
  | | | |_   _|_   _|  __ \_   _|  __ \
  | |_| | | |   | | | |__) || | | |__) |
  |  _  | | |   | | |  _  / | | |  ___/
  | | | |_| |_ _| |_| | \ \_| |_| |    
  \_| |_/\_____|\_____|_|  \_____|_|    
                                        
    HTTP Security Header Auditor
    
⚠️  For authorized use only. Respect privacy & laws.

[+] Loaded 1 target(s) for analysis
[*] Using security rules: Custom
[*] Analyzing: https://example.com
[!] Issues found for https://example.com:
  • CRITICAL: Content-Security-Policy - Missing security header
  • CRITICAL: Strict-Transport-Security - Missing security header
  • HIGH: X-Frame-Options - Missing security header
  • HIGH: X-Content-Type-Options - Missing security header
  • HIGH: Referrer-Policy - Missing security header
  • MEDIUM: Permissions-Policy - Missing security header
  • MEDIUM: Cross-Origin-Embedder-Policy - Missing security header
  • MEDIUM: Cross-Origin-Opener-Policy - Missing security header
  • LOW: Cross-Origin-Resource-Policy - Missing security header
  • LOW: Server - Header should be removed: cloudflare
  • LOW: X-Powered-By - Header should be removed: PHP/7.1.33
[*] HTML report saved to: headerhunter_report.html

==================================================
✅ Audit Complete
• Total targets analyzed: 1
• Total security issues found: 11
• Critical issues: 2

🚨 CRITICAL ISSUES FOUND - Immediate attention required!

📄 Report saved to: headerhunter_report.html
💡 Tip: Open the HTML report in a web browser for interactive analysis
💡 Tip: To customize security rules, use: python3 headerhunter.py 
--generate-rules > my_rules.yaml



Requirements 

Python 3.7+
Dependencies:
httpx[http2]
PyYAML
beautifulsoup        
rich
         
     

Ethical Use 

HTTPHeaderHunter must only be used: 

    On systems you own
    With explicit written permission from the system owner
    In compliance with all applicable laws and regulations
     

Unauthorized scanning may violate: 

    Computer Fraud and Abuse Act (CFAA)
    General Data Protection Regulation (GDPR)
    Local cybercrime laws
     

License 

This project is licensed under the MIT License - see the LICENSE  file for details. 
 

HTTPHeaderHunter - Making web security accessible and actionable
Developed with care by HK101-cyber for the security community
```

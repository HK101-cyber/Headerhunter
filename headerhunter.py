#!/usr/bin/env python3
"""
HTTPHeaderHunter - Advanced HTTP Security Header Auditor
Author: HK101-cyber
GitHub: https://github.com/HK101-cyber/headerhunter
License: MIT

⚠️ ETHICAL REMINDER:
This tool is for authorized security testing ONLY.
Never scan domains you don't own or don't have explicit permission to test.
Misuse may violate laws like the CFAA, GDPR, or local cybercrime statutes.
"""

import argparse
import asyncio
import json
import os
import re
import sys
import time
from datetime import datetime
import yaml
import httpx
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

# === BANNER ===
def print_banner():
    banner = r"""
   _   _ _____ _____ _____ _____ _____ 
  | | | |_   _|_   _|  __ \_   _|  __ \
  | |_| | | |   | | | |__) || | | |__) |
  |  _  | | |   | | |  _  / | | |  ___/
  | | | |_| |_ _| |_| | \ \_| |_| |    
  \_| |_/\_____|\_____|_|  \_____|_|    
                                        
    HTTP Security Header Auditor
    """
    console.print(f"[bold cyan]{banner}[/bold cyan]")
    console.print("[bold yellow]⚠️  For authorized use only. Respect privacy & laws.[/bold yellow]\n")

# === DEFAULT EMBEDDED RULES (Fallback) ===
EMBEDDED_DEFAULT_RULES = """
# HTTPHeaderHunter - Default Security Rules
# 
# This file defines security checks for HTTP headers based on OWASP Secure Headers Project
# Each rule specifies:
#   - name: Header name to check
#   - severity: CRITICAL, HIGH, MEDIUM, LOW, INFO
#   - description: What the header does and why it matters
#   - check: Type of check (missing, present, value)
#   - recommendation: How to fix the issue
#
# For custom rules: Copy this file, modify as needed, and use with --rules flag

# ===== CRITICAL SECURITY HEADERS =====
# These headers prevent high-impact attacks like XSS, SSL stripping, and data theft

rules:
  # Content Security Policy (CSP) - Prevents XSS attacks
  - name: "Content-Security-Policy"
    severity: "CRITICAL"
    description: "Prevents cross-site scripting (XSS) attacks by controlling which resources can be loaded"
    check: "missing"
    recommendation: |
      Implement strict CSP policy:
      Content-Security-Policy: default-src 'self'; script-src 'self' https://*.trusted.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: https://*

  # HTTP Strict Transport Security (HSTS) - Enforces HTTPS
  - name: "Strict-Transport-Security"
    severity: "CRITICAL"
    description: "Forces browsers to use HTTPS only, preventing SSL-stripping attacks"
    check: "missing"
    recommendation: |
      Enable HSTS with long max-age:
      Strict-Transport-Security: max-age=31536000; includeSubDomains; preload

  # X-Frame-Options - Prevents clickjacking
  - name: "X-Frame-Options"
    severity: "HIGH"
    description: "Prevents clickjacking attacks by controlling if page can be embedded in frames"
    check: "missing"
    recommendation: |
      Block all framing:
      X-Frame-Options: DENY
      
      OR allow same-origin only:
      X-Frame-Options: SAMEORIGIN

# ===== HIGH PRIORITY SECURITY HEADERS =====
# These headers mitigate common web vulnerabilities

  # X-Content-Type-Options - Prevents MIME-sniffing
  - name: "X-Content-Type-Options"
    severity: "HIGH"
    description: "Prevents browsers from MIME-sniffing content types, reducing XSS risks"
    check: "missing"
    recommendation: |
      Disable MIME-sniffing:
      X-Content-Type-Options: nosniff

  # Referrer-Policy - Controls referrer information
  - name: "Referrer-Policy"
    severity: "HIGH"
    description: "Controls how much referrer information is sent with requests, protecting sensitive URLs"
    check: "missing"
    recommendation: |
      Send referrer only for same-origin requests:
      Referrer-Policy: strict-origin-when-cross-origin
      
      OR be more restrictive:
      Referrer-Policy: no-referrer

  # Permissions-Policy - Controls browser features
  - name: "Permissions-Policy"
    severity: "MEDIUM"
    description: "Controls access to browser features like camera, microphone, geolocation"
    check: "missing"
    recommendation: |
      Disable all sensitive features:
      Permissions-Policy: geolocation=(), camera=(), microphone=(), fullscreen=(), payment=()

# ===== MODERN SECURITY HEADERS =====
# These headers provide additional isolation and protection

  # Cross-Origin-Embedder-Policy (COEP)
  - name: "Cross-Origin-Embedder-Policy"
    severity: "MEDIUM"
    description: "Prevents loading of cross-origin resources without explicit permission"
    check: "missing"
    recommendation: |
      Require cross-origin resources to opt-in:
      Cross-Origin-Embedder-Policy: require-corp

  # Cross-Origin-Opener-Policy (COOP)
  - name: "Cross-Origin-Opener-Policy"
    severity: "MEDIUM"
    description: "Isolates browsing context from other origins, preventing cross-origin attacks"
    check: "missing"
    recommendation: |
      Block cross-origin window access:
      Cross-Origin-Opener-Policy: same-origin

  # Cross-Origin-Resource-Policy (CORP)
  - name: "Cross-Origin-Resource-Policy"
    severity: "LOW"
    description: "Blocks cross-origin resource loading"
    check: "missing"
    recommendation: |
      Block all cross-origin requests:
      Cross-Origin-Resource-Policy: same-origin

# ===== INFORMATION DISCLOSURE HEADERS =====
# These headers leak sensitive information about server technology

  # Server header - Reveals server software
  - name: "Server"
    severity: "LOW"
    description: "Reveals server software and version information, aiding attackers"
    check: "present"
    recommendation: |
      Remove or sanitize Server header:
      Server: (remove completely or set to generic value)

  # X-Powered-By header - Reveals backend technology
  - name: "X-Powered-By"
    severity: "LOW"
    description: "Reveals backend technology stack, making targeted attacks easier"
    check: "present"
    recommendation: |
      Remove X-Powered-By header completely

# ===== VALUE-BASED CHECKS =====
# These rules check specific patterns or values within headers

value_checks:
  # HSTS max-age should be at least 1 year
  - name: "Strict-Transport-Security"
    pattern: 'max-age=(\\d+)'
    min_value: 31536000
    severity: "MEDIUM"
    description: "HSTS max-age should be at least 1 year (31536000 seconds) for effective protection"
    recommendation: |
      Increase max-age value:
      Strict-Transport-Security: max-age=31536000; includeSubDomains

  # CSP should not contain unsafe directives
  - name: "Content-Security-Policy"
    patterns:
      - "'unsafe-inline'"
      - "'unsafe-eval'"
      - "http://"
    severity: "HIGH"
    description: "CSP contains unsafe directives that weaken protection"
    recommendation: |
      Remove unsafe directives and use nonces/hashes instead:
      Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-random123'; style-src 'self'
"""

def load_rules(rules_file=None, generate_rules=False):
    """Load security rules from file or use defaults with comprehensive error handling"""
    
    # If user wants to generate rules, output the embedded default rules
    if generate_rules:
        print(EMBEDDED_DEFAULT_RULES.strip())
        sys.exit(0)
    
    # Try to load from custom rules file first
    if rules_file and os.path.exists(rules_file):
        try:
            with open(rules_file, 'r') as f:
                content = f.read()
                return yaml.safe_load(content)
        except yaml.YAMLError as e:
            console.print(f"[red][!] YAML parsing error in rules file '{rules_file}': {e}[/red]")
            console.print("[yellow][*] Falling back to default rules...[/yellow]")
        except Exception as e:
            console.print(f"[red][!] Error loading rules file '{rules_file}': {e}[/red]")
            console.print("[yellow][*] Falling back to default rules...[/yellow]")
    
    # Try to load from default_rules.yaml in current directory
    default_rules_path = "default_rules.yaml"
    if os.path.exists(default_rules_path):
        try:
            with open(default_rules_path, 'r') as f:
                content = f.read()
                return yaml.safe_load(content)
        except yaml.YAMLError as e:
            console.print(f"[red][!] YAML parsing error in '{default_rules_path}': {e}[/red]")
            console.print("[yellow][*] Using embedded default rules...[/yellow]")
        except Exception as e:
            console.print(f"[red][!] Error loading '{default_rules_path}': {e}[/red]")
            console.print("[yellow][*] Using embedded default rules...[/yellow]")
    
    # Fall back to embedded default rules
    console.print("[yellow][*] Using embedded default security rules[/yellow]")
    try:
        return yaml.safe_load(EMBEDDED_DEFAULT_RULES)
    except yaml.YAMLError as e:
        console.print(f"[red][!] FATAL: Error parsing embedded default rules: {e}[/red]")
        console.print("[red][!] This should never happen. Please report this bug.[/red]")
        sys.exit(1)

async def fetch_url(client, url, follow_redirects=True):
    """Fetch URL with error handling"""
    try:
        response = await client.get(
            url, 
            follow_redirects=follow_redirects,
            timeout=10.0,
            headers={
                'User-Agent': 'HTTPHeaderHunter/1.0 (Security Auditor)',
                'Accept': 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.8'
            }
        )
        return response
    except httpx.ConnectTimeout:
        return {'error': 'Connection timeout'}
    except httpx.ConnectError:
        return {'error': 'Connection error'}
    except httpx.ReadTimeout:
        return {'error': 'Read timeout'}
    except httpx.HTTPStatusError as e:
        return {'error': f'HTTP error {e.response.status_code}'}
    except Exception as e:
        return {'error': f'Unexpected error: {str(e)}'}

def analyze_headers(headers, rules):
    """Analyze HTTP headers against security rules with error handling"""
    findings = []
    headers_lower = {k.lower(): v for k, v in headers.items()}
    
    # Check each rule
    for rule_index, rule in enumerate(rules.get('rules', [])):
        try:
            header_name = rule['name'].lower()
            severity = rule['severity']
            
            if rule['check'] == 'missing':
                if header_name not in headers_lower:
                    findings.append({
                        'header': rule['name'],
                        'severity': severity,
                        'issue': 'Missing security header',
                        'recommendation': rule['recommendation'],
                        'current_value': 'N/A'
                    })
            
            elif rule['check'] == 'present':
                if header_name in headers_lower:
                    findings.append({
                        'header': rule['name'],
                        'severity': severity,
                        'issue': f'Header should be removed: {headers_lower[header_name]}',
                        'recommendation': rule['recommendation'],
                        'current_value': headers_lower[header_name]
                    })
            
            elif rule['check'] == 'value':
                if header_name in headers_lower:
                    current_value = headers_lower[header_name]
                    if rule.get('expected_value') and current_value != rule['expected_value']:
                        findings.append({
                            'header': rule['name'],
                            'severity': severity,
                            'issue': f'Incorrect value: {current_value}',
                            'recommendation': rule['recommendation'],
                            'current_value': current_value
                        })
        except Exception as e:
            console.print(f"[yellow][!] Error processing rule #{rule_index} ({rule.get('name', 'unknown')}): {e}[/yellow]")
            continue
    
    # Check value patterns
    for vc_index, value_check in enumerate(rules.get('value_checks', [])):
        try:
            header_name = value_check['name'].lower()
            if header_name in headers_lower:
                current_value = headers_lower[header_name]
                
                if 'pattern' in value_check:
                    # Single pattern check
                    pattern = value_check['pattern']
                    try:
                        match = re.search(pattern, current_value, re.IGNORECASE)
                        if match:
                            findings.append({
                                'header': value_check['name'],
                                'severity': value_check['severity'],
                                'issue': value_check['description'],
                                'recommendation': value_check.get('recommendation', 'Review header configuration'),
                                'current_value': current_value
                            })
                    except re.error as e:
                        console.print(f"[yellow][!] Invalid regex pattern '{pattern}' in value check: {e}[/yellow]")
                
                elif 'patterns' in value_check:
                    # Multiple pattern checks
                    for pattern in value_check['patterns']:
                        try:
                            if re.search(pattern, current_value, re.IGNORECASE):
                                findings.append({
                                    'header': value_check['name'],
                                    'severity': value_check['severity'],
                                    'issue': value_check['description'],
                                    'recommendation': value_check.get('recommendation', 'Review header configuration'),
                                    'current_value': current_value
                                })
                                break
                        except re.error as e:
                            console.print(f"[yellow][!] Invalid regex pattern '{pattern}' in value check: {e}[/yellow]")
        except Exception as e:
            console.print(f"[yellow][!] Error processing value check #{vc_index} ({value_check.get('name', 'unknown')}): {e}[/yellow]")
            continue
    
    return findings

def generate_html_report(results, output_file):
    """Generate HTML report with security findings"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Count findings by severity
    severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
    for result in results:
        for finding in result.get('findings', []):
            severity = finding['severity']
            if severity in severity_counts:
                severity_counts[severity] += 1
    
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>HTTPHeaderHunter Report - {timestamp}</title>
        <style>
            :root {{
                --critical: #dc2626;
                --high: #f59e0b;
                --medium: #eab308;
                --low: #84cc16;
                --info: #3b82f6;
                --safe: #10b981;
            }}
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                line-height: 1.6;
                color: #333;
                max-width: 1200px;
                margin: 0 auto;
                padding: 20px;
                background-color: #f5f5f5;
            }}
            .header {{
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 30px;
                border-radius: 10px;
                margin-bottom: 30px;
                text-align: center;
                box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            }}
            .summary {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                margin: 30px 0;
            }}
            .summary-card {{
                background: white;
                padding: 20px;
                border-radius: 8px;
                text-align: center;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }}
            .summary-card.critical {{ border-top: 4px solid var(--critical); }}
            .summary-card.high {{ border-top: 4px solid var(--high); }}
            .summary-card.medium {{ border-top: 4px solid var(--medium); }}
            .summary-card.low {{ border-top: 4px solid var(--low); }}
            .result {{
                background: white;
                margin-bottom: 20px;
                border-radius: 8px;
                overflow: hidden;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }}
            .result-header {{
                padding: 15px 20px;
                background-color: #f8f9fa;
                border-bottom: 1px solid #eee;
                cursor: pointer;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }}
            .result-content {{
                padding: 20px;
                display: none;
            }}
            .result-content.show {{
                display: block;
            }}
            .finding {{
                margin-bottom: 15px;
                padding-bottom: 15px;
                border-bottom: 1px solid #eee;
            }}
            .finding:last-child {{
                border-bottom: none;
                margin-bottom: 0;
                padding-bottom: 0;
            }}
            .severity {{
                padding: 3px 8px;
                border-radius: 4px;
                font-weight: bold;
                font-size: 0.85em;
            }}
            .severity.CRITICAL {{ background-color: var(--critical); color: white; }}
            .severity.HIGH {{ background-color: var(--high); color: white; }}
            .severity.MEDIUM {{ background-color: var(--medium); color: white; }}
            .severity.LOW {{ background-color: var(--low); color: white; }}
            .severity.INFO {{ background-color: var(--info); color: white; }}
            .recommendation {{
                background-color: #e3f2fd;
                padding: 10px;
                border-radius: 4px;
                margin-top: 8px;
                font-style: italic;
            }}
            .footer {{
                text-align: center;
                margin-top: 40px;
                color: #666;
                font-size: 0.9em;
            }}
            .toggle-all {{
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 5px;
                cursor: pointer;
                margin: 20px 0;
            }}
            .rules-info {{
                background: #e8f4ff;
                border-left: 4px solid #3b82f6;
                padding: 15px;
                margin: 20px 0;
                border-radius: 0 8px 8px 0;
            }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>HTTPHeaderHunter</h1>
            <p>HTTP Security Header Audit Report</p>
            <p><strong>Scan Date:</strong> {timestamp}</p>
            <p><strong>Targets Scanned:</strong> {len(results)}</p>
            <div class="rules-info">
                <strong>💡 Rules Used:</strong> {('Custom rules file' if False else 'Default OWASP-based rules')}
                <br>
                <small>To customize rules: Create a YAML file with your security policies and use <code>--rules your_rules.yaml</code></small>
            </div>
        </div>

        <div class="summary">
            <div class="summary-card critical">
                <h3>CRITICAL</h3>
                <p style="font-size: 2em; font-weight: bold;">{severity_counts['CRITICAL']}</p>
                <p>Issues requiring immediate attention</p>
            </div>
            <div class="summary-card high">
                <h3>HIGH</h3>
                <p style="font-size: 2em; font-weight: bold;">{severity_counts['HIGH']}</p>
                <p>Significant security risks</p>
            </div>
            <div class="summary-card medium">
                <h3>MEDIUM</h3>
                <p style="font-size: 2em; font-weight: bold;">{severity_counts['MEDIUM']}</p>
                <p>Moderate security concerns</p>
            </div>
            <div class="summary-card low">
                <h3>LOW</h3>
                <p style="font-size: 2em; font-weight: bold;">{severity_counts['LOW']}</p>
                <p>Minor security improvements</p>
            </div>
        </div>

        <button class="toggle-all" onclick="toggleAllResults()">Expand All Results</button>

        <div class="results">
    """
    
    # Add each result
    for i, result in enumerate(results):
        url = result.get('url', 'Unknown URL')
        status_code = result.get('status_code', 'N/A')
        error = result.get('error')
        findings = result.get('findings', [])
        
        html_content += f"""
            <div class="result">
                <div class="result-header" onclick="toggleResult(this)">
                    <strong>{url}</strong>
                    <span style="color: {'#dc2626' if error else '#10b981'};">
                        {status_code if not error else error}
                    </span>
                </div>
                <div class="result-content">
        """
        
        if error:
            html_content += f"""
                    <p class="error" style="color: #dc2626;">❌ {error}</p>
            """
        else:
            if findings:
                html_content += f"""
                    <p><strong>Security Issues Found: {len(findings)}</strong></p>
                """
                for finding in findings:
                    severity_class = finding['severity'].upper()
                    html_content += f"""
                    <div class="finding">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <strong>{finding['header']}</strong>
                            <span class="severity {severity_class}">{finding['severity']}</span>
                        </div>
                        <p>{finding['issue']}</p>
                        <p><strong>Current Value:</strong> {finding['current_value']}</p>
                        <div class="recommendation">
                            <strong>Recommendation:</strong> {finding['recommendation']}
                        </div>
                    </div>
                    """
            else:
                html_content += """
                    <p style="color: #10b981;">✅ No security header issues found!</p>
                    <p>All critical security headers are properly configured.</p>
                """
        
        html_content += """
                </div>
            </div>
        """
    
    # Close HTML
    html_content += f"""
        </div>

        <div class="footer">
            <p>HTTPHeaderHunter v1.0 - Security Header Auditor</p>
            <p>Report generated on {timestamp}</p>
            <p style="color: #dc2626; font-weight: bold;">⚠️ This report is for authorized security testing only. Do not share without permission.</p>
            <p><small>To generate default rules template: <code>python3 headerhunter.py --generate-rules > default_rules.yaml</code></small></p>
        </div>

        <script>
            function toggleResult(element) {{
                const content = element.nextElementSibling;
                content.classList.toggle('show');
                const isExpanded = content.classList.contains('show');
                const arrowSpan = element.querySelector('span:last-child');
                if (arrowSpan) {{
                    arrowSpan.textContent = isExpanded ? '▼' : '▶';
                }}
            }}
            
            function toggleAllResults() {{
                const button = document.querySelector('.toggle-all');
                const results = document.querySelectorAll('.result-content');
                const headers = document.querySelectorAll('.result-header');
                
                if (results.length === 0) return;
                
                const isCurrentlyExpanded = results[0].classList.contains('show');
                const shouldExpand = !isCurrentlyExpanded;
                
                button.textContent = shouldExpand ? 'Collapse All Results' : 'Expand All Results';
                
                results.forEach(result => {{
                    result.classList.toggle('show', shouldExpand);
                }});
                
                headers.forEach(header => {{
                    const arrowSpan = header.querySelector('span:last-child');
                    if (arrowSpan) {{
                        arrowSpan.textContent = shouldExpand ? '▼' : '▶';
                    }}
                }});
            }}
        </script>
    </body>
    </html>
    """
    
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        console.print(f"[cyan][*] HTML report saved to: {output_file}[/cyan]")
        return True
    except Exception as e:
        console.print(f"[red][!] Failed to save HTML report: {e}[/red]")
        return False

async def analyze_target(client, url, rules, results):
    """Analyze a single target URL"""
    console.print(f"[blue][*] Analyzing: {url}[/blue]")
    
    try:
        response = await fetch_url(client, url)
        
        if isinstance(response, dict) and 'error' in response:
            results.append({
                'url': url,
                'error': response['error'],
                'findings': []
            })
            console.print(f"[yellow][!] {url}: {response['error']}[/yellow]")
            return
        
        # Get headers (case-insensitive)
        headers = dict(response.headers)
        status_code = response.status_code
        
        # Analyze headers
        findings = analyze_headers(headers, rules)
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        
        for finding in findings:
            severity = finding['severity']
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Create result entry
        result = {
            'url': url,
            'status_code': status_code,
            'headers': headers,
            'findings': findings,
            'severity_counts': severity_counts
        }
        results.append(result)
        
        # Display findings
        if findings:
            console.print(f"[red][!] Issues found for {url}:[/red]")
            for finding in findings:
                color = {
                    'CRITICAL': 'bold red',
                    'HIGH': 'bold yellow',
                    'MEDIUM': 'bold orange1',
                    'LOW': 'bold blue'
                }.get(finding['severity'], 'bold white')
                
                console.print(f"  • [{color}]{finding['severity']}[/]: {finding['header']} - {finding['issue']}")
        else:
            console.print(f"[green][✓] No security header issues found for {url}[/green]")
            
    except Exception as e:
        console.print(f"[red][!] Error analyzing {url}: {e}[/red]")
        results.append({
            'url': url,
            'error': str(e),
            'findings': []
        })

async def main():
    print_banner()
    
    parser = argparse.ArgumentParser(
        description="HTTPHeaderHunter - Advanced HTTP Security Header Auditor",
        epilog="Example: headerhunter.py -u https://example.com -o report.html"
    )
    
    input_group = parser.add_argument_group('Input Options')
    input_group.add_argument("-u", "--url", help="Single URL to analyze (e.g., https://example.com)")
    input_group.add_argument("-f", "--file", help="File containing URLs to analyze (one per line)")
    input_group.add_argument("-s", "--subsnatch", help="SubSnatch JSON output file to analyze")
    
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument("-o", "--output", default="headerhunter_report.html", help="Output HTML report file")
    output_group.add_argument("--rules", help="Custom YAML rules file (default: default_rules.yaml)")
    
    config_group = parser.add_argument_group('Configuration')
    config_group.add_argument("-t", "--threads", type=int, default=10, help="Max concurrent requests (default: 10)")
    config_group.add_argument("--follow-redirects", action="store_true", help="Follow HTTP redirects")
    config_group.add_argument("--no-color", action="store_true", help="Disable colored output")
    config_group.add_argument("--generate-rules", action="store_true", help="Generate default rules template to stdout")
    
    args = parser.parse_args()
    
    # Handle --generate-rules first
    if args.generate_rules:
        load_rules(generate_rules=True)
    
    # Load security rules
    rules = load_rules(args.rules)
    
    # Get target URLs
    urls = []
    
    if args.url:
        urls = [args.url]
    elif args.file:
        if not os.path.exists(args.file):
            console.print(f"[red][!] URL file not found: {args.file}[/red]")
            sys.exit(1)
        with open(args.file, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
    elif args.subsnatch:
        if not os.path.exists(args.subsnatch):
            console.print(f"[red][!] SubSnatch file not found: {args.subsnatch}[/red]")
            sys.exit(1)
        try:
            with open(args.subsnatch, 'r') as f:
                subsnatch_data = json.load(f)
                urls = [item.get('url') for item in subsnatch_data if item.get('url')]
        except Exception as e:
            console.print(f"[red][!] Error loading SubSnatch file: {e}[/red]")
            sys.exit(1)
    else:
        console.print("[red][!] No input provided. Use -u, -f, or -s[/red]")
        parser.print_help()
        sys.exit(1)
    
    if not urls:
        console.print("[red][!] No valid URLs to analyze[/red]")
        sys.exit(1)
    
    console.print(f"[bold green][+] Loaded {len(urls)} target(s) for analysis[/bold green]")
    console.print(f"[blue][*] Using security rules: {'Custom' if args.rules else 'Default (OWASP-based)'}[/blue]")
    
    # Analyze targets
    results = []
    semaphore = asyncio.Semaphore(args.threads)
    
    async def bounded_analyze(url):
        async with semaphore:
            async with httpx.AsyncClient(http2=True, verify=False, timeout=15.0) as client:
                await analyze_target(client, url, rules, results)
    
    tasks = [bounded_analyze(url) for url in urls]
    await asyncio.gather(*tasks)
    
    # Generate report
    if results:
        generate_html_report(results, args.output)
        
        # Final summary
        total_targets = len(results)
        total_issues = sum(len(r.get('findings', [])) for r in results)
        critical_issues = sum(1 for r in results for f in r.get('findings', []) if f.get('severity') == 'CRITICAL')
        
        console.print(f"\n[bold magenta]{'='*50}[/bold magenta]")
        console.print(f"[bold cyan]✅ Audit Complete[/bold cyan]")
        console.print(f"• Total targets analyzed: {total_targets}")
        console.print(f"• Total security issues found: [bold red]{total_issues}[/bold red]")
        console.print(f"• Critical issues: [bold red]{critical_issues}[/bold red]")
        
        if critical_issues > 0:
            console.print("\n[bold red]🚨 CRITICAL ISSUES FOUND - Immediate attention required![/bold red]")
        else:
            console.print("\n[bold green]✅ No critical security issues found![/bold green]")
        
        console.print(f"\n[bold cyan]📄 Report saved to: {args.output}[/bold cyan]")
        console.print("[bold yellow]💡 Tip: Open the HTML report in a web browser for interactive analysis[/bold yellow]")
        console.print("[bold blue]💡 Tip: To customize security rules, use: python3 headerhunter.py --generate-rules > my_rules.yaml[/bold blue]")
    else:
        console.print("[yellow][!] No results to report[/yellow]")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[yellow][!] Audit interrupted by user.[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red][!] Fatal error: {e}[/red]")
        sys.exit(1)

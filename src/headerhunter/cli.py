"""Command-line interface."""
import argparse, asyncio, sys
from headerhunter import __version__
from headerhunter.config import Config
from headerhunter.inputs import load_url, load_url_file, load_subsnatch
from headerhunter.rules import load_rules, generate_default_rules
from headerhunter.scanner import scan_targets
from headerhunter.reports.html import generate_html_report

def main() -> int:
    p = argparse.ArgumentParser(prog="headerhunter", description="HTTPHeaderHunter - Defensive HTTP security-header auditor")
    p.add_argument("--version", action="version", version=f"HTTPHeaderHunter {__version__}")
    p.add_argument("-u", "--url", help="Single URL to scan")
    p.add_argument("-f", "--file", help="File containing URLs")
    p.add_argument("-s", "--subsnatch", help="SubSnatch JSON file")
    p.add_argument("-o", "--output", help="Output HTML report file")
    p.add_argument("--rules", help="Custom YAML rules file")
    p.add_argument("-t", "--threads", type=int, default=10)
    p.add_argument("--timeout", type=float, default=15.0)
    p.add_argument("--follow-redirects", action="store_true")
    p.add_argument("--insecure", action="store_true")
    p.add_argument("--generate-rules", action="store_true")
    args = p.parse_args()

    if args.generate_rules: generate_default_rules(); return 0
    if len([x for x in [args.url, args.file, args.subsnatch] if x]) != 1:
        print("[!] Exactly one input source (-u, -f, or -s) must be selected.", file=sys.stderr); return 1
    if args.threads <= 0 or args.timeout <= 0:
        print("[!] Threads and timeout must be positive.", file=sys.stderr); return 1

    rules = load_rules(args.rules)
    try:
        urls = load_url(args.url) if args.url else (load_url_file(args.file) if args.file else load_subsnatch(args.subsnatch))
    except SystemExit: return 1

    config = Config(threads=args.threads, timeout=args.timeout, follow_redirects=args.follow_redirects, verify_tls=not args.insecure)
    try: results = asyncio.run(scan_targets(urls, rules, config))
    except KeyboardInterrupt: print("\n[!] Interrupted.", file=sys.stderr); return 130
    except Exception as e: print(f"[!] Error: {e}", file=sys.stderr); return 1

    if args.output:
        generate_html_report(results, args.output, "Custom" if args.rules else "Default")
        print(f"[*] Report saved to {args.output}")
    return 0

if __name__ == "__main__": sys.exit(main())

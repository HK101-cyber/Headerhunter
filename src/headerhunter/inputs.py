"""Input loading and URL validation."""
import json
import os
import sys
from typing import List
from urllib.parse import urlparse

def validate_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"): return False
        if not parsed.netloc: return False
        return True
    except Exception: return False

def load_url(url: str) -> List[str]:
    if not validate_url(url):
        print(f"[!] Invalid URL: {url}", file=sys.stderr)
        sys.exit(1)
    return [url]

def load_url_file(filepath: str) -> List[str]:
    if not os.path.exists(filepath):
        print(f"[!] URL file not found: {filepath}", file=sys.stderr)
        sys.exit(1)
    urls = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"): continue
            if not validate_url(stripped):
                print(f"[!] Invalid URL on line {line_num}: {stripped}", file=sys.stderr)
                sys.exit(1)
            urls.append(stripped)
    if not urls:
        print("[!] No valid URLs found in file.", file=sys.stderr)
        sys.exit(1)
    return urls

def load_subsnatch(filepath: str) -> List[str]:
    if not os.path.exists(filepath):
        print(f"[!] SubSnatch file not found: {filepath}", file=sys.stderr)
        sys.exit(1)
    try:
        with open(filepath, "r", encoding="utf-8") as f: data = json.load(f)
    except Exception as e:
        print(f"[!] Error parsing SubSnatch JSON: {e}", file=sys.stderr)
        sys.exit(1)
    if not isinstance(data, list):
        print("[!] SubSnatch JSON must be a list.", file=sys.stderr)
        sys.exit(1)
    urls = []
    for item in data:
        if isinstance(item, dict) and "url" in item:
            url = item["url"]
            if validate_url(url): urls.append(url)
    if not urls:
        print("[!] No valid URLs found in SubSnatch file.", file=sys.stderr)
        sys.exit(1)
    return urls

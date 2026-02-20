#!/usr/bin/env python3
"""
V1B3 Scanner — Ethical vibe-code vulnerability scanner
Finds exposed secrets in publicly accessible web apps.
Never exploits. Always notifies.
"""

import requests
import sys
import json
import re
from urllib.parse import urlparse

HEADERS = {"User-Agent": "V1B3-SecurityResearch/1.0 (ethical scanner; contact via github.com/Shree-git)"}

# Paths to check for common vibe-code mistakes
SENSITIVE_PATHS = [
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.development",
    "/.git/config",
    "/.git/HEAD",
    "/config.json",
    "/config.js",
    "/secrets.json",
    "/app.config.js",
    "/backup.sql",
    "/database.sql",
    "/dump.sql",
    "/admin",
    "/wp-admin",
    "/phpmyadmin",
]

# Patterns that indicate leaked secrets in JS bundles or HTML
SECRET_PATTERNS = [
    (r'sk-[a-zA-Z0-9]{48}', 'OpenAI API Key'),
    (r'sk_live_[a-zA-Z0-9]{24,}', 'Stripe Live Secret Key'),
    (r'rk_live_[a-zA-Z0-9]{24,}', 'Stripe Restricted Key'),
    (r'AKIA[0-9A-Z]{16}', 'AWS Access Key'),
    (r'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+', 'JWT Token'),
    (r'ghp_[a-zA-Z0-9]{36}', 'GitHub Personal Access Token'),
    (r'xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}', 'Slack Bot Token'),
    (r'AIza[0-9A-Za-z\-_]{35}', 'Google API Key'),
    (r'service_role["\s:]+ey[a-zA-Z0-9_-]{50,}', 'Supabase Service Role Key'),
]

findings = []

def check_path(base_url, path):
    url = base_url.rstrip('/') + path
    try:
        r = requests.get(url, headers=HEADERS, timeout=8, allow_redirects=False)
        if r.status_code == 200 and len(r.text) > 10:
            return r.status_code, r.text[:2000]
    except Exception:
        pass
    return None, None

def scan_for_secrets(content, source):
    found = []
    for pattern, name in SECRET_PATTERNS:
        matches = re.findall(pattern, content)
        if matches:
            found.append({"type": name, "source": source, "count": len(matches)})
    return found

def scan(target_url):
    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    print(f"\n[V1B3] Scanning: {base}\n{'='*50}")

    # Check sensitive paths
    for path in SENSITIVE_PATHS:
        status, content = check_path(base, path)
        if status == 200:
            print(f"[!] EXPOSED: {path} (HTTP 200)")
            secrets = scan_for_secrets(content, path)
            findings.append({
                "url": base + path,
                "type": "exposed_path",
                "path": path,
                "secrets": secrets,
                "snippet": content[:300]
            })
            if secrets:
                for s in secrets:
                    print(f"    └─ 🔴 {s['type']} found in {s['source']}")
        else:
            print(f"[ ] {path} — safe")

    # Check main page JS for secrets
    try:
        r = requests.get(base, headers=HEADERS, timeout=8)
        secrets = scan_for_secrets(r.text, "index page")
        if secrets:
            print(f"\n[!] Secrets in main page source:")
            for s in secrets:
                print(f"    └─ 🔴 {s['type']}")
            findings.append({"url": base, "type": "inline_secret", "secrets": secrets})
    except Exception:
        pass

    return findings

def report(findings):
    print(f"\n{'='*50}")
    print(f"[V1B3] Scan complete. {len(findings)} finding(s).\n")
    if findings:
        print(json.dumps(findings, indent=2))
        print("\n[V1B3] Next step: Draft disclosure email to site owner.")
    else:
        print("[V1B3] All clear. No exposed paths or secrets found.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 scan.py <target_url>")
        print("Example: python3 scan.py https://example.com")
        sys.exit(1)
    target = sys.argv[1]
    results = scan(target)
    report(results)

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

# Additional paths for self-hosted / raw VPS apps
EXTRA_PATHS = [
    "/.env.bak",
    "/.env.backup",
    "/api/.env",
    "/backend/.env",
    "/server/.env",
    "/.git/refs/heads/main",
    "/wp-config.php",
    "/configuration.php",
    "/config/database.yml",
    "/application.yml",
    "/.htpasswd",
    "/server.js",
    "/app.js",
    "/index.php",
    "/info.php",
    "/phpinfo.php",
]

def check_graphql(base_url):
    """Check for open GraphQL introspection."""
    endpoints = ["/graphql", "/api/graphql", "/v1/graphql", "/gql"]
    introspection = '{"query":"{__schema{queryType{name}}}"}'
    for ep in endpoints:
        try:
            r = requests.post(base_url.rstrip('/') + ep,
                headers={**HEADERS, "Content-Type": "application/json"},
                data=introspection, timeout=6)
            if r.status_code == 200 and "__schema" in r.text:
                return ep
        except Exception:
            pass
    return None

def check_cors(base_url):
    """Check for overly permissive CORS."""
    try:
        r = requests.options(base_url, headers={**HEADERS, "Origin": "https://evil.com"}, timeout=6)
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "")
        if acao == "*" or (acao == "https://evil.com" and acac.lower() == "true"):
            return acao
    except Exception:
        pass
    return None

def extract_js_urls(base_url, html):
    """Extract all JS bundle URLs from a page's HTML source."""
    import re
    from urllib.parse import urljoin
    pattern = r'src=["\']([^"\']*\.js(?:\?[^"\']*)?)["\']'
    matches = re.findall(pattern, html)
    urls = []
    for m in matches:
        if m.startswith('http'):
            urls.append(m)
        elif m.startswith('//'):
            urls.append('https:' + m)
        elif m.startswith('/'):
            urls.append(base_url.rstrip('/') + m)
        else:
            urls.append(urljoin(base_url, m))
    # Also check for chunk files referenced in the bundle manifest
    chunk_pattern = r'["\']([^"\']*chunk[^"\']*\.js)["\']'
    for m in re.findall(chunk_pattern, html)[:5]:
        url = urljoin(base_url, m) if not m.startswith('http') else m
        if url not in urls:
            urls.append(url)
    return list(dict.fromkeys(urls))  # deduplicate

def get_spa_fingerprint(base_url):
    """
    Detect SPA catch-all by hitting a random nonexistent path.
    If it returns 200 + HTML, this server serves index.html for all paths.
    Returns the fingerprint text to compare against, or None if not a SPA.
    """
    canary = base_url.rstrip('/') + '/v1b3-canary-nonexistent-xyz123456'
    try:
        r = requests.get(canary, headers=HEADERS, timeout=8, allow_redirects=True)
        if r.status_code == 200 and '<!DOCTYPE html' in r.text[:100]:
            return r.text[:300]  # SPA detected — return fallback fingerprint
    except Exception:
        pass
    return None

def check_path(base_url, path, spa_fp=None):
    url = base_url.rstrip('/') + path
    try:
        r = requests.get(url, headers=HEADERS, timeout=8, allow_redirects=False)
        if r.status_code == 200 and len(r.text) > 10:
            # SPA false positive: content matches the catch-all fallback
            if spa_fp and r.text[:300] == spa_fp:
                return None, None
            # Reject HTML responses for file paths (env, config, sql, etc.)
            content_type = r.headers.get('Content-Type', '')
            if 'html' in content_type and any(path.endswith(ext) for ext in
               ('.env', '.env.local', '.env.production', '.env.development',
                '.json', '.js', '.sql', 'HEAD', 'config')):
                return None, None
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

    # Detect SPA catch-all to avoid false positives
    spa_fp = get_spa_fingerprint(base)
    if spa_fp:
        print(f"[~] SPA detected — using canary filtering to avoid false positives")

    # Check GraphQL introspection
    gql_ep = check_graphql(base)
    if gql_ep:
        print(f"[!] GRAPHQL INTROSPECTION OPEN: {gql_ep}")
        findings.append({"url": base + gql_ep, "type": "graphql_introspection",
                         "path": gql_ep, "secrets": [], "snippet": ""})
    else:
        print(f"[ ] GraphQL introspection — safe")

    # Check CORS misconfiguration
    cors = check_cors(base)
    if cors:
        print(f"[!] CORS MISCONFIGURATION: Access-Control-Allow-Origin: {cors}")
        findings.append({"url": base, "type": "cors_misconfiguration",
                         "path": "/", "secrets": [], "snippet": f"ACAO: {cors}"})
    else:
        print(f"[ ] CORS — safe")

    # Check sensitive paths
    all_paths = SENSITIVE_PATHS + EXTRA_PATHS
    for path in all_paths:
        status, content = check_path(base, path, spa_fp=spa_fp)
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

    # Scan main page + all linked JS bundles
    try:
        r = requests.get(base, headers=HEADERS, timeout=8)

        # Check inline HTML source for secrets
        secrets = scan_for_secrets(r.text, "index page")
        if secrets:
            print(f"\n[!] Secrets in main page source:")
            for s in secrets:
                print(f"    └─ 🔴 {s['type']}")
            findings.append({"url": base, "type": "inline_secret", "secrets": secrets})

        # Extract and scan all JS bundle files
        js_urls = extract_js_urls(base, r.text)
        if js_urls:
            print(f"\n[~] Scanning {len(js_urls)} JS bundle(s)...")
        for js_url in js_urls[:10]:  # cap at 10 bundles
            try:
                jr = requests.get(js_url, headers=HEADERS, timeout=10)
                if jr.status_code == 200:
                    js_secrets = scan_for_secrets(jr.text, js_url)
                    if js_secrets:
                        print(f"[!] SECRETS IN JS BUNDLE: {js_url}")
                        for s in js_secrets:
                            print(f"    └─ 🔴 {s['type']}")
                        findings.append({
                            "url": js_url,
                            "type": "js_bundle_secret",
                            "secrets": js_secrets,
                            "snippet": jr.text[:300]
                        })
                    else:
                        print(f"[ ] {js_url.split('/')[-1]} — clean")
            except Exception:
                pass
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

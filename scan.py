#!/usr/bin/env python3
"""
V1B3 Scanner — Ethical vibe-code vulnerability scanner
Finds exposed secrets, misconfigurations, and security gaps
in publicly accessible web apps. No exploitation. Always notifies.

Checks:
  - Exposed secrets (env files, config, SQL dumps, git objects)
  - JS bundle secret leakage (API keys, tokens, JWTs)
  - CORS misconfiguration (reflected origin + ACAC:true)
  - GraphQL introspection exposure
  - HTTP security headers audit
  - Source map (.js.map) exposure
  - Debug/admin endpoints (Actuator, Swagger, Prometheus, etc.)
  - Cookie security flags (HttpOnly, Secure, SameSite)
  - Directory listing
  - Prototype pollution markers in JS bundles
  - SPA false-positive filtering via canary requests
"""

import requests
import sys
import json
import re
import ssl
import socket
import datetime
from urllib.parse import urlparse, urljoin

# ── Scanner identity ─────────────────────────────────────────────────────────
HEADERS = {
    "User-Agent": "V1B3-SecurityResearch/2.0 (ethical; +https://shree-git.github.io/v1b3/)",
}
TIMEOUT = 8

# ── Severity levels ──────────────────────────────────────────────────────────
CRITICAL = "CRITICAL"
HIGH     = "HIGH"
MEDIUM   = "MEDIUM"
LOW      = "LOW"
INFO     = "INFO"

SEVERITY_COLOR = {CRITICAL: "🔴", HIGH: "🟠", MEDIUM: "🟡", LOW: "🔵", INFO: "⚪"}

# ── Exposed path targets ─────────────────────────────────────────────────────
SENSITIVE_PATHS = [
    ("/.env",                     HIGH,   "Environment variables — may contain API keys, DB creds"),
    ("/.env.local",               HIGH,   "Local environment overrides"),
    ("/.env.production",          HIGH,   "Production environment file"),
    ("/.env.development",         MEDIUM, "Development environment file"),
    ("/.env.bak",                 HIGH,   "Backup environment file"),
    ("/.env.backup",              HIGH,   "Backup environment file"),
    ("/api/.env",                 HIGH,   "API subdirectory env file"),
    ("/backend/.env",             HIGH,   "Backend env file"),
    ("/.git/config",              HIGH,   "Git config — may expose remote URL with credentials"),
    ("/.git/HEAD",                MEDIUM, "Git HEAD ref — confirms git exposure"),
    ("/.git/refs/heads/main",     MEDIUM, "Git ref — source tree access possible"),
    ("/config.json",              HIGH,   "JSON config file"),
    ("/config.js",                HIGH,   "JS config file"),
    ("/secrets.json",             CRITICAL,"Secrets JSON"),
    ("/app.config.js",            MEDIUM, "App config"),
    ("/application.yml",          HIGH,   "Spring Boot application config"),
    ("/application.properties",   HIGH,   "Spring Boot properties"),
    ("/config/database.yml",      HIGH,   "Database config (Rails style)"),
    ("/backup.sql",               CRITICAL,"Database dump"),
    ("/database.sql",             CRITICAL,"Database dump"),
    ("/dump.sql",                 CRITICAL,"Database dump"),
    ("/wp-config.php",            CRITICAL,"WordPress config — DB credentials"),
    ("/configuration.php",        CRITICAL,"CMS config file"),
    ("/.htpasswd",                HIGH,   "HTTP Basic Auth credentials"),
    ("/phpinfo.php",              MEDIUM, "PHP info page — version and config exposed"),
    ("/info.php",                 MEDIUM, "PHP info page"),
    ("/server.js",                LOW,    "Server entry point source"),
    ("/app.js",                   LOW,    "App entry point source"),
    ("/index.php",                INFO,   "PHP index — may indicate non-SPA"),
]

# ── Secret patterns (in JS bundles, HTML, config files) ─────────────────────
SECRET_PATTERNS = [
    (r'sk-[a-zA-Z0-9]{48}',                                    CRITICAL, "OpenAI API Key"),
    (r'sk-proj-[a-zA-Z0-9_-]{40,}',                           CRITICAL, "OpenAI Project API Key"),
    (r'sk_live_[a-zA-Z0-9]{24,}',                             CRITICAL, "Stripe Live Secret Key"),
    (r'rk_live_[a-zA-Z0-9]{24,}',                             HIGH,     "Stripe Restricted Key"),
    (r'pk_live_[a-zA-Z0-9]{24,}',                             MEDIUM,   "Stripe Live Publishable Key"),
    (r'AKIA[0-9A-Z]{16}',                                      CRITICAL, "AWS Access Key ID"),
    (r'(?:aws.{0,20})?secret.{0,10}["\s:=]+[A-Za-z0-9/+=]{40}', HIGH,  "AWS Secret Access Key (heuristic)"),
    (r'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+', MEDIUM, "Hardcoded JWT"),
    (r'ghp_[a-zA-Z0-9]{36}',                                  CRITICAL, "GitHub Personal Access Token"),
    (r'gho_[a-zA-Z0-9]{36}',                                  HIGH,     "GitHub OAuth Token"),
    (r'xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}',            HIGH,     "Slack Bot Token"),
    (r'xoxp-[0-9]{11}-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{32}', HIGH,     "Slack User Token"),
    (r'AIza[0-9A-Za-z\-_]{35}',                               HIGH,     "Google API Key"),
    (r'service_role["\s:]+ey[a-zA-Z0-9_-]{50,}',             CRITICAL, "Supabase Service Role Key"),
    (r'eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}',       MEDIUM,   "Supabase/JWT anon/service key"),
    (r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}',           HIGH,     "SendGrid API Key"),
    (r'key-[a-zA-Z0-9]{32}',                                  MEDIUM,   "Mailgun API Key"),
    (r'(?:password|passwd|pwd)\s*[=:]\s*["\'][^"\']{6,}["\']', HIGH,   "Hardcoded password"),
    (r'(?:private_key|privateKey)\s*[=:]\s*["\']-----BEGIN', CRITICAL, "Private key material"),
    (r'mongodb\+srv://[^\s"\'<>]+',                            HIGH,     "MongoDB connection string"),
    (r'postgres(?:ql)?://[a-zA-Z0-9_]+:[^@\s"\']{4,}@',      HIGH,     "PostgreSQL connection string with credentials"),
    (r'mysql://[a-zA-Z0-9_]+:[^@\s"\']{4,}@',                HIGH,     "MySQL connection string with credentials"),
    (r'redis://:[^@\s"\']{4,}@',                              MEDIUM,   "Redis connection string with password"),
]

# ── Debug/ops endpoints ──────────────────────────────────────────────────────
DEBUG_ENDPOINTS = [
    # Spring Boot Actuator
    ("/actuator",                  HIGH,   "Spring Boot Actuator root — lists all actuator endpoints"),
    ("/actuator/env",              CRITICAL,"Spring Boot Actuator /env — exposes ALL env vars and config"),
    ("/actuator/health",           LOW,    "Spring Boot health endpoint"),
    ("/actuator/info",             INFO,   "Spring Boot info endpoint"),
    ("/actuator/mappings",         MEDIUM, "Spring Boot route mappings — full API surface exposed"),
    ("/actuator/beans",            MEDIUM, "Spring Boot beans — internal component graph"),
    ("/actuator/loggers",          MEDIUM, "Spring Boot loggers"),
    ("/actuator/httptrace",        HIGH,   "Spring Boot HTTP trace — recent requests (may contain tokens)"),
    ("/actuator/dump",             HIGH,   "Spring Boot thread dump"),
    ("/actuator/heapdump",         CRITICAL,"Spring Boot heap dump — full JVM memory export"),
    # Prometheus / metrics
    ("/metrics",                   MEDIUM, "Prometheus or app metrics endpoint"),
    ("/_metrics",                  MEDIUM, "Metrics endpoint"),
    ("/prometheus",                MEDIUM, "Prometheus metrics"),
    # Swagger / OpenAPI
    ("/swagger-ui.html",           MEDIUM, "Swagger UI — full API documentation exposed"),
    ("/swagger-ui/index.html",     MEDIUM, "Swagger UI"),
    ("/swagger-ui",                MEDIUM, "Swagger UI"),
    ("/api-docs",                  MEDIUM, "OpenAPI JSON spec"),
    ("/v2/api-docs",               MEDIUM, "Swagger v2 spec"),
    ("/v3/api-docs",               MEDIUM, "OpenAPI v3 spec"),
    ("/openapi.json",              MEDIUM, "OpenAPI spec"),
    ("/openapi.yaml",              MEDIUM, "OpenAPI spec"),
    # Debug pages
    ("/debug",                     HIGH,   "Debug interface"),
    ("/__debug",                   HIGH,   "Debug interface"),
    ("/_debug",                    HIGH,   "Debug interface"),
    ("/console",                   HIGH,   "Console interface — may be H2/Rails/etc"),
    ("/h2-console",                CRITICAL,"H2 database console — unauthenticated DB access"),
    ("/phpmyadmin",                CRITICAL,"phpMyAdmin — database admin interface"),
    ("/adminer",                   CRITICAL,"Adminer — database admin interface"),
    ("/pma",                       CRITICAL,"phpMyAdmin alias"),
    # Misc
    ("/health",                    INFO,   "Health check endpoint"),
    ("/status",                    INFO,   "Status endpoint"),
    ("/version",                   LOW,    "Version endpoint — software version disclosure"),
    ("/robots.txt",                INFO,   "robots.txt — may reveal hidden paths"),
    ("/sitemap.xml",               INFO,   "Sitemap"),
    ("/.well-known/security.txt",  INFO,   "Security contact policy"),
    ("/server-status",             HIGH,   "Apache server-status — request log exposed"),
    ("/server-info",               MEDIUM, "Apache server-info — module configuration"),
    ("/nginx_status",              MEDIUM, "Nginx stub_status — connection counts"),
    ("/__admin",                   HIGH,   "Admin interface (WireMock/other)"),
    ("/__admin/mappings",          HIGH,   "WireMock admin mappings"),
]

# ── Security headers ─────────────────────────────────────────────────────────
SECURITY_HEADERS = [
    ("Strict-Transport-Security",         HIGH,   "HSTS missing — site vulnerable to protocol downgrade attacks"),
    ("Content-Security-Policy",           MEDIUM, "CSP missing — XSS attacks have no content restriction"),
    ("X-Frame-Options",                   MEDIUM, "X-Frame-Options missing — clickjacking possible"),
    ("X-Content-Type-Options",            LOW,    "X-Content-Type-Options missing — MIME sniffing possible"),
    ("Referrer-Policy",                   LOW,    "Referrer-Policy missing — referrer leaks on cross-origin nav"),
    ("Permissions-Policy",                LOW,    "Permissions-Policy missing — browser features unrestricted"),
    ("X-XSS-Protection",                  INFO,   "X-XSS-Protection missing (legacy, but still checked)"),
]

# ── Source map paths (appended to discovered JS bundle URLs) ─────────────────
SOURCE_MAP_PATHS = [
    "/static/js/main.chunk.js.map",
    "/static/js/bundle.js.map",
    "/main.js.map",
    "/app.js.map",
    "/bundle.js.map",
    "/index.js.map",
    "/vendor.js.map",
]

# ── Prototype pollution markers ──────────────────────────────────────────────
PROTO_PATTERNS = [
    r'__proto__\s*\[',
    r'constructor\s*\[constructor\]',
    r'Object\.assign\(\s*{}\s*,\s*(?:req|request|query|body|params)',
    r'Object\.merge\(',
    r'deepmerge\(',
    r'lodash\.merge\(',
    r'_\.merge\(',
    r'\$\.extend\(\s*true',
]


# ── Helper utilities ─────────────────────────────────────────────────────────

def p(symbol, msg, severity=None):
    sev = f" [{severity}]" if severity else ""
    icon = SEVERITY_COLOR.get(severity, "") + " " if severity else ""
    print(f"{icon}[{symbol}]{sev} {msg}")

def curl_repro(method, url, headers=None, data=None):
    """Generate a curl command to reproduce a request."""
    parts = ["curl", "-si"]
    if method.upper() != "GET":
        parts += ["-X", method.upper()]
    if headers:
        for k, v in headers.items():
            parts += ["-H", f"'{k}: {v}'"]
    if data:
        parts += ["-d", f"'{data}'"]
    parts.append(f"'{url}'")
    return " ".join(parts)


# ── SPA detection ─────────────────────────────────────────────────────────────

def get_spa_fingerprint(base_url):
    canary = base_url.rstrip('/') + '/v1b3-canary-xyz987654321-nonexistent'
    try:
        r = requests.get(canary, headers=HEADERS, timeout=TIMEOUT, allow_redirects=True)
        if r.status_code == 200 and '<!DOCTYPE html' in r.text[:200]:
            return r.text[:500]
    except Exception:
        pass
    return None


# ── Secret detection ─────────────────────────────────────────────────────────

def scan_for_secrets(content, source):
    found = []
    for pattern, severity, name in SECRET_PATTERNS:
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            # Redact: show first 8 chars + ...
            sample = matches[0][:8] + "..." if isinstance(matches[0], str) else "..."
            found.append({
                "type": name,
                "severity": severity,
                "source": source,
                "count": len(matches),
                "sample": sample
            })
    return found


# ── Path checks ──────────────────────────────────────────────────────────────

def check_path(base_url, path, spa_fp=None, expect_content_types=None):
    """Return (status, content, response_headers) or (None, None, None)."""
    url = base_url.rstrip('/') + path
    try:
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=False)
        if r.status_code == 200 and len(r.text) > 20:
            if spa_fp and r.text[:500] == spa_fp:
                return None, None, None
            ct = r.headers.get('Content-Type', '')
            # Reject HTML for file targets (env, sql, json, etc.)
            if 'html' in ct and any(path.endswith(ext) for ext in
               ('.env', '.env.local', '.env.production', '.env.development',
                '.env.bak', '.env.backup', '.json', '.yml', '.yaml', '.sql',
                'HEAD', 'config', '.php', '.htpasswd')):
                return None, None, None
            return r.status_code, r.text[:3000], dict(r.headers)
    except Exception:
        pass
    return None, None, None


# ── CORS check ────────────────────────────────────────────────────────────────

def check_cors(base_url):
    """
    Real CORS vulnerability = reflected arbitrary origin + ACAC:true.
    ACAO:* alone is NOT a vulnerability (no credentials with wildcard).
    """
    try:
        r = requests.get(base_url, headers={**HEADERS, "Origin": "https://evil-attacker.com"}, timeout=TIMEOUT)
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()
        if acao == "https://evil-attacker.com" and acac == "true":
            return {
                "severity": CRITICAL,
                "detail": "Reflected origin + ACAC:true — authenticated cross-origin requests possible",
                "evidence": f"ACAO: {acao}\nACAC: {acac}",
                "curl": curl_repro("GET", base_url, {"Origin": "https://evil-attacker.com"}),
            }
        if acao == "null" and acac == "true":
            return {
                "severity": HIGH,
                "detail": "null origin + ACAC:true — null-origin sandbox bypass possible",
                "evidence": f"ACAO: null\nACAC: {acac}",
                "curl": curl_repro("GET", base_url, {"Origin": "null"}),
            }
    except Exception:
        pass
    return None


# ── GraphQL introspection ─────────────────────────────────────────────────────

def check_graphql(base_url):
    endpoints = ["/graphql", "/api/graphql", "/v1/graphql", "/gql", "/query"]
    introspection = '{"query":"{__schema{queryType{name}types{name kind}}}"}'
    for ep in endpoints:
        try:
            r = requests.post(
                base_url.rstrip('/') + ep,
                headers={**HEADERS, "Content-Type": "application/json"},
                data=introspection, timeout=TIMEOUT
            )
            if r.status_code == 200 and "__schema" in r.text:
                snippet = r.text[:400]
                return {
                    "endpoint": ep,
                    "severity": MEDIUM,
                    "detail": f"GraphQL introspection enabled at {ep} — full schema exposed",
                    "evidence": snippet,
                    "curl": curl_repro("POST", base_url.rstrip('/') + ep,
                                       {"Content-Type": "application/json"}, introspection),
                }
        except Exception:
            pass
    return None


# ── Security headers audit ────────────────────────────────────────────────────

def check_security_headers(base_url):
    """Audit for missing HTTP security response headers."""
    missing = []
    try:
        r = requests.get(base_url, headers=HEADERS, timeout=TIMEOUT)
        resp_headers = {k.lower(): v for k, v in r.headers.items()}
        for header, severity, detail in SECURITY_HEADERS:
            if header.lower() not in resp_headers:
                missing.append({
                    "header": header,
                    "severity": severity,
                    "detail": detail,
                })
        return missing, dict(r.headers)
    except Exception:
        return [], {}


# ── Source map exposure ───────────────────────────────────────────────────────

def check_source_maps(base_url, js_urls):
    """
    Check for exposed JavaScript source maps.
    Source maps reconstruct original unminified source code including comments,
    variable names, and internal architecture.
    """
    exposed = []
    candidates = list(SOURCE_MAP_PATHS)
    for js_url in js_urls[:8]:
        candidates.append(js_url + ".map")

    for path in candidates:
        # Handle both absolute JS URLs and relative paths
        if path.startswith("http"):
            url = path
        else:
            url = base_url.rstrip('/') + path
        try:
            r = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
            if r.status_code == 200 and ('"sources"' in r.text or '"mappings"' in r.text):
                exposed.append({
                    "url": url,
                    "severity": HIGH,
                    "detail": "JavaScript source map exposed — original source code reconstructable",
                    "evidence": r.text[:300],
                    "curl": curl_repro("GET", url),
                })
        except Exception:
            pass
    return exposed


# ── Debug endpoint check ──────────────────────────────────────────────────────

def check_debug_endpoints(base_url, spa_fp=None):
    """Probe known debug, admin, metrics, and API-doc endpoints."""
    found = []
    for path, severity, detail in DEBUG_ENDPOINTS:
        status, content, resp_headers = check_path(base_url, path, spa_fp=spa_fp)
        if status == 200:
            found.append({
                "url": base_url.rstrip('/') + path,
                "path": path,
                "severity": severity,
                "detail": detail,
                "evidence": content[:400] if content else "",
                "curl": curl_repro("GET", base_url.rstrip('/') + path),
            })
    return found


# ── Cookie security flags ─────────────────────────────────────────────────────

def check_cookies(base_url):
    """Check Set-Cookie headers for missing security attributes."""
    issues = []
    try:
        r = requests.get(base_url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=True)
        raw_headers = r.raw.headers.getlist('Set-Cookie') if hasattr(r.raw.headers, 'getlist') else []
        # Fallback: parse from response headers
        if not raw_headers:
            raw_cookies = [v for k, v in r.headers.items() if k.lower() == 'set-cookie']
            raw_headers = raw_cookies

        for cookie_str in raw_headers:
            cookie_lower = cookie_str.lower()
            name = cookie_str.split('=')[0].strip()
            flags = []
            if 'httponly' not in cookie_lower:
                flags.append("missing HttpOnly (JS can read this cookie)")
            if 'secure' not in cookie_lower:
                flags.append("missing Secure (sent over HTTP)")
            if 'samesite' not in cookie_lower:
                flags.append("missing SameSite (CSRF risk)")
            if flags:
                severity = HIGH if 'missing HttpOnly' in ' '.join(flags) else MEDIUM
                issues.append({
                    "cookie": name,
                    "severity": severity,
                    "flags": flags,
                    "raw": cookie_str[:200],
                })
    except Exception:
        pass
    return issues


# ── Directory listing ─────────────────────────────────────────────────────────

def check_directory_listing(base_url):
    """Check common directories for enabled directory listing (Index of /)."""
    dirs = ["/static/", "/uploads/", "/files/", "/assets/", "/backup/", "/logs/", "/data/"]
    found = []
    for d in dirs:
        url = base_url.rstrip('/') + d
        try:
            r = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
            if r.status_code == 200 and any(sig in r.text for sig in
               ["Index of /", "Directory listing for", "<title>Index of"]):
                found.append({
                    "url": url,
                    "severity": HIGH,
                    "detail": f"Directory listing enabled at {d} — file tree exposed",
                    "curl": curl_repro("GET", url),
                })
        except Exception:
            pass
    return found


# ── JS bundle extraction + prototype pollution ────────────────────────────────

def extract_js_urls(base_url, html):
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
    chunk_pattern = r'["\']([^"\']*chunk[^"\']*\.js)["\']'
    for m in re.findall(chunk_pattern, html)[:5]:
        url = urljoin(base_url, m) if not m.startswith('http') else m
        if url not in urls:
            urls.append(url)
    return list(dict.fromkeys(urls))


def check_prototype_pollution(js_content, source_url):
    """Look for prototype pollution patterns in JS bundles."""
    issues = []
    for pattern in PROTO_PATTERNS:
        if re.search(pattern, js_content):
            issues.append({
                "url": source_url,
                "severity": LOW,
                "detail": f"Prototype pollution pattern: `{pattern}` — review manually",
                "pattern": pattern,
            })
    return issues


# ── TLS certificate check ─────────────────────────────────────────────────────

def check_tls(hostname):
    """Check TLS certificate expiry."""
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((hostname, 443), timeout=6), server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()
            expire_str = cert.get('notAfter', '')
            if expire_str:
                expire_dt = datetime.datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
                days_left = (expire_dt - datetime.datetime.utcnow()).days
                if days_left < 14:
                    return {
                        "severity": CRITICAL if days_left < 3 else HIGH,
                        "detail": f"TLS certificate expires in {days_left} days ({expire_str})",
                        "days_left": days_left,
                    }
                elif days_left < 30:
                    return {
                        "severity": MEDIUM,
                        "detail": f"TLS certificate expires in {days_left} days ({expire_str})",
                        "days_left": days_left,
                    }
    except ssl.SSLError as e:
        return {
            "severity": HIGH,
            "detail": f"TLS error: {e}",
        }
    except Exception:
        pass
    return None


# ── Main scanner ──────────────────────────────────────────────────────────────

def scan(target_url):
    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    hostname = parsed.netloc.split(':')[0]

    print(f"\n{'━'*60}")
    print(f"  V1B3 Scanner v2.0  //  {base}")
    print(f"{'━'*60}\n")

    all_findings = []

    # ── SPA detection ──────────────────────────────────────────────────────
    spa_fp = get_spa_fingerprint(base)
    if spa_fp:
        p("~", "SPA catch-all detected — canary filtering active")
    else:
        p("~", "No SPA catch-all — direct path responses expected")
    print()

    # ── TLS ────────────────────────────────────────────────────────────────
    if parsed.scheme == "https":
        tls = check_tls(hostname)
        if tls:
            p("!", tls["detail"], tls["severity"])
            all_findings.append({"type": "tls_expiry", **tls})
        else:
            p(" ", "TLS certificate — valid")
    print()

    # ── Security headers ───────────────────────────────────────────────────
    print("── Security Headers ─────────────────────────────────")
    missing_headers, resp_headers = check_security_headers(base)
    if resp_headers:
        for h, sev, detail in SECURITY_HEADERS:
            if any(m["header"] == h for m in missing_headers):
                p("!", f"{h} — MISSING", sev)
                all_findings.append({
                    "type": "missing_security_header",
                    "header": h,
                    "severity": sev,
                    "detail": detail,
                    "url": base,
                })
            else:
                p(" ", f"{h} — present")
    print()

    # ── CORS ───────────────────────────────────────────────────────────────
    print("── CORS ─────────────────────────────────────────────")
    cors = check_cors(base)
    if cors:
        p("!", cors["detail"], cors["severity"])
        p(" ", f"Evidence:\n{cors['evidence']}")
        p(" ", f"Reproduce:\n    {cors['curl']}")
        all_findings.append({"type": "cors_misconfiguration", "url": base, **cors})
    else:
        p(" ", "CORS — safe (no reflected-origin + ACAC:true)")
    print()

    # ── GraphQL ────────────────────────────────────────────────────────────
    print("── GraphQL ──────────────────────────────────────────")
    gql = check_graphql(base)
    if gql:
        p("!", gql["detail"], gql["severity"])
        p(" ", f"Endpoint: {gql['endpoint']}")
        p(" ", f"Reproduce:\n    {gql['curl']}")
        all_findings.append({"type": "graphql_introspection", "url": base + gql["endpoint"], **gql})
    else:
        p(" ", "GraphQL introspection — disabled or not present")
    print()

    # ── Cookies ────────────────────────────────────────────────────────────
    print("── Cookie Flags ─────────────────────────────────────")
    cookies = check_cookies(base)
    if cookies:
        for c in cookies:
            p("!", f"Cookie '{c['cookie']}': {', '.join(c['flags'])}", c["severity"])
            all_findings.append({"type": "insecure_cookie", "url": base, **c})
    else:
        p(" ", "No session cookies or all flags set correctly")
    print()

    # ── Sensitive paths ─────────────────────────────────────────────────────
    print("── Sensitive Paths ──────────────────────────────────")
    all_paths_to_check = [(p_path, sev, desc) for p_path, sev, desc in SENSITIVE_PATHS]
    for path, severity, desc in all_paths_to_check:
        status, content, resp_hdrs = check_path(base, path, spa_fp=spa_fp)
        if status == 200:
            secrets = scan_for_secrets(content, path)
            effective_sev = CRITICAL if secrets else severity
            p("!", f"EXPOSED: {path} — {desc}", effective_sev)
            if secrets:
                for s in secrets:
                    print(f"       └─ {SEVERITY_COLOR[s['severity']]} {s['type']} (sample: {s['sample']})")
            p(" ", f"Reproduce:\n    {curl_repro('GET', base + path)}")
            all_findings.append({
                "type": "exposed_path",
                "url": base + path,
                "path": path,
                "severity": effective_sev,
                "detail": desc,
                "secrets": secrets,
                "snippet": content[:500] if content else "",
                "curl": curl_repro("GET", base + path),
            })
        else:
            p(" ", path)
    print()

    # ── Debug/ops endpoints ─────────────────────────────────────────────────
    print("── Debug / Ops Endpoints ────────────────────────────")
    debug_hits = check_debug_endpoints(base, spa_fp=spa_fp)
    if debug_hits:
        for hit in debug_hits:
            p("!", f"EXPOSED: {hit['path']} — {hit['detail']}", hit["severity"])
            p(" ", f"Reproduce:\n    {hit['curl']}")
            all_findings.append({"type": "debug_endpoint", **hit})
    else:
        p(" ", "No debug/ops endpoints exposed")
    print()

    # ── Directory listing ───────────────────────────────────────────────────
    print("── Directory Listing ────────────────────────────────")
    dir_listing = check_directory_listing(base)
    if dir_listing:
        for d in dir_listing:
            p("!", d["detail"], d["severity"])
            p(" ", f"Reproduce:\n    {d['curl']}")
            all_findings.append({"type": "directory_listing", **d})
    else:
        p(" ", "No directory listing found")
    print()

    # ── JS bundles + secrets + source maps + prototype pollution ────────────
    print("── JS Bundles ───────────────────────────────────────")
    try:
        r = requests.get(base, headers=HEADERS, timeout=TIMEOUT)

        # Inline page secrets
        page_secrets = scan_for_secrets(r.text, "index page (inline)")
        if page_secrets:
            p("!", f"Secrets in main page HTML source:", CRITICAL)
            for s in page_secrets:
                print(f"       └─ {SEVERITY_COLOR[s['severity']]} {s['type']}: sample={s['sample']}")
            all_findings.append({
                "type": "inline_page_secret",
                "url": base,
                "severity": CRITICAL,
                "secrets": page_secrets,
            })
        else:
            p(" ", "No secrets in main page source")

        js_urls = extract_js_urls(base, r.text)
        p("~", f"Found {len(js_urls)} JS bundle(s)")

        for js_url in js_urls[:12]:
            try:
                jr = requests.get(js_url, headers=HEADERS, timeout=12)
                if jr.status_code != 200:
                    continue
                fname = js_url.split('/')[-1][:60]

                js_secrets = scan_for_secrets(jr.text, js_url)
                if js_secrets:
                    p("!", f"Secrets in {fname}", CRITICAL)
                    for s in js_secrets:
                        print(f"       └─ {SEVERITY_COLOR[s['severity']]} {s['type']}: sample={s['sample']}")
                    all_findings.append({
                        "type": "js_bundle_secret",
                        "url": js_url,
                        "severity": CRITICAL,
                        "secrets": js_secrets,
                        "curl": curl_repro("GET", js_url),
                    })
                else:
                    p(" ", f"{fname} — clean")

                proto = check_prototype_pollution(jr.text, js_url)
                for pp in proto:
                    p("~", f"Prototype pollution pattern in {fname} — manual review needed", LOW)
                    all_findings.append({"type": "prototype_pollution", **pp})

            except Exception:
                pass

        # Source maps
        source_maps = check_source_maps(base, js_urls)
        for sm in source_maps:
            p("!", sm["detail"], sm["severity"])
            p(" ", f"URL: {sm['url']}")
            p(" ", f"Reproduce:\n    {sm['curl']}")
            all_findings.append({"type": "source_map_exposed", **sm})

    except Exception as e:
        p("~", f"Could not fetch main page: {e}")
    print()

    # ── Summary ─────────────────────────────────────────────────────────────
    print(f"{'━'*60}")
    counts = {CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0}
    for f in all_findings:
        counts[f.get("severity", INFO)] = counts.get(f.get("severity", INFO), 0) + 1

    print(f"  Results for {base}")
    print(f"  {'─'*40}")
    for sev in [CRITICAL, HIGH, MEDIUM, LOW, INFO]:
        if counts[sev]:
            print(f"  {SEVERITY_COLOR[sev]} {sev:<12} {counts[sev]}")
    print(f"  {'─'*40}")
    print(f"  Total findings: {len(all_findings)}")
    print(f"{'━'*60}\n")

    return all_findings


def report(findings):
    if findings:
        print(json.dumps(findings, indent=2))
    else:
        print("[V1B3] All clear. No issues found.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 scan.py <target_url>")
        print("Example: python3 scan.py https://example.com")
        sys.exit(1)
    target = sys.argv[1]
    results = scan(target)
    if "--json" in sys.argv:
        report(results)

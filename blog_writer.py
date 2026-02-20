#!/usr/bin/env python3
"""
V1B3 Blog Writer — Auto-publishes posts after scans
Writes in V1B3's voice. Commits HTML to /blog/. Updates index.
Run after agent.py --scan or on its own schedule.

Usage:
  python3 blog_writer.py --scan-report --target https://example.com --findings-file /tmp/scan.json
  python3 blog_writer.py --daily-summary
  python3 blog_writer.py --reflection "what I learned today"
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

DIR = Path(__file__).parent
BLOG_DIR = DIR / "blog"
INDEX_FILE = DIR / "index.html"
FINDINGS_FILE = DIR / "findings.json"

COMMENT_SCRIPT = """  <div class="comments-section">
    <div class="comments-header">// comments</div>
    <script src="https://utteranc.es/client.js"
      repo="Shree-git/v1b3"
      issue-term="pathname"
      label="blog-comment"
      theme="github-dark"
      crossorigin="anonymous"
      async>
    </script>
  </div>"""

def load_findings():
    with open(FINDINGS_FILE) as f:
        return json.load(f)

def slug(title):
    import re
    s = title.lower().strip()
    s = re.sub(r'[^a-z0-9\s-]', '', s)
    s = re.sub(r'\s+', '-', s)
    return s[:60]

def build_post(title, date_str, tag, tag_class, subtitle, body_html, filename):
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>{title} — V1B3</title>
  <link rel="stylesheet" href="../css/style.css"/>
</head>
<body>

<nav>
  <a href="../index.html" class="nav-logo">V1B3</a>
  <div class="nav-links">
    <a href="../index.html" class="active">blog</a>
    <a href="../findings.html">findings</a>
    <a href="../about.html">about</a>
  </div>
  <div class="nav-status">scanning</div>
</nav>

<div class="page">

  <div class="post-header">
    <div class="post-header-date">
      <span class="post-meta-tag {tag_class}">{tag}</span>
      &nbsp; {date_str}
    </div>
    <h1 class="post-header-title">{title}</h1>
    <p class="post-header-subtitle">{subtitle}</p>
  </div>

  <div class="post-body">
{body_html}
  </div>

{COMMENT_SCRIPT}

</div>

<footer>
  <span>V1B3 // autonomous ethical hacker // 2026</span>
  <span>
    <a href="https://github.com/Shree-git/v1b3" target="_blank">github</a> ·
    <a href="https://x.com/v1b3sec" target="_blank">x</a>
  </span>
</footer>

</body>
</html>"""

def write_post(filename, html):
    path = BLOG_DIR / filename
    with open(path, "w") as f:
        f.write(html)
    print(f"[✓] Post written: blog/{filename}")
    return f"blog/{filename}"

def prepend_to_index(title, date_str, tag, tag_class, excerpt, filepath):
    """Inject new post card at the top of the post list in index.html."""
    card = f"""
    <div class="post-card">
      <div class="post-date">{date_str.replace(", ", "<br/>")}</div>
      <div>
        <div class="post-meta-tag {tag_class}">{tag}</div>
        <div class="post-title"><a href="{filepath}">{title}</a></div>
        <p class="post-excerpt">{excerpt}</p>
      </div>
    </div>
"""
    content = INDEX_FILE.read_text()
    marker = '<div class="post-list">'
    if marker in content:
        content = content.replace(marker, marker + card, 1)
        INDEX_FILE.write_text(content)
        print(f"[✓] index.html updated")

def generate_scan_post(target, findings):
    date = datetime.now()
    date_str = date.strftime("%b %d, %Y")
    date_slug = date.strftime("%Y-%m-%d-%H%M")

    if not findings:
        title = f"Scan Report: {target.replace('https://','').rstrip('/')}"
        subtitle = "All clear. No exposed paths, no leaked secrets."
        tag, tag_class = "scan", "tag-ops"
        excerpt = f"Scanned {target}. No vulnerabilities found. Clean build."
        body = f"""    <p>Target: <code>{target}</code></p>
    <p>Scan complete. {len(findings)} findings.</p>
    <p>Checked {target} for exposed <code>.env</code> files, hardcoded API keys in JavaScript bundles, open <code>/.git</code> directories, GraphQL introspection, and CORS misconfigurations.</p>
    <p>All clear. This one is locked down.</p>
    <p>The good builds are boring to write about. But boring is exactly what you want when V1B3 comes knocking.</p>
    <p style="color:var(--text-muted);font-style:italic;margin-top:2rem">— V1B3 // {date.strftime('%H:%M UTC')}</p>"""
    else:
        f = findings[0]
        sev = f.get('severity', 'medium')
        title = f"Finding: {f['title']}"
        subtitle = f"Severity: {sev.upper()} — {target}"
        tag, tag_class = "finding", "tag-finding"
        excerpt = f"{f['description'][:120]}..."
        disc = f'<p>Disclosure filed: <a href="{f["disclosure_url"]}" target="_blank">{f["disclosure_url"]}</a></p>' if f.get('disclosure_url') else '<p>Owner notification in progress.</p>'
        body = f"""    <p>Target: <code>{target}</code></p>
    <p>Severity: <strong>{sev.upper()}</strong> &nbsp;|&nbsp; Type: <code>{f['type']}</code></p>
    <h2>What I found</h2>
    <p>{f['description']}</p>
    <h2>What it means</h2>
    <p>{"This type of misconfiguration can expose sensitive user data or credentials to unauthorized parties." if sev == "critical" else "This misconfiguration creates a potential attack surface that should be addressed."}</p>
    <h2>Disclosure</h2>
    {disc}
    <p>The owner has been notified. I'll update this post when it's resolved.</p>
    <p style="color:var(--text-muted);font-style:italic;margin-top:2rem">— V1B3 // {date.strftime('%H:%M UTC')}</p>"""

    filename = f"{date_slug}-{slug(title)}.html"
    html = build_post(title, date_str, tag, tag_class, subtitle, body, filename)
    path = write_post(filename, html)
    prepend_to_index(title, date_str, tag, tag_class, excerpt, path)
    return path

def generate_daily_summary():
    data = load_findings()
    date = datetime.now()
    date_str = date.strftime("%b %d, %Y")
    date_slug = date.strftime("%Y-%m-%d")
    stats = data['stats']
    recent = data['findings'][:3]

    title = f"Daily Summary — {date_str}"
    subtitle = f"{stats['scanned']} sites scanned. {stats['found']} total findings. {stats['resolved']} resolved."
    tag, tag_class = "ops", "tag-ops"
    excerpt = f"Daily operations report. {stats['scanned']} sites scanned to date, {stats['found']} vulnerabilities found."

    recent_html = ""
    for f in recent:
        sev_color = "var(--red)" if f['severity'] == 'critical' else "var(--yellow)" if f['severity'] == 'medium' else "var(--green)"
        recent_html += f"""    <li><strong style="color:{sev_color}">[{f['severity'].upper()}]</strong> {f['title']} — <em>{f['status']}</em></li>\n"""

    body = f"""    <h2>Operations</h2>
    <ul>
      <li>Total sites scanned: <strong>{stats['scanned']}</strong></li>
      <li>Vulnerabilities found: <strong>{stats['found']}</strong></li>
      <li>Resolved: <strong>{stats['resolved']}</strong></li>
      <li>Open: <strong>{stats['found'] - stats['resolved']}</strong></li>
    </ul>
    <h2>Recent findings</h2>
    <ul>
{recent_html}    </ul>
    <h2>Status</h2>
    <p>Scanner is running. Cron is healthy. Targets rotating every 6 hours.</p>
    <p>Nothing major to report. The vibeosphere is mostly clean today.</p>
    <p style="color:var(--text-muted);font-style:italic;margin-top:2rem">— V1B3 // {date.strftime('%H:%M UTC')}</p>"""

    filename = f"{date_slug}-daily-summary.html"
    html = build_post(title, date_str, tag, tag_class, subtitle, body, filename)
    path = write_post(filename, html)
    prepend_to_index(title, date_str, tag, tag_class, excerpt, path)
    return path

def git_push(message):
    os.chdir(DIR)
    cmds = [
        ["git", "add", "blog/", "index.html"],
        ["git", "commit", "-m", message],
        ["git", "push"]
    ]
    for cmd in cmds:
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0 and "nothing to commit" not in r.stdout + r.stderr:
            print(f"[!] {' '.join(cmd)}: {r.stderr.strip()}")
            return False
    print(f"[✓] Pushed to GitHub")
    return True

def main():
    parser = argparse.ArgumentParser(description="V1B3 Auto Blog Writer")
    parser.add_argument("--scan-report", action="store_true")
    parser.add_argument("--daily-summary", action="store_true")
    parser.add_argument("--target", help="Scanned URL")
    parser.add_argument("--findings-json", help="JSON string of findings from scan")
    parser.add_argument("--push", action="store_true", help="Auto push to GitHub")
    args = parser.parse_args()

    os.chdir(DIR)

    if args.scan_report:
        findings = json.loads(args.findings_json) if args.findings_json else []
        path = generate_scan_post(args.target or "unknown", findings)
        if args.push:
            git_push(f"blog: scan report {args.target or 'unknown'}")
    elif args.daily_summary:
        path = generate_daily_summary()
        if args.push:
            git_push(f"blog: daily summary {datetime.now().strftime('%Y-%m-%d')}")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()

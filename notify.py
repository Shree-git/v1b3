#!/usr/bin/env python3
"""
V1B3 Notifier — Responsible disclosure email generator
Drafts and optionally sends notification emails to site owners.
"""

import argparse
import json
import os
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta

FIX_GUIDES = {
    "exposed_env": """
HOW TO FIX:
  1. Immediately rotate all exposed credentials (revoke old keys, generate new ones)
  2. Add .env to your .gitignore file
  3. Use environment variables via your hosting platform (Vercel, Netlify, Railway, etc.)
  4. Never commit secrets to version control
  5. Run `git filter-branch` or BFG Repo Cleaner to purge secrets from git history

PREVENTION:
  Use `dotenv` properly, or tools like Doppler/Infisical for secret management.
""",
    "hardcoded_secret": """
HOW TO FIX:
  1. Immediately revoke/rotate the exposed key
  2. Move all secrets to environment variables — never hardcode in source files
  3. Use .env files locally, platform env vars in production
  4. Audit your codebase: grep -r "sk-" . / grep -r "AKIA" .
  5. Set up a pre-commit hook or tool like `trufflehog` to catch this in future

PREVENTION:
  Use a secrets scanner (TruffleHog, GitGuardian) in your CI pipeline.
""",
    "exposed_git": """
HOW TO FIX:
  1. Configure your web server to deny access to /.git/
     Nginx: location /.git { deny all; }
     Apache: RedirectMatch 404 /\\.git
  2. If sensitive data is in git history, consider rotating any exposed credentials
  3. Audit what's in your git history: git log --all --full-history

PREVENTION:
  Always check your deployment config blocks access to hidden directories.
""",
    "default": """
HOW TO FIX:
  Review the finding details above and take appropriate remediation steps.
  Rotate any exposed credentials immediately.
  Consider a security review of your deployment configuration.
"""
}

def generate_email(finding, owner_email):
    publish_date = (datetime.now() + timedelta(days=7)).strftime("%B %d, %Y")
    fix_guide = FIX_GUIDES.get(finding.get("type", "default"), FIX_GUIDES["default"])
    severity = finding.get("severity", "medium").upper()

    subject = f"[V1B3 Responsible Disclosure] Security Finding on Your Application — {finding['title']}"

    body = f"""Hello,

My name is V1B3 — I'm an automated ethical security researcher that scans publicly accessible web applications for common security misconfigurations.

I've identified a security finding associated with your application that I want to bring to your attention before it's discovered and potentially exploited by someone with bad intentions.

───────────────────────────────────────
FINDING #{finding['id']} — {severity} SEVERITY
───────────────────────────────────────

Title: {finding['title']}
Date Found: {finding['date']}
Type: {finding['type']}

What I found:
{finding['description']}

{fix_guide}
───────────────────────────────────────
DISCLOSURE TIMELINE
───────────────────────────────────────

I follow responsible disclosure practices:
  • You have until {publish_date} (7 days) to remediate this issue
  • After that date, a sanitized version of this finding may be published publicly
  • I will NOT publish your actual secrets or exploitable details — only the finding type and fix guidance
  • If you need more time, reply to this email and I'll work with you

I have not exploited this vulnerability. I have not stored, used, or shared your secrets beyond this notification.

───────────────────────────────────────

If this was helpful, consider starring the repo: https://github.com/Shree-git/v1b3
If you'd like V1B3 to do a full scan of your app, open an issue there.

Stay secure,

V1B3
Autonomous Ethical Security Researcher
https://shree-git.github.io/v1b3/
github.com/Shree-git/v1b3
"""
    return subject, body

def send_email(to_email, subject, body):
    smtp_host = os.environ.get("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    smtp_user = os.environ.get("SMTP_USER")
    smtp_pass = os.environ.get("SMTP_PASS")

    if not smtp_user or not smtp_pass:
        print("[!] SMTP_USER and SMTP_PASS env vars required for sending.")
        return False

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = f"V1B3 Security Research <{smtp_user}>"
    msg["To"] = to_email

    try:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)
        print(f"[✓] Email sent to {to_email}")
        return True
    except Exception as e:
        print(f"[!] Failed to send: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="V1B3 Responsible Disclosure Notifier")
    parser.add_argument("--findings", default="findings.json", help="Path to findings.json")
    parser.add_argument("--id", required=True, help="Finding ID to notify about")
    parser.add_argument("--owner-email", required=True, help="Owner's email address")
    parser.add_argument("--send", action="store_true", help="Actually send the email (default: print only)")
    args = parser.parse_args()

    with open(args.findings) as f:
        data = json.load(f)

    finding = next((x for x in data["findings"] if x["id"] == args.id), None)
    if not finding:
        print(f"[!] Finding ID {args.id} not found.")
        return

    subject, body = generate_email(finding, args.owner_email)

    print("=" * 60)
    print(f"TO: {args.owner_email}")
    print(f"SUBJECT: {subject}")
    print("=" * 60)
    print(body)
    print("=" * 60)

    if args.send:
        send_email(args.owner_email, subject, body)
    else:
        print("\n[V1B3] Dry run — use --send to actually send this email.")

if __name__ == "__main__":
    main()

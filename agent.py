#!/usr/bin/env python3
"""
V1B3 Agent — The autonomous brain
Orchestrates scanning, findings management, notifications, and site updates.

Usage:
  python3 agent.py --scan <url>         Scan a target URL
  python3 agent.py --update-site        Push updated findings to GitHub (updates live site)
  python3 agent.py --notify --id <id> --email <email>  Send disclosure for a finding
  python3 agent.py --report             Print summary of all findings
  python3 agent.py --add-finding        Interactively add a manual finding
"""

import argparse
import json
import subprocess
import sys
import os
import logging
from datetime import datetime

LOG_FILE = "v1b3.log"
FINDINGS_FILE = "findings.json"

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
log = logging.getLogger("v1b3")

def load_findings():
    with open(FINDINGS_FILE) as f:
        return json.load(f)

def save_findings(data):
    with open(FINDINGS_FILE, "w") as f:
        json.dump(data, f, indent=2)
    log.info(f"findings.json updated")

def next_id(findings):
    if not findings:
        return "001"
    ids = [int(f["id"]) for f in findings if f["id"].isdigit()]
    return str(max(ids) + 1).zfill(3)

def cmd_scan(url):
    log.info(f"Starting scan: {url}")
    result = subprocess.run(
        [sys.executable, "scan.py", url],
        capture_output=True, text=True
    )
    print(result.stdout)
    if result.stderr:
        print(result.stderr)

    # Try to parse findings from scan output (scan.py prints JSON at end)
    lines = result.stdout.strip().split("\n")
    json_start = next((i for i, l in enumerate(lines) if l.strip().startswith("[")), None)
    if json_start is not None:
        try:
            raw = json.loads("\n".join(lines[json_start:]))
            if raw:
                data = load_findings()
                for r in raw:
                    fid = next_id(data["findings"])
                    finding = {
                        "id": fid,
                        "date": datetime.now().strftime("%Y-%m-%d"),
                        "title": f"{r.get('type', 'Finding').replace('_', ' ').title()} at {r.get('path', url)}",
                        "severity": "critical" if r.get("secrets") else "medium",
                        "type": r.get("type", "unknown"),
                        "description": f"Found at {r['url']}. " + (
                            "Secrets detected: " + ", ".join(s["type"] for s in r["secrets"]) if r.get("secrets") else "Exposed path accessible."
                        ),
                        "status": "pending",
                        "notified": False,
                        "days_to_fix": None
                    }
                    data["findings"].insert(0, finding)
                    data["stats"]["found"] += 1
                    log.info(f"New finding added: [{fid}] {finding['title']}")
                data["stats"]["scanned"] += 1
                save_findings(data)
                log.info(f"Scan complete. {len(raw)} finding(s) saved.")
            else:
                data = load_findings()
                data["stats"]["scanned"] += 1
                save_findings(data)
                log.info("Scan complete. No findings.")
        except json.JSONDecodeError:
            log.info("Scan complete. Could not parse findings JSON.")
    else:
        data = load_findings()
        data["stats"]["scanned"] += 1
        save_findings(data)
        log.info("Scan complete. No findings.")

def cmd_update_site():
    log.info("Pushing updated findings to GitHub...")
    cmds = [
        ["git", "add", "findings.json"],
        ["git", "commit", "-m", f"data: update findings [{datetime.now().strftime('%Y-%m-%d %H:%M')}]"],
        ["git", "push"]
    ]
    for cmd in cmds:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            if "nothing to commit" in result.stdout + result.stderr:
                log.info("Nothing to commit — findings.json unchanged.")
                return
            log.error(f"Git error: {result.stderr}")
            return
        log.info(f"$ {' '.join(cmd)} → OK")
    log.info("Site updated. Live at https://shree-git.github.io/v1b3/")

def cmd_notify(finding_id, owner_email):
    log.info(f"Generating disclosure for finding #{finding_id} → {owner_email}")
    result = subprocess.run(
        [sys.executable, "notify.py", "--id", finding_id, "--owner-email", owner_email],
        capture_output=False
    )
    if result.returncode == 0:
        data = load_findings()
        for f in data["findings"]:
            if f["id"] == finding_id:
                f["notified"] = True
                if f["status"] == "pending":
                    f["status"] = "notified"
        save_findings(data)
        log.info(f"Finding #{finding_id} marked as notified.")

def cmd_report():
    data = load_findings()
    stats = data["stats"]
    findings = data["findings"]

    print(f"\n{'='*55}")
    print(f"  V1B3 FINDINGS REPORT — {datetime.now().strftime('%Y-%m-%d')}")
    print(f"{'='*55}")
    print(f"  Sites Scanned : {stats['scanned']}")
    print(f"  Vulns Found   : {stats['found']}")
    print(f"  Resolved      : {stats['resolved']}")
    print(f"  Open          : {stats['found'] - stats['resolved']}")
    print(f"{'='*55}\n")

    for f in findings:
        icon = "🔴" if f["severity"] == "critical" else "🟡" if f["severity"] == "medium" else "🟢"
        notified = "✓ notified" if f["notified"] else "✗ not notified"
        print(f"  [{f['id']}] {icon} {f['title']}")
        print(f"       Status: {f['status']} | {notified} | {f['date']}")
        print()

def cmd_mark_resolved(finding_id, days):
    data = load_findings()
    for f in data["findings"]:
        if f["id"] == finding_id:
            f["status"] = "resolved"
            f["days_to_fix"] = int(days) if days else None
            data["stats"]["resolved"] += 1
            log.info(f"Finding #{finding_id} marked as resolved.")
    save_findings(data)

def main():
    parser = argparse.ArgumentParser(description="V1B3 Autonomous Agent")
    parser.add_argument("--scan", metavar="URL", help="Scan a target URL")
    parser.add_argument("--update-site", action="store_true", help="Push findings to GitHub")
    parser.add_argument("--notify", action="store_true", help="Send disclosure email")
    parser.add_argument("--report", action="store_true", help="Print findings summary")
    parser.add_argument("--resolve", action="store_true", help="Mark a finding as resolved")
    parser.add_argument("--id", help="Finding ID (for --notify / --resolve)")
    parser.add_argument("--email", help="Owner email (for --notify)")
    parser.add_argument("--days", help="Days to fix (for --resolve)")
    args = parser.parse_args()

    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    if args.scan:
        cmd_scan(args.scan)
    elif args.update_site:
        cmd_update_site()
    elif args.notify:
        if not args.id or not args.email:
            print("[!] --notify requires --id and --email")
            sys.exit(1)
        cmd_notify(args.id, args.email)
    elif args.report:
        cmd_report()
    elif args.resolve:
        if not args.id:
            print("[!] --resolve requires --id")
            sys.exit(1)
        cmd_mark_resolved(args.id, args.days)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()

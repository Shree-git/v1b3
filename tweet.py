#!/usr/bin/env python3
"""
V1B3 Tweeter — Posts to X (Twitter) as V1B3
Uses Twitter API v2.

Setup:
  1. Create account @v1b3sec on x.com
  2. Get API keys from developer.x.com
  3. Save config: python3 tweet.py --setup

Usage:
  python3 tweet.py --post "your tweet text"
  python3 tweet.py --scan-complete --target https://example.com
  python3 tweet.py --weekly-stats
  python3 tweet.py --tip
  python3 tweet.py --dry-run --weekly-stats   (preview without posting)
"""

import argparse
import json
import os
import random
import sys
from datetime import datetime

CONFIG_FILE = ".twitter_config.json"

# V1B3's security tips rotation
SECURITY_TIPS = [
    "if you vibe coded your app this weekend,\ncheck these paths right now:\n\n/.env\n/.env.local\n/.git/config\n/config.json\n\ni'll wait.",
    "your .env file is not hidden just because it's dotted.\n\nif your server isn't configured to block it,\nit's public.\n\n`curl https://yourapp.com/.env`\n\ntry it.",
    "using vercel/netlify/railway?\n\nset your secrets in the platform env vars.\nnot in .env files you commit.\nnot hardcoded in components.\n\nin. the. platform. vars.",
    "AI wrote your app fast.\nAI also hardcoded your openai key in 3 places.\n\ngrep -r 'sk-' src/\n\ndo it now.",
    "before you ship:\n\n[ ] .env in .gitignore?\n[ ] no keys in JS files?\n[ ] /.git blocked?\n[ ] no /backup.sql?\n[ ] CORS configured?\n\ncheck the list. then ship.",
    "a $.01 openai key leak can become a $3,000 bill.\n\nnot a joke.\nnot a threat.\njust math.\n\ncheck your bundles.",
    "git history is forever.\n\neven if you delete the file,\nthe key is still in the commit.\n\n`git log --all -S 'sk-'`\n\ncheck it.",
    "vibe coding is fine.\nshipping exposed secrets is not.\n\nthe vibes don't fix your stripe key being public.",
    "someone is scanning your app right now.\n\nit's either me (friendly)\nor someone else (not).\n\nwhich would you prefer?",
    "supabase service role keys bypass row-level security.\n\nif yours is in your frontend bundle,\nyour entire database is public.\n\nthis is not a drill.",
]

def load_config():
    if not os.path.exists(CONFIG_FILE):
        return None
    with open(CONFIG_FILE) as f:
        return json.load(f)

def save_config(config):
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)
    os.chmod(CONFIG_FILE, 0o600)  # Restrict permissions

def setup():
    print("\n[V1B3 Twitter Setup]")
    print("Get your keys from developer.x.com → Your App → Keys and Tokens\n")
    config = {
        "api_key": input("API Key (Consumer Key): ").strip(),
        "api_secret": input("API Secret (Consumer Secret): ").strip(),
        "access_token": input("Access Token: ").strip(),
        "access_token_secret": input("Access Token Secret: ").strip(),
        "bearer_token": input("Bearer Token: ").strip(),
    }
    save_config(config)
    print(f"\n[✓] Config saved to {CONFIG_FILE}")
    print("[✓] V1B3 Twitter is ready to post.")

def post_tweet(text, dry_run=False):
    if dry_run:
        print("\n[DRY RUN] Would post:")
        print("─" * 40)
        print(text)
        print("─" * 40)
        print(f"({len(text)} chars)\n")
        return True

    config = load_config()
    if not config:
        print("[!] No Twitter config found. Run: python3 tweet.py --setup")
        return False

    try:
        import tweepy
    except ImportError:
        print("[!] tweepy not installed. Run: pip install tweepy")
        return False

    try:
        client = tweepy.Client(
            bearer_token=config["bearer_token"],
            consumer_key=config["api_key"],
            consumer_secret=config["api_secret"],
            access_token=config["access_token"],
            access_token_secret=config["access_token_secret"]
        )
        response = client.create_tweet(text=text)
        tweet_id = response.data["id"]
        print(f"[✓] Posted: https://x.com/v1b3sec/status/{tweet_id}")
        return True
    except Exception as e:
        print(f"[!] Tweet failed: {e}")
        return False

def tweet_scan_complete(target, dry_run=False):
    # Load findings to see if anything was found
    try:
        with open("findings.json") as f:
            data = json.load(f)
        findings = [f for f in data["findings"] if datetime.now().strftime("%Y-%m-%d") in f.get("date", "")]
        if findings:
            f = findings[0]
            severity = f["severity"]
            icon = "🔴" if severity == "critical" else "🟡"
            text = f"scan complete.\n\n{icon} {f['title'].lower()}\n\nowner notified. standing by.\n\n// {target[:30]}..."
        else:
            text = f"scan complete on {target[:40]}.\n\nall clear. no exposed paths, no leaked secrets.\n\nstay clean out there."
    except Exception:
        text = f"scan complete.\n\nresults logged. site updated.\n\n// shree-git.github.io/v1b3/"

    post_tweet(text[:280], dry_run=dry_run)

def tweet_weekly_stats(dry_run=False):
    try:
        with open("findings.json") as f:
            data = json.load(f)
        stats = data["stats"]
        text = (
            f"weekly report:\n\n"
            f"→ {stats['scanned']} sites scanned\n"
            f"→ {stats['found']} vulnerabilities found\n"
            f"→ {stats['resolved']} resolved\n"
            f"→ {stats['found'] - stats['resolved']} still open\n\n"
            f"0 secrets exploited. ever.\n\n"
            f"// shree-git.github.io/v1b3/"
        )
    except Exception:
        text = "weekly report: still scanning. still finding things. still not exploiting them.\n\n// shree-git.github.io/v1b3/"

    post_tweet(text[:280], dry_run=dry_run)

def tweet_tip(dry_run=False):
    tip = random.choice(SECURITY_TIPS)
    post_tweet(tip[:280], dry_run=dry_run)

def main():
    parser = argparse.ArgumentParser(description="V1B3 Twitter Bot")
    parser.add_argument("--setup", action="store_true", help="Configure Twitter API keys")
    parser.add_argument("--post", metavar="TEXT", help="Post a custom tweet")
    parser.add_argument("--scan-complete", action="store_true", help="Tweet scan completion")
    parser.add_argument("--weekly-stats", action="store_true", help="Tweet weekly stats")
    parser.add_argument("--tip", action="store_true", help="Tweet a random security tip")
    parser.add_argument("--target", metavar="URL", help="Target URL (for --scan-complete)")
    parser.add_argument("--dry-run", action="store_true", help="Preview without posting")
    args = parser.parse_args()

    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    if args.setup:
        setup()
    elif args.post:
        post_tweet(args.post, dry_run=args.dry_run)
    elif args.scan_complete:
        tweet_scan_complete(args.target or "unknown", dry_run=args.dry_run)
    elif args.weekly_stats:
        tweet_weekly_stats(dry_run=args.dry_run)
    elif args.tip:
        tweet_tip(dry_run=args.dry_run)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()

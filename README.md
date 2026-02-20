# V1B3 🕵️

> Autonomous ethical hacker of vibe-coded systems.

I find what vibe-coders accidentally leave in the open — exposed `.env` files, hardcoded API keys, leaked secrets in JS bundles — and I tell the people who built them before someone worse does.

## What I scan for

- Exposed `.env` / `.env.local` / `.env.production` files
- Hardcoded API keys in JS bundles (OpenAI, Stripe, AWS, GitHub, Supabase, etc.)
- Accessible `/.git/` directories
- Backup files, config dumps, open admin panels

## Rules of engagement

- Only publicly accessible surfaces — no auth bypass, no exploitation
- Owners are notified before anything is published
- Secrets are never stored, used, or shared
- Findings published after 7-day responsible disclosure window

## Usage

```bash
pip install requests
python3 scan.py https://your-vibe-app.vercel.app
```

## Submit a target

Open an issue with a URL you want scanned. I'll handle it.

---

*Built with curiosity. Operated with ethics. // 2026*

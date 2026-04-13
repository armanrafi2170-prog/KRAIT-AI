# KRAIT — Network Security Intelligence Platform

> Educational network security scanner with AI-powered analysis, built for Replit free tier.

![Python](https://img.shields.io/badge/Python-3.11-blue)
![Flask](https://img.shields.io/badge/Flask-3.0.3-green)
![License](https://img.shields.io/badge/License-Educational-orange)

---

## Architecture

```
Browser ──► Flask (Replit) ──► TCP Connect Scanner (pure Python, no root)
                 │
                 ├──► PostgreSQL (Replit built-in DB)
                 │
                 └──► Groq LLaMA-3 70B (AI security reports)
                 
                 Optional:
                 └──► Oracle Cloud Worker (Nmap/Scapy, root access)
```

## Features

- **Cyberpunk dark UI** — Terminal-style dashboard with real-time WebSocket scan updates
- **Pure Python async scanner** — TCP connect scanning, works on Replit free tier (no root/raw sockets needed)
- **AI Security Reports** — Groq LLaMA-3 70B generates executive summaries, risk tables, CVE mapping, and remediation steps
- **PostgreSQL persistence** — Scan history never lost, full audit logs
- **Rate limiting + CSRF** — Flask-Limiter and Flask-WTF protection built-in
- **External worker support** — `worker.py` for Oracle Cloud (Nmap SYN scans, root access)
- **Banner grabbing** — Service version detection per port
- **Target validation** — Private IPs, loopback, reserved ranges all blocked

## Files

| File | Purpose |
|------|---------|
| `main.py` | Flask app, routes, SocketIO events, scan threading |
| `scanner.py` | Async TCP connect port scanner, target validation |
| `ai_engine.py` | Groq AI integration, rate-limited report generation |
| `database.py` | DB abstraction (PostgreSQL + SQLite fallback), scan CRUD |
| `worker.py` | External Oracle Cloud worker (Nmap/Scapy) |
| `templates/` | Jinja2 HTML templates |
| `static/` | CSS dark theme + JavaScript Socket.IO client |

## Quick Start (Replit)

1. Fork/import this repo into Replit
2. Add secrets: `GROQ_API_KEY`, `ADMIN_PASSWORD`
3. Run — the app starts on port 5000

## Secrets

| Key | Required | Purpose |
|-----|----------|---------|
| `GROQ_API_KEY` | Yes | Groq AI (free at console.groq.com) |
| `ADMIN_PASSWORD` | Yes | Dashboard login |
| `SECRET_KEY` | Auto | Flask session key |
| `ALLOWED_TARGETS` | No | Comma-separated scan whitelist |
| `WORKER_TOKEN` | No | Oracle Cloud worker auth |

## Replit Free Tier Workarounds

| Limitation | Solution |
|-----------|---------|
| No raw sockets | Async TCP connect scan |
| No root access | User-space ports only |
| Ephemeral storage | PostgreSQL built-in DB |
| 512MB RAM | Single-worker, async scanning |

## External Worker (Oracle Cloud — Optional)

Deploy `worker.py` on Oracle Cloud Always Free for full Nmap/Scapy capabilities:

```bash
pip install python-nmap requests groq
export REPLIT_API_URL="https://your-app.replit.app"
export WORKER_TOKEN="your_token"
export GROQ_API_KEY="your_key"
python worker.py
```

## Legal / Ethics

This tool is for **authorized educational use only**.

- Only scan targets you own or have written permission to test
- All scans are logged with IP and timestamp
- Private/internal IP ranges are blocked by default
- `scanme.nmap.org` is an authorized public test target

---

Built with Python, Flask, Socket.IO, Groq, PostgreSQL.

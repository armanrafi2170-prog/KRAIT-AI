# KRAIT — Network Security Intelligence Platform

Educational network security scanner with AI-powered analysis, built for Replit free tier.

## Architecture

- **Frontend/UI**: Flask + Jinja2 templates, dark cyberpunk theme, real-time WebSocket updates
- **Scanner**: Pure Python async TCP connect scanner (no root/raw sockets needed)
- **AI Engine**: Groq LLaMA-3 70B for automated security report generation
- **Database**: PostgreSQL (Replit built-in) with SQLite fallback
- **WebSocket**: Flask-SocketIO (threading mode) for live scan progress

## Files

| File | Purpose |
|------|---------|
| `main.py` | Flask app, routes, SocketIO events, scan threading |
| `scanner.py` | Async TCP connect port scanner, target validation |
| `ai_engine.py` | Groq AI integration, rate-limited report generation |
| `database.py` | DB abstraction (PostgreSQL + SQLite), scan CRUD |
| `worker.py` | External Oracle Cloud worker (for Nmap/Scapy beyond Replit) |
| `templates/` | Jinja2 HTML templates |
| `static/` | CSS (dark theme) + JavaScript (Socket.IO client) |

## Secrets Required

| Key | Purpose |
|-----|---------|
| `GROQ_API_KEY` | Groq AI API for LLaMA-3 reports (free at console.groq.com) |
| `ADMIN_PASSWORD` | Dashboard login password |
| `SECRET_KEY` | Flask session key (auto-generated) |

## Optional Secrets

| Key | Purpose |
|-----|---------|
| `ALLOWED_TARGETS` | Comma-separated whitelist of allowed scan targets |
| `WORKER_TOKEN` | Auth token for external Oracle Cloud worker |
| `ENABLE_KEEPALIVE` | Set to `true` to enable self-ping (not recommended on free tier) |

## Default Login

- Username: `admin`
- Password: whatever you set in `ADMIN_PASSWORD`

## Replit Limitations & Workarounds

| Limitation | Workaround Used |
|-----------|----------------|
| No raw sockets | Pure Python async TCP connect scanner |
| No root access | User-space ports only, no Nmap SYN scans |
| Ephemeral storage | PostgreSQL via Replit's built-in DB |
| RAM limits | Single gevent worker, async scanning |

## External Worker (Optional)

Deploy `worker.py` on Oracle Cloud Always Free (4 ARM cores, 24GB RAM, root access) for Nmap/Scapy scanning. Set `WORKER_TOKEN` and `ORACLE_WORKER_URL` secrets.

## Running

```bash
python main.py
```

## Deployment

Uses gunicorn with gevent worker for production.

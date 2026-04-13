import os
import json
import sqlite3
import logging
from datetime import datetime
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

DATABASE_URL = os.environ.get("DATABASE_URL")
USE_POSTGRES = bool(DATABASE_URL)

if USE_POSTGRES:
    try:
        import psycopg2
        import psycopg2.extras
    except ImportError:
        USE_POSTGRES = False
        logger.warning("psycopg2 not available, falling back to SQLite")


def get_connection():
    if USE_POSTGRES:
        url = urlparse(DATABASE_URL)
        connect_kwargs = dict(
            host=url.hostname,
            port=url.port or 5432,
            database=url.path[1:],
            user=url.username,
            password=url.password,
        )
        if url.query and "sslmode" in url.query:
            connect_kwargs["sslmode"] = "require"
        try:
            conn = psycopg2.connect(**connect_kwargs)
        except psycopg2.OperationalError:
            connect_kwargs.pop("sslmode", None)
            conn = psycopg2.connect(**connect_kwargs)
        return conn
    else:
        conn = sqlite3.connect("krait.db", check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn


def placeholder(n=1):
    if USE_POSTGRES:
        return ", ".join([f"%s"] * n)
    else:
        return ", ".join(["?"] * n)


def ph(index=1):
    if USE_POSTGRES:
        return f"%s"
    else:
        return "?"


def init_db():
    conn = get_connection()
    cur = conn.cursor()

    if USE_POSTGRES:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id SERIAL PRIMARY KEY,
                target VARCHAR(255) NOT NULL,
                scan_type VARCHAR(100) DEFAULT 'tcp_connect',
                port_range VARCHAR(100) DEFAULT '1-1024',
                status VARCHAR(50) DEFAULT 'queued',
                results TEXT,
                ai_report TEXT,
                open_ports TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP,
                user_ip VARCHAR(45),
                duration_seconds FLOAT
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS auth_logs (
                id SERIAL PRIMARY KEY,
                ip VARCHAR(45),
                action VARCHAR(100),
                details TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(100) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        """)
    else:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                scan_type TEXT DEFAULT 'tcp_connect',
                port_range TEXT DEFAULT '1-1024',
                status TEXT DEFAULT 'queued',
                results TEXT,
                ai_report TEXT,
                open_ports TEXT,
                created_at TEXT DEFAULT (datetime('now')),
                completed_at TEXT,
                user_ip TEXT,
                duration_seconds REAL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS auth_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                action TEXT,
                details TEXT,
                timestamp TEXT DEFAULT (datetime('now'))
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT DEFAULT (datetime('now')),
                last_login TEXT
            )
        """)

    conn.commit()
    cur.close()
    conn.close()
    logger.info(f"Database initialized ({'PostgreSQL' if USE_POSTGRES else 'SQLite'})")


def _serialize_row(row: dict) -> dict:
    """Normalize a DB row: convert datetime objects to ISO strings, JSON strings to objects."""
    result = {}
    for k, v in row.items():
        if hasattr(v, 'isoformat'):
            result[k] = v.isoformat()
        else:
            result[k] = v
    for field in ("results", "open_ports"):
        if result.get(field) and isinstance(result[field], str):
            try:
                result[field] = json.loads(result[field])
            except Exception:
                pass
    return result


def create_scan(target, scan_type, port_range, user_ip):
    conn = get_connection()
    cur = conn.cursor()
    now = datetime.utcnow().isoformat()

    if USE_POSTGRES:
        cur.execute(
            "INSERT INTO scans (target, scan_type, port_range, status, user_ip, created_at) VALUES (%s, %s, %s, %s, %s, %s) RETURNING id",
            (target, scan_type, port_range, "queued", user_ip, now)
        )
        scan_id = cur.fetchone()[0]
    else:
        cur.execute(
            "INSERT INTO scans (target, scan_type, port_range, status, user_ip, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (target, scan_type, port_range, "queued", user_ip, now)
        )
        scan_id = cur.lastrowid

    conn.commit()
    cur.close()
    conn.close()
    return scan_id


def update_scan(scan_id, status, results=None, ai_report=None, open_ports=None, duration=None):
    conn = get_connection()
    cur = conn.cursor()
    now = datetime.utcnow().isoformat()

    results_str = json.dumps(results) if results is not None else None
    open_ports_str = json.dumps(open_ports) if open_ports is not None else None

    if USE_POSTGRES:
        cur.execute(
            """UPDATE scans SET status=%s, results=%s, ai_report=%s, open_ports=%s,
               completed_at=%s, duration_seconds=%s WHERE id=%s""",
            (status, results_str, ai_report, open_ports_str, now, duration, scan_id)
        )
    else:
        cur.execute(
            """UPDATE scans SET status=?, results=?, ai_report=?, open_ports=?,
               completed_at=?, duration_seconds=? WHERE id=?""",
            (status, results_str, ai_report, open_ports_str, now, duration, scan_id)
        )

    conn.commit()
    cur.close()
    conn.close()


def get_scan(scan_id):
    conn = get_connection()
    cur = conn.cursor()

    if USE_POSTGRES:
        cur.execute("SELECT * FROM scans WHERE id=%s", (scan_id,))
        row = cur.fetchone()
        if row:
            cols = [desc[0] for desc in cur.description]
            result = dict(zip(cols, row))
        else:
            result = None
    else:
        cur.execute("SELECT * FROM scans WHERE id=?", (scan_id,))
        row = cur.fetchone()
        result = dict(row) if row else None

    cur.close()
    conn.close()

    if result:
        result = _serialize_row(result)
    return result


def get_all_scans(limit=50):
    conn = get_connection()
    cur = conn.cursor()

    if USE_POSTGRES:
        cur.execute("SELECT * FROM scans ORDER BY created_at DESC LIMIT %s", (limit,))
        cols = [desc[0] for desc in cur.description]
        rows = [dict(zip(cols, row)) for row in cur.fetchall()]
    else:
        cur.execute("SELECT * FROM scans ORDER BY created_at DESC LIMIT ?", (limit,))
        rows = [dict(row) for row in cur.fetchall()]

    cur.close()
    conn.close()

    return [_serialize_row(row) for row in rows]


def get_pending_scans():
    conn = get_connection()
    cur = conn.cursor()

    if USE_POSTGRES:
        cur.execute("SELECT * FROM scans WHERE status='queued' ORDER BY created_at ASC LIMIT 10")
        cols = [desc[0] for desc in cur.description]
        rows = [dict(zip(cols, row)) for row in cur.fetchall()]
    else:
        cur.execute("SELECT * FROM scans WHERE status='queued' ORDER BY created_at ASC LIMIT 10")
        rows = [dict(row) for row in cur.fetchall()]

    cur.close()
    conn.close()
    return rows


def log_auth(ip, action, details=""):
    conn = get_connection()
    cur = conn.cursor()

    if USE_POSTGRES:
        cur.execute(
            "INSERT INTO auth_logs (ip, action, details) VALUES (%s, %s, %s)",
            (ip, action, details)
        )
    else:
        cur.execute(
            "INSERT INTO auth_logs (ip, action, details) VALUES (?, ?, ?)",
            (ip, action, details)
        )

    conn.commit()
    cur.close()
    conn.close()


def get_stats():
    conn = get_connection()
    cur = conn.cursor()

    if USE_POSTGRES:
        cur.execute("SELECT COUNT(*) FROM scans")
        total = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM scans WHERE status='completed'")
        completed = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM scans WHERE status='running'")
        running = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM scans WHERE status='failed'")
        failed = cur.fetchone()[0]
    else:
        cur.execute("SELECT COUNT(*) FROM scans")
        total = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM scans WHERE status='completed'")
        completed = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM scans WHERE status='running'")
        running = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM scans WHERE status='failed'")
        failed = cur.fetchone()[0]

    cur.close()
    conn.close()

    return {
        "total": total,
        "completed": completed,
        "running": running,
        "failed": failed
    }

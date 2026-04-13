import os
import json
import secrets
import logging
import threading
import time
import hashlib
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, request, jsonify, session, render_template,
    redirect, url_for, flash, Response
)
from flask_socketio import SocketIO, emit
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect, generate_csrf

import database as db
import scanner
import ai_engine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s"
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=4)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["WTF_CSRF_TIME_LIMIT"] = 3600
app.config["WTF_CSRF_CHECK_DEFAULT"] = False

csrf = CSRFProtect(app)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["60 per minute", "10 per second"],
    storage_uri="memory://"
)

socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="threading",
    logger=False,
    engineio_logger=False
)

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "krait2024")
WORKER_TOKEN = os.environ.get("WORKER_TOKEN", secrets.token_hex(16))

ALLOWED_TARGETS_ENV = os.environ.get("ALLOWED_TARGETS", "")
ALLOWED_TARGETS = [t.strip() for t in ALLOWED_TARGETS_ENV.split(",") if t.strip()] if ALLOWED_TARGETS_ENV else []

active_scans = {}


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("authenticated"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def worker_auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization", "")
        if token != WORKER_TOKEN:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


db.init_db()


@app.route("/")
@login_required
def index():
    stats = db.get_stats()
    recent_scans = db.get_all_scans(limit=5)
    return render_template("index.html", stats=stats, recent_scans=recent_scans)


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    if session.get("authenticated"):
        return redirect(url_for("index"))

    if request.method == "POST":
        password = request.form.get("password", "")
        username = request.form.get("username", "admin")

        if password == ADMIN_PASSWORD:
            session.permanent = True
            session["authenticated"] = True
            session["username"] = username
            db.log_auth(request.remote_addr, "login_success", f"user={username}")
            logger.info(f"Login success from {request.remote_addr}")
            return redirect(url_for("index"))
        else:
            db.log_auth(request.remote_addr, "login_failed", f"user={username}")
            logger.warning(f"Failed login from {request.remote_addr}")
            flash("Invalid credentials", "error")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    db.log_auth(request.remote_addr, "logout", f"user={session.get('username')}")
    session.clear()
    return redirect(url_for("login"))


@app.route("/scan")
@login_required
def scan_page():
    return render_template("scan.html", allowed_targets=ALLOWED_TARGETS)


@app.route("/history")
@login_required
def history():
    scans = db.get_all_scans(limit=100)
    return render_template("history.html", scans=scans)


@app.route("/results/<int:scan_id>")
@login_required
def results(scan_id):
    scan = db.get_scan(scan_id)
    if not scan:
        flash("Scan not found", "error")
        return redirect(url_for("history"))
    return render_template("results.html", scan=scan)


@app.route("/api/csrf-token")
@login_required
def get_csrf_token():
    return jsonify({"csrf_token": generate_csrf()})


@app.route("/api/scan", methods=["POST"])
@login_required
@limiter.limit("5 per minute")
def api_start_scan():
    data = request.get_json(silent=True) or {}
    target = data.get("target", "").strip()
    scan_type = data.get("scan_type", "tcp_connect")
    port_range = data.get("port_range", "common")

    if not target:
        return jsonify({"error": "Target is required"}), 400

    valid, message = scanner.validate_target(target)
    if not valid:
        db.log_auth(request.remote_addr, "scan_blocked", f"target={target} reason={message}")
        return jsonify({"error": message}), 403

    if ALLOWED_TARGETS and target not in ALLOWED_TARGETS:
        resolved_ip = message
        if resolved_ip not in ALLOWED_TARGETS:
            db.log_auth(request.remote_addr, "scan_blocked", f"target={target} not in whitelist")
            return jsonify({"error": "Target not in authorized whitelist. Add it to ALLOWED_TARGETS to permit."}), 403

    ports = scanner.parse_port_range(port_range)
    if not ports:
        return jsonify({"error": "Invalid port range"}), 400

    if len(ports) > 10000:
        return jsonify({"error": "Port range too large (max 10,000 ports)"}), 400

    scan_id = db.create_scan(target, scan_type, port_range, request.remote_addr)

    thread = threading.Thread(
        target=_run_scan_thread,
        args=(scan_id, target, ports),
        daemon=True
    )
    active_scans[scan_id] = {"status": "running", "thread": thread}
    thread.start()

    logger.info(f"Scan {scan_id} started: target={target}, ports={len(ports)}, by={request.remote_addr}")

    return jsonify({
        "scan_id": scan_id,
        "status": "running",
        "target": target,
        "total_ports": len(ports)
    })


def _run_scan_thread(scan_id, target, ports):
    db.update_scan(scan_id, "running")
    socketio.emit("scan_update", {
        "scan_id": scan_id,
        "status": "running",
        "progress": 0,
        "message": f"Scanning {target}..."
    })

    def progress_cb(pct, done, total):
        socketio.emit("scan_update", {
            "scan_id": scan_id,
            "status": "running",
            "progress": pct,
            "message": f"Scanned {done}/{total} ports..."
        })

    try:
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        async def run():
            async def async_cb(pct, done, total):
                progress_cb(pct, done, total)
            return await scanner.run_scan(target, ports, max_concurrent=100, timeout=2.0, progress_callback=async_cb)

        results = loop.run_until_complete(run())
        loop.close()

        socketio.emit("scan_update", {
            "scan_id": scan_id,
            "status": "analyzing",
            "progress": 95,
            "message": "Running AI analysis..."
        })

        ai_report = ai_engine.generate_scan_report(results)

        db.update_scan(
            scan_id,
            status="completed",
            results=results,
            ai_report=ai_report,
            open_ports=results.get("open_ports", []),
            duration=results.get("scan_duration")
        )

        socketio.emit("scan_update", {
            "scan_id": scan_id,
            "status": "completed",
            "progress": 100,
            "message": "Scan complete!",
            "open_ports": results.get("open_ports", []),
            "total_scanned": results.get("total_scanned", 0),
            "duration": results.get("scan_duration", 0)
        })

        logger.info(f"Scan {scan_id} completed: {len(results.get('open_ports', []))} open ports")

    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {e}", exc_info=True)
        db.update_scan(scan_id, "failed")
        socketio.emit("scan_update", {
            "scan_id": scan_id,
            "status": "failed",
            "progress": 0,
            "message": f"Scan failed: {str(e)}"
        })
    finally:
        active_scans.pop(scan_id, None)


@app.route("/api/scan/<int:scan_id>/status")
@login_required
def scan_status(scan_id):
    scan = db.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify({
        "scan_id": scan_id,
        "status": scan["status"],
        "target": scan["target"],
        "open_ports": scan.get("open_ports", []),
        "created_at": scan.get("created_at"),
        "completed_at": scan.get("completed_at"),
        "duration": scan.get("duration_seconds")
    })


@app.route("/api/scans")
@login_required
def api_get_scans():
    scans = db.get_all_scans(limit=50)
    return jsonify(scans)


@app.route("/api/stats")
@login_required
def api_stats():
    return jsonify(db.get_stats())


@app.route("/api/worker/pending")
@worker_auth_required
def worker_pending():
    scans = db.get_pending_scans()
    return jsonify(scans)


@app.route("/api/worker/complete/<int:scan_id>", methods=["POST"])
@worker_auth_required
def worker_complete(scan_id):
    data = request.get_json(silent=True) or {}
    results = data.get("results", {})
    ai_report = data.get("report", "")

    db.update_scan(
        scan_id,
        status="completed",
        results=results,
        ai_report=ai_report,
        open_ports=results.get("open_ports", []),
        duration=results.get("scan_duration")
    )

    socketio.emit("scan_update", {
        "scan_id": scan_id,
        "status": "completed",
        "progress": 100,
        "message": "Scan complete (worker)!"
    })

    return jsonify({"success": True})


@app.route("/favicon.ico")
def favicon():
    svg = b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" fill="#0a0d0f"/><text x="16" y="24" font-size="22" text-anchor="middle" fill="#00ff88">&#9670;</text></svg>'
    return Response(svg, mimetype="image/svg+xml")


@app.route("/ping")
def ping():
    return "OK", 200


@app.route("/health")
def health():
    stats = db.get_stats()
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "db_connected": True,
        "stats": stats
    })


@socketio.on("connect")
def on_connect():
    if not session.get("authenticated"):
        return False
    logger.debug(f"WebSocket connected: {request.sid}")


@socketio.on("disconnect")
def on_disconnect():
    logger.debug(f"WebSocket disconnected: {request.sid}")


@socketio.on("join_scan")
def on_join_scan(data):
    scan_id = data.get("scan_id")
    if scan_id:
        scan = db.get_scan(scan_id)
        if scan:
            emit("scan_state", {
                "scan_id": scan_id,
                "status": scan["status"],
                "target": scan["target"]
            })


def _keep_alive():
    import requests as req_lib
    app_url = os.environ.get("REPLIT_DEV_DOMAIN", "")
    if not app_url:
        return
    while True:
        try:
            req_lib.get(f"https://{app_url}/ping", timeout=10)
        except Exception:
            pass
        time.sleep(280)


if os.environ.get("ENABLE_KEEPALIVE", "false").lower() == "true":
    threading.Thread(target=_keep_alive, daemon=True).start()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV", "production") == "development"
    logger.info(f"KRAIT starting on port {port}")
    logger.info(f"Worker token: {WORKER_TOKEN}")
    socketio.run(app, host="0.0.0.0", port=port, debug=debug, use_reloader=False, log_output=False, allow_unsafe_werkzeug=True)

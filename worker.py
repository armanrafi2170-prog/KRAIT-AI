"""
KRAIT External Worker — Deploy this on Oracle Cloud Free Tier or any server with root access.
This allows full Nmap/Scapy scanning capabilities beyond Replit's limitations.

Usage:
    pip install python-nmap requests groq
    export REPLIT_API_URL="https://your-replit-app.replit.app"
    export WORKER_TOKEN="your_worker_token"
    export GROQ_API_KEY="your_groq_key"
    python worker.py
"""

import os
import json
import time
import logging
import requests
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

REPLIT_API = os.environ.get("REPLIT_API_URL", "https://your-replit-app.replit.app")
WORKER_TOKEN = os.environ.get("WORKER_TOKEN", "")
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")

HEADERS = {"Authorization": WORKER_TOKEN, "Content-Type": "application/json"}


def fetch_pending_scans():
    try:
        resp = requests.get(
            f"{REPLIT_API}/api/worker/pending",
            headers=HEADERS,
            timeout=15
        )
        if resp.status_code == 200:
            return resp.json()
        logger.warning(f"Unexpected response: {resp.status_code}")
    except Exception as e:
        logger.error(f"Failed to fetch pending scans: {e}")
    return []


def run_nmap_scan(target, arguments="-sS -sV --top-ports 1000 -T4"):
    try:
        import nmap
        nm = nmap.PortScanner()
        nm.scan(target, arguments=arguments)

        open_ports = []
        port_details = []

        if target in nm.all_hosts():
            host_data = nm[target]
            for proto in host_data.all_protocols():
                for port, info in host_data[proto].items():
                    if info["state"] == "open":
                        open_ports.append(port)
                        port_details.append({
                            "port": port,
                            "state": "open",
                            "service": info.get("name", "unknown"),
                            "version": info.get("version", ""),
                            "product": info.get("product", ""),
                            "banner": f"{info.get('product', '')} {info.get('version', '')}".strip()
                        })

        return {
            "target": target,
            "hostname": nm[target].hostname() if target in nm.all_hosts() else target,
            "open_ports": open_ports,
            "port_details": port_details,
            "total_scanned": len(nm[target]["tcp"]) if target in nm.all_hosts() and "tcp" in nm[target] else 0,
            "scan_stats": nm.scanstats(),
            "scan_type": "Nmap SYN Scan",
            "timestamp": datetime.utcnow().isoformat()
        }

    except ImportError:
        logger.error("python-nmap not installed. Run: pip install python-nmap")
        return {"error": "nmap not available", "open_ports": [], "port_details": []}
    except Exception as e:
        logger.error(f"Nmap scan failed: {e}")
        return {"error": str(e), "open_ports": [], "port_details": []}


def generate_ai_report(results, target):
    if not GROQ_API_KEY:
        logger.warning("GROQ_API_KEY not set, skipping AI analysis")
        return "AI analysis not available (GROQ_API_KEY not configured)"

    try:
        from groq import Groq
        client = Groq(api_key=GROQ_API_KEY)

        port_summary = "\n".join([
            f"  Port {p['port']}/tcp - {p.get('service', 'unknown')} {p.get('product', '')} {p.get('version', '')}".strip()
            for p in results.get("port_details", [])
        ])

        prompt = f"""Analyze this Nmap scan result for {target}:

Open Ports:
{port_summary if port_summary else "No open ports found"}

Total ports scanned: {results.get('total_scanned', 'unknown')}
Scan type: {results.get('scan_type', 'unknown')}

Provide:
1. Executive Summary (overall risk: Critical/High/Medium/Low)
2. Attack Surface Analysis per port
3. Risk table: Port | Service | Risk | Known CVEs
4. Top 3 Critical Findings
5. Specific remediation steps

This is for authorized educational security assessment only."""

        chat = client.chat.completions.create(
            messages=[
                {"role": "system", "content": "You are a senior cybersecurity analyst. Be precise, technical, and actionable."},
                {"role": "user", "content": prompt}
            ],
            model="llama3-70b-8192",
            temperature=0.3,
            max_tokens=2000
        )
        return chat.choices[0].message.content

    except Exception as e:
        logger.error(f"AI report generation failed: {e}")
        return f"AI analysis failed: {str(e)}"


def push_results(scan_id, results, ai_report):
    try:
        resp = requests.post(
            f"{REPLIT_API}/api/worker/complete/{scan_id}",
            headers=HEADERS,
            json={"results": results, "report": ai_report},
            timeout=15
        )
        if resp.status_code == 200:
            logger.info(f"Scan {scan_id} results submitted successfully")
            return True
        else:
            logger.error(f"Failed to submit results: {resp.status_code} - {resp.text}")
    except Exception as e:
        logger.error(f"Failed to push results for scan {scan_id}: {e}")
    return False


def process_scans():
    logger.info("KRAIT Worker started")
    logger.info(f"Replit API: {REPLIT_API}")

    while True:
        scans = fetch_pending_scans()

        if not scans:
            time.sleep(15)
            continue

        for scan in scans:
            scan_id = scan["id"]
            target = scan["target"]

            logger.info(f"[+] Processing scan {scan_id}: {target}")

            results = run_nmap_scan(target)
            ai_report = generate_ai_report(results, target)
            push_results(scan_id, results, ai_report)

            time.sleep(2)

        time.sleep(5)


if __name__ == "__main__":
    if not WORKER_TOKEN:
        logger.error("WORKER_TOKEN not set! Set it with: export WORKER_TOKEN='your_token'")
        exit(1)
    process_scans()

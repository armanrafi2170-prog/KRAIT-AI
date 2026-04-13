import os
import time
import json
import logging
from functools import wraps

logger = logging.getLogger(__name__)

GROQ_API_KEY = os.environ.get("GROQ_API_KEY")

_last_call_time = [0.0]
_min_interval = 3.0


def rate_limited(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        elapsed = time.time() - _last_call_time[0]
        wait = _min_interval - elapsed
        if wait > 0:
            time.sleep(wait)
        _last_call_time[0] = time.time()
        return func(*args, **kwargs)
    return wrapper


def get_groq_client():
    if not GROQ_API_KEY:
        return None
    try:
        from groq import Groq
        return Groq(api_key=GROQ_API_KEY)
    except ImportError:
        logger.error("groq package not installed")
        return None
    except Exception as e:
        logger.error(f"Failed to initialize Groq client: {e}")
        return None


@rate_limited
def generate_scan_report(scan_results: dict) -> str:
    client = get_groq_client()

    if not client:
        return _generate_fallback_report(scan_results)

    target = scan_results.get("target", "unknown")
    open_ports = scan_results.get("open_ports", [])
    port_details = scan_results.get("port_details", [])
    scan_duration = scan_results.get("scan_duration", 0)
    total_scanned = scan_results.get("total_scanned", 0)

    port_summary = []
    for p in port_details:
        line = f"  Port {p['port']}/tcp - {p.get('service', 'unknown')}"
        if p.get("banner"):
            line += f" | Banner: {p['banner'][:100]}"
        port_summary.append(line)

    port_text = "\n".join(port_summary) if port_summary else "  No open ports found"

    prompt = f"""You are a senior cybersecurity analyst reviewing a network port scan report for EDUCATIONAL purposes.

TARGET: {target}
SCAN TYPE: TCP Connect Scan
SCAN DURATION: {scan_duration} seconds
PORTS SCANNED: {total_scanned}
OPEN PORTS FOUND: {len(open_ports)}

OPEN PORTS:
{port_text}

Please provide a structured security analysis report with the following sections:

## Executive Summary
Brief overview of findings and overall risk level (Critical/High/Medium/Low/Informational)

## Attack Surface Analysis
Analyze each open port/service for potential vulnerabilities and exposure

## Risk Assessment
| Port | Service | Risk Level | Common Vulnerabilities |
|------|---------|------------|----------------------|
(fill in for each open port)

## Critical Findings
List the most concerning findings that require immediate attention

## Remediation Recommendations
Specific, actionable steps to reduce the attack surface

## Security Posture Score
Rate 1-10 (10 = highly secure) with brief justification

Note: This analysis is for authorized security assessment and educational purposes only.
"""

    try:
        chat = client.chat.completions.create(
            messages=[
                {
                    "role": "system",
                    "content": "You are an expert cybersecurity analyst specializing in network security assessments. Provide detailed, technical, and actionable security reports."
                },
                {"role": "user", "content": prompt}
            ],
            model="llama3-70b-8192",
            temperature=0.3,
            max_tokens=2000
        )
        return chat.choices[0].message.content
    except Exception as e:
        logger.error(f"Groq API error: {e}")
        return _generate_fallback_report(scan_results)


def _generate_fallback_report(scan_results: dict) -> str:
    target = scan_results.get("target", "unknown")
    open_ports = scan_results.get("open_ports", [])
    port_details = scan_results.get("port_details", [])
    total_scanned = scan_results.get("total_scanned", 0)
    duration = scan_results.get("scan_duration", 0)

    risk_ports = {
        21: ("High", "FTP - plaintext credentials, anonymous access possible"),
        23: ("Critical", "Telnet - unencrypted, legacy protocol"),
        25: ("Medium", "SMTP - potential mail relay abuse"),
        53: ("Medium", "DNS - zone transfer, cache poisoning risks"),
        110: ("Medium", "POP3 - plaintext email credentials"),
        135: ("High", "MSRPC - worm propagation vector"),
        139: ("High", "NetBIOS - SMB relay attacks, legacy"),
        143: ("Medium", "IMAP - potential plaintext credentials"),
        445: ("Critical", "SMB - EternalBlue, ransomware propagation"),
        1433: ("High", "MSSQL - brute force, SQL injection risks"),
        1521: ("High", "Oracle DB - exposed database"),
        3306: ("High", "MySQL - exposed database"),
        3389: ("High", "RDP - BlueKeep, brute force target"),
        5432: ("Medium", "PostgreSQL - exposed database"),
        5900: ("High", "VNC - often weak/no auth"),
        6379: ("Critical", "Redis - typically no auth, RCE possible"),
        27017: ("Critical", "MongoDB - often no auth by default"),
    }

    report = f"""## Executive Summary

Automated scan of **{target}** completed in {duration}s. Scanned {total_scanned} ports, found **{len(open_ports)} open**.

*Note: AI analysis unavailable — add GROQ_API_KEY for enhanced AI reports.*

## Open Ports Found

"""
    if not port_details:
        report += "No open ports detected.\n"
    else:
        for p in port_details:
            port = p["port"]
            service = p.get("service", "unknown")
            risk_info = risk_ports.get(port, ("Low", "Standard service"))
            risk_level, note = risk_info
            report += f"- **Port {port}** ({service}) — Risk: **{risk_level}** — {note}\n"
            if p.get("banner"):
                report += f"  - Banner: `{p['banner'][:100]}`\n"

    report += "\n## Remediation Recommendations\n\n"

    has_critical = any(p["port"] in [23, 445, 6379, 27017] for p in port_details)
    has_db = any(p["port"] in [3306, 5432, 1433, 1521, 27017] for p in port_details)

    if has_critical:
        report += "- **URGENT**: Close or firewall critical services (Telnet, SMB, Redis, MongoDB)\n"
    if has_db:
        report += "- **HIGH**: Database ports should never be directly internet-accessible\n"
    if any(p["port"] == 21 for p in port_details):
        report += "- Replace FTP with SFTP/SCP for file transfers\n"
    if any(p["port"] == 3389 for p in port_details):
        report += "- Restrict RDP to VPN only; enable NLA authentication\n"

    report += "- Apply principle of least exposure: close all non-essential ports\n"
    report += "- Implement a Web Application Firewall (WAF) for web services\n"
    report += "- Enable intrusion detection/prevention (IDS/IPS)\n"
    report += "- Regular vulnerability scanning schedule recommended\n"

    return report


def analyze_service(port: int, banner: str) -> dict:
    insights = {
        "port": port,
        "risk": "low",
        "notes": [],
        "cves": []
    }

    if banner:
        banner_lower = banner.lower()
        if "openssh" in banner_lower:
            version_match = banner_lower.split("openssh_")
            if len(version_match) > 1:
                version = version_match[1].split()[0]
                insights["version"] = f"OpenSSH {version}"
                insights["notes"].append("Verify SSH version for known CVEs")
        if "apache" in banner_lower:
            insights["notes"].append("Apache HTTP Server detected - check for version-specific vulnerabilities")
        if "nginx" in banner_lower:
            insights["notes"].append("Nginx detected - ensure latest security patches applied")
        if "microsoft" in banner_lower or "iis" in banner_lower:
            insights["notes"].append("Microsoft IIS detected - check patch level")

    return insights

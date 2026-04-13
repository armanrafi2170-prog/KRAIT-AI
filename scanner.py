import asyncio
import socket
import ipaddress
import logging
import re
from datetime import datetime

logger = logging.getLogger(__name__)

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 587: "SMTP-TLS",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    8888: "HTTP-Alt2", 9200: "Elasticsearch", 27017: "MongoDB",
    6443: "Kubernetes", 2376: "Docker", 2181: "Zookeeper",
    7001: "WebLogic", 8009: "AJP", 9090: "Cockpit", 9100: "Prometheus",
    11211: "Memcached", 50000: "DB2"
}

SERVICE_BANNERS = {
    21: b"USER anonymous\r\n",
    22: None,
    25: b"EHLO test\r\n",
    80: b"HEAD / HTTP/1.0\r\n\r\n",
    443: None,
    3306: None,
    5432: None,
}

BLOCKED_TARGETS = [
    "localhost", "127.0.0.1", "0.0.0.0", "::1",
    "169.254.0.0/16",
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "100.64.0.0/10",
]


def validate_target(target: str) -> tuple[bool, str]:
    target = target.strip()

    if not target:
        return False, "Target cannot be empty"

    if len(target) > 253:
        return False, "Target too long"

    if re.search(r'[;&|`$\\]', target):
        return False, "Invalid characters in target"

    resolved_ip = None
    try:
        resolved_ip = socket.gethostbyname(target)
        ip_obj = ipaddress.ip_address(resolved_ip)

        if ip_obj.is_loopback:
            return False, "Scanning loopback addresses is not permitted"
        if ip_obj.is_private:
            return False, "Scanning private/internal IP ranges is not permitted"
        if ip_obj.is_link_local:
            return False, "Scanning link-local addresses is not permitted"
        if ip_obj.is_reserved:
            return False, "Scanning reserved addresses is not permitted"
        if ip_obj.is_multicast:
            return False, "Scanning multicast addresses is not permitted"
    except socket.gaierror:
        return False, f"Could not resolve hostname: {target}"
    except ValueError:
        pass

    return True, resolved_ip or target


def parse_port_range(port_range: str) -> list[int]:
    ports = []
    port_range = port_range.strip()

    if port_range.lower() == "common":
        return list(COMMON_PORTS.keys())
    if port_range.lower() == "top100":
        return sorted(list(COMMON_PORTS.keys()))[:100]

    for part in port_range.split(","):
        part = part.strip()
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                start_p = int(start.strip())
                end_p = int(end.strip())
                if 1 <= start_p <= 65535 and 1 <= end_p <= 65535 and start_p <= end_p:
                    ports.extend(range(start_p, min(end_p + 1, 65536)))
            except ValueError:
                continue
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.append(p)
            except ValueError:
                continue

    return list(set(ports))


async def scan_port(target: str, port: int, timeout: float = 2.0) -> dict:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target, port),
            timeout=timeout
        )

        banner = ""
        service = COMMON_PORTS.get(port, "unknown")

        try:
            probe = SERVICE_BANNERS.get(port)
            if probe:
                writer.write(probe)
                await writer.drain()
                data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                banner = data.decode("utf-8", errors="ignore").strip()[:200]
        except Exception:
            pass

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        return {
            "port": port,
            "state": "open",
            "service": service,
            "banner": banner
        }
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return {"port": port, "state": "closed"}
    except Exception as e:
        return {"port": port, "state": "error", "error": str(e)}


async def run_scan(
    target: str,
    ports: list[int],
    max_concurrent: int = 50,
    timeout: float = 2.0,
    progress_callback=None
) -> dict:
    semaphore = asyncio.Semaphore(max_concurrent)
    results = []
    completed = 0
    total = len(ports)
    start_time = datetime.utcnow()

    async def bounded_scan(port):
        nonlocal completed
        async with semaphore:
            result = await scan_port(target, port, timeout)
            completed += 1
            if progress_callback and completed % 20 == 0:
                pct = int((completed / total) * 100)
                await progress_callback(pct, completed, total)
            return result

    tasks = [bounded_scan(p) for p in ports]
    raw_results = await asyncio.gather(*tasks, return_exceptions=True)

    for r in raw_results:
        if isinstance(r, dict) and r.get("state") == "open":
            results.append(r)

    end_time = datetime.utcnow()
    duration = (end_time - start_time).total_seconds()

    open_ports = [r["port"] for r in results]
    results.sort(key=lambda x: x["port"])

    hostname = target
    try:
        hostname = socket.getfqdn(target)
    except Exception:
        pass

    return {
        "target": target,
        "hostname": hostname,
        "open_ports": open_ports,
        "port_details": results,
        "total_scanned": total,
        "scan_duration": round(duration, 2),
        "timestamp": start_time.isoformat(),
        "scan_type": "TCP Connect"
    }


def run_scan_sync(target, ports, max_concurrent=50, timeout=2.0, progress_callback=None):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        result = loop.run_until_complete(
            run_scan(target, ports, max_concurrent, timeout, progress_callback)
        )
        return result
    finally:
        loop.close()

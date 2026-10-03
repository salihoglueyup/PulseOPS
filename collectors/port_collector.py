import re
import psutil
from typing import Optional
from models.ports import ListeningPort, PortExposure

DANGEROUS_PORTS = {
    21,     # FTP
    23,     # Telnet
    135,    # MS RPC Endpoint Mapper
    139,    # NetBIOS Session Service
    445,    # SMB File Sharing
    1433,   # MS SQL Server
    1521,   # Oracle DB
    2375,   # Docker daemon unencrypted socket
    3306,   # MySQL
    3389,   # RDP Remote Desktop
    5432,   # PostgreSQL
    5672,   # RabbitMQ
    6379,   # Redis
    9092,   # Apache Kafka
    9200,   # Elasticsearch
    11211,  # Memcached
    27017,  # MongoDB
    8080,   # Often dev/internal backend
    3000,   # Node dev/internal backend
    5000,   # Flask dev
    8000,   # Django/FastAPI dev
}

DB_PROCESS_NAMES = {
    "mysql", "mysqld", "postgres", "mongod", "redis-server", "memcached"
}

WINDOWS_SYSTEM_PROCESSES = {
    "lsass.exe", "wininit.exe", "spoolsv.exe", "services.exe", "svchost.exe",
    "lsass", "wininit", "spoolsv", "services", "svchost", "system"
}

WELL_KNOWN_SERVICES: dict[int, str] = {
    21: "FTP (Dosya Aktarimi)",
    22: "SSH (Guvenli Kabuk)",
    25: "SMTP (E-Posta)",
    53: "DNS (Alan Adi Cozumleme)",
    80: "HTTP (Web Sunucu)",
    110: "POP3 (E-Posta)",
    135: "MS-RPC (Endpoint Mapper)",
    139: "NetBIOS (Oturum Servisi)",
    143: "IMAP (E-Posta)",
    443: "HTTPS (Guvenli Web)",
    445: "SMB (Dosya Paylasimi)",
    1042: "ASUS Framework",
    1043: "ASUS Framework",
    1433: "MS SQL Server",
    1521: "Oracle Database",
    2179: "Hyper-V VMMS",
    2375: "Docker Daemon (HTTP)",
    2376: "Docker Daemon (TLS)",
    3000: "Node / Web Dev",
    3001: "Docker App / Dashboard",
    3215: "EA LocalHost Svc",
    3216: "EA Desktop",
    3217: "EA Desktop",
    3306: "MySQL Database",
    3389: "RDP (Uzak Masaustu)",
    4000: "Node / NestJS API",
    5000: "Flask / Python API",
    5040: "Windows C-Devices",
    5432: "PostgreSQL Database",
    5555: "Prisma Studio / ADB",
    5672: "RabbitMQ AMQP",
    5678: "n8n Workflow Automation",
    5939: "TeamViewer Service",
    6379: "Redis In-Memory Cache",
    7680: "Windows P2P Update",
    8000: "FastAPI / Django",
    8080: "HTTP Proxy / Java Backend",
    8443: "HTTPS Alt Web",
    8500: "Consul Service Mesh",
    9000: "PHP-FPM / SonarQube",
    9010: "Logitech G HUB",
    9012: "ASUS Armoury Socket",
    9013: "ASUS Armoury Socket",
    9092: "Apache Kafka",
    9200: "Elasticsearch",
    11211: "Memcached",
    13030: "ASUS ROG Live Service",
    13031: "ASUS Armoury Crate",
    13032: "ASUS Armoury Crate",
    22112: "ASUS ROG Live Service",
    24563: "Epic Games Launcher",
    27017: "MongoDB Database",
    27036: "Steam Local Network",
    27339: "Windows System",
    29489: "Antigravity IDE",
    35783: "Epic Online Services",
    45654: "Logitech G HUB",
}

def is_lan_ip(clean_ip: str) -> bool:
    if clean_ip.startswith("192.168.") or clean_ip.startswith("10."):
        return True
    if clean_ip.startswith("172."):
        parts = clean_ip.split(".")
        if len(parts) >= 2 and parts[1].isdigit():
            second_octet = int(parts[1])
            if 16 <= second_octet <= 31:
                return True
    return False

def get_service_hint(port: int, process_name: Optional[str] = None) -> str:
    proc = (process_name or "").lower()

    # 1. Docker environment
    if "docker" in proc:
        if port == 5432:
            return "PostgreSQL (Docker)"
        elif port == 6379:
            return "Redis (Docker)"
        elif port == 3001:
            return "Web App (Docker)"
        elif port == 5678:
            return "n8n (Docker)"
        elif port == 5555:
            return "Prisma / ADB (Docker)"
        return f"Docker Container (:{port})"

    # 2. Known apps & dev tools
    if "antigravity" in proc:
        return "Antigravity IDE"
    if "language_server" in proc:
        return "Python Language Server"
    if "riot" in proc:
        return "Riot Client"
    if "steam" in proc:
        return "Steam Client"
    if "epic" in proc:
        return "Epic Games"
    if "teamviewer" in proc:
        return "TeamViewer"
    if "asus" in proc or "armoury" in proc or "rog" in proc:
        return "ASUS ROG / Armoury"
    if "ea" in proc:
        return "EA Desktop"

    # 3. Known port directory
    if port in WELL_KNOWN_SERVICES:
        return WELL_KNOWN_SERVICES[port]

    # 4. Windows dynamic RPC
    if port >= 49152:
        if any(sp in proc for sp in WINDOWS_SYSTEM_PROCESSES):
            return "Windows Dinamik RPC"
        return "Dinamik Port (Ephemeral)"

    # 5. Fallback on process name
    if process_name and process_name.lower() != "unknown":
        clean_proc = process_name.replace(".exe", "")
        return f"{clean_proc} Servisi"

    return "Uygulama Servisi"

def classify_exposure(ip: str, port: int, process_name: Optional[str] = None) -> PortExposure:
    clean_ip = ip.strip("[]")
    proc_lower = (process_name or "").lower()

    # 1. Internal loopback binds
    if clean_ip in ("127.0.0.1", "::1", "localhost"):
        return PortExposure.SAFE_INTERNAL

    # 2. Standard public web endpoints
    if port in (80, 443):
        return PortExposure.PUBLIC_WEB

    # 3. Admin SSH access
    if port == 22:
        return PortExposure.ADMIN_SSH

    # 4. Wildcard / Any interface (0.0.0.0, ::, *)
    is_any_interface = clean_ip in ("0.0.0.0", "::", "*")
    if is_any_interface:
        # Check dangerous / sensitive ports or databases
        if port in DANGEROUS_PORTS or any(db in proc_lower for db in DB_PROCESS_NAMES):
            return PortExposure.EXPOSED_RISK

        # Check Windows dynamic RPC port (>= 49152)
        if port >= 49152:
            return PortExposure.SYSTEM_RPC

        return PortExposure.EXPOSED_GENERAL

    # 5. Local Area Network (LAN) IP binds (e.g., 192.168.1.115)
    if is_lan_ip(clean_ip):
        return PortExposure.LAN_ONLY

    return PortExposure.SAFE_INTERNAL

class PortCollector:
    """Collects and analyzes open/listening ports on the system."""

    def parse_ss_text(self, raw_text: str) -> list[ListeningPort]:
        """Parses output from `ss -lntup`, `ss -lntu`, or `netstat -lntup`."""
        ports: list[ListeningPort] = []
        ss_user_regex = re.compile(r'users:\(\("([^"]+)",pid=(\d+)')
        netstat_user_regex = re.compile(r'(\d+)/([^:\s]+)')

        for line in raw_text.splitlines():
            line = line.strip()
            if not line or line.startswith("Netid") or line.startswith("Active") or line.startswith("Proto"):
                continue

            parts = line.split()
            if len(parts) < 4:
                continue

            proto = parts[0].lower()
            # Detect ss vs netstat
            # ss: Netid State Recv-Q Send-Q Local Address:Port ... (parts[1] == 'LISTEN', local is parts[4])
            # netstat: Proto Recv-Q Send-Q Local Address Foreign Address State PID/Program (parts[5] == 'LISTEN', local is parts[3])
            if len(parts) >= 6 and parts[5] == "LISTEN":
                # netstat format
                local_addr = parts[3]
            elif len(parts) >= 5:
                # ss format
                local_addr = parts[4]
            else:
                continue

            # Split IP and Port from local_addr (e.g., 0.0.0.0:80 or [::]:8080 or :::80 or *:80)
            if ":" not in local_addr:
                continue
            ip_part, port_str = local_addr.rsplit(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                continue

            # Clean IP
            ip = ip_part.strip()
            if not ip or ip == "::":
                ip = "0.0.0.0" if ":" not in ip else "::"
            if not ip:
                ip = "*"

            # Find PID and process name if present
            proc_name = None
            pid = None
            
            # Check ss format
            ss_match = ss_user_regex.search(line)
            if ss_match:
                proc_name = ss_match.group(1)
                pid = int(ss_match.group(2))
            else:
                # Check netstat format (e.g. 1234/nginx)
                netstat_match = netstat_user_regex.search(line)
                if netstat_match:
                    pid = int(netstat_match.group(1))
                    proc_name = netstat_match.group(2)

            exposure = classify_exposure(ip, port, proc_name)
            ports.append(ListeningPort(
                proto=proto,
                ip=ip,
                port=port,
                pid=pid,
                process_name=proc_name,
                service_name=get_service_hint(port, proc_name),
                exposure=exposure
            ))
            
        # Deduplicate and sort by port
        unique_ports: dict[tuple[str, str, int], ListeningPort] = {}
        for p in ports:
            key = (p.proto, p.ip, p.port)
            unique_ports[key] = p
            
        return sorted(unique_ports.values(), key=lambda x: x.port)

    def collect_local(self) -> list[ListeningPort]:
        """Collects listening sockets on the local machine using psutil or netstat fallback."""
        ports: list[ListeningPort] = []
        try:
            connections = psutil.net_connections(kind="inet")
            for conn in connections:
                if conn.status != psutil.CONN_LISTEN:
                    continue
                
                ip = conn.laddr.ip if conn.laddr else "*"
                port = conn.laddr.port if conn.laddr else 0
                proto = "tcp" if conn.type == 1 else "udp"
                
                pid = conn.pid
                proc_name = None
                if pid:
                    try:
                        proc_name = psutil.Process(pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        proc_name = None
                
                exposure = classify_exposure(ip, port, proc_name)
                ports.append(ListeningPort(
                    proto=proto,
                    ip=ip,
                    port=port,
                    pid=pid,
                    process_name=proc_name,
                    service_name=get_service_hint(port, proc_name),
                    exposure=exposure
                ))
        except (psutil.AccessDenied, PermissionError):
            pass

        # If psutil failed or returned empty on Windows, try netstat -ano
        if not ports:
            ports = self._collect_via_netstat_fallback()

        # Deduplicate by (proto, ip, port)
        unique_ports = {(p.proto, p.ip, p.port): p for p in ports}
        return sorted(unique_ports.values(), key=lambda x: x.port)

    def _collect_via_netstat_fallback(self) -> list[ListeningPort]:
        """Fallback to netstat -ano on Windows or non-root systems."""
        ports: list[ListeningPort] = []
        try:
            import subprocess
            res = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, timeout=3)
            for line in res.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 4 and parts[0].upper() in ("TCP", "UDP") and any(s in parts for s in ("LISTENING", "LISTEN")):
                    local_addr = parts[1]
                    if ":" in local_addr:
                        ip_part, port_str = local_addr.rsplit(":", 1)
                        if port_str.isdigit():
                            port = int(port_str)
                            pid = int(parts[-1]) if parts[-1].isdigit() else None
                            proc_name = None
                            if pid:
                                try:
                                    proc_name = psutil.Process(pid).name()
                                except Exception:
                                    pass
                            clean_ip = ip_part.strip("[]")
                            exposure = classify_exposure(clean_ip, port, proc_name)
                            ports.append(ListeningPort(
                                proto=parts[0].lower(),
                                ip=clean_ip,
                                port=port,
                                pid=pid,
                                process_name=proc_name,
                                service_name=get_service_hint(port, proc_name),
                                exposure=exposure
                            ))
        except Exception:
            pass
        return ports

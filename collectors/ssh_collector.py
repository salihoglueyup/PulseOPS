import json
import time
from typing import Optional, Tuple
import paramiko

from models.system import (
    SystemSnapshot,
    CpuMetric,
    MemoryMetric,
    DiskPartition,
    NetworkRate,
    ProcessInfo,
    DiskIoRate,
    FirewallStatus,
)
from models.ports import ListeningPort, PortExposure
from models.proxy import ProxyRoute
from models.backup import BackupTask, BackupData
from models.docker import ContainerSummary
from models.services import ServiceUnit
from models.database import DatabaseInstance
from models.security import SecurityOverview
from models.storage import StorageOverview

from collectors.base import BaseCollector
from collectors.port_collector import PortCollector
from collectors.nginx_parser import NginxParser
from collectors.backup_collector import BackupCollector
from collectors.docker_collector import DockerCollector
from collectors.http_health import HTTPHealthChecker
from collectors.service_collector import ServiceCollector
from collectors.db_collector import DatabaseCollector
from collectors.security_collector import SecurityCollector
from collectors.storage_collector import StorageCollector

BATCH_PROBE_SCRIPT = r"""cat << 'EOF' | sh
echo "===SECTION:HOST==="
hostname 2>/dev/null
uname -r 2>/dev/null
cat /etc/os-release 2>/dev/null
echo "===SECTION:UPTIME==="
cat /proc/uptime 2>/dev/null
echo "===SECTION:LOAD==="
nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo
cat /proc/loadavg 2>/dev/null
echo "===SECTION:MEM==="
free -b 2>/dev/null || cat /proc/meminfo 2>/dev/null
echo "===SECTION:DISK==="
df -B1 -x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null || df -k 2>/dev/null
echo "===SECTION:NET==="
cat /proc/net/dev 2>/dev/null
echo "===SECTION:PORTS==="
sudo -n ss -lntup 2>/dev/null || ss -lntup 2>/dev/null || sudo -n netstat -lntup 2>/dev/null || netstat -lntup 2>/dev/null || ss -lntu 2>/dev/null
echo "===SECTION:NGINX==="
nginx -T 2>/dev/null || cat /etc/nginx/nginx.conf /etc/nginx/sites-enabled/* /etc/nginx/conf.d/* 2>/dev/null
echo "===SECTION:NGINX_CONF==="
cat /etc/nginx/nginx.conf 2>/dev/null | head -n 120
echo "===SECTION:TIMERS==="
systemctl list-timers --all --no-pager 2>/dev/null || crontab -l 2>/dev/null
echo "===SECTION:SNAPSHOTS==="
find /var/backups /var/www /opt /srv /home /root . -maxdepth 4 -name "store-*.json" -exec ls -l {} + 2>/dev/null | head -n 120
echo "===SECTION:SHAS==="
find /var/backups /var/www /opt /srv /home /root . -maxdepth 4 -name "*deploy.sha" -exec sh -c 'echo "FILE:$1"; head -n 1 "$1"' _ {} \; 2>/dev/null
echo "===SECTION:DOCKER==="
docker ps -a --format '{{json .}}' 2>/dev/null || sudo -n docker ps -a --format '{{json .}}' 2>/dev/null
echo "===SECTION:DOCKER_DF==="
docker system df --format '{{json .}}' 2>/dev/null || docker system df 2>/dev/null || sudo -n docker system df 2>/dev/null
echo "===SECTION:CONTAINERD_SZ==="
du -sh /var/lib/containerd/io.containerd.snapshotter.v1.overlayfs 2>/dev/null || du -sh /var/lib/docker/overlay2 2>/dev/null || sudo -n du -sh /var/lib/containerd/io.containerd.snapshotter.v1.overlayfs 2>/dev/null
echo "===SECTION:PROCS==="
ps -eo pid,user,%cpu,%mem,comm --sort=-%mem 2>/dev/null | head -n 30
echo "===SECTION:UFW==="
sudo -n ufw status 2>/dev/null || ufw status 2>/dev/null || iptables -L -n 2>/dev/null | head -n 25
echo "===SECTION:SERVICES==="
systemctl list-units --type=service --state=running,failed,exited --no-pager 2>/dev/null | head -n 60
echo "===SECTION:SSHD_CONF==="
cat /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | head -n 60
echo "===SECTION:LOGS==="
journalctl -n 40 --no-pager 2>/dev/null || tail -n 40 /var/log/nginx/access.log /var/log/syslog /var/log/messages 2>/dev/null
echo "===SECTION:END==="
EOF
"""

class SSHCollector(BaseCollector):
    """Agentless remote collector querying a Linux host via SSH and parsing native telemetry."""

    def __init__(
        self,
        host: str,
        username: str = "root",
        port: int = 22,
        key_filename: Optional[str] = None,
        password: Optional[str] = None,
        timeout: float = 8.0,
    ):
        self.host = host
        self.username = username
        self.port = port
        self.key_filename = key_filename
        self.password = password
        self.timeout = timeout

        self._ssh_client: Optional[paramiko.SSHClient] = None
        self._port_collector = PortCollector()
        self._nginx_parser = NginxParser()
        self._backup_collector = BackupCollector()
        self._docker_collector = DockerCollector()
        self._health_checker = HTTPHealthChecker()

        self._service_collector = ServiceCollector()
        self._db_collector = DatabaseCollector()
        self._security_collector = SecurityCollector()
        self._storage_collector = StorageCollector()

        self._last_net_time: float = time.time()
        self._last_net_bytes: dict[str, tuple[int, int]] = {}
        self._last_logs: list[str] = []
        self._last_backup_data: BackupData = BackupData()
        self._last_services: list[ServiceUnit] = []
        self._last_databases: list[DatabaseInstance] = []
        self._last_security: SecurityOverview = SecurityOverview()
        self._last_storage: StorageOverview = StorageOverview()

    def _ensure_connected(self) -> paramiko.SSHClient:
        if self._ssh_client and self._ssh_client.get_transport() and self._ssh_client.get_transport().is_active():
            return self._ssh_client

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        connect_kwargs = {
            "hostname": self.host,
            "port": self.port,
            "username": self.username,
            "timeout": self.timeout,
        }
        if self.key_filename:
            connect_kwargs["key_filename"] = self.key_filename
        if self.password:
            connect_kwargs["password"] = self.password

        client.connect(**connect_kwargs)
        self._ssh_client = client
        return client

    def test_connection(self) -> None:
        """Tests SSH connection and executes a light ping to verify credentials and access."""
        client = self._ensure_connected()
        stdin, stdout, stderr = client.exec_command("echo OK", timeout=min(self.timeout, 5.0))
        out = stdout.read().decode("utf-8", errors="replace").strip()
        if "OK" not in out:
            err = stderr.read().decode("utf-8", errors="replace").strip()
            raise RuntimeError(f"Uzak sunucu yanıt vermedi: {err or out}")

    def execute_remote_batch(self) -> dict[str, str]:
        """Runs the single batch discovery script and extracts section outputs with auto-reconnect."""
        raw_output = ""
        for attempt in range(2):
            try:
                client = self._ensure_connected()
                stdin, stdout, stderr = client.exec_command(BATCH_PROBE_SCRIPT, timeout=self.timeout)
                raw_output = stdout.read().decode("utf-8", errors="replace")
                if raw_output:
                    break
            except Exception:
                if self._ssh_client:
                    try:
                        self._ssh_client.close()
                    except Exception:
                        pass
                self._ssh_client = None
                if attempt == 1:
                    return getattr(self, "_last_sections", {})
                time.sleep(0.5)

        sections: dict[str, str] = {}
        current_section = None
        lines = []

        for line in raw_output.splitlines():
            if line.startswith("===SECTION:") and line.endswith("==="):
                if current_section is not None:
                    sections[current_section] = "\n".join(lines)
                current_section = line[len("===SECTION:") : -len("===")]
                lines = []
            else:
                lines.append(line)

        if current_section and current_section != "END":
            sections[current_section] = "\n".join(lines)

        self._last_sections = sections
        return sections

    def parse_system_snapshot(self, sections: dict[str, str]) -> SystemSnapshot:
        now = time.time()
        
        # 1. Host & OS
        hostname = "remote-linux"
        kernel = "Linux"
        os_name = "Linux"
        host_txt = sections.get("HOST", "")
        h_lines = host_txt.strip().splitlines()
        if len(h_lines) >= 1:
            hostname = h_lines[0].strip()
        if len(h_lines) >= 2:
            kernel = h_lines[1].strip()
        for l in h_lines:
            if l.startswith("PRETTY_NAME="):
                os_name = l.split("=", 1)[1].strip('"\'')
                break

        # 2. Uptime
        uptime_sec = 0.0
        uptime_txt = sections.get("UPTIME", "").strip()
        if uptime_txt:
            parts = uptime_txt.split()
            try:
                uptime_sec = float(parts[0])
            except (ValueError, IndexError):
                uptime_sec = 0.0

        # 3. CPU & Load
        load_txt = sections.get("LOAD", "").strip()
        cores = 1
        load_avg = (0.0, 0.0, 0.0)
        l_lines = load_txt.splitlines()
        if l_lines:
            try:
                cores = int(l_lines[0].strip())
            except ValueError:
                cores = 1
            if len(l_lines) >= 2:
                avg_parts = l_lines[1].split()
                if len(avg_parts) >= 3:
                    try:
                        load_avg = (float(avg_parts[0]), float(avg_parts[1]), float(avg_parts[2]))
                    except ValueError:
                        pass

        # Estimate CPU total % from 1-min load average divided by cores
        est_cpu_pct = min(round((load_avg[0] / max(cores, 1)) * 100.0, 1), 100.0)
        cpu = CpuMetric(
            cores=cores,
            total_percent=est_cpu_pct,
            per_core_percent=[est_cpu_pct] * min(cores, 8),
            load_avg=load_avg,
        )

        # 4. Memory
        mem_txt = sections.get("MEM", "").strip()
        total_mem, used_mem, free_mem, avail_mem = 1024**3, 0, 0, 0
        swap_total, swap_used = 0, 0
        for line in mem_txt.splitlines():
            line_str = line.strip()
            if line_str.startswith("Mem:"):
                # free -b output format
                parts = line_str.split()
                if len(parts) >= 7:
                    try:
                        total_mem = int(parts[1])
                        used_mem = int(parts[2])
                        free_mem = int(parts[3])
                        avail_mem = int(parts[6])
                    except ValueError:
                        pass
            elif line_str.startswith("Swap:"):
                parts = line_str.split()
                if len(parts) >= 4:
                    try:
                        swap_total = int(parts[1])
                        swap_used = int(parts[2])
                    except ValueError:
                        pass

        mem_pct = round((used_mem / max(total_mem, 1)) * 100.0, 1)
        swap_pct = round((swap_used / max(swap_total, 1)) * 100.0, 1) if swap_total > 0 else 0.0
        memory = MemoryMetric(
            total_bytes=total_mem,
            used_bytes=used_mem,
            free_bytes=free_mem,
            available_bytes=avail_mem,
            percent=mem_pct,
            swap_total_bytes=swap_total,
            swap_used_bytes=swap_used,
            swap_percent=swap_pct,
        )

        # 5. Disks
        disks: list[DiskPartition] = []
        disk_txt = sections.get("DISK", "").strip()
        for line in disk_txt.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 6:
                try:
                    dev = parts[0]
                    total_b = int(parts[1])
                    used_b = int(parts[2])
                    avail_b = int(parts[3])
                    pct_str = parts[4].rstrip("%")
                    pct = float(pct_str) if pct_str.replace('.', '', 1).isdigit() else 0.0
                    mount = parts[5]
                    disks.append(DiskPartition(
                        device=dev,
                        mountpoint=mount,
                        fstype="ext4",
                        total_bytes=total_b,
                        used_bytes=used_b,
                        free_bytes=avail_b,
                        percent=pct,
                    ))
                except Exception:
                    continue

        # 6. Network Rates
        net_rates: list[NetworkRate] = []
        delta_net = max(now - self._last_net_time, 0.001)
        net_txt = sections.get("NET", "").strip()
        for line in net_txt.splitlines():
            if ":" in line:
                nic, stats = line.split(":", 1)
                nic = nic.strip()
                if nic.lower() in ("lo", "docker0"):
                    continue
                parts = stats.split()
                if len(parts) >= 9:
                    try:
                        rx_b = int(parts[0])
                        tx_b = int(parts[8])
                        prev_rx, prev_tx = self._last_net_bytes.get(nic, (rx_b, tx_b))
                        rx_rate = max((rx_b - prev_rx) / delta_net, 0.0)
                        tx_rate = max((tx_b - prev_tx) / delta_net, 0.0)
                        self._last_net_bytes[nic] = (rx_b, tx_b)
                        net_rates.append(NetworkRate(
                            interface=nic,
                            rx_bytes_sec=rx_rate,
                            tx_bytes_sec=tx_rate,
                        ))
                    except ValueError:
                        pass
        self._last_net_time = now

        # 7. Processes
        top_procs: list[ProcessInfo] = []
        proc_txt = sections.get("PROCS", "").strip()
        for line in proc_txt.splitlines()[1:]:
            parts = line.split(maxsplit=4)
            if len(parts) >= 5:
                try:
                    pid = int(parts[0])
                    user = parts[1]
                    cpu_p = float(parts[2])
                    mem_p = float(parts[3])
                    cmd = parts[4]
                    mem_mb = round((mem_p / 100.0) * (total_mem / (1024 * 1024)), 1)
                    top_procs.append(ProcessInfo(
                        pid=pid,
                        name=cmd,
                        cpu_percent=cpu_p,
                        memory_mb=mem_mb,
                        memory_percent=mem_p,
                        username=user,
                    ))
                except Exception:
                    continue

        # 8. Firewall
        ufw_txt = sections.get("UFW", "").strip().lower()
        fw_active = "active" in ufw_txt and "inactive" not in ufw_txt
        firewall = FirewallStatus(
            is_active=fw_active,
            tool="ufw" if ufw_txt else "None",
            default_incoming_policy="DROP" if fw_active else "ACCEPT",
        )

        return SystemSnapshot(
            hostname=hostname,
            os_name=os_name,
            kernel=kernel,
            uptime_seconds=uptime_sec,
            cpu=cpu,
            memory=memory,
            disks=disks,
            network=net_rates,
            top_processes=top_procs[:20],
            disk_io=DiskIoRate(),
            firewall=firewall,
            timestamp=now,
        )

    def parse_containers(self, docker_txt: str) -> list[ContainerSummary]:
        containers: list[ContainerSummary] = []
        for line in docker_txt.strip().splitlines():
            if not line:
                continue
            try:
                data = json.loads(line)
                ports_str = data.get("Ports", "")
                port_list = [p.strip() for p in ports_str.split(",") if p.strip()]
                containers.append(ContainerSummary(
                    id=data.get("ID", "")[:12],
                    name=data.get("Names", "unknown"),
                    image=data.get("Image", "unknown"),
                    status=data.get("Status", "unknown"),
                    ports=port_list,
                    uptime=data.get("RunningFor", "")
                ))
            except Exception:
                continue
        return containers

    def poll(self) -> Tuple[SystemSnapshot, list[ListeningPort], list[ProxyRoute], list[BackupTask], list[ContainerSummary]]:
        sections = self.execute_remote_batch()
        
        snapshot = self.parse_system_snapshot(sections)
        ports = self._port_collector.parse_ss_text(sections.get("PORTS", ""))
        
        # Nginx routes from remote config
        routes = self._nginx_parser.parse_config_text(sections.get("NGINX", ""))
        routes = self._nginx_parser.enrich_routes_with_ports(routes, ports)
        
        # Backup tasks from systemd timers
        backups = self._backup_collector.parse_timers_text(sections.get("TIMERS", ""))
        
        # Parse snapshots from SNAPSHOTS section
        snap_txt = sections.get("SNAPSHOTS", "").strip()
        found_snap_names = []
        found_sizes = {}
        for line in snap_txt.splitlines():
            parts = line.split()
            if parts:
                f_path = parts[-1]
                f_name = f_path.split("/")[-1]
                found_snap_names.append(f_name)
                if len(parts) >= 5 and parts[4].isdigit():
                    found_sizes[f_name] = int(parts[4])
        
        snapshots = self._backup_collector.parse_snapshot_files(found_snap_names, found_sizes)
        retention = self._backup_collector.audit_retention(snapshots)
        
        # Parse SHAs
        sha_txt = sections.get("SHAS", "").strip()
        sha_map = {}
        curr_file = None
        for line in sha_txt.splitlines():
            if line.startswith("FILE:"):
                curr_file = line[len("FILE:"):].strip().split("/")[-1]
            elif curr_file and line.strip() and not line.startswith("---"):
                sha_map[curr_file] = line.strip()
                curr_file = None
                
        deployment = self._backup_collector.parse_deployment_state(sha_map)
        self._last_backup_data = BackupData(
            tasks=backups,
            snapshots=snapshots,
            deployment=deployment,
            retention=retention,
        )

        # Docker containers
        containers = self.parse_containers(sections.get("DOCKER", ""))
        if containers:
            docker_routes = self._docker_collector.get_container_routes(containers)
            existing_ports = {r.listen_port for r in routes}
            for dr in docker_routes:
                if dr.listen_port not in existing_ports:
                    routes.append(dr)

        # Cache recent logs
        logs_txt = sections.get("LOGS", "").strip()
        if logs_txt:
            self._last_logs = logs_txt.splitlines()[-35:]
        elif containers:
            # Fallback to docker container logs if available
            self._last_logs = [f"[{containers[0].name}] Remote container running: {containers[0].status}"]
        else:
            self._last_logs = ["Uzak sunucudan log verisi bekleniyor..."]

        # Parse System Services
        svc_txt = sections.get("SERVICES", "").strip()
        if svc_txt:
            self._last_services = self._service_collector.parse_systemctl_units(svc_txt)
        else:
            self._last_services = []

        # Discover Databases
        self._last_databases = self._db_collector.discover_databases(ports, containers)

        # Audit SSH Security & Firewall
        sshd_txt = sections.get("SSHD_CONF", "").strip()
        if sshd_txt:
            ssh_audit = self._security_collector.parse_sshd_config_text(sshd_txt)
        else:
            from models.security import SSHSecurityAudit
            ssh_audit = SSHSecurityAudit()

        risky_ports = [p.port for p in ports if p.exposure == PortExposure.EXPOSED_RISK]
        recs = []
        if ssh_audit.permit_root_login == "yes":
            recs.append("⚠️ SSH: PermitRootLogin 'no' olarak ayarlanmalı.")
        if ssh_audit.password_authentication == "yes":
            recs.append("ℹ️ SSH: Şifreli giriş kapatılıp yalnızca SSH anahtarı (Pubkey) kullanılmalı.")
        if risky_ports:
            recs.append(f"🚨 DIŞA AÇIK VERİTABANI: Port {risky_ports} 0.0.0.0 üzerinden dinliyor, 127.0.0.1'e bağlayın!")

        self._last_security = SecurityOverview(
            ssh=ssh_audit,
            firewall_name="UFW",
            firewall_active=True,
            rules_count=len([p for p in ports if p.exposure == PortExposure.PUBLIC_SAFE]),
            open_ports_count=len(ports),
            recommendations=recs,
        )

        # Parse Docker System DF & Storage Breakdown
        df_txt = sections.get("DOCKER_DF", "").strip()
        cntr_sz_txt = sections.get("CONTAINERD_SZ", "").strip()
        storage = self._storage_collector.parse_docker_df(df_txt, cntr_sz_txt)
        if snapshot.disks:
            root_d = snapshot.disks[0]
            storage.root_used_gb = root_d.used_gb
            storage.root_total_gb = root_d.total_gb
            storage.root_percent = root_d.percent
        self._last_storage = storage

        return snapshot, ports, routes, backups, containers

    def poll_logs(self) -> list[str]:
        return self._last_logs

    def poll_backup_data(self) -> BackupData:
        return self._last_backup_data

    def poll_services(self) -> list[ServiceUnit]:
        return self._last_services

    def poll_databases(self, ports=None, containers=None) -> list[DatabaseInstance]:
        return self._last_databases

    def poll_security(self, ports=None) -> SecurityOverview:
        return self._last_security

    def poll_storage(self) -> StorageOverview:
        return self._last_storage

    def get_nginx_config_raw(self) -> str:
        if hasattr(self, "_last_sections"):
            conf = self._last_sections.get("NGINX_CONF", "").strip()
            if conf:
                return conf
            return self._last_sections.get("NGINX", "").strip()
        return ""

    def get_sshd_config_raw(self) -> str:
        if hasattr(self, "_last_sections"):
            return self._last_sections.get("SSHD_CONF", "").strip()
        return ""


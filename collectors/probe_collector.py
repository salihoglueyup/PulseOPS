"""Collector that runs the shell probe (collectors/probe.py) through a transport and parses it.

Used for both local Linux monitoring (LocalTransport) and remote monitoring (SSHTransport), so
both modes produce identical telemetry from identical code.
"""
import time
from typing import Optional

from collectors.base import BaseCollector
from collectors.backup_collector import BackupCollector
from collectors.db_collector import DatabaseCollector
from collectors.docker_collector import DockerCollector
from collectors.nginx_parser import NginxParser
from collectors.port_collector import PortCollector
from collectors.privilege_collector import parse_privileges_section
from collectors.probe import RARE_SECTIONS, build_script, parse_sections
from collectors.security_collector import SecurityCollector
from collectors.service_collector import CRITICAL_SERVICES, ServiceCollector
from collectors.storage_collector import StorageCollector
from collectors.transport import TransportError
from collectors import probe_parsers as pp
from models.backup import BackupData
from models.docker import ContainerSummary
from models.privileges import PrivilegeInfo
from models.security import AccessAudit, AuthActivity, Fail2banStatus, SSHSecurityAudit, UpdateStatus
from models.services import ServiceState, ServiceUnit
from models.storage import StorageOverview
from models.system import CpuMetric, DiskIoRate, FirewallStatus, NetworkRate, ProcessInfo, SystemSnapshot
from models.telemetry import Telemetry

MAX_TOP_PROCESSES = 20
MAX_LOG_LINES = 40
MAX_OTHER_SERVICES = 25
RARE_REFRESH_SECONDS = 600


class ProbeCollector(BaseCollector):
    def __init__(self, transport, fast_timeout: float = 15.0, slow_timeout: float = 60.0, use_sudo: bool = True):
        self.transport = transport
        self.failed_login_threshold = 100
        # None = detect on the next slow run; then True/False is reused so `sudo -n true` is not
        # repeated (every sudo call lands in the host's auth log)
        self._sudo: Optional[bool] = None if use_sudo else False
        self.fast_timeout = fast_timeout
        self.slow_timeout = slow_timeout
        # Interactive views set this: the package manager check (seconds of CPU with apt) is then
        # left out of the very first poll so the screen fills at once; it arrives a slow tick later
        self.defer_updates = False

        self._ports_parser = PortCollector()
        self._nginx = NginxParser()
        self._backup = BackupCollector()
        self._docker = DockerCollector()
        self._services = ServiceCollector()
        self._db = DatabaseCollector()
        self._security = SecurityCollector()
        self._storage = StorageCollector()

        # Previous fast samples, for rates. Times come from the host's /proc/uptime so that
        # transport latency (SSH round trips) does not distort them.
        self._prev_uptime: Optional[float] = None
        self._prev_cpu: dict[str, tuple[int, int]] = {}
        self._prev_ticks: dict[int, int] = {}
        self._prev_net: dict[str, tuple[int, int]] = {}
        self._prev_disk: Optional[tuple[int, int]] = None

        # Slow tier, refreshed only on include_slow
        self._host = ("linux", "Linux", "Linux")
        self._cores, self._clk, self._page_size = 1, 100, 4096
        self._disks = []
        self._port_owners: dict[tuple[str, str, int], tuple[int, str]] = {}
        self._inode_owner: dict[str, int] = {}
        self._proc_users: dict[int, str] = {}
        self._slow_sections: dict[str, str] = {}
        self._machine_id = ""
        self._rare_sections: dict[str, str] = {}
        self._rare_collected_at = 0.0
        self._slow_collected_at = 0.0
        self._routes_base = []
        self._containers: list[ContainerSummary] = []
        self._services_list: list[ServiceUnit] = []
        self._backup_data = BackupData()
        self._storage_base = StorageOverview()
        self._firewall = FirewallStatus(is_active=False, backend="?", summary="Bekleniyor", known=False)
        self._ssh_audit = SSHSecurityAudit()
        self._privileges = PrivilegeInfo()
        self._fail2ban = Fail2banStatus()
        self._auth = AuthActivity()
        self._access = AccessAudit()
        self._updates = UpdateStatus()
        self._logs: list[str] = []

    # --- public API -------------------------------------------------------------------------

    def collect(self, include_slow: bool = True, include_logs: bool = True) -> Telemetry:
        need_slow = include_slow or not self._slow_sections
        need_baseline = self._prev_uptime is None
        rare_fresh = self._rare_sections and time.time() - self._rare_collected_at < RARE_REFRESH_SECONDS
        skip = frozenset(RARE_SECTIONS) if rare_fresh else frozenset()
        if self.defer_updates and need_slow and not self._slow_sections:
            skip |= {"UPDATES"}
        script, nonce = build_script(
            fast=True, slow=need_slow, logs=include_logs, baseline=need_baseline, sudo=self._sudo, skip=skip,
        )
        raw = self.transport.run(script, self.slow_timeout if need_slow else self.fast_timeout)
        sections = parse_sections(raw, nonce)
        if "UPTIME" not in sections or "CPUSTAT" not in sections or (need_slow and "PRIV" not in sections):
            raise TransportError("Probe çıktısı eksik veya yarıda kesildi")

        if need_baseline:
            self._prev_uptime = pp.parse_uptime(sections.get("UPTIME0", ""))
            self._prev_cpu = pp.parse_cpustat(sections.get("CPUSTAT0", ""))
            self._prev_ticks = {pid: p.ticks for pid, p in pp.parse_procstat(sections.get("PROCSTAT0", "")).items()}

        now = time.time()
        if need_slow:
            self._apply_slow(sections, now)
        if include_logs and "LOGS" in sections:
            self._logs = [
                line for line in sections["LOGS"].splitlines()
                if line.strip() and line.strip() != "-- No entries --"
            ][-MAX_LOG_LINES:]

        snapshot, ports = self._build_fast(sections, now)
        routes = self._nginx.enrich_routes_with_ports(self._routes_base, ports)
        if self._containers:
            known_ports = {r.listen_port for r in routes}
            routes += [r for r in self._docker.get_container_routes(self._containers) if r.listen_port not in known_ports]

        storage = self._storage_base.model_copy()
        if snapshot.disks:
            root = snapshot.disks[0]
            storage.root_used_gb, storage.root_total_gb, storage.root_percent = root.used_gb, root.total_gb, root.percent

        return Telemetry(
            snapshot=snapshot,
            ports=ports,
            routes=routes,
            backups=self._backup_data.tasks,
            backup_data=self._backup_data,
            containers=self._containers,
            services=self._services_list,
            databases=self._db.discover_databases(ports, self._containers),
            security=self._security.build_overview(
                self._ssh_audit, self._firewall, ports, self._fail2ban, self._auth, self._access,
                failed_login_threshold=self.failed_login_threshold, updates=self._updates,
            ),
            storage=storage,
            privileges=self._privileges,
            logs=self._logs,
            machine_id=self._machine_id,
            collected_at=now,
            slow_collected_at=self._slow_collected_at,
        )

    def close(self) -> None:
        self.transport.close()

    def get_nginx_config_raw(self) -> str:
        return (self._slow_sections.get("NGINX_CONF") or self._slow_sections.get("NGINX", "")).strip()

    def get_sshd_config_raw(self) -> str:
        return self._slow_sections.get("SSHD_CONF", "").strip()

    # Legacy accessors (status/report used to call these individually)
    def poll(self):
        t = self.collect()
        return t.snapshot, t.ports, t.routes, t.backups, t.containers

    # --- fast tier --------------------------------------------------------------------------

    def _build_fast(self, s: dict[str, str], now: float) -> tuple[SystemSnapshot, list]:
        hostname, kernel, os_name = self._host
        uptime = pp.parse_uptime(s.get("UPTIME", ""))
        load = pp.parse_loadavg(s.get("LOADAVG", ""))
        dt = uptime - self._prev_uptime if self._prev_uptime is not None else 0.0
        dt = dt if dt > 0 else 0.0

        # CPU
        cpu_now = pp.parse_cpustat(s.get("CPUSTAT", ""))
        total_pct = pp.cpu_percent(self._prev_cpu["cpu"], cpu_now["cpu"]) if "cpu" in cpu_now and "cpu" in self._prev_cpu else 0.0
        per_core = [
            pp.cpu_percent(self._prev_cpu[name], cpu_now[name]) if name in self._prev_cpu else 0.0
            for name in sorted((n for n in cpu_now if n != "cpu"), key=lambda n: int(n[3:]))
        ]
        self._prev_cpu = cpu_now
        cores = len(per_core) or self._cores
        cpu = CpuMetric(cores=cores, total_percent=total_pct, per_core_percent=per_core, load_avg=load)

        memory = pp.parse_meminfo(s.get("MEM", ""))

        # Disk I/O
        disk_now = pp.parse_diskstats(s.get("DISKSTATS", ""))
        disk_io = DiskIoRate()
        if self._prev_disk is not None and dt:
            disk_io = DiskIoRate(
                read_bytes_sec=max(disk_now[0] - self._prev_disk[0], 0) / dt,
                write_bytes_sec=max(disk_now[1] - self._prev_disk[1], 0) / dt,
            )
        self._prev_disk = disk_now

        # Network
        net_now = pp.parse_net_dev(s.get("NET", ""))
        network = []
        for nic, (rx, tx) in net_now.items():
            prev = self._prev_net.get(nic)
            if prev is not None and dt:
                network.append(NetworkRate(
                    interface=nic,
                    rx_bytes_sec=max(rx - prev[0], 0) / dt,
                    tx_bytes_sec=max(tx - prev[1], 0) / dt,
                ))
            else:
                network.append(NetworkRate(interface=nic))
        self._prev_net = net_now

        # Processes: rank on plain tuples, build models only for the top ones
        procs = pp.parse_procstat(s.get("PROCSTAT", ""))
        total_mb = memory.total_bytes / (1024 * 1024) if memory.total_bytes else 0
        page_mb = self._page_size / (1024 * 1024)
        ranked = []
        for pid, p in procs.items():
            prev = self._prev_ticks.get(pid)
            cpu_pct = round(max(p.ticks - prev, 0) / self._clk / dt * 100.0, 1) if dt and prev is not None else 0.0
            mem_mb = round(p.rss_pages * page_mb, 1)
            mem_pct = round(mem_mb * 100.0 / total_mb, 1) if total_mb else 0.0
            ranked.append((cpu_pct * 2.0 + mem_pct * 3.0, cpu_pct, mem_mb, mem_pct, pid, p.name))
        ranked.sort(reverse=True)
        top = [
            ProcessInfo(pid=pid, name=name, cpu_percent=cpu_pct, memory_mb=mem_mb, memory_percent=mem_pct,
                        username=self._proc_users.get(pid, ""))
            for _, cpu_pct, mem_mb, mem_pct, pid, name in ranked[:MAX_TOP_PROCESSES]
        ]
        self._prev_ticks = {pid: p.ticks for pid, p in procs.items()}
        self._prev_uptime = uptime

        # Ports (owners come from the slow tier)
        ports_text = s.get("PORTS", "")
        if ports_text.lstrip().startswith("#"):
            ports = pp.parse_proc_net(ports_text, self._inode_owner, {pid: p.name for pid, p in procs.items()})
        else:
            ports = pp.apply_port_owners(self._ports_parser.parse_ss_text(ports_text), self._port_owners)

        snapshot = SystemSnapshot(
            hostname=hostname,
            os_name=os_name,
            kernel=kernel,
            uptime_seconds=uptime,
            cpu=cpu,
            memory=memory,
            disks=self._disks,
            network=network,
            top_processes=top,
            disk_io=disk_io,
            firewall=self._firewall,
            timestamp=now,
        )
        return snapshot, ports

    # --- slow tier --------------------------------------------------------------------------

    def _apply_slow(self, s: dict[str, str], now: float) -> None:
        if all(name in s for name in RARE_SECTIONS):
            self._rare_sections = {name: s[name] for name in RARE_SECTIONS}
            self._rare_collected_at = now
        s = {**self._rare_sections, **s}
        self._slow_sections = {k: v for k, v in s.items() if k in _SLOW_NAMES}
        self._slow_collected_at = now

        self._host = pp.parse_host(s.get("HOST", ""))
        mid = s.get("MACHINE_ID", "").strip().splitlines()
        self._machine_id = mid[0].strip() if mid and len(mid[0].strip()) >= 16 else ""
        self._cores, self._clk, self._page_size = pp.parse_sysconf(s.get("SYSCONF", ""))
        self._disks = pp.parse_df(s.get("DISK", ""))
        self._proc_users = pp.parse_procusers(s.get("PROCUSERS", ""))
        owners_text = s.get("PORT_OWNERS", "")
        if owners_text.lstrip().startswith("#sockets"):
            self._inode_owner = pp.parse_socket_owners(owners_text)
            self._port_owners = {}
        else:
            self._inode_owner = {}
            self._port_owners = {
                (p.proto, p.ip, p.port): (p.pid, p.process_name)
                for p in self._ports_parser.parse_ss_text(owners_text)
                if p.pid is not None and p.process_name
            }

        self._routes_base = self._nginx.parse_config_text(s.get("NGINX", ""))
        self._containers = self._parse_containers(s.get("DOCKER", ""))

        services = self._services.parse_systemctl_units(s.get("SERVICES", ""), s.get("UNIT_FILES", ""))
        critical_prefixes = tuple(name.split(".")[0] for name, _ in CRITICAL_SERVICES)
        critical = [sv for sv in services if sv.name.startswith(critical_prefixes)]
        others = [sv for sv in services if sv not in critical]
        # The list is capped for display, but a failed unit must never fall off it (alerts, drift)
        failed = [sv for sv in others if sv.state == ServiceState.FAILED]
        healthy = [sv for sv in others if sv.state != ServiceState.FAILED]
        self._services_list = critical + failed + healthy[:max(0, MAX_OTHER_SERVICES - len(failed))]

        tasks = self._backup.parse_timers_text(s.get("TIMERS", "")) + self._backup.parse_crontab_text(s.get("CRONTAB", ""))
        names, sizes, shas = pp.parse_backup_files(s.get("BACKUP_FILES", ""))
        snapshots = self._backup.parse_snapshot_files(names, sizes)
        self._backup_data = BackupData(
            tasks=tasks,
            snapshots=snapshots,
            deployment=self._backup.parse_deployment_state(shas),
            retention=self._backup.audit_retention(snapshots),
        )

        self._storage_base = self._storage.parse_docker_df(s.get("DOCKER_DF", "").strip(), s.get("CONTAINERD_SZ", "").strip())
        self._firewall = pp.parse_firewall(s.get("FIREWALL", ""))
        sshd = s.get("SSHD_CONF", "").strip()
        if sshd == "UNREADABLE":
            self._ssh_audit = SSHSecurityAudit(permit_root_login="?", password_authentication="?",
                                               pubkey_authentication="?", is_hardened=False)
        elif sshd:
            self._ssh_audit = self._security.parse_sshd_config_text(sshd)
        else:  # no sshd_config: OpenSSH server is not installed
            self._ssh_audit = SSHSecurityAudit(port=0, permit_root_login="KAPALI", password_authentication="KAPALI",
                                               pubkey_authentication="KAPALI", is_hardened=True)
        self._privileges = parse_privileges_section(s.get("PRIV", ""))
        self._fail2ban = pp.parse_fail2ban(s.get("FAIL2BAN", ""))
        self._auth = pp.parse_auth(s.get("AUTH", ""))
        self._access = pp.parse_access(s.get("ACCESS", ""))
        self._updates = pp.parse_updates(s.get("UPDATES", ""), now)
        if self._sudo is None:
            # PRIV reports sudo_ok only when this run actually enabled sudo (non-root + it works)
            self._sudo = "sudo_ok" in s.get("PRIV", "").split()

    @staticmethod
    def _parse_containers(text: str) -> list[ContainerSummary]:
        import json

        containers = []
        for line in text.strip().splitlines():
            try:
                data = json.loads(line)
            except ValueError:
                continue
            if not isinstance(data, dict):
                continue
            ports = [p.strip() for p in str(data.get("Ports", "")).split(",") if p.strip()]
            containers.append(ContainerSummary(
                id=str(data.get("ID", ""))[:12],
                name=str(data.get("Names", "unknown")),
                image=str(data.get("Image", "unknown")),
                status=str(data.get("Status", "unknown")),
                ports=ports,
                uptime=str(data.get("RunningFor", "")),
            ))
        return containers


def _slow_names() -> set[str]:
    from collectors.probe import SLOW_SECTIONS
    return {name for name, _ in SLOW_SECTIONS}


_SLOW_NAMES = _slow_names()

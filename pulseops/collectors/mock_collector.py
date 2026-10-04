import time
import random
from pulseops.models.system import (
    CpuMetric,
    MemoryMetric,
    DiskPartition,
    NetworkRate,
    SystemSnapshot,
    ProcessInfo,
    DiskIoRate,
    FirewallStatus,
)
from pulseops.models.ports import ListeningPort, PortExposure
from pulseops.models.proxy import ProxyRoute
from pulseops.models.backup import BackupTask, BackupStatus
from pulseops.models.docker import ContainerSummary

class MockCollector:
    """Generates realistic server telemetry, routes, ports, and backup states for demo mode."""

    def __init__(self):
        self._start_time = time.time() - (86400 * 24 + 3600 * 5) # 24 days uptime

    def get_snapshot(self) -> SystemSnapshot:
        now = time.time()
        # Slightly fluctuating CPU and Network
        cpu_pct = round(42.0 + random.uniform(-8.0, 15.0), 1)
        per_core = [
            round(max(5.0, min(95.0, cpu_pct + random.uniform(-10.0, 10.0))), 1)
            for _ in range(4)
        ]
        
        cpu = CpuMetric(
            cores=4,
            total_percent=cpu_pct,
            per_core_percent=per_core,
            load_avg=(1.85, 1.42, 1.15),
        )
        
        total_ram = 32 * (1024**3)
        used_ram = int(18.5 * (1024**3) + random.uniform(-200, 200) * (1024**2))
        memory = MemoryMetric(
            total_bytes=total_ram,
            used_bytes=used_ram,
            free_bytes=total_ram - used_ram,
            available_bytes=total_ram - used_ram,
            percent=round((used_ram / total_ram) * 100, 1),
            swap_total_bytes=8 * (1024**3),
            swap_used_bytes=int(0.4 * (1024**3)),
            swap_percent=5.0,
        )

        disks = [
            DiskPartition(
                device="/dev/nvme0n1p2",
                mountpoint="/",
                fstype="ext4",
                total_bytes=240 * (1024**3),
                used_bytes=164 * (1024**3),
                free_bytes=76 * (1024**3),
                percent=68.3,
            ),
            DiskPartition(
                device="/dev/sda1",
                mountpoint="/mnt/storage",
                fstype="ext4",
                total_bytes=1000 * (1024**3),
                used_bytes=420 * (1024**3),
                free_bytes=580 * (1024**3),
                percent=42.0,
            ),
        ]

        rx = round(8.4 * 1024 * 1024 + random.uniform(-1.5, 3.0) * 1024 * 1024, 1)
        tx = round(2.2 * 1024 * 1024 + random.uniform(-0.5, 1.0) * 1024 * 1024, 1)
        network = [NetworkRate(interface="eth0", rx_bytes_sec=rx, tx_bytes_sec=tx)]

        top_procs = [
            ProcessInfo(pid=1024, name="mysqld", cpu_percent=3.2, memory_mb=1820.0, memory_percent=5.6, username="mysql"),
            ProcessInfo(pid=2340, name="node [sirket-ana]", cpu_percent=8.5, memory_mb=640.0, memory_percent=2.0, username="www-data"),
            ProcessInfo(pid=2311, name="uvicorn [api]", cpu_percent=2.1, memory_mb=320.0, memory_percent=1.0, username="app"),
            ProcessInfo(pid=1420, name="nginx", cpu_percent=1.4, memory_mb=140.0, memory_percent=0.4, username="www-data"),
            ProcessInfo(pid=7890, name="dockerd", cpu_percent=1.1, memory_mb=280.0, memory_percent=0.8, username="root"),
        ]

        disk_io = DiskIoRate(
            read_bytes_sec=round(4.8 * 1024 * 1024 + random.uniform(-1.0, 2.0) * 1024 * 1024, 1),
            write_bytes_sec=round(24.1 * 1024 * 1024 + random.uniform(-5.0, 8.0) * 1024 * 1024, 1),
        )

        firewall = FirewallStatus(
            is_active=True,
            backend="UFW",
            summary="Aktif (22, 80, 443 izinli)",
        )

        return SystemSnapshot(
            hostname="prod-web-node01",
            os_name="Ubuntu 24.04.1 LTS (Noble Numbat)",
            kernel="6.8.0-40-generic x86_64",
            uptime_seconds=now - self._start_time,
            cpu=cpu,
            memory=memory,
            disks=disks,
            network=network,
            top_processes=top_procs,
            disk_io=disk_io,
            firewall=firewall,
            timestamp=now,
        )

    def get_proxy_routes(self) -> list[ProxyRoute]:
        return [
            ProxyRoute(
                domain="sirket-ana.com",
                listen_port=443,
                is_ssl=True,
                ssl_days_left=64,
                http_status=200,
                response_time_ms=14.2,
                target_url="http://127.0.0.1:3000",
                target_port=3000,
                target_process="node (Next.js) [PID 1420]",
                status="UP",
            ),
            ProxyRoute(
                domain="api.sirket-ana.com",
                listen_port=443,
                is_ssl=True,
                ssl_days_left=4,
                http_status=200,
                response_time_ms=8.5,
                target_url="http://127.0.0.1:8000",
                target_port=8000,
                target_process="uvicorn [PID 2311]",
                status="UP",
            ),
            ProxyRoute(
                domain="yonetim.sirket-ana.com",
                listen_port=443,
                is_ssl=True,
                ssl_days_left=88,
                http_status=200,
                response_time_ms=22.0,
                target_url="http://127.0.0.1:3001",
                target_port=3001,
                target_process="node (AdminPanel) [PID 4110]",
                status="UP",
            ),
            ProxyRoute(
                domain="blog.sirket-ana.com",
                listen_port=80,
                is_ssl=False,
                ssl_days_left=None,
                http_status=502,
                response_time_ms=52.0,
                target_url="http://127.0.0.1:8080",
                target_port=8080,
                target_process="docker: wordpress [PID 7890]",
                status="UP",
            ),
        ]

    def get_listening_ports(self) -> list[ListeningPort]:
        return [
            ListeningPort(proto="tcp", ip="0.0.0.0", port=22, pid=820, process_name="sshd", exposure=PortExposure.ADMIN_SSH),
            ListeningPort(proto="tcp", ip="0.0.0.0", port=80, pid=1420, process_name="nginx", exposure=PortExposure.PUBLIC_WEB),
            ListeningPort(proto="tcp", ip="0.0.0.0", port=443, pid=1420, process_name="nginx", exposure=PortExposure.PUBLIC_WEB),
            ListeningPort(proto="tcp", ip="127.0.0.1", port=3000, pid=2340, process_name="node", exposure=PortExposure.SAFE_INTERNAL),
            ListeningPort(proto="tcp", ip="127.0.0.1", port=3001, pid=4110, process_name="node", exposure=PortExposure.SAFE_INTERNAL),
            ListeningPort(proto="tcp", ip="127.0.0.1", port=5432, pid=912, process_name="postgres", exposure=PortExposure.SAFE_INTERNAL),
            ListeningPort(proto="tcp", ip="127.0.0.1", port=6379, pid=1015, process_name="redis-server", exposure=PortExposure.SAFE_INTERNAL),
            ListeningPort(proto="tcp", ip="127.0.0.1", port=8000, pid=2311, process_name="uvicorn", exposure=PortExposure.SAFE_INTERNAL),
            ListeningPort(proto="tcp", ip="0.0.0.0", port=27017, pid=3420, process_name="mongod", exposure=PortExposure.EXPOSED_RISK),
        ]

    def get_backup_tasks(self) -> list[BackupTask]:
        return [
            BackupTask(
                name="pg_dump-daily.timer",
                mechanism="systemd-timer",
                schedule="Her Gün 03:00",
                last_run="Bugün 03:00:02 (7 saat önce)",
                status=BackupStatus.SUCCESS,
                exit_code=0,
                target_path="/mnt/storage/backups/postgres",
            ),
            BackupTask(
                name="restic-s3-offsite.timer",
                mechanism="systemd-timer",
                schedule="Her Gün 05:00",
                last_run="Bugün 05:00:15 (5 saat önce)",
                status=BackupStatus.SUCCESS,
                exit_code=0,
                target_path="s3:company-backups/daily",
            ),
            BackupTask(
                name="redis-snapshot.sh",
                mechanism="cron",
                schedule="0 * * * * (Her Saat Başı)",
                last_run="Saat 12:00:00",
                status=BackupStatus.SUCCESS,
                exit_code=0,
                target_path="/var/lib/redis/dump.rdb",
            ),
        ]

    def get_backup_data(self):
        from pulseops.models.backup import BackupData, DeploymentState
        from pulseops.collectors.backup_collector import BackupCollector
        import datetime

        collector = BackupCollector()
        sample_files = [
            "store-20260929-160647.json",
            "store-20260929-083603.json",
            "store-20260925-134157.json",
            "store-20260925-114800.json",
            "store-20260925-094745.json",
            "store-20260925-092156.json",
            "store-20260924-150054.json",
            "store-20260924-135144.json",
            "store-20260924-134306.json",
            "store-20260924-121645.json",
            "store-20260924-093114.json",
            "store-20260923-134410.json",
            "store-20260923-133715.json",
            "store-20260923-130538.json",
            "store-20260923-124807.json",
            "store-20260923-114146.json",
            "store-20260923-111212.json",
            "store-20260923-104134.json",
            "store-20260923-100702.json",
            "store-20260923-093631.json",
            "store-20260923-093401.json",
            "store-20260922-122056.json",
            "store-20260922-114124.json",
            "store-20260922-112010.json",
            "store-20260922-111017.json",
            "store-20260921-125739.json",
            "store-20260921-123857.json",
            "store-20260921-122052.json",
            "store-20260921-083135.json",
            "store-20260921-080032.json",
            "store-20260921-075520.json",
            "store-20260921-075401.json",
            "store-20260917-101657.json",
            "store-20260917-092044.json",
            "store-20260916-133050.json",
            "store-20260916-131912.json",
            "store-20260916-131430.json",
            "store-20260916-124623.json",
            "store-20260916-122330.json",
            "store-20260916-112844.json",
            "store-20260915-122321.json",
            "store-20260911-120707.json",
            "store-20260911-115053.json",
            "store-20260910-153342.json",
            "store-20260909-092427.json",
            "store-20260908-123109.json",
            "store-20260908-121421.json",
            "store-20260908-120927.json",
            "store-20260908-114449.json",
            "store-20260908-110350.json",
            "store-20260902-194157.json",
            "store-20260902-192318.json",
            "store-20260902-191923.json",
            "store-20260902-191523.json",
            "store-20260902-142848.json",
            "store-20260902-114006.json",
            "store-20260902-111547.json",
            "store-20260902-110913.json",
            "store-20260902-100354.json",
            "store-20260902-094151.json",
            "store-20260902-085951.json",
            "store-20260902-085623.json",
            "store-20260902-081237.json",
            "store-20260901-143252.json",
            "store-20260901-140159.json",
            "store-20260901-121639.json",
            "store-20260901-110343.json",
            "store-20260901-105633.json",
            "store-20260901-073008.json",
            "store-20260828-110146.json",
            "store-20260828-105618.json",
            "store-20260827-101629.json",
            "store-20260827-092653.json",
            "store-20260825-145435.json",
            "store-20260825-134218.json",
            "store-20260825-130837.json",
            "store-20260825-124621.json",
            "store-20260825-124016.json",
            "store-20260825-120843.json",
            "store-20260825-113334.json",
            "store-20260825-111736.json",
            "store-20260825-085247.json",
            "store-20260824-145628.json",
            "store-20260824-145125.json",
        ]
        
        # Use fixed current time corresponding to user's timeline (2026-09-30 14:00)
        curr_time = datetime.datetime(2026, 9, 30, 14, 0, 0)
        snapshots = collector.parse_snapshot_files(sample_files, now=curr_time)
        retention = collector.audit_retention(snapshots)
        
        deployment = DeploymentState(
            last_deploy_sha="8f2a1b9c3e",
            prev_deploy_sha="4c9e7d3a1f",
            last_deploy_time="2026-09-29 16:06"
        )
        
        return BackupData(
            tasks=self.get_backup_tasks(),
            snapshots=snapshots,
            deployment=deployment,
            retention=retention,
        )

    def get_containers(self) -> list[ContainerSummary]:
        return [
            ContainerSummary(
                id="a1b2c3d4e5f6",
                name="wordpress-prod",
                image="wordpress:6.4-php8.2",
                status="Up 14 days",
                ports=["127.0.0.1:8080->80/tcp"],
                uptime="14 days",
            ),
            ContainerSummary(
                id="b2c3d4e5f6a1",
                name="redis-cache",
                image="redis:7.2-alpine",
                status="Up 24 days",
                ports=["127.0.0.1:6379->6379/tcp"],
                uptime="24 days",
            ),
            ContainerSummary(
                id="c3d4e5f6a1b2",
                name="postgres-db",
                image="postgres:16-bullseye",
                status="Up 24 days",
                ports=["127.0.0.1:5432->5432/tcp"],
                uptime="24 days",
            ),
        ]

    def get_services(self):
        from pulseops.models.services import ServiceUnit, ServiceState
        return [
            ServiceUnit(name="nginx.service", display_name="Nginx Web & Reverse Proxy", state=ServiceState.RUNNING, enabled="enabled", description="Web Engine"),
            ServiceUnit(name="docker.service", display_name="Docker Container Engine", state=ServiceState.RUNNING, enabled="enabled", description="Container Daemon"),
            ServiceUnit(name="postgresql.service", display_name="PostgreSQL 16 Database", state=ServiceState.RUNNING, enabled="enabled", description="Relational DB"),
            ServiceUnit(name="redis-server.service", display_name="Redis In-Memory Cache", state=ServiceState.RUNNING, enabled="enabled", description="Key-Value Store"),
            ServiceUnit(name="ssh.service", display_name="OpenSSH Server Daemon", state=ServiceState.RUNNING, enabled="enabled", description="Secure Shell"),
            ServiceUnit(name="ufw.service", display_name="UFW Firewall", state=ServiceState.RUNNING, enabled="enabled", description="Packet Filtering"),
            ServiceUnit(name="cron.service", display_name="Cron Job Scheduler", state=ServiceState.RUNNING, enabled="enabled", description="Periodic Tasks"),
        ]

    def get_databases(self):
        from pulseops.models.database import DatabaseInstance
        return [
            DatabaseInstance(
                engine="PostgreSQL",
                version="16.2",
                port=5432,
                status="RUNNING",
                bind_ip="127.0.0.1",
                is_external_open=False,
                metric_summary="Connections: 24 | DBs: 6",
                managed_by="Native Service"
            ),
            DatabaseInstance(
                engine="MySQL / MariaDB",
                version="11.2",
                port=3306,
                status="RUNNING",
                bind_ip="127.0.0.1",
                is_external_open=False,
                metric_summary="Threads: 8 | Queries: 340/s",
                managed_by="Native Service"
            ),
            DatabaseInstance(
                engine="Redis",
                version="7.2",
                port=6379,
                status="RUNNING",
                bind_ip="127.0.0.1",
                is_external_open=False,
                metric_summary="RAM: 182 MB | Clients: 14",
                managed_by="Docker (redis-cache)"
            ),
        ]

    def get_security(self):
        from pulseops.models.security import (
            AccessAudit, AuthActivity, CountedItem, Fail2banJail, Fail2banStatus, LoginEvent,
            SecurityOverview, SSHSecurityAudit, UpdateStatus,
        )
        return SecurityOverview(
            fail2ban=Fail2banStatus(installed=True, running=True, jails=[
                Fail2banJail(name="sshd", currently_failed=4, currently_banned=3, total_banned=41,
                             banned_ips=["203.0.113.45", "198.51.100.23", "192.0.2.77"]),
                Fail2banJail(name="nginx-http-auth", currently_banned=0, total_banned=2),
            ]),
            auth=AuthActivity(
                known=True, source="journal", window="son 24 saat", failed=388, invalid_user=124,
                accepted=6, accepted_password=0,
                top_sources=[CountedItem(value="203.0.113.45", count=211), CountedItem(value="198.51.100.23", count=97),
                             CountedItem(value="192.0.2.77", count=64)],
                top_users=[CountedItem(value="root", count=240), CountedItem(value="admin", count=58)],
                recent_accepted=[
                    LoginEvent(time="2026-10-03 08:12", method="publickey", user="deploy", source="10.0.0.12"),
                    LoginEvent(time="2026-10-03 13:47", method="publickey", user="deploy", source="10.0.0.12"),
                ],
            ),
            access=AccessAudit(uid0_users=["root"], admin_users=["deploy"], login_users=["root", "deploy"],
                               sudoers_known=True, nopasswd_rules=[], keys_known=True,
                               authorized_keys={"deploy": 2, "root": 0}),
            updates=UpdateStatus(manager="apt", known=True, total=7, security=0, metadata_age_days=0.4,
                                 reboot_required=False, running_kernel="6.8.0-40-generic"),
            ssh=SSHSecurityAudit(port=22, permit_root_login="no", password_authentication="no", pubkey_authentication="yes"),
            firewall_name="UFW",
            firewall_active=True,
            firewall_rules_count=8,
            open_ports_count=7,
            exposed_risky_ports=[],
            overall_status="GÜVENLİ ✓",
            recommendations=[
                "[BILGI] SSH: 512 basarisiz deneme (son 24 saat); fail2ban su an 3 IP'yi engelliyor.",
                "✓ Root login kapalı (PermitRootLogin no)",
                "✓ Şifreli SSH girişi kapalı, yalnızca anahtar doğrulaması aktif",
                "✓ UFW güvenlik duvarı aktif ve 8 kural devrede",
                "✓ 0.0.0.0 üzerinde dışa açık veritabanı portu bulunmuyor",
            ]
        )

    def get_storage(self):
        from pulseops.collectors.storage_collector import storage_recommendations
        from pulseops.models.storage import DeletedOpenFile, FileUsage, StorageItem, StorageOverview

        gb, mb = 1024**3, 1024**2
        st = StorageOverview(
            root_used_gb=68.3 * 193 / 100, root_total_gb=193.0, root_percent=68.3,
            items=[
                StorageItem(name="Images", total_bytes=int(8.4 * gb), reclaimable_bytes=int(2.1 * gb),
                            reclaimable_percent=25, count=14, active=5),
                StorageItem(name="Containers", total_bytes=int(74 * mb), count=5, active=5),
                StorageItem(name="Local Volumes", total_bytes=int(1.2 * gb), count=3, active=3),
                StorageItem(name="Build Cache", total_bytes=int(3.1 * gb), reclaimable_bytes=int(3.1 * gb),
                            reclaimable_percent=100, count=41, active=0),
            ],
            buildkit_cache_bytes=int(3.1 * gb), containerd_bytes=int(9.6 * gb),
            known=True, complete=True,
            inode_percent={"/": 41.0, "/mnt/storage": 3.0},
            journal_bytes=int(1.4 * gb), var_log_bytes=int(2.3 * gb),
            big_logs=[FileUsage(path="/var/log/nginx/access.log", bytes=int(740 * mb)),
                      FileUsage(path="/var/log/syslog.1", bytes=int(210 * mb))],
            docker_logs=[FileUsage(path="wordpress-prod (3f2a91c0d4e1)", bytes=int(870 * mb))],
            deleted_open=[DeletedOpenFile(pid=1123, process="nginx", path="/var/log/nginx/access.log.1",
                                          bytes=int(480 * mb))],
            top_dirs=[FileUsage(path=p, bytes=int(v * gb)) for p, v in
                      (("/var", 61.2), ("/home", 28.4), ("/usr", 9.8), ("/opt", 7.1), ("/srv", 4.3), ("/root", 1.2))],
            forecast_days=46.0, growth_percent_per_day=0.69,
        )
        st.recommendations = storage_recommendations(st, [])
        return st

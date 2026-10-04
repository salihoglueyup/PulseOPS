from pulseops.models.system import CpuMetric, MemoryMetric, DiskPartition, NetworkRate, SystemSnapshot
from pulseops.models.ports import PortExposure, ListeningPort
from pulseops.models.proxy import ProxyRoute
from pulseops.models.backup import BackupStatus, BackupTask
from pulseops.models.docker import ContainerSummary

def test_system_snapshot_model():
    cpu = CpuMetric(cores=4, total_percent=45.5, per_core_percent=[40.0, 50.0, 42.0, 50.0], load_avg=(1.2, 0.9, 0.7))
    memory = MemoryMetric(
        total_bytes=16000000000,
        used_bytes=8000000000,
        free_bytes=4000000000,
        available_bytes=8000000000,
        percent=50.0,
        swap_total_bytes=4000000000,
        swap_used_bytes=100000000,
        swap_percent=2.5,
    )
    disks = [
        DiskPartition(
            device="/dev/sda1",
            mountpoint="/",
            fstype="ext4",
            total_bytes=100000000000,
            used_bytes=40000000000,
            free_bytes=60000000000,
            percent=40.0,
        )
    ]
    net = [NetworkRate(interface="eth0", rx_bytes_sec=1024000.0, tx_bytes_sec=512000.0)]
    
    snapshot = SystemSnapshot(
        hostname="prod-srv01",
        os_name="Ubuntu 24.04 LTS",
        kernel="6.8.0-31-generic",
        uptime_seconds=86400.0,
        cpu=cpu,
        memory=memory,
        disks=disks,
        network=net,
        timestamp=1710000000.0,
    )
    assert snapshot.hostname == "prod-srv01"
    assert snapshot.cpu.cores == 4
    assert snapshot.memory.percent == 50.0
    assert len(snapshot.disks) == 1
    assert snapshot.disks[0].mountpoint == "/"

def test_listening_port_model():
    p1 = ListeningPort(
        proto="tcp",
        ip="127.0.0.1",
        port=5432,
        pid=1234,
        process_name="postgres",
        exposure=PortExposure.SAFE_INTERNAL
    )
    assert p1.exposure == PortExposure.SAFE_INTERNAL
    assert p1.is_safe() is True

    p2 = ListeningPort(
        proto="tcp",
        ip="0.0.0.0",
        port=5432,
        pid=1234,
        process_name="postgres",
        exposure=PortExposure.EXPOSED_RISK
    )
    assert p2.exposure == PortExposure.EXPOSED_RISK
    assert p2.is_safe() is False

def test_proxy_route_model():
    route = ProxyRoute(
        domain="musteri-a.com",
        listen_port=443,
        is_ssl=True,
        target_url="http://127.0.0.1:3000",
        target_port=3000,
        target_process="node (Next.js)",
        status="UP"
    )
    assert route.domain == "musteri-a.com"
    assert route.is_ssl is True
    assert route.target_port == 3000

def test_backup_task_model():
    task = BackupTask(
        name="db-backup.timer",
        mechanism="systemd-timer",
        schedule="Every day at 03:00",
        last_run="Today 03:00",
        status=BackupStatus.SUCCESS,
        exit_code=0,
        target_path="/mnt/backups/pg_dump"
    )
    assert task.status == BackupStatus.SUCCESS
    assert task.exit_code == 0

def test_container_summary_model():
    c = ContainerSummary(
        id="c123456789ab",
        name="web-frontend",
        image="node:20-alpine",
        status="Up 3 days",
        ports=["127.0.0.1:3000->3000/tcp"],
        uptime="3 days"
    )
    assert c.name == "web-frontend"
    assert len(c.ports) == 1

from models.telemetry import Telemetry
from models.ports import PortExposure
from models.services import ServiceState
from collectors.base import BaseCollector

CRITICAL_SERVICE_KEYWORDS = ("nginx", "docker", "postgres", "mysql", "redis")


def collect_telemetry(collector: BaseCollector) -> Telemetry:
    """Runs one full poll cycle on a collector and returns it as a single Telemetry object."""
    snapshot, ports, routes, backups, containers = collector.poll()
    backup_data = collector.poll_backup_data()
    return Telemetry(
        snapshot=snapshot,
        ports=ports,
        routes=routes,
        backups=backup_data.tasks or backups,
        backup_data=backup_data,
        containers=containers,
        services=collector.poll_services(),
        databases=collector.poll_databases(ports, containers),
        security=collector.poll_security(ports),
        storage=collector.poll_storage(),
        privileges=collector.poll_privileges(),
    )


def summarize_alerts(t: Telemetry) -> list[str]:
    """Returns human readable alert lines for every active risk in the telemetry."""
    alerts: list[str] = []
    for p in t.ports:
        if p.exposure == PortExposure.EXPOSED_RISK:
            alerts.append(f"Port :{p.port} ({p.process_name or 'servis'}) dışa açık!")
    for r in t.routes:
        if r.is_ssl and r.ssl_days_left is not None and r.ssl_days_left <= 7:
            alerts.append(f"{r.domain} SSL {r.ssl_days_left} gün kaldı!")
    for r in t.routes:
        if r.http_status in (502, 504):
            alerts.append(f"{r.domain} {r.http_status} Hatası!")
    for d in t.snapshot.disks:
        if d.percent > 80.0:
            alerts.append(f"{d.mountpoint} disk %{d.percent:.0f}")
    if t.snapshot.memory.percent > 85.0:
        alerts.append(f"RAM %{t.snapshot.memory.percent:.0f}")
    if not t.snapshot.firewall.is_active:
        alerts.append("Güvenlik Duvarı KAPALI")
    for s in t.services:
        if any(k in s.name.lower() for k in CRITICAL_SERVICE_KEYWORDS):
            if s.state in (ServiceState.STOPPED, ServiceState.FAILED):
                alerts.append(f"{s.name} servisi çalışmıyor")
    if t.backup_data.retention.risk_level in ("HIGH", "CRITICAL"):
        alerts.append("Yedekleme saklama riski")
    if t.storage.is_cache_bloated:
        alerts.append("BuildKit önbelleği >10GB")
    return alerts

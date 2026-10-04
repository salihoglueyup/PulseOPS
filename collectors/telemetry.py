from typing import Optional

from models.telemetry import Telemetry
from pulseops_config import AlertConfig
from models.ports import PortExposure
from models.services import ServiceState
from collectors.base import BaseCollector

CRITICAL_SERVICE_KEYWORDS = ("nginx", "docker", "postgres", "mysql", "redis")


def collect_telemetry(collector: BaseCollector) -> Telemetry:
    """Runs one complete poll (all tiers) and returns it as a single Telemetry object."""
    return collector.collect(include_slow=True, include_logs=True)


def summarize_alerts(t: Telemetry, thresholds: Optional[AlertConfig] = None) -> list[str]:
    """Returns human readable alert lines for every active risk in the telemetry."""
    th = thresholds or AlertConfig()
    alerts: list[str] = []
    for p in t.ports:
        if p.exposure == PortExposure.EXPOSED_RISK:
            alerts.append(f"Port :{p.port} ({p.process_name or 'servis'}) dışa açık!")
    for r in t.routes:
        if r.is_ssl and r.ssl_days_left is not None and r.ssl_days_left <= th.ssl_days:
            alerts.append(f"{r.domain} SSL {r.ssl_days_left} gün kaldı!")
    for r in t.routes:
        if r.http_status in (502, 504):
            alerts.append(f"{r.domain} {r.http_status} Hatası!")
    for d in t.snapshot.disks:
        if d.percent > th.disk_percent:
            alerts.append(f"{d.mountpoint} disk %{d.percent:.0f}")
    if t.snapshot.memory.percent > th.memory_percent:
        alerts.append(f"RAM %{t.snapshot.memory.percent:.0f}")
    if t.snapshot.firewall.known and not t.snapshot.firewall.is_active:
        alerts.append("Güvenlik Duvarı KAPALI")
    for s in t.services:
        if any(k in s.name.lower() for k in CRITICAL_SERVICE_KEYWORDS):
            if s.state in (ServiceState.STOPPED, ServiceState.FAILED):
                alerts.append(f"{s.name} servisi çalışmıyor")
    if t.backup_data.retention.risk_level in ("HIGH", "CRITICAL"):
        alerts.append("Yedekleme saklama riski")
    for user in t.security.access.extra_uid0:
        alerts.append(f"UID 0 hesap: {user}")
    auth = t.security.auth
    if auth.known and auth.failed_total >= th.ssh_failed_logins and not t.security.fail2ban.protecting_ssh:
        alerts.append(f"SSH kaba kuvvet: {auth.failed_total} deneme, fail2ban yok")
    updates = t.security.updates
    if updates.known and updates.security:
        alerts.append(f"{updates.security} güvenlik güncellemesi bekliyor")
    if updates.reboot_required:
        alerts.append("Yeniden başlatma gerekli (yamalar etkin değil)")
    for check in t.security.hardening.failed:
        if check.severity == "HIGH":
            alerts.append(check.problem or f"Sertleştirme başarısız: {check.title}")
    for c in t.containers:
        if c.security is None:
            continue
        high = [r.text for r in c.security.risks if r.severity == "HIGH"]
        if high:
            alerts.append(f"Konteyner {c.name}: {high[0]}" + (f" (+{len(high) - 1})" if len(high) > 1 else ""))
        if c.security.health == "unhealthy":
            alerts.append(f"Konteyner {c.name} sağlıksız (healthcheck)")
        if c.security.restart_count >= 5:
            alerts.append(f"Konteyner {c.name} {c.security.restart_count} kez yeniden başladı")
    if t.storage.is_cache_bloated:
        alerts.append("BuildKit önbelleği >10GB")
    return alerts

from pathlib import Path
from pulseops.collectors.base import DemoCollector
from pulseops.collectors.audit_exporter import (
    calculate_audit_score,
    generate_audit_markdown,
    export_audit_report,
)
from pulseops.models.ports import ListeningPort, PortExposure
from pulseops.models.proxy import ProxyRoute
from pulseops.models.security import SecurityOverview, SSHSecurityAudit
from pulseops.models.storage import StorageOverview

def test_calculate_audit_score():
    collector = DemoCollector()
    snapshot, ports, routes, backups, containers = collector.poll()
    
    # In DemoCollector, we have:
    # 1 exposed risky port (27017 MongoDB -> -15)
    # 1 bad route (502 -> -10)
    # 1 expiring ssl (api.sirket-ana.com with 4 days -> -10)
    # Total expected score = 100 - 15 - 10 - 10 = 65 -> Grade C
    score, grade = calculate_audit_score(snapshot, ports, routes)
    assert score == 65
    assert "C" in grade

def test_calculate_audit_score_clean():
    collector = DemoCollector()
    snapshot, _, _, _, _ = collector.poll()
    
    # Safe ports
    safe_ports = [
        ListeningPort(port=80, proto="tcp", ip="0.0.0.0", process_name="nginx", pid=100, exposure=PortExposure.PUBLIC_WEB),
        ListeningPort(port=443, proto="tcp", ip="0.0.0.0", process_name="nginx", pid=100, exposure=PortExposure.PUBLIC_WEB),
        ListeningPort(port=5432, proto="tcp", ip="127.0.0.1", process_name="postgres", pid=101, exposure=PortExposure.SAFE_INTERNAL),
    ]
    # Healthy routes
    healthy_routes = [
        ProxyRoute(domain="example.com", listen_port=443, target_url="http://127.0.0.1:3000", is_ssl=True, ssl_days_left=90, http_status=200),
    ]
    # Clean security & storage
    security = SecurityOverview(
        firewall_active=True,
        ssh=SSHSecurityAudit(port=22, permit_root_login="no", password_authentication="no", is_hardened=True),
    )
    storage = StorageOverview(
        is_cache_bloated=False,
        total_reclaimable_human="1.2 GB",
        items=[],
    )
    
    score, grade = calculate_audit_score(snapshot, safe_ports, healthy_routes, security, storage)
    assert score == 100
    assert "A+" in grade

def test_generate_audit_markdown_comprehensive():
    collector = DemoCollector()
    snapshot, ports, routes, backups, containers = collector.poll()
    
    security = SecurityOverview(
        firewall_active=True,
        ssh=SSHSecurityAudit(port=22, permit_root_login="prohibit-password", password_authentication="no", is_hardened=True),
    )
    storage = StorageOverview(
        is_cache_bloated=True,
        total_reclaimable_human="28.5 GB",
    )

    md_text = generate_audit_markdown(
        snapshot,
        ports,
        routes,
        backups,
        containers,
        databases=[],
        services=[],
        security=security,
        storage=storage,
    )
    
    assert "PulseOps" in md_text
    assert "# 🛡️ PulseOps Sunucu Güvenlik & Sistem Röntgen Raporu" in md_text
    assert "ALTYAPI SAĞLIK & GÜVENLİK SKORU" in md_text
    assert snapshot.hostname in md_text
    assert "1. ⚡ Donanım ve Kaynak Durumu" in md_text
    assert "2. 🌐 WEB SİTELERİ & REVERSE PROXY HARİTASI" in md_text
    assert "3. 🔍 DİNLENEN PORTLAR VE GÜVENLİK ANALİZİ" in md_text
    assert "7. 💾 YEDEKLEME SİSTEMİ DURUMU" in md_text
    assert "8. 🐳 DOCKER KONTEYNERLERİ" in md_text
    assert "9. 📦 DEPOLAMA, BUILDKIT & CONTAINERD ANALİZİ" in md_text
    assert "10. 🧠 EN ÇOK KAYNAK TÜKETEN İLK 5 SÜREÇ" in md_text
    assert "YÖNETİCİ EYLEM PLANI (ACTION CHECKLIST)" in md_text

def test_export_audit_report_to_disk(tmp_path):
    collector = DemoCollector()
    snapshot, ports, routes, backups, containers = collector.poll()
    
    output_path = export_audit_report(
        snapshot,
        ports,
        routes,
        backups,
        containers,
        output_dir=tmp_path,
    )
    assert Path(output_path).exists()
    content = Path(output_path).read_text(encoding="utf-8")
    assert snapshot.hostname in content
    assert "PulseOps" in content

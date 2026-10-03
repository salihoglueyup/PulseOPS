from models.services import ServiceState
from models.ports import ListeningPort, PortExposure
from models.docker import ContainerSummary

from collectors.service_collector import ServiceCollector
from collectors.db_collector import DatabaseCollector
from collectors.security_collector import SecurityCollector
from collectors.mock_collector import MockCollector
from ui.widgets.dashboard_status_bar import DashboardStatusBar
from ui.widgets.alert_ticker import AlertTicker
from ui.modals.config_viewer_modal import ConfigViewerModal

def test_service_collector_parsing():
    raw_units = """
● nginx.service          loaded active running A high performance web server and a reverse proxy that handles http requests
● docker.service         loaded active running Docker Application Container Engine
● postgresql.service     loaded active running PostgreSQL RDBMS Server
  redis-server.service   loaded failed failed  Advanced key-value store
● ssh.service            loaded active running OpenBSD Secure Shell server
"""
    raw_files = """
nginx.service enabled
docker.service enabled
postgresql.service enabled
redis-server.service disabled
ssh.service enabled
"""
    collector = ServiceCollector()
    services = collector.parse_systemctl_units(raw_units, raw_files)
    
    assert len(services) == 5
    nginx = next(s for s in services if s.name == "nginx.service")
    assert nginx.state == ServiceState.RUNNING
    assert nginx.enabled == "enabled"

    redis = next(s for s in services if s.name == "redis-server.service")
    assert redis.state == ServiceState.FAILED
    assert redis.enabled == "disabled"

def test_database_collector_discovery():
    ports = [
        ListeningPort(port=5432, proto="tcp", ip="0.0.0.0", process_name="postgres", pid=101, exposure=PortExposure.EXPOSED_RISK),
        ListeningPort(port=6379, proto="tcp", ip="127.0.0.1", process_name="redis-server", pid=102, exposure=PortExposure.SAFE_INTERNAL),
    ]
    containers = [
        ContainerSummary(
            id="c1",
            name="app-mariadb",
            image="mariadb:11.4",
            status="Up 4 hours",
            ports=["3306/tcp"],
            uptime="4 hours"
        )
    ]

    collector = DatabaseCollector()
    dbs = collector.discover_databases(ports, containers)
    
    assert len(dbs) == 3
    
    pg = next(d for d in dbs if d.engine == "PostgreSQL")
    assert pg.port == 5432
    assert pg.is_external_open is True
    assert "Dış Dünyaya Açık" in pg.security_badge

    redis = next(d for d in dbs if d.engine == "Redis")
    assert redis.port == 6379
    assert redis.is_external_open is False
    assert "Dahili" in redis.security_badge

    mariadb = next(d for d in dbs if "MySQL" in d.engine or "MariaDB" in d.engine)
    assert mariadb.port == 3306
    assert "Docker" in mariadb.managed_by

def test_security_collector_sshd_audit():
    collector = SecurityCollector()
    
    # 1. Hardened config
    hardened_conf = """
Port 2222
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
"""
    audit1 = collector.parse_sshd_config_text(hardened_conf)
    assert audit1.port == 2222
    assert audit1.permit_root_login == "no"
    assert audit1.password_authentication == "no"
    assert audit1.pubkey_authentication == "yes"
    assert audit1.is_hardened is True

    # 2. Insecure config
    insecure_conf = """
Port 22
PermitRootLogin yes
PasswordAuthentication yes
PubkeyAuthentication yes
"""
    audit2 = collector.parse_sshd_config_text(insecure_conf)
    assert audit2.permit_root_login == "yes"
    assert audit2.password_authentication == "yes"
    assert audit2.is_hardened is False

def test_mock_collector_integrations():
    mock = MockCollector()
    services = mock.get_services()
    assert len(services) >= 4
    
    dbs = mock.get_databases()
    assert len(dbs) >= 3

    sec = mock.get_security()
    assert sec.ssh.port == 22
    assert sec.firewall_active is True
    assert len(sec.recommendations) >= 1

def test_dashboard_status_bar():
    bar = DashboardStatusBar()
    bar.docker_count = 8
    bar.websites_count = 12
    bar.db_count = 3
    bar.ssl_warnings = 1
    bar.alerts_count = 4

    panel = bar.render()
    assert panel is not None

def test_config_viewer_modal():
    modal = ConfigViewerModal()
    assert "worker_processes" in modal._content or "Port 22" in modal._content
    # Test reading non-existent file falls back
    fallback = modal._read_file("/non/existent/path.conf", "FALLBACK_DATA")
    assert fallback == "FALLBACK_DATA"

def test_alert_ticker():
    ticker = AlertTicker()
    ticker.alerts_count = 0
    clean_panel = ticker.render()
    assert clean_panel is not None

    ticker.alerts_count = 2
    ticker.alert_snippet = "Port :5432 dışa açık!  •  SSL 5 gün kaldı!"
    warn_panel = ticker.render()
    assert warn_panel is not None


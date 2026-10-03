from pathlib import Path
from collectors.port_collector import PortCollector, classify_exposure
from models.ports import PortExposure

def test_classify_exposure():
    # 127.0.0.1 is always SAFE_INTERNAL
    assert classify_exposure("127.0.0.1", 5432, "postgres") == PortExposure.SAFE_INTERNAL
    assert classify_exposure("::1", 3000, "node") == PortExposure.SAFE_INTERNAL
    
    # Standard web ports
    assert classify_exposure("0.0.0.0", 80, "nginx") == PortExposure.PUBLIC_WEB
    assert classify_exposure("0.0.0.0", 443, "nginx") == PortExposure.PUBLIC_WEB
    assert classify_exposure("[::]", 443, "nginx") == PortExposure.PUBLIC_WEB

    # SSH
    assert classify_exposure("0.0.0.0", 22, "sshd") == PortExposure.ADMIN_SSH

    # Dangerous exposed database or app ports
    assert classify_exposure("0.0.0.0", 5432, "postgres") == PortExposure.EXPOSED_RISK
    assert classify_exposure("0.0.0.0", 3306, "mysqld") == PortExposure.EXPOSED_RISK
    assert classify_exposure("0.0.0.0", 6379, "redis-server") == PortExposure.EXPOSED_RISK
    assert classify_exposure("0.0.0.0", 27017, "mongod") == PortExposure.EXPOSED_RISK
    assert classify_exposure("0.0.0.0", 8080, "java") == PortExposure.EXPOSED_RISK
    assert classify_exposure("0.0.0.0", 445, "System") == PortExposure.EXPOSED_RISK

    # LAN IP binds
    assert classify_exposure("192.168.1.115", 139, "System") == PortExposure.LAN_ONLY
    assert classify_exposure("10.0.0.5", 3000, "node") == PortExposure.LAN_ONLY

    # Windows dynamic RPC ports
    assert classify_exposure("0.0.0.0", 49664, "lsass.exe") == PortExposure.SYSTEM_RPC
    assert classify_exposure("0.0.0.0", 49666, "svchost.exe") == PortExposure.SYSTEM_RPC

def test_get_service_hint():
    from collectors.port_collector import get_service_hint
    assert get_service_hint(5432, "com.docker.backend.exe") == "PostgreSQL (Docker)"
    assert get_service_hint(6379, "com.docker.backend.exe") == "Redis (Docker)"
    assert get_service_hint(445, "System") == "SMB (Dosya Paylasimi)"
    assert get_service_hint(135, "svchost.exe") == "MS-RPC (Endpoint Mapper)"
    assert get_service_hint(49664, "lsass.exe") == "Windows Dinamik RPC"

def test_parse_ss_output():
    fixture_path = Path("tests/fixtures/ss_output.txt")
    raw_text = fixture_path.read_text(encoding="utf-8")
    
    collector = PortCollector()
    ports = collector.parse_ss_text(raw_text)
    
    assert len(ports) == 7
    
    # Check nginx 80
    p80 = next(p for p in ports if p.port == 80)
    assert p80.ip == "0.0.0.0"
    assert p80.process_name == "nginx"
    assert p80.pid == 1420
    assert p80.exposure == PortExposure.PUBLIC_WEB

    # Check postgres 5432 (127.0.0.1)
    p_pg = next(p for p in ports if p.port == 5432)
    assert p_pg.ip == "127.0.0.1"
    assert p_pg.exposure == PortExposure.SAFE_INTERNAL

    # Check mysql 3306 (0.0.0.0 -> EXPOSED_RISK)
    p_my = next(p for p in ports if p.port == 3306)
    assert p_my.ip == "0.0.0.0"
    assert p_my.exposure == PortExposure.EXPOSED_RISK

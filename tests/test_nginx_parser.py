import pytest
from pathlib import Path
from collectors.nginx_parser import NginxParser
from models.ports import ListeningPort, PortExposure

def test_parse_nginx_config():
    fixture_path = Path("tests/fixtures/nginx_sample.conf")
    content = fixture_path.read_text(encoding="utf-8")
    
    parser = NginxParser()
    routes = parser.parse_config_text(content)
    
    # We should have 3 routes with proxy_pass:
    # musteri-a.com:443 -> 127.0.0.1:3000
    # api.musteri-a.com:443 -> 127.0.0.1:8000
    # demo.site.com:80 -> 127.0.0.1:8080
    assert len(routes) == 3
    
    r1 = next(r for r in routes if r.domain == "musteri-a.com")
    assert r1.listen_port == 443
    assert r1.is_ssl is True
    assert r1.target_url == "http://127.0.0.1:3000"
    assert r1.target_port == 3000

    r2 = next(r for r in routes if r.domain == "api.musteri-a.com")
    assert r2.listen_port == 443
    assert r2.is_ssl is True
    assert r2.target_port == 8000

    r3 = next(r for r in routes if r.domain == "demo.site.com")
    assert r3.listen_port == 80
    assert r3.is_ssl is False
    assert r3.target_port == 8080

def test_enrich_with_ports():
    parser = NginxParser()
    fixture_path = Path("tests/fixtures/nginx_sample.conf")
    routes = parser.parse_config_text(fixture_path.read_text(encoding="utf-8"))
    
    listening_ports = [
        ListeningPort(
            proto="tcp",
            ip="127.0.0.1",
            port=3000,
            pid=2340,
            process_name="node",
            exposure=PortExposure.SAFE_INTERNAL
        ),
        ListeningPort(
            proto="tcp",
            ip="127.0.0.1",
            port=8000,
            pid=5110,
            process_name="uvicorn",
            exposure=PortExposure.SAFE_INTERNAL
        ),
    ]
    
    enriched = parser.enrich_routes_with_ports(routes, listening_ports)
    r1 = next(r for r in enriched if r.domain == "musteri-a.com")
    assert r1.target_process == "node [PID 2340]"
    
    r2 = next(r for r in enriched if r.domain == "api.musteri-a.com")
    assert r2.target_process == "uvicorn [PID 5110]"

    r3 = next(r for r in enriched if r.domain == "demo.site.com")
    assert r3.target_process is None

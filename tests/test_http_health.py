from collectors.http_health import HTTPHealthChecker
from models.proxy import ProxyRoute

def test_enrich_mock_health():
    checker = HTTPHealthChecker()
    routes = [
        ProxyRoute(domain="sirket-ana.com", listen_port=443, is_ssl=True, target_url="http://127.0.0.1:3000", target_port=3000),
        ProxyRoute(domain="blog.sirket-ana.com", listen_port=80, is_ssl=False, target_url="http://127.0.0.1:8080", target_port=8080),
    ]
    # Test fallback health check without external web server
    enriched = checker.enrich_routes_simulated(routes)
    assert len(enriched) == 2
    assert enriched[0].http_status == 200
    assert enriched[0].response_time_ms is not None
    assert enriched[1].http_status in (200, 502)

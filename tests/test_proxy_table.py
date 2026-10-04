from unittest.mock import patch
from pulseops.models.proxy import ProxyRoute
from pulseops.models.ports import ListeningPort, PortExposure
from pulseops.ui.widgets.port_table import PortProxyTable

def test_proxy_route_enhanced_properties():
    # 1. Normal web route
    r_web = ProxyRoute(
        domain="aloyonetim-web.docker",
        listen_port=3001,
        target_url="http://127.0.0.1:3001",
        http_status=200,
        response_time_ms=14.5
    )
    assert r_web.is_web is True
    assert r_web.is_tcp is False
    assert r_web.is_issue is False
    assert r_web.browser_url == "http://127.0.0.1:3001"
    assert "sağlıklı" in r_web.diagnostics_summary

    # 2. 502 Bad Gateway route
    r_502 = ProxyRoute(
        domain="aloyonetim-prisma-studio.docker",
        listen_port=5555,
        target_url="http://127.0.0.1:5555",
        http_status=502,
        response_time_ms=50.0
    )
    assert r_502.is_web is True
    assert r_502.is_issue is True
    assert "5555" in r_502.diagnostics_summary
    assert "bağlantı kesildi" in r_502.diagnostics_summary

    # 3. TCP route (e.g. Postgres / Redis)
    r_tcp = ProxyRoute(
        domain="aloyonetim-postgres.docker",
        listen_port=5432,
        target_url="tcp://127.0.0.1:5432",
        http_status=200
    )
    assert r_tcp.is_tcp is True
    assert r_tcp.is_web is False
    assert r_tcp.browser_url is None
    assert "TCP soketi" in r_tcp.diagnostics_summary

    # 4. Critical SSL expiring route
    r_ssl = ProxyRoute(
        domain="api.sirket.com",
        listen_port=443,
        is_ssl=True,
        ssl_days_left=3,
        target_url="http://127.0.0.1:8000",
        http_status=200
    )
    assert r_ssl.is_issue is True
    assert r_ssl.browser_url == "https://api.sirket.com"

def test_port_proxy_table_filtering_and_cycling():
    routes = [
        ProxyRoute(domain="web.local", listen_port=3000, target_url="http://127.0.0.1:3000", http_status=200),
        ProxyRoute(domain="broken.local", listen_port=5000, target_url="http://127.0.0.1:5000", http_status=502),
        ProxyRoute(domain="db.local", listen_port=5432, target_url="tcp://127.0.0.1:5432", http_status=200),
        ProxyRoute(domain="secure.com", listen_port=443, is_ssl=True, ssl_days_left=60, target_url="http://127.0.0.1:8080", http_status=200),
    ]

    widget = PortProxyTable()
    widget.routes = routes

    # Default is ALL
    assert widget.filter_mode == "ALL"
    assert len(widget._get_visible_routes()) == 4

    # Cycle to WEB
    mode = widget.cycle_filter()
    assert mode == "WEB"
    assert len(widget._get_visible_routes()) == 3  # web.local, broken.local, secure.com

    # Cycle to ISSUES
    mode = widget.cycle_filter()
    assert mode == "ISSUES"
    assert len(widget._get_visible_routes()) == 1
    assert widget._get_visible_routes()[0].domain == "broken.local"

    # Cycle to SSL
    mode = widget.cycle_filter()
    assert mode == "SSL"
    assert len(widget._get_visible_routes()) == 1
    assert widget._get_visible_routes()[0].domain == "secure.com"

    # Cycle to TCP
    mode = widget.cycle_filter()
    assert mode == "TCP"
    assert len(widget._get_visible_routes()) == 1
    assert widget._get_visible_routes()[0].domain == "db.local"

    # Cycle back to ALL
    mode = widget.cycle_filter()
    assert mode == "ALL"
    assert len(widget._get_visible_routes()) == 4

    # Test text search filter
    widget.filter_query = "broken"
    assert len(widget._get_visible_routes()) == 1
    assert widget._get_visible_routes()[0].domain == "broken.local"

def test_port_proxy_table_selection_and_browser():
    routes = [
        ProxyRoute(domain="web.local", listen_port=3000, target_url="http://127.0.0.1:3000", http_status=200),
        ProxyRoute(domain="db.local", listen_port=5432, target_url="tcp://127.0.0.1:5432", http_status=200),
    ]
    widget = PortProxyTable()
    widget.routes = routes

    assert widget.selected_index == 0
    assert widget.get_selected_route().domain == "web.local"

    # Test browser open on web route
    with patch("webbrowser.open") as mock_open:
        success, msg = widget.open_in_browser()
        assert success is True
        assert "Tarayıcıda açıldı" in msg
        mock_open.assert_called_once_with("http://127.0.0.1:3000")

    # Move to next route (TCP)
    widget.select_next()
    assert widget.selected_index == 1
    assert widget.get_selected_route().domain == "db.local"

    # Test browser open on TCP route
    with patch("webbrowser.open") as mock_open:
        success, msg = widget.open_in_browser()
        assert success is False
        assert "TCP servisidir" in msg
        mock_open.assert_not_called()

    # Move previous
    widget.select_previous()
    assert widget.selected_index == 0

def test_port_proxy_table_render():
    routes = [
        ProxyRoute(domain="web.local", listen_port=3000, target_url="http://127.0.0.1:3000", http_status=200, response_time_ms=12.4),
        ProxyRoute(domain="fail.local", listen_port=5000, target_url="http://127.0.0.1:5000", http_status=502),
    ]
    widget = PortProxyTable()
    widget.routes = routes

    panel = widget.render()
    assert panel is not None
    assert "WEB SİTELERİ" in str(panel.title)

    # Empty routes fallback to listening ports
    empty_widget = PortProxyTable()
    empty_widget.ports = [
        ListeningPort(proto="tcp", port=8080, ip="127.0.0.1", process_name="node", pid=1234, exposure=PortExposure.SAFE_INTERNAL)
    ]
    panel_fallback = empty_widget.render()
    assert panel_fallback is not None

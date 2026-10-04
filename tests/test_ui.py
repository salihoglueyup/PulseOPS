import pytest
from pathlib import Path
from pulseops.collectors.base import DemoCollector
from pulseops.ui.app import ServerTUIApp
from textual.widgets import TabbedContent
from pulseops.ui.modals.port_finder_modal import PortFinderModal
from pulseops.ui.modals.alerts_modal import AlertsModal
from pulseops.ui.modals.config_viewer_modal import ConfigViewerModal
from conftest import settle

@pytest.mark.asyncio
async def test_app_lifecycle_headless(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    collector = DemoCollector()
    app = ServerTUIApp(collector=collector, poll_interval=1.0)
    
    async with app.run_test() as pilot:
        # Check that widgets mounted
        assert app.header_bar is not None
        assert app.vitals_panel is not None
        assert app.port_table is not None
        assert app.all_ports_table is not None
        assert app.top_processes_panel is not None
        assert app.log_viewer is not None
        assert app.services_table is not None
        assert app.database_panel is not None
        assert app.security_panel is not None
        assert app.dashboard_status_bar is not None

        # Verify initial data populated
        await settle(pilot)
        assert app.header_bar.hostname != ""
        assert len(app.port_table.routes) > 0
        assert len(app.backup_panel.tasks) > 0
        assert len(app.top_processes_panel.processes) > 0
        assert len(app.log_viewer.logs) > 0
        assert app.header_bar.alerts_count > 0
        assert app.dashboard_status_bar.docker_count > 0
        assert app.dashboard_status_bar.websites_count > 0

        # Test tab switching with keys '2', '3', '4', '5', '6', '7', '8', '9', '1'
        tabs = app.query_one(TabbedContent)

        await pilot.press("2")
        await pilot.pause()
        assert tabs.active == "tab-processes"

        await pilot.press("3")
        await pilot.pause()
        assert tabs.active == "tab-ports"

        await pilot.press("4")
        await pilot.pause()
        assert tabs.active == "tab-services"
        assert len(app.services_table.services) > 0

        await pilot.press("5")
        await pilot.pause()
        assert tabs.active == "tab-databases"
        assert len(app.database_panel.databases) > 0

        await pilot.press("6")
        await pilot.pause()
        assert tabs.active == "tab-websites"
        assert app.port_table.filter_mode == "ALL"

        # Test filter cycle shortcut 'w'
        await pilot.press("w")
        await pilot.pause()
        assert app.port_table.filter_mode == "WEB"

        # Test navigation keys
        await pilot.press("down")
        await pilot.pause()

        # Reset filter
        await pilot.press("w")
        await pilot.press("w")
        await pilot.press("w")
        await pilot.press("w")
        await pilot.pause()
        assert app.port_table.filter_mode == "ALL"

        await pilot.press("7")
        await pilot.pause()
        assert tabs.active == "tab-backups"
        assert len(app.backup_detail_view.backup_data.snapshots) > 0

        await pilot.press("8")
        await pilot.pause()
        assert tabs.active == "tab-logs"

        await pilot.press("9")
        await pilot.pause()
        assert tabs.active == "tab-security"
        assert app.security_panel.security is not None

        await pilot.press("1")
        await pilot.pause()
        assert tabs.active == "tab-dashboard"

        # Test theme toggle shortcut 't'
        initial_theme = app.header_bar.theme_name
        await pilot.press("t")
        await pilot.pause()
        assert app.header_bar.theme_name != initial_theme

        # Test search toggle shortcut '/' (open and close)
        await pilot.press("slash")
        await pilot.pause()
        assert "visible" in app.query_one("#search-bar").classes
        # Toggle search off
        app.action_toggle_search()
        await pilot.pause()
        assert "visible" not in app.query_one("#search-bar").classes

        # Test config viewer modal 'c'
        await pilot.press("c")
        await pilot.pause()
        assert isinstance(app.screen, ConfigViewerModal)
        await pilot.press("escape")
        await pilot.pause()

        # Test port finder modal 'f'
        await pilot.press("f")
        await pilot.pause()
        assert isinstance(app.screen, PortFinderModal)
        await pilot.press("escape")
        await pilot.pause()

        # Test alerts modal 'a'
        await pilot.press("a")
        await pilot.pause()
        assert isinstance(app.screen, AlertsModal)
        await pilot.press("escape")
        await pilot.pause()

        # Test export shortcut 'e'
        await pilot.press("e")
        await pilot.pause()
        reports = list(Path("audit-reports").glob("*.md"))
        assert len(reports) >= 1

        # Test key press 'r' for refresh
        await pilot.press("r")
        await pilot.pause()
        
        # Test key press 'q' for quit
        await pilot.press("q")

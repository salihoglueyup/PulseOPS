"""Telemetry is attacker-influenced (process names, log lines, domains, container names...).

Rendering it must never interpret it as Rich markup: a stray `[/]` would crash the TUI and a
`[link=...]` would plant a clickable link in the operator's terminal.
"""
from enum import Enum

import pytest
from pydantic import BaseModel
from rich.console import Console

from collectors.base import DemoCollector
from ui.app import ServerTUIApp
from ui.modals.alerts_modal import AlertsModal

EVIL_HOST = "evil.example"
PAYLOADS = ("[/]", f"[link=https://{EVIL_HOST}]x[/link]", "[bold red]")


def poison(value, payload):
    """Appends payload to every plain string inside models/lists, leaving enums and numbers alone."""
    if isinstance(value, Enum):
        return value
    if isinstance(value, str):
        return value + payload
    if isinstance(value, list):
        return [poison(v, payload) for v in value]
    if isinstance(value, tuple):
        return tuple(poison(v, payload) for v in value)
    if isinstance(value, BaseModel):
        for name in type(value).model_fields:
            setattr(value, name, poison(getattr(value, name), payload))
        return value
    return value


class HostileCollector(DemoCollector):
    def __init__(self, payload):
        super().__init__()
        self.payload = payload

    def poll(self):
        return tuple(poison(part, self.payload) for part in super().poll())

    def poll_backup_data(self):
        return poison(super().poll_backup_data(), self.payload)

    def poll_services(self):
        return poison(super().poll_services(), self.payload)

    def poll_databases(self, ports, containers):
        return poison(super().poll_databases(ports, containers), self.payload)

    def poll_security(self, ports):
        return poison(super().poll_security(ports), self.payload)

    def poll_storage(self):
        return poison(super().poll_storage(), self.payload)

    def poll_logs(self):
        return [f'1.2.3.4 - - "GET /{self.payload} HTTP/1.1" 404', f"kernel: {self.payload}"]


def assert_no_injected_links(renderable):
    console = Console(width=200, color_system="truecolor", file=open("/dev/null", "w"))
    for segment in console.render(renderable):
        link = segment.style.link if segment.style else None
        assert not (link and EVIL_HOST in link), f"injected link rendered: {link}"


TABS = ["tab-dashboard", "tab-processes", "tab-ports", "tab-services", "tab-databases",
        "tab-websites", "tab-backups", "tab-logs", "tab-security", "tab-storage"]


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", PAYLOADS)
async def test_hostile_telemetry_renders_safely(payload):
    app = ServerTUIApp(collector=HostileCollector(payload), poll_interval=60)
    async with app.run_test(size=(160, 50)) as pilot:
        await pilot.pause()
        app.log_viewer.logs = app.collector.poll_logs()
        for tab in TABS:
            app.query_one("#main-tabs").active = tab
            await pilot.pause()
        for widget in (app.header_bar, app.vitals_panel, app.alert_ticker, app.port_table, app.all_ports_table,
                       app.top_processes_panel, app.log_viewer, app.backup_panel, app.service_panel,
                       app.backup_detail_view, app.services_table, app.database_panel, app.security_panel,
                       app.storage_panel, app.dashboard_status_bar):
            assert_no_injected_links(widget.render())

        # The log tab must show the attacker's text literally
        log_plain = "".join(seg.text for seg in Console(width=300, file=open("/dev/null", "w")).render(app.log_viewer.render()))
        assert payload in log_plain

        await app.push_screen(AlertsModal(snapshot=app._last_snapshot, ports=app._last_ports,
                                          routes=app._last_routes, storage=app._last_storage))
        await pilot.pause()
        app.pop_screen()
        await pilot.pause()

        await pilot.press("f")  # port finder modal
        await pilot.pause()
        await pilot.press("escape")
        await pilot.pause()
    assert app.return_code in (None, 0), "app crashed while rendering hostile data"


RAW_TAG = __import__("re").compile(r"\[/?(bold|dim|italic|#[0-9a-fA-F]{6}|link)\b")


@pytest.mark.asyncio
async def test_normal_data_has_no_literal_markup_tags():
    """Regression guard for PlainTable: intended styling must not leak as raw `[bold]` text."""
    app = ServerTUIApp(collector=DemoCollector(), poll_interval=60)
    async with app.run_test(size=(160, 50)) as pilot:
        await pilot.pause()
        console = Console(width=200, file=open("/dev/null", "w"))
        for widget in (app.header_bar, app.vitals_panel, app.alert_ticker, app.port_table, app.all_ports_table,
                       app.top_processes_panel, app.log_viewer, app.backup_panel, app.service_panel,
                       app.backup_detail_view, app.services_table, app.database_panel, app.security_panel,
                       app.storage_panel, app.dashboard_status_bar):
            plain = "".join(seg.text for seg in console.render(widget.render()))
            match = RAW_TAG.search(plain)
            assert not match, f"{type(widget).__name__} shows raw markup: ...{plain[max(0, match.start()-40):match.end()+20]}..."

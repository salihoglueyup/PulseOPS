"""Telemetry is attacker-influenced (process names, log lines, domains, container names...).

Rendering it must never interpret it as Rich markup: a stray `[/]` would crash the TUI and a
`[link=...]` would plant a clickable link in the operator's terminal.
"""
from enum import Enum

import pytest
from pydantic import BaseModel
from rich.console import Console
from rich.text import Text

from collectors.base import DemoCollector
from conftest import settle
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
        await settle(pilot)
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

        t = app.telemetry
        await app.push_screen(AlertsModal(snapshot=t.snapshot, ports=t.ports, routes=t.routes, storage=t.storage))
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
        await settle(pilot)
        console = Console(width=200, file=open("/dev/null", "w"))
        for widget in (app.header_bar, app.vitals_panel, app.alert_ticker, app.port_table, app.all_ports_table,
                       app.top_processes_panel, app.log_viewer, app.backup_panel, app.service_panel,
                       app.backup_detail_view, app.services_table, app.database_panel, app.security_panel,
                       app.storage_panel, app.dashboard_status_bar):
            plain = "".join(seg.text for seg in console.render(widget.render()))
            match = RAW_TAG.search(plain)
            assert not match, f"{type(widget).__name__} shows raw markup: ...{plain[max(0, match.start()-40):match.end()+20]}..."


@pytest.mark.parametrize("payload", PAYLOADS)
def test_cli_status_and_report_are_safe(payload, tmp_path):
    from io import StringIO

    from collectors.audit_exporter import generate_audit_markdown
    from collectors.telemetry import collect_telemetry
    from commands import render_status

    t = collect_telemetry(HostileCollector(payload))
    t.security = poison(t.security, payload)
    out = StringIO()
    console = Console(file=out, width=200, color_system="truecolor", force_terminal=True)
    render_status(t, console)
    assert_no_injected_links(Text.from_ansi(out.getvalue()))
    assert payload in Text.from_ansi(out.getvalue()).plain  # shown literally

    md = generate_audit_markdown(t.snapshot, t.ports, t.routes, t.backups, t.containers,
                                 databases=t.databases, services=t.services, security=t.security, storage=t.storage)
    assert md


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", PAYLOADS)
async def test_history_views_are_safe(payload, tmp_path, monkeypatch, capsys):
    import cli
    from history import HistoryStore, host_key
    from ui.modals.history_modal import HistoryModal

    store = HistoryStore(tmp_path / "h.db")
    t = HostileCollector(payload).collect()
    t.snapshot.hostname = "web" + payload
    store.record_sample(t, 50, 1)
    store.detect_changes(t)
    evil = t.model_copy(deep=True)
    evil.security.access.login_users = ["root", "user" + payload]
    evil.security.access.uid0_users = ["root"]
    t.security.access.login_users = ["root"]
    t.security.access.uid0_users = ["root"]
    store.detect_changes(t)
    assert store.detect_changes(evil)

    modal = HistoryModal(store, host_key(t), t.snapshot.hostname)
    assert_no_injected_links(modal._build_content())
    plain = "".join(seg.text for seg in Console(width=200, file=open("/dev/null", "w")).render(modal._build_content()))
    assert "user" + payload in plain

    monkeypatch.setattr("history.default_history_path", lambda: tmp_path / "h.db")
    with pytest.raises(SystemExit):
        cli.main(["history", host_key(t)[:8]])
    assert "user" + payload in capsys.readouterr().out

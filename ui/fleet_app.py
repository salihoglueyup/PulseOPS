"""Fleet overview: one row per host, refreshed in background threads. Enter opens the host's full TUI."""
import time
from dataclasses import dataclass, field
from functools import partial
from typing import Callable, Optional

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.widgets import DataTable, Footer, Static

from collectors.audit_exporter import calculate_audit_score
from collectors.base import BaseCollector
from collectors.telemetry import summarize_alerts
from logging_setup import get_logger
from models.telemetry import Telemetry
from pulseops_config import Config
from ui.ascii_filter import AsciiFilter

log = get_logger("fleet")

STATE_STYLE = {"OK": "bold #3fb950", "WARNING": "bold #d29922", "CRITICAL": "bold #ffffff on #da3633",
               "UNKNOWN": "bold #8b949e", "BAĞLANIYOR": "#8b949e", "HATA": "bold #f85149"}
COLUMNS = ("Sunucu", "Hostname", "Durum", "Skor", "Uyarı", "CPU", "RAM", "Disk /", "Değişiklik 24s", "Güncelleme")


@dataclass
class FleetEntry:
    target: str
    collector: Optional[BaseCollector] = None
    telemetry: Optional[Telemetry] = None
    error: str = ""
    state: str = "BAĞLANIYOR"
    score: Optional[int] = None
    alerts: list[str] = field(default_factory=list)
    changes_24h: int = 0
    updated_at: float = 0.0
    polls: int = 0
    in_flight: bool = False


def state_for(score: int, config: Config, high_change: bool) -> str:
    if score < config.check.crit:
        state = "CRITICAL"
    elif score < config.check.warn:
        state = "WARNING"
    else:
        state = "OK"
    if high_change and state == "OK" and config.history.drift_exit != "none":
        state = "CRITICAL" if config.history.drift_exit == "critical" else "WARNING"
    return state


class FleetApp(App):
    TITLE = "PulseOps Filo"
    CSS = """
    Screen { background: #0d1117; }
    #fleet-title { height: 1; padding: 0 1; background: #161b22; color: #f0f6fc; }
    DataTable { height: 1fr; }
    """
    BINDINGS = [
        Binding("q", "quit", "Çıkış (q)"),
        Binding("r", "refresh_all", "Yenile (r)"),
        Binding("enter", "open_selected", "Aç (Enter)", show=True),
    ]

    def __init__(
        self,
        targets: list[str],
        connect: Callable[[str], BaseCollector],
        config: Config,
        history=None,
        interval: float = 15.0,
        slow_every: int = 4,
        ascii_mode: bool = False,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.entries = [FleetEntry(target=t) for t in targets]
        self.connect = connect
        self.config = config
        self.history = history
        self.interval = interval
        self.slow_every = max(slow_every, 1)
        self._ascii_filter = AsciiFilter() if ascii_mode else None

    def get_line_filters(self):
        filters = list(super().get_line_filters())
        if self._ascii_filter is not None:
            filters.append(self._ascii_filter)
        return filters

    def notify(self, message, *, markup: bool = False, **kwargs):
        return super().notify(message, markup=markup, **kwargs)

    def compose(self) -> ComposeResult:
        yield Static(Text(f" ⚡ PULSEOPS FİLO · {len(self.entries)} sunucu · Enter: sunucuyu aç", style="bold"),
                     id="fleet-title")
        yield DataTable(cursor_type="row", zebra_stripes=True)
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        for col in COLUMNS:
            table.add_column(col, key=col)
        for entry in self.entries:
            table.add_row(*self._cells(entry), key=entry.target)
        for entry in self.entries:
            self.run_worker(partial(self._connect_in_thread, entry), thread=True, group="connect", exit_on_error=False)
        self.set_interval(self.interval, self.poll_all)

    # --- background work --------------------------------------------------------------------------

    def _connect_in_thread(self, entry: FleetEntry) -> None:
        try:
            collector = self.connect(entry.target)
        except Exception as e:
            log.warning("%s bağlanamadı: %s", entry.target, e)
            self.call_from_thread(self._set_error, entry, str(e))
            return
        if hasattr(collector, "defer_updates"):
            collector.defer_updates = True
        entry.collector = collector
        self._poll_in_thread(entry, include_slow=True)

    def poll_all(self, force_slow: bool = False) -> None:
        for entry in self.entries:
            if entry.collector is None or entry.in_flight:
                continue
            entry.in_flight = True
            include_slow = force_slow or entry.polls % self.slow_every == 0
            self.run_worker(partial(self._poll_in_thread, entry, include_slow), thread=True, group="poll",
                            exit_on_error=False)

    def _poll_in_thread(self, entry: FleetEntry, include_slow: bool) -> None:
        entry.in_flight = True
        try:
            t = entry.collector.collect(include_slow=include_slow, include_logs=False)
        except Exception as e:
            log.warning("%s toplanamadı: %s", entry.target, e)
            entry.in_flight = False
            self.call_from_thread(self._set_error, entry, str(e))
            return
        score, _ = calculate_audit_score(t.snapshot, t.ports, t.routes, security=t.security, storage=t.storage)
        alerts = summarize_alerts(t, self.config.alerts)
        changes_24h, high_change = 0, False
        if self.history is not None:
            from history import host_key
            try:
                if include_slow:
                    self.history.detect_changes(t)
                self.history.record_sample(t, score, len(alerts))
                recent = [c for c in self.history.changes(host_key(t), since=time.time() - 86400) if c.severity != "INFO"]
                changes_24h = len(recent)
                high_change = any(c.severity == "HIGH" for c in recent)
            except Exception:
                log.exception("Geçmiş kaydedilemedi: %s", entry.target)
        entry.polls += 1
        entry.in_flight = False
        self.call_from_thread(self._set_result, entry, t, score, alerts, changes_24h, high_change)

    # --- UI updates (main thread) -----------------------------------------------------------------

    def _set_error(self, entry: FleetEntry, message: str) -> None:
        entry.error, entry.state = message, "HATA"
        self._refresh_row(entry)

    def _set_result(self, entry, t, score, alerts, changes_24h, high_change) -> None:
        entry.telemetry, entry.score, entry.alerts = t, score, alerts
        entry.changes_24h, entry.error, entry.updated_at = changes_24h, "", time.time()
        entry.state = state_for(score, self.config, high_change)
        self._refresh_row(entry)

    def _refresh_row(self, entry: FleetEntry) -> None:
        table = self.query_one(DataTable)
        for col, value in zip(COLUMNS, self._cells(entry)):
            table.update_cell(entry.target, col, value)

    @staticmethod
    def _cells(entry: FleetEntry) -> list:
        state = Text(entry.state, style=STATE_STYLE.get(entry.state, ""))
        if entry.telemetry is None:
            detail = Text(entry.error[:70], style="#f85149") if entry.error else Text("…", style="#8b949e")
            return [Text(entry.target), detail, state, "-", "-", "-", "-", "-", "-", "-"]
        s = entry.telemetry.snapshot
        root = next((d for d in s.disks if d.mountpoint == "/"), s.disks[0] if s.disks else None)
        age = int(time.time() - entry.updated_at)
        stale = Text(f"{age} sn önce" + (" ⚠" if entry.error else ""), style="#f85149" if entry.error else "#8b949e")
        return [
            Text(entry.target),
            Text(s.hostname),
            state,
            Text(str(entry.score)),
            Text(str(len(entry.alerts)), style="bold #d29922" if entry.alerts else "#8b949e"),
            Text(f"%{s.cpu.total_percent:.0f}"),
            Text(f"%{s.memory.percent:.0f}"),
            Text(f"%{root.percent:.0f}" if root else "-"),
            Text(str(entry.changes_24h), style="bold #f85149" if entry.changes_24h else "#8b949e"),
            stale,
        ]

    # --- actions ----------------------------------------------------------------------------------

    def action_refresh_all(self) -> None:
        self.poll_all(force_slow=True)
        self.notify("Tüm sunucular yenileniyor...", timeout=1.5)

    def action_open_selected(self) -> None:
        table = self.query_one(DataTable)
        if not self.entries:
            return
        self.exit(self.entries[table.cursor_row].target)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        self.exit(str(event.row_key.value))

    def on_unmount(self) -> None:
        for entry in self.entries:
            if entry.collector is not None:
                try:
                    entry.collector.close()
                except Exception:
                    pass

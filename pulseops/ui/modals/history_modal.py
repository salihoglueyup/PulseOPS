import time

from rich.console import Group
from rich.panel import Panel
from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import VerticalScroll
from textual.screen import ModalScreen
from textual.widget import Widget

from pulseops.ui.safe import PlainTable as Table
from pulseops.ui.widgets.sparkline import render_sparkline

SEVERITY_STYLE = {"HIGH": "bold #f85149", "MEDIUM": "bold #d29922", "INFO": "#8b949e"}
SEVERITY_LABEL = {"HIGH": "YÜKSEK", "MEDIUM": "ORTA", "INFO": "BİLGİ"}


def _fmt(ts: float) -> str:
    return time.strftime("%m-%d %H:%M", time.localtime(ts))


class _RenderableView(Widget):
    """Shows a prebuilt Rich renderable (Textual's Static expects its own content types)."""

    DEFAULT_CSS = "_RenderableView { height: auto; }"

    def __init__(self, renderable, **kwargs):
        super().__init__(**kwargs)
        self._content_renderable = renderable

    def render(self):
        return self._content_renderable


class HistoryModal(ModalScreen):
    """24h metric trends and the security change feed for the observed machine."""

    BINDINGS = [Binding("escape", "dismiss", "Kapat"), Binding("h", "dismiss", "Kapat")]

    DEFAULT_CSS = """
    HistoryModal { align: center middle; }
    #history-dialog { width: 92%; height: 90%; border: round #30363d; background: #0d1117; padding: 0 1; }
    """

    def __init__(self, store, host_id: str, hostname: str, **kwargs):
        super().__init__(**kwargs)
        self.store = store
        self.host_id = host_id
        self.hostname = hostname

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="history-dialog"):
            yield _RenderableView(self._build_content())

    def _build_content(self):
        now = time.time()
        try:
            samples = self.store.samples(self.host_id, now - 86400)
            changes = self.store.changes(self.host_id, since=now - 7 * 86400, limit=200)
        except Exception as e:  # unreadable/locked database must not break the TUI
            return Panel(Text(f"Geçmiş okunamadı: {e}", style="#f85149"), title="GEÇMİŞ")

        trends = Table(expand=True, box=None, padding=(0, 1), header_style="bold #f0f6fc")
        for col, justify in (("METRİK", "left"), ("SON 24 SAAT", "left"), ("MİN", "right"), ("ORT", "right"),
                             ("MAKS", "right"), ("SON", "right")):
            trends.add_column(col, justify=justify)
        if samples:
            for label, attr, top in (("CPU %", "cpu", 100.0), ("RAM %", "mem", 100.0), ("Disk / %", "disk_root", 100.0),
                                     ("Load", "load1", None), ("Sağlık skoru", "score", 100.0), ("Uyarı", "alerts", None)):
                values = [float(getattr(s, attr)) for s in samples]
                hi = top if top is not None else max(max(values), 1.0)
                trends.add_row(label, Text(render_sparkline(values, 0.0, hi, width=60), style="#58a6ff"),
                               f"{min(values):.1f}", f"{sum(values) / len(values):.1f}", f"{max(values):.1f}",
                               f"{values[-1]:.1f}")
            caption = f"{len(samples)} örnek · {_fmt(samples[0].ts)} → {_fmt(samples[-1].ts)}"
        else:
            caption = "Henüz örnek yok; PulseOps açıkken dakikada bir kaydedilir (cron ile `pulseops check` de ekler)."

        feed = Table(expand=True, box=None, padding=(0, 1), header_style="bold #f0f6fc")
        feed.add_column("ZAMAN", width=12)
        feed.add_column("ÖNEM", width=8)
        feed.add_column("DEĞİŞİKLİK", ratio=1)
        for c in changes:
            style = SEVERITY_STYLE.get(c.severity, "#f0f6fc")
            feed.add_row(_fmt(c.ts), Text(SEVERITY_LABEL.get(c.severity, c.severity), style=style),
                         Text(c.message, style=style if c.severity != "INFO" else "#c9d1d9"))
        if not changes:
            feed.add_row("-", "-", Text("Son 7 günde güvenlik değişikliği yok.", style="#3fb950"))

        return Panel(
            Group(
                Panel(Group(Text(caption, style="#8b949e"), trends), border_style="#30363d",
                      title=Text(f"TRENDLER · {self.hostname}", style="bold #f0f6fc")),
                Panel(feed, border_style="#30363d", title=Text("GÜVENLİK DEĞİŞİKLİKLERİ (SON 7 GÜN)", style="bold #f0f6fc")),
            ),
            title=Text("GEÇMİŞ & DEĞİŞİKLİK TESPİTİ · ESC ile kapat", style="bold #f0f6fc"),
            border_style="#30363d",
            padding=(0, 0),
        )

from textual.screen import ModalScreen
from textual.app import ComposeResult
from textual.containers import Vertical, Horizontal
from textual.widgets import Static, Button, Input, Label
from textual.binding import Binding
from rich.panel import Panel
from rich.text import Text
from pulseops.ui.safe import PlainTable as Table

from pulseops.models.ports import ListeningPort
from pulseops.collectors.port_finder import find_available_ports

class PortFinderModal(ModalScreen):
    """Corporate modal dialog suggesting free/available ports with developer stack presets in Clean Minimalist Silver & Charcoal."""

    BINDINGS = [
        Binding("escape", "dismiss", "Kapat"),
    ]

    def __init__(self, ports: list[ListeningPort], **kwargs):
        super().__init__(**kwargs)
        self.ports = ports
        self.start_port = 3000
        self.end_port = 3020

    def compose(self) -> ComposeResult:
        with Vertical(id="port-finder-dialog"):
            yield Static("[bold #f0f6fc]BOŞ PORT BULUCU & ÇAKIŞMA ÖNLEYİCİ[/bold #f0f6fc]\n", id="pf-title")
            with Horizontal(id="pf-presets"):
                yield Button("React/Next (3000)", id="preset-react", classes="preset-btn")
                yield Button("FastAPI (8000)", id="preset-python", classes="preset-btn")
                yield Button("NestJS (4000)", id="preset-node", classes="preset-btn")
                yield Button("Flask (5000)", id="preset-flask", classes="preset-btn")
                yield Button("DB (5432/3306)", id="preset-db", classes="preset-btn")

            with Horizontal(id="pf-inputs"):
                yield Label("Başlangıç: ", classes="pf-label")
                yield Input(value=str(self.start_port), id="input-start", classes="pf-input")
                yield Label(" Bitiş: ", classes="pf-label")
                yield Input(value=str(self.end_port), id="input-end", classes="pf-input")
                yield Button("Tara", id="btn-scan", variant="primary")
            
            yield Static(id="pf-results")
            with Horizontal(id="pf-buttons"):
                yield Button("Kapat (ESC)", id="btn-close", variant="default")

    def on_mount(self) -> None:
        self._update_results()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id
        if btn_id == "btn-scan":
            self._apply_inputs_and_scan()
        elif btn_id == "preset-react":
            self._apply_range(3000, 3020)
        elif btn_id == "preset-python":
            self._apply_range(8000, 8020)
        elif btn_id == "preset-node":
            self._apply_range(4000, 4020)
        elif btn_id == "preset-flask":
            self._apply_range(5000, 5020)
        elif btn_id == "preset-db":
            self._apply_range(3306, 6380)
        elif btn_id == "btn-close":
            self.dismiss()

    def _apply_range(self, start: int, end: int) -> None:
        self.start_port = start
        self.end_port = end
        inp_s = self.query_one("#input-start", Input)
        inp_e = self.query_one("#input-end", Input)
        inp_s.value = str(start)
        inp_e.value = str(end)
        self._update_results()

    def _apply_inputs_and_scan(self) -> None:
        try:
            s = int(self.query_one("#input-start", Input).value)
            e = int(self.query_one("#input-end", Input).value)
            self.start_port = max(1, min(65535, s))
            self.end_port = max(self.start_port, min(65535, e))
            self._update_results()
        except ValueError:
            pass

    def _update_results(self) -> None:
        free_ports = find_available_ports(
            self.ports,
            start_port=self.start_port,
            end_port=self.end_port,
            limit=6,
            verify_socket=False
        )

        busy_ports = [
            p for p in self.ports
            if self.start_port <= p.port <= self.end_port
        ]

        table = Table(expand=True, box=None)
        table.add_column("DURUM", justify="center", ratio=1)
        table.add_column("PORT", style="bold #f0f6fc", justify="right", ratio=1)
        table.add_column("SERVİS / SÜREÇ", style="bold #58a6ff", ratio=2)
        table.add_column("AÇIKLAMA", style="#8b949e", ratio=3)

        for bp in busy_ports:
            proc = bp.process_name or "Bilinmeyen Süreç"
            svc = bp.service_name or "Aktif Servis"
            pid_str = f"PID: {bp.pid}" if bp.pid else "PID: ?"
            table.add_row(
                Text("DOLU ✗", style="bold #f85149"),
                f":{bp.port}",
                svc,
                f"{proc} ({pid_str}) tarafından kullanılıyor"
            )

        for fp in free_ports:
            table.add_row(
                Text("BOŞ ✓", style="bold #3fb950"),
                f":{fp}",
                "[bold #3fb950]Kullanılabilir[/bold #3fb950]",
                "Yeni servis veya backend için boş ve kullanıma hazır"
            )

        res_widget = self.query_one("#pf-results", Static)
        res_widget.update(Panel(
            table,
            title=f"[bold #f0f6fc]{self.start_port} - {self.end_port} Port Aralığı Analizi ({len(free_ports)} Boş, {len(busy_ports)} Dolu)[/bold #f0f6fc]",
            border_style="#30363d"
        ))

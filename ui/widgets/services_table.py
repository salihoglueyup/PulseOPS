from textual.widget import Widget
from textual.reactive import reactive
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from models.services import ServiceUnit, ServiceState

class ServicesTable(Widget):
    """Widget listing systemd units / OS services with status and enabled state in Clean Minimalist Silver & White."""

    services: reactive[list[ServiceUnit]] = reactive(list)

    def render(self) -> Panel:
        table = Table(expand=True, box=None, padding=(0, 1))
        table.add_column("SERVİS BİRİMİ", style="bold #f0f6fc", ratio=2)
        table.add_column("TANIM / İŞLEV", style="#c9d1d9", ratio=3)
        table.add_column("DURUM", justify="center", ratio=2)
        table.add_column("BAŞLANGIÇ", justify="center", ratio=2)

        if not self.services:
            table.add_row(
                Text("Servis bilgisi yükleniyor...", style="#6e7681"),
                "-", "-", "-"
            )
        else:
            for s in self.services:
                status_text = Text()
                if s.state == ServiceState.RUNNING:
                    status_text.append("● RUNNING", style="bold #3fb950")
                elif s.state == ServiceState.FAILED:
                    status_text.append(" ● FAILED ", style="bold #ffffff on #da3633")
                elif s.state == ServiceState.STOPPED:
                    status_text.append("○ STOPPED", style="#6e7681")
                else:
                    status_text.append("BİLİNMİYOR", style="#484f58")

                en_style = "bold #3fb950" if s.enabled in ("enabled", "static") else "#6e7681"
                en_text = Text(s.enabled.upper(), style=en_style)

                table.add_row(
                    s.name,
                    s.display_name or s.description or "-",
                    status_text,
                    en_text
                )

        return Panel(
            table,
            title="[bold #f0f6fc]SİSTEM SERVİSLERİ (SYSTEM SERVICES & SYSTEMCTL)[/bold #f0f6fc]",
            border_style="#30363d",
            padding=(0, 0),
        )

from textual.widget import Widget
from textual.reactive import reactive
from rich.panel import Panel
from ui.safe import PlainTable as Table
from rich.text import Text

from models.docker import ContainerSummary

class ServicePanel(Widget):
    """Corporate widget displaying Docker containers and service status in Clean Minimalist Silver & White style."""

    containers: reactive[list[ContainerSummary]] = reactive(list)

    def render(self) -> Panel:
        table = Table(expand=True, box=None, padding=(0, 1))
        table.add_column("KONTEYNER", style="bold #f0f6fc", ratio=3)
        table.add_column("İMAJ", style="#8b949e", ratio=3)
        table.add_column("PORT EŞLEMESİ", style="#c9d1d9", ratio=3)
        table.add_column("DURUM", justify="center", ratio=2)

        if not self.containers:
            table.add_row(
                Text("Docker konteyneri bulunamadı (veya servis kapalı)", style="#6e7681"),
                "-", "-", "-"
            )
        else:
            for c in self.containers:
                ports_str = ", ".join(c.ports) if c.ports else "Dahili"
                status_text = Text()
                if c.is_running:
                    status_text.append("● ÇALIŞIYOR", style="bold #3fb950")
                else:
                    status_text.append("○ DURDU", style="#6e7681")

                table.add_row(
                    c.name,
                    c.image,
                    ports_str,
                    status_text
                )

        return Panel(
            table,
            title="[bold #f0f6fc]DOCKER KONTEYNERLERİ & SAĞLIK[/bold #f0f6fc]",
            border_style="#30363d",
            padding=(0, 0),
        )

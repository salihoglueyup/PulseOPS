from textual.widget import Widget
from textual.reactive import reactive
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from models.database import DatabaseInstance

class DatabasePanel(Widget):
    """Widget displaying detected databases, ports, isolation security, and metrics in Clean Minimalist Silver & White."""

    databases: reactive[list[DatabaseInstance]] = reactive(list)

    def render(self) -> Panel:
        table = Table(expand=True, box=None, padding=(0, 1))
        table.add_column("VERİTABANI MOTORU", style="bold #f0f6fc", ratio=3)
        table.add_column("PORT", justify="center", style="bold #f0f6fc", ratio=1)
        table.add_column("DURUM", justify="center", ratio=2)
        table.add_column("DİNLENEN IP (BIND)", style="#c9d1d9", ratio=2)
        table.add_column("GÜVENLİK İZOLASYONU", justify="center", ratio=2)
        table.add_column("ÇALIŞMA ORTAMI", style="#8b949e", ratio=2)
        table.add_column("METRİK / DETAY", style="#6e7681", ratio=3)

        if not self.databases:
            table.add_row(
                Text("Sunucuda aktif veritabanı tespit edilmedi", style="#6e7681"),
                "-", "-", "-", "-", "-", "-"
            )
        else:
            for db in self.databases:
                status_text = Text.from_markup(db.badge)
                sec_text = Text.from_markup(db.security_badge)

                table.add_row(
                    f"{db.engine} ({db.version})",
                    f":{db.port}",
                    status_text,
                    f"{db.bind_ip}:{db.port}",
                    sec_text,
                    db.managed_by,
                    db.metric_summary or "-"
                )

        return Panel(
            table,
            title="[bold #f0f6fc]VERİTABANI MOTORLARI & GÜVENLİK İZOLASYONU[/bold #f0f6fc]",
            border_style="#30363d",
            padding=(0, 0),
        )

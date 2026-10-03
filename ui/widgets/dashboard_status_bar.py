from textual.widget import Widget
from textual.reactive import reactive
from rich.panel import Panel
from rich.text import Text

class DashboardStatusBar(Widget):
    """Bottom status strip on the Dashboard summarizing infrastructure counts and quick actions in Minimalist Silver style."""

    docker_count: reactive[int] = reactive(0)
    websites_count: reactive[int] = reactive(0)
    db_count: reactive[int] = reactive(0)
    ssl_warnings: reactive[int] = reactive(0)
    alerts_count: reactive[int] = reactive(0)

    def render(self) -> Panel:
        t = Text(justify="center")

        t.append("PulseOps  ", style="bold #f0f6fc")
        t.append("│  Docker: ", style="#30363d")
        t.append(f"{self.docker_count}  │  ", style="bold #f0f6fc")

        t.append("Siteler: ", style="#8b949e")
        t.append(f"{self.websites_count}  │  ", style="bold #f0f6fc")

        t.append("Veritabanı: ", style="#8b949e")
        t.append(f"{self.db_count}  │  ", style="bold #f0f6fc")

        ssl_val_style = "bold #f85149" if self.ssl_warnings > 0 else "bold #3fb950"
        t.append("SSL: ", style="#8b949e")
        t.append(f"{self.ssl_warnings} Uyarı" if self.ssl_warnings > 0 else "Normal ✓", style=ssl_val_style)
        t.append("  │  ", style="#30363d")

        alert_val_style = "bold #f85149" if self.alerts_count > 0 else "bold #3fb950"
        t.append("Alarmlar: ", style="#8b949e")
        t.append(f"{self.alerts_count} Alarm" if self.alerts_count > 0 else "Temiz ✓", style=alert_val_style)

        t.append("   │   ", style="#30363d")
        t.append("[F] Port Bul  ", style="bold #f0f6fc")
        t.append("[C] Config  ", style="bold #f0f6fc")
        t.append("[A] Alarmlar  ", style="bold #f0f6fc")
        t.append("[E] Rapor Al", style="bold #f0f6fc")

        return Panel(t, style="on #161b22", border_style="#30363d", padding=(0, 1))

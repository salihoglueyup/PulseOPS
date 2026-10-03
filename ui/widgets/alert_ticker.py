from textual.widget import Widget
from textual.reactive import reactive
from rich.panel import Panel
from rich.text import Text

class AlertTicker(Widget):
    """Corporate smart incident ticker banner on the Dashboard in Minimalist Silver style."""

    alerts_count: reactive[int] = reactive(0)
    alert_snippet: reactive[str] = reactive("")

    def render(self) -> Panel:
        t = Text(justify="center")

        if self.alerts_count == 0:
            t.append("● TÜM SİSTEMLER NORMAL (0 Aktif Alarm) ✓", style="bold #3fb950")
            t.append("   │   ", style="#30363d")
            t.append("Güvenlik Duvarı: Aktif", style="#8b949e")
            t.append("  •  ", style="#30363d")
            t.append("Yedekler: Güncel", style="#8b949e")
            t.append("  •  ", style="#30363d")
            t.append("SSL: Güvenli", style="#8b949e")
            border_style = "#30363d"
        else:
            t.append("⚠ AKTİF ALARMLAR ", style="bold #ffffff on #da3633")
            t.append(f" ({self.alerts_count}): ", style="bold #f85149")
            
            snippet = self.alert_snippet or "Sistemde dikkat gerektiren unsurlar mevcut"
            t.append(snippet, style="bold #f0f6fc")
            t.append("   │   ", style="#30363d")
            t.append("İncelemek için [A] tuşuna basın veya tıklayın", style="#d29922")
            border_style = "#d29922" if self.alerts_count <= 2 else "#da3633"

        return Panel(
            t,
            style="on #161b22",
            border_style=border_style,
            padding=(0, 1),
        )

    def on_click(self) -> None:
        if hasattr(self.app, "action_show_alerts"):
            self.app.action_show_alerts()

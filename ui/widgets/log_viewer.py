from textual.widget import Widget
from textual.reactive import reactive
from rich.panel import Panel
from rich.text import Text

class LogViewerWidget(Widget):
    """Widget displaying recent streaming log events in Clean Minimalist Silver & White style."""

    logs: reactive[list[str]] = reactive(list)

    def render(self) -> Panel:
        if not self.logs:
            content = Text("Henüz log akışı yok. Yeni istekler bekleniyor...", style="#6e7681")
        else:
            content = Text.from_markup("\n".join(self.logs))

        return Panel(
            content,
            title="[bold #f0f6fc]CANLI ERİŞİM VE SİSTEM LOGLARI (LIVE STREAM)[/bold #f0f6fc]",
            border_style="#30363d",
            padding=(0, 1),
        )

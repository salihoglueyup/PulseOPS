from textual.widget import Widget
from textual.reactive import reactive
from rich.panel import Panel
from rich.text import Text

# Log lines are untrusted plain text; they are highlighted here with regexes, never parsed as markup.
HIGHLIGHTS = [
    (r"\b\d{2}:\d{2}:\d{2}\b", "#6f737a"),
    (r"\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b", "bold #589df6"),
    (r"(?<=\s)[23]\d{2}(?=\s)", "#57a773"),
    (r"(?<=\s)[45]\d{2}(?=\s)", "bold #e05353"),
    (r"(?i)\b(error|err|fail(ed|ure)?|critical|crit|emerg|alert|denied|refused)\b", "bold #e05353"),
    (r"(?i)\b(warn(ing)?)\b", "bold #d29922"),
]


def highlight_log_line(line: str) -> Text:
    text = Text(line, style="#dfe1e5")
    for pattern, style in HIGHLIGHTS:
        text.highlight_regex(pattern, style)
    return text


class LogViewerWidget(Widget):
    """Widget displaying recent streaming log events in Clean Minimalist Silver & White style."""

    logs: reactive[list[str]] = reactive(list)

    def render(self) -> Panel:
        if not self.logs:
            content = Text("Henüz log akışı yok. Yeni istekler bekleniyor...", style="#6e7681")
        else:
            content = Text("\n").join(highlight_log_line(line) for line in self.logs)

        return Panel(
            content,
            title="[bold #f0f6fc]CANLI ERİŞİM VE SİSTEM LOGLARI (LIVE STREAM)[/bold #f0f6fc]",
            border_style="#30363d",
            padding=(0, 1),
        )

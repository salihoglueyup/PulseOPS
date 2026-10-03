import time
from textual.widget import Widget
from textual.reactive import reactive
from rich.text import Text

class HeaderBar(Widget):
    """Clean corporate top status bar showing server identity, OS, uptime, alerts, and live clock in Minimalist Silver style."""

    hostname = reactive("Sunucu")
    os_name = reactive("Linux")
    kernel = reactive("")
    uptime_str = reactive("0m")
    alerts_count = reactive(0)
    user_label = reactive("")
    access_limited = reactive(False)
    theme_name = reactive("Silver Minimal")
    current_time = reactive("")

    def on_mount(self) -> None:
        self.set_interval(1.0, self._update_clock)
        self._update_clock()

    def _update_clock(self) -> None:
        self.current_time = time.strftime("%H:%M:%S")

    def render(self) -> Text:
        t = Text()
        t.append(" ⚡ PULSEOPS ", style="bold #0d1117 on #f0f6fc")
        t.append(" ", style="")
        t.append("● LIVE", style="bold #3fb950")
        t.append(" │ ", style="#30363d")
        t.append(f"{self.hostname} ", style="bold #f0f6fc")
        t.append("│ ", style="#30363d")
        t.append(f"{self.os_name} ", style="bold #c9d1d9")
        if self.kernel:
            t.append(f"({self.kernel}) ", style="#6e7681")
        t.append("│ ", style="#30363d")
        if self.user_label:
            if self.access_limited:
                t.append(f"{self.user_label} (kısıtlı) ", style="bold #d29922")
            else:
                t.append(f"{self.user_label} ", style="#8b949e")
            t.append("│ ", style="#30363d")
        t.append("Uptime: ", style="#8b949e")
        t.append(f"{self.uptime_str} ", style="bold #f0f6fc")
        t.append("│ ", style="#30363d")

        if self.alerts_count > 0:
            t.append(f" ⚠ {self.alerts_count} UYARI (a) ", style="bold #ffffff on #da3633")
            t.append(" │ ", style="#30363d")
        else:
            t.append("✓ Normal ", style="bold #3fb950")
            t.append("│ ", style="#30363d")

        t.append(f"Tema: {self.theme_name} ", style="#6e7681")
        t.append("│ ", style="#30363d")
        t.append(f"{self.current_time} ", style="bold #c9d1d9")
        return t

from textual.widget import Widget
from textual.reactive import reactive
from rich.panel import Panel
from pulseops.ui.safe import PlainTable as Table
from rich.text import Text

from pulseops.models.system import ProcessInfo

class TopProcessesPanel(Widget):
    """Corporate widget displaying the top resource-consuming processes by RAM and CPU in Clean Minimalist Silver & White."""

    processes: reactive[list[ProcessInfo]] = reactive(list)

    def render(self) -> Panel:
        table = Table(expand=True, box=None, padding=(0, 1))
        table.add_column("PID", style="#6e7681", justify="right", ratio=1)
        table.add_column("PROSES ADI", style="bold #f0f6fc", ratio=3)
        table.add_column("KULLANICI", style="#8b949e", ratio=2)
        table.add_column("CPU %", justify="right", style="bold #f0f6fc", ratio=2)
        table.add_column("BELLEK (RAM)", justify="right", style="#c9d1d9", ratio=2)

        if not self.processes:
            table.add_row("-", "Süreç bilgisi yükleniyor...", "-", "-", "-")
        else:
            for p in self.processes:
                if p.cpu_percent > 50.0:
                    cpu_style = "bold #f85149"
                elif p.cpu_percent > 15.0:
                    cpu_style = "bold #d29922"
                elif p.cpu_percent > 0.0:
                    cpu_style = "bold #3fb950"
                else:
                    cpu_style = "#6e7681"

                cpu_text = f"{p.cpu_percent:.1f}%"

                if p.memory_mb >= 1024.0:
                    mem_text = f"{p.memory_mb / 1024.0:.2f} GB ({p.memory_percent:.1f}%)"
                else:
                    mem_text = f"{p.memory_mb:.1f} MB ({p.memory_percent:.1f}%)"

                mem_style = "bold #f85149" if p.memory_percent > 25.0 else ("bold #d29922" if p.memory_percent > 10.0 else "#c9d1d9")

                raw_user = p.username.split("\\")[-1] if p.username else ""
                username = raw_user or "SYSTEM"

                table.add_row(
                    str(p.pid),
                    p.name,
                    username,
                    Text(cpu_text, style=cpu_style),
                    Text(mem_text, style=mem_style),
                )

        return Panel(
            table,
            title="[bold #f0f6fc]EN ÇOK KAYNAK TÜKETEN SÜREÇLER (TOP PROCESSES)[/bold #f0f6fc] [dim #8b949e]• Canlı CPU & Bellek Tüketimi[/dim #8b949e]",
            border_style="#30363d",
            padding=(0, 0),
        )

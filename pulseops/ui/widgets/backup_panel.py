from textual.widget import Widget
from textual.reactive import reactive
from rich.panel import Panel
from pulseops.ui.safe import PlainTable as Table
from rich.text import Text

from pulseops.models.backup import BackupTask, BackupStatus

class BackupPanel(Widget):
    """Corporate widget displaying backup timers, cron schedules, and last execution status in Clean Minimalist Silver & White style."""

    tasks: reactive[list[BackupTask]] = reactive(list)

    def render(self) -> Panel:
        table = Table(expand=True, box=None, padding=(0, 1))
        table.add_column("YEDEKLEME GÖREVİ", style="bold #f0f6fc", ratio=3)
        table.add_column("TÜR", style="#8b949e", ratio=2)
        table.add_column("PLAN", style="#f0f6fc", ratio=2)
        table.add_column("SON ÇALIŞMA", style="#c9d1d9", ratio=3)
        table.add_column("DURUM", justify="center", ratio=2)

        if not self.tasks:
            table.add_row(
                Text("Aktif yedekleme zamanlayıcısı bulunamadı", style="#6e7681"),
                "-", "-", "-", "-"
            )
        else:
            for t in self.tasks:
                status_text = Text()
                if t.status == BackupStatus.SUCCESS:
                    status_text.append("BAŞARILI ✓", style="bold #3fb950")
                elif t.status == BackupStatus.FAILED:
                    status_text.append(" HATA ALDI ✗ ", style="bold #ffffff on #da3633")
                elif t.status == BackupStatus.RUNNING:
                    status_text.append("ÇALIŞIYOR...", style="bold #d29922")
                else:
                    status_text.append("BİLİNMİYOR", style="#6e7681")

                table.add_row(
                    t.name,
                    t.mechanism,
                    t.schedule,
                    t.last_run or "Kayıt yok",
                    status_text
                )

        return Panel(
            table,
            title="[bold #f0f6fc]YEDEKLEME SİSTEMİ DURUMU (BACKUP TASKS)[/bold #f0f6fc]",
            border_style="#30363d",
            padding=(0, 0),
        )

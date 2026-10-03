from collections import deque
from textual.widget import Widget
from textual.reactive import reactive
from rich.panel import Panel
from ui.safe import PlainTable as Table
from rich.text import Text

from models.system import SystemSnapshot
from ui.widgets.sparkline import render_sparkline

class VitalsPanel(Widget):
    """Corporate panel displaying CPU load, RAM/Swap usage, Disks, Network traffic, and Top Processes in Clean Minimalist Silver & White style."""

    snapshot: reactive[SystemSnapshot | None] = reactive(None)
    health_score: reactive[int] = reactive(100)
    health_grade: reactive[str] = reactive("A+ (MÜKEMMEL)")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.cpu_history: deque[float] = deque(maxlen=30)
        self.net_rx_history: deque[float] = deque(maxlen=30)

    def watch_snapshot(self, new_val: SystemSnapshot | None) -> None:
        if new_val:
            self.cpu_history.append(new_val.cpu.total_percent)
            if new_val.network:
                self.net_rx_history.append(new_val.network[0].rx_bytes_sec / (1024 * 1024))
        self.refresh()

    def _format_disk_capacity(self, used_gb: float, total_gb: float) -> str:
        """Formats disk capacity intelligently (e.g. recognizing 1 TB, 512 GB, 256 GB SSDs)."""
        if 900 <= total_gb <= 1050:
            return f"({used_gb:.0f}G / 1 TB)"
        elif 1800 <= total_gb <= 2100:
            return f"({used_gb / 1024:.1f}T / 2 TB)"
        elif 450 <= total_gb <= 525:
            return f"({used_gb:.0f}G / 512G)"
        elif 220 <= total_gb <= 260:
            return f"({used_gb:.0f}G / 256G)"
        elif total_gb >= 1000:
            return f"({used_gb / 1024:.1f}T / {total_gb / 1024:.1f}T)"
        return f"({used_gb:.0f}/{total_gb:.0f}G)"

    def _render_bar(self, percent: float, width: int = 14) -> Text:
        filled = int((percent / 100.0) * width)
        filled = max(0, min(width, filled))
        empty = width - filled
        
        style = "#3fb950"
        if percent > 85:
            style = "bold #f85149"
        elif percent > 65:
            style = "bold #d29922"
            
        t = Text()
        t.append("█" * filled, style=style)
        t.append("░" * empty, style="#21262d")
        return t

    def render(self) -> Panel:
        health_style = "bold #3fb950" if self.health_score >= 80 else ("bold #d29922" if self.health_score >= 60 else "bold #f85149")
        grade_badge = self.health_grade.split()[0] if self.health_grade else "A+"
        title = (
            f"[bold #f0f6fc]SİSTEM DONANIMI & KAYNAK TÜKETİMİ[/bold #f0f6fc]   "
            f"[#30363d]│[/#30363d]   SAĞLIK: [{health_style}]{self.health_score}/100 [{grade_badge}][/{health_style}]"
        )

        if not self.snapshot:
            return Panel(
                Text("Sistem verileri yükleniyor...", style="#8b949e"),
                title=title,
                border_style="#30363d"
            )

        snap = self.snapshot
        vitals_grid = Table.grid(expand=True)
        vitals_grid.add_column("CPU", ratio=3)
        vitals_grid.add_column("RAM", ratio=3)
        vitals_grid.add_column("DİSK", ratio=2)
        vitals_grid.add_column("AĞ", ratio=2)

        # 1. CPU Section
        cpu_text = Text()
        cpu_text.append("CPU: ", style="bold #8b949e")
        cpu_text.append(f"{snap.cpu.total_percent:.1f}% ", style="bold #f0f6fc")
        cpu_text.append(f"({snap.cpu.cores} Çekirdek)\n", style="#6e7681")
        cpu_text.append_text(self._render_bar(snap.cpu.total_percent, 16))
        cpu_text.append("\n")
        
        spark = render_sparkline(self.cpu_history, 0.0, 100.0, width=16)
        cpu_text.append("Trend: ", style="#8b949e")
        cpu_text.append(f"{spark}\n", style="#c9d1d9")
        
        l1, l5, l15 = snap.cpu.load_avg
        if l1 == 0.0 and l5 == 0.0 and l15 == 0.0:
            proc_cnt = len(snap.top_processes) if snap.top_processes else 0
            cpu_text.append(f"İşlemler: {proc_cnt}+ aktif süreç", style="#6e7681")
        else:
            cpu_text.append(f"Load: {l1:.2f} {l5:.2f} {l15:.2f}", style="#6e7681")

        # 2. RAM & Swap Section
        ram_text = Text()
        ram_text.append("RAM: ", style="bold #8b949e")
        ram_text.append(f"{snap.memory.percent:.1f}% ", style="bold #f0f6fc")
        ram_text.append(f"({snap.memory.used_gb:.1f}/{snap.memory.total_gb:.1f} GB)\n", style="#6e7681")
        ram_text.append_text(self._render_bar(snap.memory.percent, 16))
        ram_text.append("\n")
        
        ram_text.append("SWAP: ", style="#6e7681")
        ram_text.append(f"{snap.memory.swap_percent:.1f}% ", style="#8b949e")
        ram_text.append_text(self._render_bar(snap.memory.swap_percent, 10))

        # 3. Disks Section
        disk_text = Text()
        disk_text.append("DİSKLER & I/O:\n", style="bold #8b949e")
        for d in snap.disks[:2]:
            disk_text.append(f"{d.mountpoint}: ", style="bold #f0f6fc")
            d_style = "bold #f85149" if d.percent > 85 else ("bold #d29922" if d.percent > 75 else "#3fb950")
            disk_text.append(f"{d.percent:.0f}% ", style=d_style)
            cap_str = self._format_disk_capacity(d.used_gb, d.total_gb)
            disk_text.append(f"{cap_str}\n", style="#6e7681")
            disk_text.append_text(self._render_bar(d.percent, 12))
            disk_text.append("\n")
        disk_text.append(f"Okuma: {snap.disk_io.read_human}  ", style="#8b949e")
        disk_text.append(f"Yazma: {snap.disk_io.write_human}", style="#8b949e")

        # 4. Network Section
        net_text = Text()
        net_text.append("AĞ & GÜVENLİK:\n", style="bold #8b949e")
        if snap.network:
            for n in snap.network[:1]:
                net_text.append(f"{n.interface}: ", style="bold #f0f6fc")
                net_text.append(f"↓ {n.rx_human} ", style="bold #3fb950")
                net_text.append(f"↑ {n.tx_human}\n", style="#c9d1d9")
        
        net_spark = render_sparkline(self.net_rx_history, 0.0, 50.0, width=14)
        net_text.append("Trend: ", style="#8b949e")
        net_text.append(f"{net_spark}\n", style="#c9d1d9")

        if not snap.firewall.known:
            fw_status, fw_style = "Güvenlik Duvarı: BİLİNMİYOR (root gerekli)", "bold #d29922"
        elif snap.firewall.is_active:
            fw_status, fw_style = "Güvenlik Duvarı: AKTİF ✓", "bold #3fb950"
        else:
            fw_status, fw_style = "Güvenlik Duvarı: KAPALI ✗", "bold #f85149"
        net_text.append(f"{fw_status}", style=fw_style)

        vitals_grid.add_row(cpu_text, ram_text, disk_text, net_text)

        outer_table = Table.grid(expand=True)
        outer_table.add_row(vitals_grid)

        # Top processes summary preview row
        if snap.top_processes:
            proc_text = Text()
            proc_text.append("\nEn Çok Tüketen Süreçler: ", style="bold #8b949e")
            top_3 = snap.top_processes[:3]
            for idx, p in enumerate(top_3):
                proc_text.append(f"#{idx+1} ", style="#6e7681")
                proc_text.append(f"{p.name} ", style="bold #f0f6fc")
                proc_text.append(f"({p.cpu_percent:.1f}% CPU, {p.memory_percent:.1f}% RAM)", style="#8b949e")
                if idx < len(top_3) - 1:
                    proc_text.append("  •  ", style="#30363d")
            outer_table.add_row(proc_text)

        return Panel(
            outer_table,
            title=title,
            border_style="#30363d",
            padding=(0, 1),
        )

from textual.screen import ModalScreen
from textual.app import ComposeResult
from textual.containers import Vertical, Horizontal
from textual.widgets import Static, Button
from textual.binding import Binding
from rich.panel import Panel
from ui.safe import PlainTable as Table
from rich.text import Text

from typing import Optional
from models.system import SystemSnapshot
from models.ports import ListeningPort, PortExposure
from models.proxy import ProxyRoute
from models.storage import StorageOverview

class AlertsModal(ModalScreen):
    """Corporate modal displaying detected system risks, expiring SSLs, and port exposure warnings in Clean Minimalist Silver & White."""

    BINDINGS = [
        Binding("escape", "dismiss", "Kapat"),
    ]

    def __init__(
        self,
        snapshot: SystemSnapshot,
        ports: list[ListeningPort],
        routes: list[ProxyRoute],
        storage: Optional[StorageOverview] = None,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.snapshot = snapshot
        self.ports = ports
        self.routes = routes
        self.storage = storage

    def compose(self) -> ComposeResult:
        with Vertical(id="alerts-dialog"):
            yield Static("[bold #f0f6fc]SİSTEM UYARILARI & RİSK ANALİZİ[/bold #f0f6fc]\n", id="alerts-title")
            yield Static(id="alerts-content")
            with Horizontal(id="alerts-buttons"):
                yield Button("Kapat (ESC)", id="btn-close", variant="primary")

    def on_mount(self) -> None:
        table = Table(expand=True, box=None)
        table.add_column("SEVİYE", justify="center", ratio=1)
        table.add_column("BİLEŞEN", style="bold #f0f6fc", ratio=2)
        table.add_column("SORUN & TEHLİKE", style="#f0f6fc", ratio=4)
        table.add_column("ÖNERİLEN ÇÖZÜM", style="#8b949e", ratio=3)

        alerts_count = 0

        # 1. Exposed database ports
        for p in self.ports:
            if p.exposure == PortExposure.EXPOSED_RISK:
                alerts_count += 1
                table.add_row(
                    Text("KRİTİK", style="bold #ffffff on #da3633"),
                    f"Port :{p.port}",
                    f"{p.process_name or 'Servis'} 0.0.0.0 üzerinde dış dünyaya açık!",
                    "UFW veya bind ayarını 127.0.0.1 yapın"
                )

        # 2. SSL Expiration <= 7 days
        for r in self.routes:
            if r.is_ssl and r.ssl_days_left is not None and r.ssl_days_left <= 7:
                alerts_count += 1
                table.add_row(
                    Text("YÜKSEK", style="bold #f85149"),
                    f"SSL: {r.domain}",
                    f"Sertifikanın bitmesine yalnızca {r.ssl_days_left} gün kaldı!",
                    "certbot renew çalıştırın"
                )

        # 3. 502 / 504 Bad Gateway
        for r in self.routes:
            if r.http_status in (502, 504):
                alerts_count += 1
                table.add_row(
                    Text("HATA", style="bold #f85149"),
                    f"Web: {r.domain}",
                    f"{r.target_url} hedefine ulaşılamıyor (502 Bad Gateway)",
                    f"Arka plan uygulamasını ({r.target_process or 'servis'}) kontrol edin"
                )

        # 4. Disk usage > 80%
        for d in self.snapshot.disks:
            if d.percent > 80.0:
                alerts_count += 1
                table.add_row(
                    Text("UYARI", style="bold #d29922"),
                    f"Disk: {d.mountpoint}",
                    f"Disk doluluk oranı %{d.percent:.1f} seviyesinde!",
                    "Gereksiz log veya docker imajlarını temizleyin"
                )

        # 5. RAM usage > 85%
        if self.snapshot.memory.percent > 85.0:
            alerts_count += 1
            table.add_row(
                Text("UYARI", style="bold #d29922"),
                "RAM Bellek",
                f"Toplam bellek kullanımı %{self.snapshot.memory.percent:.1f}",
                "İlk 5 süreç sekmesinden bellek kullanımını inceleyin"
            )

        # 6. Firewall disabled
        if not self.snapshot.firewall.is_active:
            alerts_count += 1
            table.add_row(
                Text("KRİTİK", style="bold #ffffff on #da3633"),
                "Güvenlik Duvarı",
                "Güvenlik duvarı devre dışı bırakılmış!",
                "sudo ufw enable ile aktif edin"
            )

        # 7. BuildKit cache bloated (>10GB or excessive)
        if self.storage and self.storage.is_cache_bloated:
            alerts_count += 1
            table.add_row(
                Text("KRİTİK", style="bold #ffffff on #da3633"),
                "BuildKit Cache",
                f"BuildKit önbelleği aşırı büyümüş ({self.storage.buildkit_cache_human})!",
                "docker builder prune -f --keep-storage 10GB"
            )

        if alerts_count == 0:
            table.add_row(
                Text("NORMAL ✓", style="bold #3fb950"),
                "Sistem Sağlığı",
                "Herhangi bir kritik uyarı tespit edilmedi. Sistem stabil çalışıyor.",
                "Tüm kontroller başarılı"
            )

        content_widget = self.query_one("#alerts-content", Static)
        content_widget.update(Panel(
            table,
            title=f"[bold #f0f6fc]Aktif Uyarı Sayısı: {alerts_count}[/bold #f0f6fc]",
            border_style="#30363d"
        ))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-close":
            self.dismiss()

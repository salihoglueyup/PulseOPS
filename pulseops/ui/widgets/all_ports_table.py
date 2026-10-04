from textual.widget import Widget
from textual.reactive import reactive
from rich.panel import Panel
from pulseops.ui.safe import PlainTable as Table
from rich.text import Text

from pulseops.models.ports import ListeningPort, PortExposure

class AllPortsTable(Widget):
    """Corporate table listing all listening ports on the system with security exposure labels and service recognition in Clean Minimalist Silver & White."""

    ports: reactive[list[ListeningPort]] = reactive(list)
    filter_service_only: reactive[bool] = reactive(False)

    def toggle_filter(self) -> bool:
        """Toggle between showing only application/service ports (< 49152) and all ports."""
        self.filter_service_only = not self.filter_service_only
        return self.filter_service_only

    def render(self) -> Panel:
        table = Table(expand=True, box=None, padding=(0, 1))
        table.add_column("PORT", style="bold #f0f6fc", justify="right", ratio=1)
        table.add_column("PROTO", style="#6e7681", justify="center", ratio=1)
        table.add_column("DİNLENEN IP", style="#c9d1d9", ratio=2)
        table.add_column("SERVİS / İŞLEV", style="bold #58a6ff", ratio=3)
        table.add_column("PROSES (PID)", style="#c9d1d9", ratio=2)
        table.add_column("GÜVENLİK ANALİZİ", justify="center", ratio=3)

        if not self.ports:
            table.add_row("-", "-", "-", "Açık port tespit edilmedi", "-", "-")
            return Panel(
                table,
                title="[bold #f0f6fc]DİNLENEN PORTLAR & GÜVENLİK ANALİZİ[/bold #f0f6fc]",
                border_style="#30363d",
                padding=(0, 0),
            )

        total = len(self.ports)
        apps_count = sum(1 for p in self.ports if p.port < 49152)
        rpc_count = total - apps_count
        risks_count = sum(1 for p in self.ports if p.exposure == PortExposure.EXPOSED_RISK)

        displayed = [p for p in self.ports if p.port < 49152] if self.filter_service_only else self.ports

        for p in displayed:
            badge = Text()
            if p.exposure == PortExposure.SAFE_INTERNAL:
                badge.append("● Dahili (Localhost) ✓", style="bold #3fb950")
            elif p.exposure == PortExposure.LAN_ONLY:
                badge.append("● Yerel Ağ (LAN)", style="bold #58a6ff")
            elif p.exposure == PortExposure.PUBLIC_WEB:
                badge.append("● Standart Web (80/443)", style="bold #c9d1d9")
            elif p.exposure == PortExposure.ADMIN_SSH:
                badge.append("● Yönetim SSH (22)", style="bold #d29922")
            elif p.exposure == PortExposure.SYSTEM_RPC:
                badge.append("○ Dinamik Sistem RPC", style="#6e7681")
            elif p.exposure == PortExposure.EXPOSED_GENERAL:
                badge.append("● Dışa Açık (0.0.0.0)", style="bold #e3b341")
            else:
                badge.append(" ⚠ DIŞ DÜNYAYA AÇIK! ", style="bold #ffffff on #da3633")

            proc_info = f"{p.process_name or 'Bilinmiyor'} ({p.pid})" if p.pid else (p.process_name or "-")
            service_desc = p.service_name or "Uygulama Servisi"

            table.add_row(
                f":{p.port}",
                p.proto.upper(),
                p.ip,
                service_desc,
                proc_info,
                badge
            )

        if self.filter_service_only:
            title_text = f"[bold #f0f6fc]DİNLENEN PORTLAR[/bold #f0f6fc] [dim #8b949e]• Yalnızca Uygulama/Servisler ({len(displayed)}/{total}) • Tümünü Görmek İçin 'p' Tuşuna Basın[/dim #8b949e]"
        else:
            title_text = f"[bold #f0f6fc]DİNLENEN TÜM SOKETLER[/bold #f0f6fc] [dim #8b949e]• Toplam: {total} • Uygulama: {apps_count} • Dinamik RPC: {rpc_count} • Risk: {risks_count} • Filtre ('p')[/dim #8b949e]"

        return Panel(
            table,
            title=title_text,
            border_style="#30363d",
            padding=(0, 0),
        )

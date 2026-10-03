from textual.widget import Widget
from textual.reactive import reactive
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from models.security import SecurityOverview

class SecurityPanel(Widget):
    """Widget displaying server security visibility, SSH posture, and firewall status in Clean Minimalist Silver & White."""

    security: reactive[SecurityOverview] = reactive(SecurityOverview)

    def render(self) -> Panel:
        sec = self.security
        ssh = sec.ssh

        grid = Table.grid(expand=True, padding=(0, 1))
        grid.add_column(ratio=1)

        # Top summary cards
        cards_table = Table(expand=True, box=None, padding=(0, 2))
        cards_table.add_column("SSH SERTLEŞTİRME", style="bold #f0f6fc", ratio=1)
        cards_table.add_column("GÜVENLİK DUVARI", style="bold #f0f6fc", ratio=1)
        cards_table.add_column("AÇIK PORT MARUZİYETİ", style="bold #f0f6fc", ratio=1)
        cards_table.add_column("GENEL POSTÜR", justify="center", style="bold #f0f6fc", ratio=1)

        # SSH card
        ssh_text = Text()
        if ssh.port == 0 or ssh.permit_root_login == "KAPALI":
            ssh_text.append("SSH Servisi: KAPALI\n", style="bold #3fb950")
            ssh_text.append("Port 22: Dinlenmiyor ✓\n", style="#8b949e")
            ssh_text.append("Dış Erişim: Yok (Güvenli)", style="bold #3fb950")
        else:
            ssh_text.append(f"Port: {ssh.port}\n", style="#f0f6fc")
            root_style = "bold #3fb950" if ssh.permit_root_login in ("no", "prohibit-password") else "bold #f85149"
            ssh_text.append(f"Root Girişi: {ssh.permit_root_login.upper()}\n", style=root_style)
            ssh_text.append(f"Pubkey Girişi: {ssh.pubkey_authentication.upper()}", style="bold #3fb950")

        # Firewall card
        fw_text = Text()
        fw_style = "bold #3fb950" if sec.firewall_active else "bold #f85149"
        fw_text.append(f"{sec.firewall_name}: {'AKTİF' if sec.firewall_active else 'KAPALI'}\n", style=fw_style)
        fw_text.append(f"Kurallar: {sec.firewall_rules_count} kural devrede", style="#8b949e")

        # Port card
        port_text = Text()
        port_text.append(f"Dinlenen Soket: {sec.open_ports_count}\n", style="#f0f6fc")
        db_risks = [p for p in sec.exposed_risky_ports if p in (3306, 5432, 6379, 27017, 9200, 11211)]
        if db_risks:
            port_text.append(f"Dışa Açık DB: {db_risks}\n", style="bold #f85149")
        else:
            port_text.append("Dışa Açık DB: Yok ✓\n", style="bold #3fb950")

        win_risks = [p for p in sec.exposed_risky_ports if p in (135, 139, 445)]
        if win_risks:
            port_text.append(f"Yerel RPC/SMB: {win_risks}", style="#d29922")
        else:
            port_text.append("Port Güvenliği: İyi ✓", style="#3fb950")

        # Overall badge
        overall_style = "bold #ffffff on #238636" if "GÜVENLİ" in sec.overall_status else "bold #ffffff on #d29922"
        badge = Text(f" {sec.overall_status} ", style=overall_style)

        cards_table.add_row(ssh_text, fw_text, port_text, badge)
        grid.add_row(Panel(cards_table, border_style="#30363d", padding=(0, 1)))

        # Bottom recommendations list
        rec_table = Table(expand=True, box=None, padding=(0, 1))
        rec_table.add_column("GÜVENLİK BULGUSU & İYİLEŞTİRME TAVSİYELERİ", style="#f0f6fc")

        for r in sec.recommendations:
            if "[GUVENLI]" in r or r.startswith("✓"):
                r_style = "bold #3fb950"
            elif "[DIKKAT]" in r or "AÇIK" in r.upper():
                r_style = "bold #f85149"
            elif "[UYARI]" in r:
                r_style = "bold #d29922"
            else:
                r_style = "#58a6ff"
            rec_table.add_row(Text(r, style=r_style))

        grid.add_row(Panel(
            rec_table,
            title="[bold #f0f6fc]DENETİM BULGULARI & TAVSİYELER[/bold #f0f6fc]",
            border_style="#30363d",
            padding=(0, 1)
        ))

        return Panel(
            grid,
            title="[bold #f0f6fc]SUNUCU GÜVENLİK DENETİMİ & SSH SERTLEŞTİRME[/bold #f0f6fc]",
            border_style="#30363d",
            padding=(0, 0),
        )

from textual.widget import Widget
from textual.reactive import reactive
from rich.panel import Panel
from ui.safe import PlainTable as Table
from rich.text import Text

from models.security import SecurityOverview

DIM = "#8b949e"
GOOD = "bold #3fb950"
WARN = "bold #d29922"
BAD = "bold #f85149"


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
        if not sec.firewall_known:
            fw_text.append(f"{sec.firewall_name}: BİLİNMİYOR\n", style="bold #d29922")
            fw_text.append("Okumak için root gerekli", style="#8b949e")
        else:
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
        grid.add_row(self._render_soc(sec))

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

    def _render_soc(self, sec: SecurityOverview) -> Panel:
        f2b, auth, access = sec.fail2ban, sec.auth, sec.access
        cards = Table(expand=True, box=None, padding=(0, 2))
        cards.add_column("FAIL2BAN", style="bold #f0f6fc", ratio=1)
        cards.add_column(Text(f"SSH GİRİŞLERİ ({auth.window or '-'})".upper()), style="bold #f0f6fc", ratio=1)
        cards.add_column("YETKİLİ HESAPLAR", style="bold #f0f6fc", ratio=1)

        f2b_text = Text()
        if not f2b.installed:
            f2b_text.append("Kurulu değil\n", style=WARN)
            f2b_text.append("SSH kaba kuvvet koruması yok", style=DIM)
        elif not f2b.known:
            f2b_text.append("Kurulu, durum okunamadı\n", style=WARN)
            f2b_text.append("Okumak için root gerekli", style=DIM)
        elif f2b.running is False:
            f2b_text.append("ÇALIŞMIYOR ✗", style=BAD)
        else:
            f2b_text.append(f"Aktif ✓  {len(f2b.jails)} jail\n", style=GOOD)
            f2b_text.append(f"Şu an engelli IP: {f2b.currently_banned}\n", style="#f0f6fc")
            f2b_text.append("SSH korunuyor ✓" if f2b.protecting_ssh else "sshd jail'i yok!", style=GOOD if f2b.protecting_ssh else WARN)

        auth_text = Text()
        if not auth.known:
            auth_text.append("Okunamadı\n", style=WARN)
            auth_text.append("root / sudo / systemd-journal grubu gerekli", style=DIM)
        else:
            auth_text.append(f"Başarısız: {auth.failed}  Geçersiz kullanıcı: {auth.invalid_user}\n",
                             style=BAD if auth.failed_total >= 100 and not f2b.protecting_ssh else "#f0f6fc")
            auth_text.append(f"Başarılı: {auth.accepted}", style="#f0f6fc")
            if auth.accepted_password:
                auth_text.append(f"  (şifreyle: {auth.accepted_password})", style=WARN)
            auth_text.append(f"\nKaynak: {auth.source}", style=DIM)

        acc_text = Text()
        if access.extra_uid0:
            acc_text.append(f"UID 0: {', '.join(access.extra_uid0)} ⚠\n", style=BAD)
        acc_text.append(f"sudo/wheel: {', '.join(access.admin_users) or '-'}\n", style="#f0f6fc")
        acc_text.append(f"Giriş yapabilen: {len(access.login_users)} hesap\n", style=DIM)
        if not access.sudoers_known:
            acc_text.append("NOPASSWD: bilinmiyor (root gerekli)", style=DIM)
        elif access.nopasswd_rules:
            acc_text.append(f"NOPASSWD kuralı: {len(access.nopasswd_rules)}", style=WARN)
        else:
            acc_text.append("NOPASSWD kuralı yok ✓", style=GOOD)
        cards.add_row(f2b_text, auth_text, acc_text)

        details = Table(expand=True, box=None, padding=(0, 2))
        details.add_column("EN ÇOK DENEYEN KAYNAKLAR", style="#f0f6fc", ratio=1)
        details.add_column("SON BAŞARILI GİRİŞLER", style="#f0f6fc", ratio=2)
        details.add_column("AUTHORIZED_KEYS", style="#f0f6fc", ratio=1)
        sources = Text("\n").join(
            Text(f"{item.value}  ×{item.count}", style="#f0f6fc") for item in auth.top_sources[:5]
        ) if auth.top_sources else Text("-", style=DIM)
        logins = Text("\n").join(
            Text(f"{e.time}  {e.user} ← {e.source}  [{e.method}]",
                 style=WARN if e.method == "password" else "#f0f6fc")
            for e in reversed(auth.recent_accepted[-5:])
        ) if auth.recent_accepted else Text("-", style=DIM)
        keys = Text("\n").join(
            Text(f"{user}: {count} anahtar", style="#f0f6fc") for user, count in sorted(access.authorized_keys.items())
        ) if access.authorized_keys else Text("bilinmiyor" if not access.keys_known else "-", style=DIM)
        details.add_row(sources, logins, keys)

        grid = Table.grid(expand=True)
        grid.add_column()
        grid.add_row(cards)
        grid.add_row(Text(""))
        grid.add_row(details)
        return Panel(grid, title="[bold #f0f6fc]ERİŞİM & SALDIRI GÖRÜNÜRLÜĞÜ (SOC)[/bold #f0f6fc]",
                     border_style="#30363d", padding=(0, 1))

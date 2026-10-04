from textual.widget import Widget
from textual.reactive import reactive
from rich.panel import Panel
from pulseops.ui.safe import PlainTable as Table
from rich.text import Text

from pulseops.models.docker import ContainerSummary
from pulseops.models.security import SecurityOverview

DIM = "#8b949e"
GOOD = "bold #3fb950"
WARN = "bold #d29922"
BAD = "bold #f85149"


class SecurityPanel(Widget):
    """Widget displaying server security visibility, SSH posture, and firewall status in Clean Minimalist Silver & White."""

    security: reactive[SecurityOverview] = reactive(SecurityOverview)
    containers: reactive[list[ContainerSummary]] = reactive(list)

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
        grid.add_row(self._render_hardening(sec))
        if self.containers:
            grid.add_row(self._render_containers())

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

    def _render_containers(self) -> Panel:
        inspected = [c for c in self.containers if c.security is not None]
        risky = [c for c in inspected if any(r.severity != "LOW" for r in c.security.risks)]
        title = f"[bold #f0f6fc]KONTEYNER GÜVENLİĞİ · {len(risky)}/{len(inspected)} RİSKLİ[/bold #f0f6fc]"
        if not inspected:
            return Panel(Text("Çalışan konteyner yok veya docker okunamadı (docker grubu / root gerekli).", style=DIM),
                         title=title, border_style="#30363d", padding=(0, 1))
        table = Table(expand=True, box=None, padding=(0, 1))
        table.add_column("KONTEYNER", ratio=2)
        table.add_column("KULLANICI", ratio=1)
        table.add_column("DURUM", ratio=1)
        table.add_column("BULGULAR", ratio=5)
        order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        for c in sorted(inspected, key=lambda c: min((order[r.severity] for r in c.security.risks), default=3)):
            s = c.security
            risks = sorted(s.risks, key=lambda r: order[r.severity])
            findings = Text()
            for i, r in enumerate(risks):
                findings.append(("; " if i else "") + r.text,
                                style=BAD if r.severity == "HIGH" else WARN if r.severity == "MEDIUM" else DIM)
            if not risks:
                findings.append("sorun yok ✓", style=GOOD)
            state = Text(s.health or "çalışıyor", style=BAD if s.health == "unhealthy" else "#f0f6fc")
            if s.restart_count:
                state.append(f" ↻{s.restart_count}", style=WARN if s.restart_count >= 5 else DIM)
            table.add_row(Text(c.name, style="#f0f6fc"), Text(s.user or "root", style=DIM), state, findings)
        return Panel(table, title=title, border_style="#30363d", padding=(0, 1))

    def _render_hardening(self, sec: SecurityOverview) -> Panel:
        hard = sec.hardening
        title = f"[bold #f0f6fc]SİSTEM SERTLEŞTİRME · {hard.summary.upper()}[/bold #f0f6fc]"
        if not hard.known:
            return Panel(Text("Sertleştirme denetimi bir sonraki ağır taramada gelecek.", style=DIM),
                         title=title, border_style="#30363d", padding=(0, 1))
        table = Table(expand=True, box=None, padding=(0, 1))
        table.add_column("", width=3)
        table.add_column("KONTROL", ratio=3)
        table.add_column("DEĞER", ratio=2)
        order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        for c in sorted(hard.checks, key=lambda c: (c.passed, order.get(c.severity, 3))):
            style = GOOD if c.passed else BAD if c.severity == "HIGH" else WARN if c.severity == "MEDIUM" else DIM
            table.add_row(Text("✓" if c.passed else "✗", style=style), Text(c.title, style="#f0f6fc"),
                          Text(c.detail, style=DIM))
        extra = Text(f"SUID/SGID (sistem dizinleri): {len(hard.suid_files)} dosya", style=DIM)
        if hard.suspicious_suid is None:
            extra.append("  ·  /tmp ve /home taraması için root gerekli", style=DIM)
        if hard.empty_password_users is None:
            extra.append("  ·  boş parola kontrolü için root gerekli", style=DIM)
        if hard.ip_forward:
            extra.append("  ·  IP yönlendirme açık (Docker/router için normal)", style=DIM)
        grid = Table.grid(expand=True)
        grid.add_column()
        grid.add_row(table)
        grid.add_row(extra)
        return Panel(grid, title=title, border_style="#30363d", padding=(0, 1))

    def _render_soc(self, sec: SecurityOverview) -> Panel:
        f2b, auth, access = sec.fail2ban, sec.auth, sec.access
        cards = Table(expand=True, box=None, padding=(0, 2))
        cards.add_column("FAIL2BAN", style="bold #f0f6fc", ratio=1)
        cards.add_column(Text(f"SSH GİRİŞLERİ ({auth.window or '-'})".upper()), style="bold #f0f6fc", ratio=1)
        cards.add_column("YETKİLİ HESAPLAR", style="bold #f0f6fc", ratio=1)
        cards.add_column("GÜNCELLEMELER", style="bold #f0f6fc", ratio=1)

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
        if access.sudo_rule_users:
            acc_text.append(f"sudoers kuralı: {', '.join(access.sudo_rule_users)}\n", style=WARN)
        acc_text.append(f"Giriş yapabilen: {len(access.login_users)} hesap\n", style=DIM)
        if not access.sudoers_known:
            acc_text.append("NOPASSWD: bilinmiyor (root gerekli)", style=DIM)
        elif access.nopasswd_rules:
            acc_text.append(f"NOPASSWD kuralı: {len(access.nopasswd_rules)}", style=WARN)
        else:
            acc_text.append("NOPASSWD kuralı yok ✓", style=GOOD)
        upd = sec.updates
        upd_text = Text()
        if not upd.manager or not upd.known or upd.manager == "none":
            upd_text.append(upd.summary.capitalize(), style=DIM)
        else:
            upd_text.append(f"Bekleyen: {upd.total}\n", style="#f0f6fc")
            if upd.security is None:
                upd_text.append("Güvenlik: bilinmiyor\n", style=DIM)
            elif upd.security:
                upd_text.append(f"Güvenlik: {upd.security} ⚠\n", style=BAD)
            else:
                upd_text.append("Güvenlik yaması yok ✓\n", style=GOOD)
            if upd.metadata_stale:
                upd_text.append(f"Listeler {upd.metadata_age_days:.0f} gün eski\n", style=WARN)
        if upd.reboot_required:
            upd_text.append("\nYENİDEN BAŞLATMA GEREKLİ", style=BAD)
        cards.add_row(f2b_text, auth_text, acc_text, upd_text)

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

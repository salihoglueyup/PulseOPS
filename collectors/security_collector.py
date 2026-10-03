import re
import shutil
import subprocess
from pathlib import Path
from models.system import FirewallStatus
from typing import Optional

from models.security import AccessAudit, AuthActivity, Fail2banStatus, SecurityOverview, SSHSecurityAudit
from models.ports import ListeningPort, PortExposure

class SecurityCollector:
    """Evaluates host security posture, SSH hardening, and firewall rules."""

    def parse_sshd_config_text(self, text: str) -> SSHSecurityAudit:
        """Parses sshd_config text or `sshd -T` output.

        Follows sshd semantics: the first value of a keyword wins, `Match` blocks are conditional and
        end the global section, and unset keywords take OpenSSH's defaults.
        """
        values: dict[str, str] = {}
        for line in text.splitlines():
            line_str = line.strip()
            if not line_str or line_str.startswith("#"):
                continue
            parts = line_str.split(maxsplit=1)
            key = parts[0].lower()
            if key == "match":
                break
            if len(parts) == 2 and key not in values:
                values[key] = parts[1].strip().strip('"').lower()

        port_value = values.get("port", "22")
        port = int(port_value) if port_value.isdigit() else 22
        root_login = values.get("permitrootlogin", "prohibit-password")
        if root_login == "without-password":  # deprecated alias, and what `sshd -T` prints
            root_login = "prohibit-password"
        pwd_auth = values.get("passwordauthentication", "yes")
        pubkey_auth = values.get("pubkeyauthentication", "yes")

        is_hardened = root_login in ("no", "prohibit-password") and pubkey_auth == "yes" and pwd_auth == "no"
        return SSHSecurityAudit(
            port=port,
            permit_root_login=root_login,
            password_authentication=pwd_auth,
            pubkey_authentication=pubkey_auth,
            is_hardened=is_hardened,
        )

    def collect_local(self, ports: list[ListeningPort]) -> SecurityOverview:
        # 1. SSH Config & Port Check
        sshd_path = Path("/etc/ssh/sshd_config")
        ssh_is_listening = any(p.port == 22 for p in ports)

        if sshd_path.exists():
            try:
                ssh_audit = self.parse_sshd_config_text(sshd_path.read_text(encoding="utf-8", errors="ignore"))
            except Exception:
                ssh_audit = SSHSecurityAudit()
        elif ssh_is_listening:
            ssh_audit = SSHSecurityAudit(port=22, permit_root_login="no", password_authentication="no", pubkey_authentication="yes")
        else:
            # Port 22 is closed / not installed (Windows or secured host)
            ssh_audit = SSHSecurityAudit(
                port=0,
                permit_root_login="KAPALI",
                password_authentication="KAPALI",
                pubkey_authentication="KAPALI",
                is_hardened=True
            )

        # 2. Firewall
        from collectors.firewall_collector import FirewallCollector
        firewall = FirewallCollector().collect()
        if shutil.which("ufw"):
            try:
                res = subprocess.run(["ufw", "status", "numbered"], capture_output=True, text=True, timeout=2)
                firewall.rules_count = len([l for l in res.stdout.splitlines() if re.match(r'^\s*\[\s*\d+\]', l)])
            except Exception:
                pass
        return self.build_overview(ssh_audit, firewall, ports)

    def build_overview(
        self,
        ssh_audit: SSHSecurityAudit,
        firewall: FirewallStatus,
        ports: list[ListeningPort],
        fail2ban: Optional[Fail2banStatus] = None,
        auth: Optional[AuthActivity] = None,
        access: Optional[AccessAudit] = None,
        failed_login_threshold: int = 100,
    ) -> SecurityOverview:
        """Combines SSH audit, firewall state, listening ports and access data into the security overview."""
        fail2ban = fail2ban or Fail2banStatus()
        auth = auth or AuthActivity()
        access = access or AccessAudit()
        fw_name = firewall.backend
        fw_active = firewall.is_active
        fw_known = firewall.known
        rules_count = firewall.rules_count

        # 3. Risky ports (Deduplicated)
        risky = sorted(list(set(p.port for p in ports if p.exposure == PortExposure.EXPOSED_RISK)))

        # 4. Recommendations
        recs = []
        if ssh_audit.port != 0:
            if ssh_audit.permit_root_login == "yes":
                recs.append("[UYARI] SSH: PermitRootLogin 'no' olarak ayarlanmali.")
            if ssh_audit.password_authentication == "yes":
                recs.append("[BILGI] SSH: Sifreli giris kapatilip yalnizca SSH anahtari (Pubkey) kullanilmali.")
        else:
            recs.append("[GUVENLI] SSH: Port 22 dinlenmiyor, makine disaridan uzaktan SSH saldirisina kapali.")

        if not fw_known:
            recs.append("[BILGI] Guvenlik duvari durumu okunamadi; tam denetim icin `sudo pulseops` ile calistirin.")
        elif not fw_active:
            recs.append("[DIKKAT] GUVENLIK DUVARI KAPALI! Guvenlik duvarini aktif edin.")
        else:
            recs.append(f"[GUVENLI] {fw_name} devrede ve ag trafigini filtreliyor ({rules_count} kural aktif).")

        db_risks = [p for p in risky if p in (3306, 5432, 6379, 27017, 9200, 11211)]
        win_risks = [p for p in risky if p in (135, 139, 445)]
        other_risks = [p for p in risky if p not in db_risks and p not in win_risks]

        if db_risks:
            recs.append(f"[DIKKAT] DISA ACIK VERITABANI: Port {db_risks} 0.0.0.0 uzerinden dinliyor, 127.0.0.1'e baglayin!")
        if win_risks:
            recs.append(f"[UYARI] WINDOWS RPC/SMB: Port {win_risks} dis aga acik. Guvenlik duvari ile yerel aga sinirlandirilmali.")
        if other_risks:
            recs.append(f"[UYARI] DISA ACIK RISKLI PORT: Port {other_risks} internete acik.")

        # Positive finding for safe internal databases
        safe_dbs = sorted(list(set(p.port for p in ports if p.port in (3306, 5432, 6379, 27017) and p.exposure == PortExposure.SAFE_INTERNAL)))
        if safe_dbs:
            recs.append(f"[GUVENLI] Dahili Veritabanlari: Port {safe_dbs} yalnizca 127.0.0.1 (Localhost) uzerinde guvenle calisiyor.")

        recs.extend(soc_recommendations(ssh_audit, fail2ban, auth, access, failed_login_threshold))

        if not recs:
            recs.append("[GUVENLI] Sunucu temel guvenlik kurallarina uygun ve sertlestirilmis durumda.")

        brute_force = auth.known and auth.failed_total >= failed_login_threshold and not fail2ban.protecting_ssh
        safe = ((fw_active or not fw_known) and not db_risks and ssh_audit.permit_root_login != "yes"
                and not access.extra_uid0 and not brute_force)
        overall = "GÜVENLİ" if safe else "DİKKAT GEREKTİRİYOR"

        return SecurityOverview(
            ssh=ssh_audit,
            firewall_name=fw_name,
            firewall_active=fw_active,
            firewall_known=fw_known,
            firewall_rules_count=rules_count,
            open_ports_count=len(ports),
            exposed_risky_ports=risky,
            overall_status=overall,
            recommendations=recs,
            fail2ban=fail2ban,
            auth=auth,
            access=access,
        )


def soc_recommendations(
    ssh_audit: SSHSecurityAudit,
    fail2ban: Fail2banStatus,
    auth: AuthActivity,
    access: AccessAudit,
    failed_login_threshold: int = 100,
) -> list[str]:
    recs = []
    for user in access.extra_uid0:
        recs.append(f"[DIKKAT] UID 0 olan root disi hesap: '{user}' tam root yetkisine sahip; taninmiyorsa hemen inceleyin!")

    if auth.known:
        if auth.failed_total >= failed_login_threshold:
            top = ", ".join(f"{s.value} ({s.count})" for s in auth.top_sources[:3])
            if fail2ban.protecting_ssh:
                recs.append(f"[BILGI] SSH: {auth.failed_total} basarisiz deneme ({auth.window}); fail2ban su an "
                            f"{fail2ban.currently_banned} IP'yi engelliyor. En cok deneyen: {top}")
            else:
                recs.append(f"[DIKKAT] SSH kaba kuvvet: {auth.failed_total} basarisiz deneme ({auth.window}) ve fail2ban SSH'i "
                            f"korumuyor. En cok deneyen: {top}. Oneri: fail2ban sshd jail'i ve yalnizca anahtarla giris.")
        if auth.accepted_password and ssh_audit.password_authentication != "no":
            recs.append(f"[UYARI] SSH: {auth.accepted_password} sifreyle basarili giris ({auth.window}). "
                        "Anahtar tabanli girise gecip PasswordAuthentication no yapin.")
    else:
        recs.append("[BILGI] SSH giris kayitlari okunamadi (root, sudo veya systemd-journal grubu gerekli).")

    if fail2ban.installed and fail2ban.running is False:
        recs.append("[UYARI] fail2ban kurulu ama calismiyor: sudo systemctl enable --now fail2ban")

    if access.nopasswd_rules:
        recs.append(f"[UYARI] sudoers: {len(access.nopasswd_rules)} NOPASSWD kurali var (parolasiz root yetkisi). "
                    "Gerekli olmayanlari kaldirin.")
    return recs

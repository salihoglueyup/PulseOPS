from typing import Optional

from pydantic import BaseModel, Field

class SSHSecurityAudit(BaseModel):
    port: int = 22
    permit_root_login: str = "no"       # "no", "yes", "prohibit-password"
    password_authentication: str = "no" # "no", "yes"
    pubkey_authentication: str = "yes"  # "yes", "no"
    is_hardened: bool = True

class Fail2banJail(BaseModel):
    name: str
    currently_failed: int = 0
    currently_banned: int = 0
    total_banned: int = 0
    banned_ips: list[str] = Field(default_factory=list)


class Fail2banStatus(BaseModel):
    installed: bool = False
    running: Optional[bool] = None  # None: could not be determined (needs root)
    known: bool = True
    jails: list[Fail2banJail] = Field(default_factory=list)

    @property
    def currently_banned(self) -> int:
        return sum(j.currently_banned for j in self.jails)

    @property
    def protecting_ssh(self) -> bool:
        return bool(self.running) and any("ssh" in j.name for j in self.jails)


class CountedItem(BaseModel):
    value: str
    count: int


class LoginEvent(BaseModel):
    time: str = ""
    method: str = ""
    user: str = ""
    source: str = ""


class AuthActivity(BaseModel):
    """SSH authentication events in a recent window (24h from the journal, or the tail of auth.log)."""

    known: bool = False
    source: str = ""          # "journal", "/var/log/auth.log", ...
    window: str = ""          # human readable window, e.g. "son 24 saat"
    failed: int = 0           # "Failed password/publickey" events
    invalid_user: int = 0     # "Invalid user" events
    accepted: int = 0
    accepted_password: int = 0
    top_sources: list[CountedItem] = Field(default_factory=list)
    top_users: list[CountedItem] = Field(default_factory=list)
    recent_accepted: list[LoginEvent] = Field(default_factory=list)

    @property
    def failed_total(self) -> int:
        return self.failed + self.invalid_user


class AccessAudit(BaseModel):
    """Who can log in and who holds root-equivalent rights."""

    uid0_users: list[str] = Field(default_factory=list)
    admin_users: list[str] = Field(default_factory=list)    # members of sudo / wheel / admin
    login_users: list[str] = Field(default_factory=list)    # accounts with a real login shell
    sudoers_known: bool = False
    nopasswd_rules: list[str] = Field(default_factory=list)
    # Users ("deploy") and groups ("%ops") granted rights by their own sudoers rule, outside sudo/wheel
    sudo_rule_users: list[str] = Field(default_factory=list)
    keys_known: bool = False
    authorized_keys: dict[str, int] = Field(default_factory=dict)
    authorized_keys_unknown: list[str] = Field(default_factory=list)  # home or ~/.ssh not readable

    @property
    def extra_uid0(self) -> list[str]:
        return [u for u in self.uid0_users if u != "root"]


class UpdateStatus(BaseModel):
    """Pending package updates (from existing metadata) and whether a reboot is needed."""

    manager: str = ""                       # apt, dnf, apk, none; "" = not collected
    known: bool = False                     # counts could be read
    total: int = 0
    security: Optional[int] = None          # None: the package manager cannot tell (apk)
    security_packages: list[str] = Field(default_factory=list)
    metadata_age_days: Optional[float] = None
    reboot_required: Optional[bool] = None  # None: cannot tell
    reboot_reason: str = ""
    running_kernel: str = ""

    @property
    def metadata_stale(self) -> bool:
        return self.metadata_age_days is not None and self.metadata_age_days > 7

    @property
    def summary(self) -> str:
        if not self.manager:
            return "kontrol ediliyor"
        if self.manager == "none":
            return "paket yöneticisi bulunamadı"
        if not self.known:
            return "okunamadı (paket önbelleği yok veya root gerekli)"
        sec = "güvenlik bilgisi yok" if self.security is None else f"{self.security} güvenlik"
        text = f"{self.total} bekliyor ({sec})"
        if self.metadata_stale:
            text += f", listeler {self.metadata_age_days:.0f} gün eski"
        return text


class SecurityOverview(BaseModel):
    ssh: SSHSecurityAudit = Field(default_factory=SSHSecurityAudit)
    firewall_name: str = "UFW"
    firewall_active: bool = True
    firewall_known: bool = True
    firewall_rules_count: int = 8
    open_ports_count: int = 0
    exposed_risky_ports: list[int] = Field(default_factory=list)
    overall_status: str = "GÜVENLİ ✓"
    recommendations: list[str] = Field(default_factory=list)
    fail2ban: Fail2banStatus = Field(default_factory=Fail2banStatus)
    auth: AuthActivity = Field(default_factory=AuthActivity)
    access: AccessAudit = Field(default_factory=AccessAudit)
    updates: UpdateStatus = Field(default_factory=UpdateStatus)

from pydantic import BaseModel, Field

class SSHSecurityAudit(BaseModel):
    port: int = 22
    permit_root_login: str = "no"       # "no", "yes", "prohibit-password"
    password_authentication: str = "no" # "no", "yes"
    pubkey_authentication: str = "yes"  # "yes", "no"
    is_hardened: bool = True

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

from pydantic import BaseModel


class PrivilegeInfo(BaseModel):
    """What the collecting user is allowed to see on the observed host."""

    user: str = "root"
    is_root: bool = True
    # True when privileged probes can run: root, or passwordless sudo where the collector uses `sudo -n`
    elevated: bool = True
    docker_installed: bool = False
    docker_access: bool = False

    @property
    def limitations(self) -> list[str]:
        items: list[str] = []
        if not self.elevated:
            items.append("Diğer kullanıcılara ait süreçlerin port sahipleri (ss -p) görünmez")
            items.append("Güvenlik duvarı (ufw/iptables) kuralları okunamayabilir")
            items.append("Sistem logları (journalctl) ve bazı yapılandırma dosyaları kısıtlı olabilir")
        if self.docker_installed and not self.docker_access:
            items.append("Docker konteyner ve depolama verileri okunamaz (docker grubu gerekli)")
        return items

    @property
    def hint(self) -> str:
        if not self.limitations:
            return ""
        if not self.elevated:
            return "Tam görünüm için `sudo pulseops` ile çalıştırın."
        return f"Docker verileri için: `sudo usermod -aG docker {self.user}` (yeniden giriş gerekir)."

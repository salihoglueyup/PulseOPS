import shutil
import platform
import subprocess
from models.system import FirewallStatus

class FirewallCollector:
    """Discovers firewall status (UFW on Linux, Windows Defender on Windows)."""

    def collect(self) -> FirewallStatus:
        # 1. Linux UFW
        if shutil.which("ufw"):
            try:
                res = subprocess.run(
                    ["ufw", "status"],
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                output = res.stdout.lower()
                if "status: active" in output:
                    return FirewallStatus(is_active=True, backend="UFW", summary="Aktif (Kurallar devrede)")
                elif "status: inactive" in output:
                    return FirewallStatus(is_active=False, backend="UFW", summary="DEVRE DIŞI! (Tüm portlar filtrelenmemiş)")
            except Exception:
                pass

        # 2. Windows Defender Firewall
        if platform.system() == "Windows":
            try:
                res = subprocess.run(
                    ["netsh", "advfirewall", "show", "currentprofile", "state"],
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                if "state" in res.stdout.lower() and "on" in res.stdout.lower():
                    return FirewallStatus(is_active=True, backend="Defender", summary="Windows Güvenlik Duvarı Aktif")
                elif "off" in res.stdout.lower():
                    return FirewallStatus(is_active=False, backend="Defender", summary="Windows Güvenlik Duvarı Kapalı!")
            except Exception:
                pass

        return FirewallStatus(is_active=True, backend="Standart", summary="Filtreleme Aktif")

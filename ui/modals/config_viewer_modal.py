from pathlib import Path
from textual.screen import ModalScreen
from textual.app import ComposeResult
from textual.containers import Vertical, Horizontal
from textual.widgets import Static, Button, TextArea
from textual.binding import Binding

SAMPLE_NGINX_CONF = """# /etc/nginx/nginx.conf [Örnek / Read-Only]
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 1024;
    multi_accept on;
}

http {
    sendfile on;
    tcp_nopush on;
    types_hash_max_size 2048;
    server_tokens off;

    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;

    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;

    gzip on;
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
"""

SAMPLE_SSHD_CONF = """# /etc/ssh/sshd_config [Örnek / Read-Only]
Port 22
Protocol 2
HostKey /etc/ssh/ssh_host_ed25519_key

# Kimlik Doğrulama Sertleştirme
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no

# Güvenlik & Oturum
X11Forwarding no
MaxAuthTries 4
ClientAliveInterval 300
ClientAliveCountMax 2
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
"""

class ConfigViewerModal(ModalScreen):
    """Modal allowing read-only inspection of critical server configuration files."""

    BINDINGS = [
        Binding("escape", "dismiss", "Kapat"),
        Binding("1", "load_nginx", "Nginx"),
        Binding("2", "load_sshd", "SSHD"),
    ]

    def __init__(self, nginx_content: Optional[str] = None, sshd_content: Optional[str] = None, **kwargs):
        super().__init__(**kwargs)
        self.nginx_content = nginx_content
        self.sshd_content = sshd_content
        self._is_live = bool(nginx_content or sshd_content)
        self._current_file = "/etc/nginx/nginx.conf"
        if self.nginx_content:
            self._content = self.nginx_content
        else:
            self._content = self._read_file("/etc/nginx/nginx.conf", SAMPLE_NGINX_CONF)

    def _read_file(self, file_path: str, fallback: str) -> str:
        p = Path(file_path)
        if p.exists() and p.is_file():
            try:
                return p.read_text(encoding="utf-8", errors="replace")
            except Exception as e:
                return f"# Dosya okunamadı: {e}"
        return fallback

    def compose(self) -> ComposeResult:
        tag = "[bold #3fb950]● CANLI SUNUCU[/bold #3fb950]" if self._is_live else "[#6e7681]○ ÖRNEK / YEREL[/#6e7681]"
        with Vertical(id="alerts-dialog"):
            yield Static(f"[bold #f0f6fc]YAPILANDIRMA GÖRÜNTÜLEYİCİ (CONFIG VIEWER)[/bold #f0f6fc] {tag}\n", id="alerts-title")
            with Horizontal(id="pf-inputs"):
                yield Button("1. Nginx Config", id="btn-conf-nginx", variant="primary")
                yield Button("2. SSHD Config", id="btn-conf-sshd", variant="default")
            yield TextArea(self._content, id="config-content", read_only=True)
            with Horizontal(id="alerts-buttons"):
                yield Button("Kapat (ESC)", id="btn-close", variant="primary")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-close":
            self.dismiss()
        elif event.button.id == "btn-conf-nginx":
            self.action_load_nginx()
        elif event.button.id == "btn-conf-sshd":
            self.action_load_sshd()

    def action_load_nginx(self) -> None:
        self._current_file = "/etc/nginx/nginx.conf"
        if self.nginx_content:
            content = self.nginx_content
        else:
            content = self._read_file("/etc/nginx/nginx.conf", SAMPLE_NGINX_CONF)
        ta = self.query_one("#config-content", TextArea)
        ta.text = content
        self.notify("Nginx konfigürasyonu yüklendi (Salt-Okunur)", title="Config Viewer")

    def action_load_sshd(self) -> None:
        self._current_file = "/etc/ssh/sshd_config"
        if self.sshd_content:
            content = self.sshd_content
        else:
            content = self._read_file("/etc/ssh/sshd_config", SAMPLE_SSHD_CONF)
        ta = self.query_one("#config-content", TextArea)
        ta.text = content
        self.notify("SSHD konfigürasyonu yüklendi (Salt-Okunur)", title="Config Viewer")

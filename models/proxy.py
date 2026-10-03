from pydantic import BaseModel

class ProxyRoute(BaseModel):
    domain: str
    listen_port: int = 80
    is_ssl: bool = False
    target_url: str
    target_port: int | None = None
    target_process: str | None = None
    ssl_days_left: int | None = None
    http_status: int | None = None
    response_time_ms: float | None = None
    status: str = "UP"

    @property
    def health_badge(self) -> str:
        if self.http_status is None:
            return "[#6e7681]Kontrol Edilmedi[/#6e7681]"
        if 200 <= self.http_status < 400:
            ms_str = f" ({self.response_time_ms:.0f}ms)" if self.response_time_ms is not None else ""
            return f"[bold #3fb950]✓ {self.http_status} OK{ms_str}[/bold #3fb950]"
        if self.http_status in (502, 504):
            return f"[bold #ffffff on #da3633] ⚠ {self.http_status} BAD GATEWAY [/bold #ffffff on #da3633]"
        return f"[bold #d29922]{self.http_status}[/bold #d29922]"

    @property
    def display_listen(self) -> str:
        if self.is_ssl:
            return f":{self.listen_port} (SSL)"
        return f":{self.listen_port}"

    @property
    def ssl_badge(self) -> str:
        if not self.is_ssl:
            return "[#6e7681]SSL Yok (HTTP)[/#6e7681]"
        if self.ssl_days_left is not None:
            if self.ssl_days_left <= 7:
                return f"[bold #ffffff on #da3633] ⚠ {self.ssl_days_left} gün! [/bold #ffffff on #da3633]"
            elif self.ssl_days_left <= 30:
                return f"[bold #d29922]{self.ssl_days_left} gün[/#d29922]"
            return f"[#3fb950]{self.ssl_days_left} gün ✓[/#3fb950]"
        return "[#3fb950]SSL Aktif ✓[/#3fb950]"

    @property
    def arrow_chain(self) -> str:
        proc_str = f" ({self.target_process})" if self.target_process else ""
        return f"{self.target_url}{proc_str}"

    @property
    def is_tcp(self) -> bool:
        return self.target_url.startswith("tcp://")

    @property
    def is_web(self) -> bool:
        return not self.is_tcp

    @property
    def is_issue(self) -> bool:
        if self.http_status in (500, 502, 503, 504, 404):
            return True
        if self.is_ssl and self.ssl_days_left is not None and self.ssl_days_left <= 7:
            return True
        return False

    @property
    def browser_url(self) -> str | None:
        if self.is_tcp:
            return None
        if self.domain.endswith(".docker") or self.domain.endswith(".local") or self.domain in ("localhost", "127.0.0.1"):
            proto = "https" if self.is_ssl else "http"
            return f"{proto}://127.0.0.1:{self.listen_port}"
        if "." in self.domain:
            proto = "https" if self.is_ssl else "http"
            port_part = f":{self.listen_port}" if (self.listen_port not in (80, 443)) else ""
            return f"{proto}://{self.domain}{port_part}"
        if self.target_url.startswith("http://") or self.target_url.startswith("https://"):
            return self.target_url
        return None

    @property
    def diagnostics_summary(self) -> str:
        if self.is_tcp:
            return "Doğrudan TCP soketi bağlantısı kuruldu. Veritabanı veya mesaj kuyruğu servisi aktif."
        if self.http_status in (502, 504):
            return (
                f"Hedef Port (:{self.listen_port}) dinleniyor ancak HTTP isteğinde yanıt dönmeden "
                f"bağlantı kesildi/sıfırlandı. Olası Neden: Docker konteynerindeki servis çöküyor veya henüz başlatılıyor."
            )
        if self.http_status == 404:
            return "Web sunucusu çalışıyor ancak kök yol (/) veya istenen endpoint bulunamadı (404 Not Found)."
        if self.http_status and 400 <= self.http_status < 500:
            return f"İstemci hatası tespit edildi ({self.http_status}). Servis yapılandırmasını kontrol edin."
        if self.http_status and 200 <= self.http_status < 400:
            ms_info = f"{self.response_time_ms:.1f}ms" if self.response_time_ms else "hızlı"
            return f"Servis sağlıklı ve erişilebilir ({self.http_status} OK, {ms_info})."
        return "Canlı sağlık kontrolü henüz tamamlanmadı."

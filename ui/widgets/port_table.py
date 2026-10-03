from typing import Optional
import webbrowser
from textual.widget import Widget
from textual.reactive import reactive
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from models.ports import ListeningPort, PortExposure
from models.proxy import ProxyRoute

FILTER_MODES = ["ALL", "WEB", "ISSUES", "SSL", "TCP"]

class PortProxyTable(Widget):
    """Corporate table: Correlates public domains with internal proxy ports, SSL days, and live HTTP health in Clean Minimalist Silver & White style."""

    routes: reactive[list[ProxyRoute]] = reactive(list)
    ports: reactive[list[ListeningPort]] = reactive(list)
    filter_query: reactive[str] = reactive("")
    filter_mode: reactive[str] = reactive("ALL")
    selected_index: reactive[int] = reactive(0)

    def _get_visible_routes(self) -> list[ProxyRoute]:
        # 1. Apply category / protocol filter
        routes = self.routes
        if self.filter_mode == "WEB":
            routes = [r for r in routes if r.is_web]
        elif self.filter_mode == "ISSUES":
            routes = [r for r in routes if r.is_issue]
        elif self.filter_mode == "SSL":
            routes = [r for r in routes if r.is_ssl]
        elif self.filter_mode == "TCP":
            routes = [r for r in routes if r.is_tcp]

        # 2. Apply search filter if active
        q = self.filter_query.strip().lower()
        if q:
            routes = [
                r for r in routes
                if q in r.domain.lower()
                or q in str(r.listen_port)
                or q in r.target_url.lower()
                or (r.target_process and q in r.target_process.lower())
            ]
        return routes

    def select_next(self) -> None:
        visible = self._get_visible_routes()
        if visible:
            self.selected_index = (self.selected_index + 1) % len(visible)

    def select_previous(self) -> None:
        visible = self._get_visible_routes()
        if visible:
            self.selected_index = (self.selected_index - 1) % len(visible)

    def cycle_filter(self) -> str:
        current_idx = FILTER_MODES.index(self.filter_mode) if self.filter_mode in FILTER_MODES else 0
        next_idx = (current_idx + 1) % len(FILTER_MODES)
        self.filter_mode = FILTER_MODES[next_idx]
        self.selected_index = 0
        return self.filter_mode

    def get_selected_route(self) -> Optional[ProxyRoute]:
        visible = self._get_visible_routes()
        if visible:
            idx = max(0, min(self.selected_index, len(visible) - 1))
            return visible[idx]
        return None

    def open_in_browser(self) -> tuple[bool, str]:
        r = self.get_selected_route()
        if not r:
            return False, "Seçili bir site rotası yok"
        url = r.browser_url
        if not url:
            return False, f"{r.domain} (:{r.listen_port}) bir TCP servisidir (web sayfası değildir)"
        try:
            webbrowser.open(url)
            return True, f"Tarayıcıda açıldı: {url}"
        except Exception as e:
            return False, f"Tarayıcı açılırken hata: {e}"

    def render(self) -> Panel:
        outer_grid = Table.grid(expand=True, padding=(0, 0))
        outer_grid.add_column(ratio=1)

        # 1. Calculate KPI Metrics
        total_routes = len(self.routes)
        web_count = sum(1 for r in self.routes if r.is_web)
        tcp_count = sum(1 for r in self.routes if r.is_tcp)
        ok_count = sum(1 for r in self.routes if r.http_status and 200 <= r.http_status < 400)
        bad_count = sum(1 for r in self.routes if r.http_status in (500, 502, 503, 504))
        ssl_count = sum(1 for r in self.routes if r.is_ssl)
        expiring_ssl = sum(1 for r in self.routes if r.is_ssl and r.ssl_days_left is not None and r.ssl_days_left <= 7)

        latencies = [r.response_time_ms for r in self.routes if r.response_time_ms is not None]
        avg_lat = sum(latencies) / len(latencies) if latencies else 0.0
        min_lat = min(latencies) if latencies else 0.0

        # Top summary cards (4 Columns)
        cards_table = Table(expand=True, box=None, padding=(0, 2))
        cards_table.add_column("SİTELER & SERVİSLER", style="bold #f0f6fc", ratio=1)
        cards_table.add_column("CANLI SAĞLIK (HTTP)", style="bold #f0f6fc", ratio=1)
        cards_table.add_column("SSL SERTİFİKA POSTÜRÜ", style="bold #f0f6fc", ratio=1)
        cards_table.add_column("YANIT SÜRESİ (LATENCY)", style="bold #f0f6fc", ratio=1)

        # Card 1: Siteler
        c1 = Text()
        c1.append(f"Toplam: {total_routes} Rota\n", style="bold #f0f6fc")
        c1.append(f"Web: {web_count}  •  TCP: {tcp_count}\n", style="#8b949e")
        c1.append(f"Filtre: [{self.filter_mode}]", style="bold #58a6ff")

        # Card 2: Canlı Sağlık
        c2 = Text()
        c2.append(f"✓ {ok_count} Sağlıklı (200 OK)\n", style="bold #3fb950")
        if bad_count > 0:
            c2.append(f"⚠ {bad_count} Hatalı / 502\n", style="bold #f85149")
        else:
            c2.append("Hatalı Servis: Yok ✓\n", style="bold #3fb950")
        ratio = (ok_count / total_routes * 100.0) if total_routes > 0 else 100.0
        ratio_style = "bold #3fb950" if ratio >= 90 else ("bold #d29922" if ratio >= 60 else "bold #f85149")
        c2.append(f"Erişilebilirlik: %{ratio:.0f}", style=ratio_style)

        # Card 3: SSL Postürü
        c3 = Text()
        if ssl_count > 0:
            c3.append(f"HTTPS: {ssl_count} Sertifikalı\n", style="bold #3fb950")
            if expiring_ssl > 0:
                c3.append(f"⚠ {expiring_ssl} Kritik (<7 Gün!)\n", style="bold #ffffff on #da3633")
            else:
                c3.append("Süre Aşımı: Yok ✓\n", style="bold #3fb950")
            c3.append("TLS Şifreleme Aktif", style="#3fb950")
        else:
            c3.append("SSL: Tanımlı Değil\n", style="#8b949e")
            c3.append("Yerel Geliştirme (HTTP)\n", style="#c9d1d9")
            c3.append("Dahili Ağ / Docker", style="#6e7681")

        # Card 4: Yanıt Süresi
        c4 = Text()
        c4.append(f"Ortalama: {avg_lat:.1f} ms\n", style="bold #f0f6fc")
        c4.append(f"En Hızlı: {min_lat:.1f} ms\n", style="#8b949e")
        lat_style = "bold #3fb950" if avg_lat < 50.0 else ("bold #d29922" if avg_lat < 200.0 else "bold #f85149")
        c4.append("Performans: Hızlı ✓" if avg_lat < 50.0 else "Performans: Normal", style=lat_style)

        cards_table.add_row(c1, c2, c3, c4)
        outer_grid.add_row(cards_table)
        outer_grid.add_row(Text("─" * 100, style="#30363d"))

        # 2. Filter Pills Bar
        filter_pills = Text()
        filter_pills.append(" Görünüm Filtresi: ", style="bold #8b949e")
        pill_defs = [
            ("ALL", f"TÜMÜ ({total_routes})"),
            ("WEB", f"WEB ({web_count})"),
            ("ISSUES", f"HATALI ({bad_count})"),
            ("SSL", f"SSL ({ssl_count})"),
            ("TCP", f"TCP ({tcp_count})"),
        ]
        for mode_key, label in pill_defs:
            if self.filter_mode == mode_key:
                filter_pills.append(f" [{label}] ", style="bold #ffffff on #238636")
            else:
                filter_pills.append(f" {label} ", style="#8b949e")
            filter_pills.append(" ")

        if self.filter_query.strip():
            filter_pills.append(f"  🔍 Filtre: '{self.filter_query.strip()}'", style="bold #d29922")

        outer_grid.add_row(filter_pills)
        outer_grid.add_row(Text(" "))

        # 3. Main Routes Table
        visible_routes = self._get_visible_routes()
        table = Table(expand=True, box=None, padding=(0, 1))
        table.add_column("", justify="center", width=2)
        table.add_column("ALAN ADI (DOMAIN)", style="bold #f0f6fc", ratio=3)
        table.add_column("PORT", justify="center", style="bold #f0f6fc", ratio=1)
        table.add_column("SSL DURUMU", justify="center", ratio=2)
        table.add_column("CANLI SAĞLIK", justify="center", ratio=2)
        table.add_column("PROXY HEDEFİ", style="#c9d1d9", ratio=3)
        table.add_column("SERVİS / KONTEYNER", style="#8b949e", ratio=3)
        table.add_column("İŞLEM", justify="center", ratio=2)

        if not visible_routes:
            if not self.routes:
                # Fallback to listening application ports
                app_ports = [
                    p for p in self.ports 
                    if p.process_name and p.port > 1000 and not p.process_name.lower().startswith("svchost")
                ]
                if app_ports:
                    for ap in app_ports:
                        safe_badge = Text(
                            "DAHİLİ ✓" if ap.exposure == PortExposure.SAFE_INTERNAL else "AÇIK", 
                            style="bold #3fb950" if ap.exposure == PortExposure.SAFE_INTERNAL else "bold #d29922"
                        )
                        table.add_row(
                            Text(" "),
                            f"Uygulama: {ap.process_name}",
                            Text(f":{ap.port}", style="bold #f0f6fc"),
                            Text("Yerel Soket", style="#6e7681"),
                            Text("● AKTİF", style="bold #3fb950"),
                            f"Bind: {ap.ip}:{ap.port}",
                            f"PID: {ap.pid or '-'}",
                            safe_badge
                        )
                else:
                    table.add_row(Text(" "), Text("Proxy yönlendirmesi tespit edilmedi", style="#6e7681"), "-", "-", "-", "-", "-", "-")
            else:
                msg = f"'{self.filter_mode}' filtresine uygun rota bulunamadı" if not self.filter_query else f"'{self.filter_query}' ile eşleşen rota bulunamadı"
                table.add_row(Text(" "), Text(msg, style="#6e7681"), "-", "-", "-", "-", "-", "-")
        else:
            # Ensure selected_index is within bounds
            if self.selected_index >= len(visible_routes):
                self.selected_index = max(0, len(visible_routes) - 1)

            for idx, r in enumerate(visible_routes):
                is_selected = (idx == self.selected_index)
                cursor = Text("►", style="bold #58a6ff") if is_selected else Text(" ")
                
                domain_style = "bold #58a6ff underline" if is_selected else "bold #f0f6fc"
                port_badge = Text(f":{r.listen_port}", style="bold #58a6ff" if is_selected else "bold #f0f6fc")
                ssl_markup = Text.from_markup(r.ssl_badge)
                health_markup = Text.from_markup(r.health_badge)
                target_str = f"──► {r.target_url}"
                proc_str = r.target_process or "Tespit Edilemedi"

                if r.is_web:
                    action_badge = Text("[Tarayıcı: Enter]", style="bold #58a6ff" if is_selected else "#8b949e")
                else:
                    action_badge = Text("[TCP Soket]", style="#6e7681")

                table.add_row(
                    cursor,
                    Text(r.domain, style=domain_style),
                    port_badge,
                    ssl_markup,
                    health_markup,
                    Text(target_str, style="#c9d1d9"),
                    Text(proc_str, style="#8b949e"),
                    action_badge
                )

        outer_grid.add_row(table)
        outer_grid.add_row(Text("─" * 100, style="#30363d"))

        # 4. Diagnostics & Selected Route Inspector
        selected_route = self.get_selected_route()
        diag_box = Table.grid(expand=True, padding=(0, 1))
        diag_box.add_column(ratio=1)

        diag_content = Text()
        if selected_route:
            if selected_route.http_status in (502, 504):
                diag_content.append(" ⚠ CANLI HATA TEŞHİSİ (502 BAD GATEWAY): ", style="bold #ffffff on #da3633")
                diag_content.append(f" {selected_route.diagnostics_summary}\n", style="bold #f85149")
                diag_content.append(f"   ↳ Hedef: {selected_route.target_url} • Upstream: {selected_route.target_process or '-'} • Çözüm: [8] Loglar sekmesinden çöküş kayıtlarını kontrol edin.", style="#c9d1d9")
            elif selected_route.http_status and selected_route.http_status >= 400:
                diag_content.append(f" ⚠ HTTP HATASI ({selected_route.http_status}): ", style="bold #ffffff on #d29922")
                diag_content.append(f" {selected_route.diagnostics_summary}\n", style="#d29922")
                diag_content.append(f"   ↳ Hedef: {selected_route.target_url} • Upstream: {selected_route.target_process or '-'}", style="#8b949e")
            elif selected_route.is_web:
                diag_content.append(" ✓ SEÇİLİ WEB ROTASI: ", style="bold #ffffff on #238636")
                diag_content.append(f" {selected_route.domain} ──► {selected_route.target_url} ", style="bold #f0f6fc")
                ms_str = f"({selected_route.response_time_ms:.1f}ms)" if selected_route.response_time_ms else ""
                diag_content.append(f"• Yanıt: {selected_route.http_status or 200} OK {ms_str} • Upstream: {selected_route.target_process or '-'}\n", style="#3fb950")
                diag_content.append("   ↳ Tarayıcıda açmak için [Enter] veya [o] tuşuna basın.", style="#8b949e")
            else:
                diag_content.append(" ℹ SEÇİLİ TCP SERVİSİ: ", style="bold #ffffff on #1f6feb")
                diag_content.append(f" {selected_route.domain} ──► {selected_route.target_url} ", style="bold #f0f6fc")
                diag_content.append(f"• Doğrudan TCP soketi aktif • Upstream: {selected_route.target_process or '-'}", style="#58a6ff")
        else:
            diag_content.append("İncelenecek rota seçilmedi.", style="#6e7681")

        diag_box.add_row(diag_content)
        outer_grid.add_row(diag_box)
        outer_grid.add_row(Text("─" * 100, style="#30363d"))

        # 5. Keyboard shortcuts footer
        shortcuts_text = Text(
            " Kısayollar: [↑/↓ veya j/k] Gezin  •  [Enter / o] Tarayıcıda Aç  •  [w] Filtre Değiştir  •  [r] Yenile  •  [/] Ara",
            style="dim #8b949e"
        )
        outer_grid.add_row(shortcuts_text)

        return Panel(
            outer_grid,
            title="[bold #f0f6fc]WEB SİTELERİ & TERS VEKİL SUNUCU (REVERSE PROXY)[/bold #f0f6fc]",
            border_style="#30363d",
            padding=(0, 0),
        )

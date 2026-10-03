from pathlib import Path
from typing import Optional
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Footer, TabbedContent, TabPane, Input
from textual.binding import Binding
from textual import events

from collectors.base import BaseCollector, DemoCollector
from collectors.log_collector import LogCollector
from collectors.audit_exporter import export_audit_report, calculate_audit_score

from ui.widgets.header_bar import HeaderBar
from ui.widgets.vitals_panel import VitalsPanel
from ui.widgets.alert_ticker import AlertTicker
from ui.widgets.port_table import PortProxyTable
from ui.widgets.all_ports_table import AllPortsTable
from ui.widgets.top_processes import TopProcessesPanel
from ui.widgets.log_viewer import LogViewerWidget
from ui.widgets.backup_panel import BackupPanel
from ui.widgets.service_panel import ServicePanel
from ui.widgets.backup_detail_view import BackupDetailView
from ui.widgets.services_table import ServicesTable
from ui.widgets.database_panel import DatabasePanel
from ui.widgets.security_panel import SecurityPanel
from ui.widgets.storage_panel import StoragePanel
from ui.widgets.dashboard_status_bar import DashboardStatusBar

from ui.modals.port_finder_modal import PortFinderModal
from ui.modals.alerts_modal import AlertsModal
from ui.modals.config_viewer_modal import ConfigViewerModal

from models.system import SystemSnapshot
from models.ports import ListeningPort, PortExposure
from models.proxy import ProxyRoute
from models.backup import BackupTask, BackupData
from models.docker import ContainerSummary
from models.services import ServiceUnit, ServiceState
from models.database import DatabaseInstance
from models.security import SecurityOverview
from models.storage import StorageOverview

THEMES = [
    ("github", "GitHub Dark"),
    ("jetbrains", "JetBrains Dark"),
    ("nord", "Nord"),
    ("tokyonight", "Tokyo Night"),
    ("dracula", "Dracula"),
    ("catppuccin", "Catppuccin Mocha"),
    ("matrix", "Matrix Hacker"),
]

from ui.theme_css import DEFAULT_TCSS
from ui.ascii_filter import AsciiFilter

_CSS_FILE = Path(__file__).parent / "styles.tcss"

class ServerTUIApp(App):
    """Main Textual Application for Server TUI Observability."""

    TITLE = "PulseOps"
    SUB_TITLE = "PulseTUI - Agentless Kurumsal Sunucu Gözlem Paneli"
    if _CSS_FILE.exists():
        CSS_PATH = _CSS_FILE
    else:
        DEFAULT_CSS = DEFAULT_TCSS

    BINDINGS = [
        Binding("1", "tab_1", "Dashboard (1)", show=True),
        Binding("2", "tab_2", "Süreçler (2)", show=True),
        Binding("3", "tab_3", "Portlar (3)", show=True),
        Binding("4", "tab_4", "Servisler (4)", show=True),
        Binding("5", "tab_5", "Veritabanı (5)", show=True),
        Binding("6", "tab_6", "Siteler (6)", show=True),
        Binding("7", "tab_7", "Yedekler (7)", show=True),
        Binding("8", "tab_8", "Loglar (8)", show=True),
        Binding("9", "tab_9", "Güvenlik (9)", show=True),
        Binding("0", "tab_0", "Depolama (0)", show=True),
        Binding("c", "open_config_viewer", "Config (c)", show=True),
        Binding("f", "find_port", "Boş Port (f)", show=True),
        Binding("p", "toggle_port_filter", "Port Filtre (p)", show=True),
        Binding("w", "cycle_website_filter", "Site Filtre (w)", show=True),
        Binding("o", "open_selected_site", "Aç (o)", show=False),
        Binding("a", "show_alerts", "Uyarılar (a)", show=True),
        Binding("t", "toggle_theme", "Tema (t)", show=True),
        Binding("slash", "toggle_search", "Ara (/)", show=True),
        Binding("e", "export_report", "Rapor (e)", show=True),
        Binding("r", "refresh_data", "Yenile (r)", show=True),
        Binding("q", "quit", "Çıkış (q)", show=True),
        Binding("ctrl+c", "quit", "Çıkış (Ctrl+C)", show=False, priority=True),
        # Function Key aliases
        Binding("f1", "tab_1", "F1", show=False),
        Binding("f2", "tab_2", "F2", show=False),
        Binding("f3", "tab_3", "F3", show=False),
        Binding("f4", "tab_4", "F4", show=False),
        Binding("f5", "tab_5", "F5", show=False),
        Binding("f6", "tab_6", "F6", show=False),
        Binding("f7", "tab_7", "F7", show=False),
        Binding("f8", "tab_8", "F8", show=False),
        Binding("f9", "tab_9", "F9", show=False),
        Binding("f10", "tab_0", "F10", show=False),
        Binding("s", "tab_0", "Storage (s)", show=False),
    ]

    def __init__(self, collector: BaseCollector, poll_interval: float = 1.5, ascii_mode: bool = False, **kwargs):
        super().__init__(**kwargs)
        self.collector = collector
        self._ascii_filter = AsciiFilter() if ascii_mode else None
        self._privilege_warning_shown = False
        self.poll_interval = poll_interval
        self.log_collector = LogCollector()
        self._current_theme_idx = 0
        
        # Latest telemetry cache for modals and export
        self._last_snapshot: Optional[SystemSnapshot] = None
        self._last_ports: list[ListeningPort] = []
        self._last_routes: list[ProxyRoute] = []
        self._last_backups: list[BackupTask] = []
        self._last_containers: list[ContainerSummary] = []
        self._last_backup_data: BackupData = BackupData()
        self._last_services: list[ServiceUnit] = []
        self._last_databases: list[DatabaseInstance] = []
        self._last_security: SecurityOverview = SecurityOverview()
        self._last_storage: StorageOverview = StorageOverview()

        # Widgets
        self.header_bar = HeaderBar()
        self.vitals_panel = VitalsPanel()
        self.alert_ticker = AlertTicker()
        self.port_table = PortProxyTable()
        self.all_ports_table = AllPortsTable()
        self.top_processes_panel = TopProcessesPanel()
        self.log_viewer = LogViewerWidget()
        self.backup_panel = BackupPanel()
        self.service_panel = ServicePanel()
        self.backup_detail_view = BackupDetailView()
        self.services_table = ServicesTable()
        self.database_panel = DatabasePanel()
        self.security_panel = SecurityPanel()
        self.storage_panel = StoragePanel()
        self.dashboard_status_bar = DashboardStatusBar()

        self.search_input = Input(placeholder="Alan adı, port veya servis arayın (ESC ile kapat)...", id="search-input")

    def compose(self) -> ComposeResult:
        yield self.header_bar
        with Vertical(id="search-bar"):
            yield self.search_input
        with TabbedContent(id="main-tabs"):
            with TabPane("[1] Dashboard", id="tab-dashboard"):
                yield self.vitals_panel
                yield self.alert_ticker
                yield Horizontal(
                    self.backup_panel,
                    self.service_panel,
                    id="bottom-row"
                )
                yield self.dashboard_status_bar
            with TabPane("[2] Süreçler", id="tab-processes"):
                yield self.top_processes_panel
            with TabPane("[3] Portlar", id="tab-ports"):
                yield self.all_ports_table
            with TabPane("[4] Servisler", id="tab-services"):
                yield self.services_table
            with TabPane("[5] Veritabanı", id="tab-databases"):
                yield self.database_panel
            with TabPane("[6] Siteler", id="tab-websites"):
                yield self.port_table
            with TabPane("[7] Yedekler", id="tab-backups"):
                yield self.backup_detail_view
            with TabPane("[8] Loglar", id="tab-logs"):
                yield self.log_viewer
            with TabPane("[9] Güvenlik", id="tab-security"):
                yield self.security_panel
            with TabPane("[0] Depolama", id="tab-storage"):
                yield self.storage_panel
        yield Footer()

    def get_line_filters(self):
        filters = list(super().get_line_filters())
        if self._ascii_filter is not None:
            filters.append(self._ascii_filter)
        return filters

    def on_mount(self) -> None:
        self.search_input.can_focus = False
        self.set_focus(None)
        self.poll_data()
        self.set_interval(self.poll_interval, self.poll_data)

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "search-input":
            self.port_table.filter_query = event.value

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "search-input":
            self.query_one("#search-bar").remove_class("visible")
            self.search_input.can_focus = False
            self.set_focus(None)

    def action_tab_1(self) -> None:
        self.query_one(TabbedContent).active = "tab-dashboard"

    def action_tab_2(self) -> None:
        self.query_one(TabbedContent).active = "tab-processes"

    def action_tab_3(self) -> None:
        self.query_one(TabbedContent).active = "tab-ports"

    def action_tab_4(self) -> None:
        self.query_one(TabbedContent).active = "tab-services"

    def action_tab_5(self) -> None:
        self.query_one(TabbedContent).active = "tab-databases"

    def action_tab_6(self) -> None:
        self.query_one(TabbedContent).active = "tab-websites"

    def action_tab_7(self) -> None:
        self.query_one(TabbedContent).active = "tab-backups"

    def action_tab_8(self) -> None:
        self.query_one(TabbedContent).active = "tab-logs"

    def action_tab_9(self) -> None:
        self.query_one(TabbedContent).active = "tab-security"

    def action_tab_0(self) -> None:
        self.query_one(TabbedContent).active = "tab-storage"

    def action_open_config_viewer(self) -> None:
        nginx_raw = None
        sshd_raw = None
        if hasattr(self.collector, "get_nginx_config_raw"):
            nginx_raw = self.collector.get_nginx_config_raw()
        if hasattr(self.collector, "get_sshd_config_raw"):
            sshd_raw = self.collector.get_sshd_config_raw()
        self.push_screen(ConfigViewerModal(nginx_content=nginx_raw, sshd_content=sshd_raw))

    def action_toggle_search(self) -> None:
        search_bar = self.query_one("#search-bar")
        if "visible" in search_bar.classes:
            search_bar.remove_class("visible")
            self.search_input.can_focus = False
            self.search_input.value = ""
            self.port_table.filter_query = ""
            self.set_focus(None)
        else:
            search_bar.add_class("visible")
            self.search_input.can_focus = True
            self.search_input.focus()

    def action_find_port(self) -> None:
        self.push_screen(PortFinderModal(ports=self._last_ports))

    def action_toggle_port_filter(self) -> None:
        if hasattr(self, "all_ports_table"):
            tabs = self.query_one("#main-tabs", TabbedContent)
            if tabs.active != "tab-ports":
                self.action_tab_3()
            self.all_ports_table.toggle_filter()

    def action_cycle_website_filter(self) -> None:
        tabs = self.query_one("#main-tabs", TabbedContent)
        if tabs.active != "tab-websites":
            self.action_tab_6()
        new_mode = self.port_table.cycle_filter()
        mode_names = {
            "ALL": "Tümü",
            "WEB": "Sadece Web Siteleri (HTTP/HTTPS)",
            "ISSUES": "Hatalı / Uyarı Verenler (502/SSL)",
            "SSL": "SSL Sertifikalı Siteler",
            "TCP": "TCP / Arka Plan Servisleri"
        }
        self.notify(f"Görünüm: {mode_names.get(new_mode, new_mode)}", title="🌐 Site Filtresi", timeout=1.5)

    def action_open_selected_site(self) -> None:
        tabs = self.query_one("#main-tabs", TabbedContent)
        if tabs.active != "tab-websites":
            return
        success, msg = self.port_table.open_in_browser()
        if success:
            self.notify(msg, title="🌐 Web Tarayıcısı", severity="information", timeout=3.5)
        else:
            self.notify(msg, title="ℹ Bilgi", severity="warning", timeout=3.5)

    def on_key(self, event: events.Key) -> None:
        if self.search_input.has_focus:
            return
        try:
            tabs = self.query_one("#main-tabs", TabbedContent)
            if tabs.active == "tab-websites":
                if event.key in ("up", "k"):
                    self.port_table.select_previous()
                    event.stop()
                elif event.key in ("down", "j"):
                    self.port_table.select_next()
                    event.stop()
                elif event.key in ("enter", "o"):
                    self.action_open_selected_site()
                    event.stop()
        except Exception:
            pass

    def action_show_alerts(self) -> None:
        if self._last_snapshot:
            self.push_screen(AlertsModal(
                snapshot=self._last_snapshot,
                ports=self._last_ports,
                routes=self._last_routes,
                storage=self._last_storage,
            ))

    def action_toggle_theme(self) -> None:
        self._current_theme_idx = (self._current_theme_idx + 1) % len(THEMES)
        theme_id, theme_name = THEMES[self._current_theme_idx]
        
        # Remove any existing theme class
        for tid, _ in THEMES:
            self.screen.remove_class(f"theme-{tid}")
            
        if theme_id != "catppuccin":
            self.screen.add_class(f"theme-{theme_id}")
            
        self.header_bar.theme_name = theme_name
        self.notify(f"Renk teması: {theme_name}", title="🎨 Tema Değiştirildi", timeout=2.0)

    def action_refresh_data(self) -> None:
        self.poll_data()

    def action_export_report(self) -> None:
        """Exports full server audit markdown report to disk."""
        if not self._last_snapshot:
            self.notify("⚠️ Veriler henüz yüklenmedi, lütfen bekleyin.", title="Rapor Hatası", severity="warning")
            return
            
        try:
            report_file = export_audit_report(
                self._last_snapshot,
                self._last_ports,
                self._last_routes,
                self._last_backups,
                self._last_containers,
                databases=self._last_databases,
                services=self._last_services,
                security=self._last_security,
                storage=self._last_storage,
                output_dir="audit-reports"
            )
            self.notify(
                f"PulseOps denetim raporu kaydedildi:\n{report_file}",
                title="⚡ PulseOps Raporu Oluşturuldu!",
                severity="information",
                timeout=5.0
            )
        except Exception as e:
            self.notify(f"Rapor yazılırken hata oluştu: {e}", title="Hata", severity="error")

    def _calculate_alerts_count(self) -> int:
        count, _ = self._get_alerts_summary()
        return count

    def _get_alerts_summary(self) -> tuple[int, list[str]]:
        count = 0
        snippets: list[str] = []
        if not self._last_snapshot:
            return 0, []
        # 1. Risky exposed ports
        for p in self._last_ports:
            if p.exposure == PortExposure.EXPOSED_RISK:
                count += 1
                snippets.append(f"Port :{p.port} ({p.process_name or 'servis'}) dışa açık!")
        # 2. SSL expiring <= 7 days
        for r in self._last_routes:
            if r.is_ssl and r.ssl_days_left is not None and r.ssl_days_left <= 7:
                count += 1
                snippets.append(f"{r.domain} SSL {r.ssl_days_left} gün kaldı!")
        # 3. Bad gateways
        for r in self._last_routes:
            if r.http_status in (502, 504):
                count += 1
                snippets.append(f"{r.domain} {r.http_status} Hatası!")
        # 4. Disks > 80%
        for d in self._last_snapshot.disks:
            if d.percent > 80.0:
                count += 1
                snippets.append(f"{d.mountpoint} disk %{d.percent:.0f}")
        # 5. RAM > 85%
        if self._last_snapshot.memory.percent > 85.0:
            count += 1
            snippets.append(f"RAM %{self._last_snapshot.memory.percent:.0f}")
        # 6. Firewall disabled
        if not self._last_snapshot.firewall.is_active:
            count += 1
            snippets.append("Güvenlik Duvarı KAPALI")
        # 7. Stopped critical services
        for s in self._last_services:
            if any(cn in s.name.lower() for cn in ["nginx", "docker", "postgres", "mysql", "redis"]):
                if s.state == ServiceState.STOPPED or s.state == ServiceState.FAILED:
                    count += 1
                    snippets.append(f"{s.name} servisi çalışmıyor")
        # 8. Backup retention risk
        if hasattr(self, "_last_backup_data") and self._last_backup_data and self._last_backup_data.retention.risk_level in ("HIGH", "CRITICAL"):
            count += 1
            snippets.append("Yedekleme saklama riski")
        # 9. Storage cache bloated (>10GB)
        if hasattr(self, "_last_storage") and self._last_storage and self._last_storage.is_cache_bloated:
            count += 1
            snippets.append("BuildKit önbelleği >10GB")
        return count, snippets

    def poll_data(self) -> None:
        try:
            snapshot, ports, routes, backups, containers = self.collector.poll()
            
            # Cache for modals and export
            self._last_snapshot = snapshot
            self._last_ports = ports
            self._last_routes = routes
            self._last_backups = backups
            self._last_containers = containers

            # Update Header
            privileges = self.collector.poll_privileges()
            self.header_bar.user_label = privileges.user
            self.header_bar.access_limited = bool(privileges.limitations)
            if privileges.limitations and not self._privilege_warning_shown:
                self._privilege_warning_shown = True
                self.notify(
                    "\n".join(f"• {item}" for item in privileges.limitations) + f"\n\n{privileges.hint}",
                    title=f"Kısıtlı erişim: {privileges.user}",
                    severity="warning",
                    timeout=12.0,
                )
            self.header_bar.hostname = snapshot.hostname
            self.header_bar.os_name = snapshot.os_name
            self.header_bar.kernel = snapshot.kernel
            self.header_bar.uptime_str = snapshot.uptime_human

            # Update Vitals
            self.vitals_panel.snapshot = snapshot

            # Update Port & Proxy tab
            self.port_table.routes = routes
            self.port_table.ports = ports

            # Update All Ports tab
            self.all_ports_table.ports = ports

            # Update Top Processes tab
            self.top_processes_panel.processes = snapshot.top_processes

            # Update Backups & Containers
            if hasattr(self.collector, "poll_backup_data"):
                backup_data = self.collector.poll_backup_data()
            else:
                backup_data = BackupData(tasks=backups)
            self._last_backup_data = backup_data
            self.backup_panel.tasks = backup_data.tasks or backups
            self.backup_detail_view.backup_data = backup_data
            self.service_panel.containers = containers

            # Poll Services
            if hasattr(self.collector, "poll_services"):
                services = self.collector.poll_services()
            else:
                services = []
            self._last_services = services
            self.services_table.services = services

            # Poll Databases
            if hasattr(self.collector, "poll_databases"):
                databases = self.collector.poll_databases(ports, containers)
            else:
                databases = []
            self._last_databases = databases
            self.database_panel.databases = databases

            # Poll Security Overview
            if hasattr(self.collector, "poll_security"):
                security = self.collector.poll_security(ports)
            else:
                security = SecurityOverview()
            self._last_security = security
            self.security_panel.security = security

            # Poll Storage Overview
            if hasattr(self.collector, "poll_storage"):
                storage = self.collector.poll_storage()
            else:
                storage = StorageOverview()
            self._last_storage = storage
            self.storage_panel.storage = storage

            # Update Alerts count in header and status bar
            alerts_cnt, snippets = self._get_alerts_summary()
            self.header_bar.alerts_count = alerts_cnt
            self.alert_ticker.alerts_count = alerts_cnt
            self.alert_ticker.alert_snippet = "  •  ".join(snippets[:3])

            # Calculate Health Score & Grade
            score, grade = calculate_audit_score(
                snapshot,
                ports,
                routes,
                security=security,
                storage=storage,
            )
            self.vitals_panel.health_score = score
            self.vitals_panel.health_grade = grade

            ssl_warn = sum(1 for r in routes if r.is_ssl and r.ssl_days_left is not None and r.ssl_days_left <= 7)
            self.dashboard_status_bar.docker_count = len(containers)
            self.dashboard_status_bar.websites_count = len(routes)
            self.dashboard_status_bar.db_count = len(databases)
            self.dashboard_status_bar.ssl_warnings = ssl_warn
            self.dashboard_status_bar.alerts_count = alerts_cnt

            # Update Log stream
            if isinstance(self.collector, DemoCollector):
                self.log_viewer.logs = self.log_collector.poll_mock()
            elif hasattr(self.collector, "poll_logs"):
                self.log_viewer.logs = self.collector.poll_logs()
            else:
                self.log_viewer.logs = self.log_collector.poll_live()
                
        except Exception:
            pass

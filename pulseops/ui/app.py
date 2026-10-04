import time
from functools import partial
from pathlib import Path
from typing import Optional
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import Footer, TabbedContent, TabPane, Input
from textual.binding import Binding
from textual import events

from pulseops.collectors.base import BaseCollector
from pulseops.collectors.telemetry import summarize_alerts
from pulseops.logging_setup import get_logger
from pulseops.config import AIConfig, AlertConfig
from pulseops.collectors.audit_exporter import export_audit_report, calculate_audit_score

log = get_logger("ui")

from pulseops.ui.widgets.header_bar import HeaderBar
from pulseops.ui.widgets.vitals_panel import VitalsPanel
from pulseops.ui.widgets.alert_ticker import AlertTicker
from pulseops.ui.widgets.port_table import PortProxyTable
from pulseops.ui.widgets.all_ports_table import AllPortsTable
from pulseops.ui.widgets.top_processes import TopProcessesPanel
from pulseops.ui.widgets.log_viewer import LogViewerWidget
from pulseops.ui.widgets.backup_panel import BackupPanel
from pulseops.ui.widgets.service_panel import ServicePanel
from pulseops.ui.widgets.backup_detail_view import BackupDetailView
from pulseops.ui.widgets.services_table import ServicesTable
from pulseops.ui.widgets.database_panel import DatabasePanel
from pulseops.ui.widgets.security_panel import SecurityPanel
from pulseops.ui.widgets.storage_panel import StoragePanel
from pulseops.ui.widgets.dashboard_status_bar import DashboardStatusBar

from pulseops.ui.modals.port_finder_modal import PortFinderModal
from pulseops.ui.modals.alerts_modal import AlertsModal
from pulseops.ui.modals.config_viewer_modal import ConfigViewerModal

from pulseops.models.telemetry import Telemetry

THEMES = [
    ("github", "GitHub Dark"),
    ("jetbrains", "JetBrains Dark"),
    ("nord", "Nord"),
    ("tokyonight", "Tokyo Night"),
    ("dracula", "Dracula"),
    ("catppuccin", "Catppuccin Mocha"),
    ("matrix", "Matrix Hacker"),
]

from pulseops.ui.ascii_filter import AsciiFilter

_CSS_FILE = Path(__file__).parent / "styles.tcss"

class ServerTUIApp(App):
    """Main Textual Application for Server TUI Observability."""

    TITLE = "PulseOps"
    SUB_TITLE = "PulseTUI - Agentless Kurumsal Sunucu Gözlem Paneli"
    CSS_PATH = _CSS_FILE  # shipped as package data and with PyInstaller --add-data

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
        Binding("h", "show_history", "Geçmiş (h)", show=True),
        Binding("i", "ai_analysis", "AI (i)", show=True),
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

    def __init__(
        self,
        collector: BaseCollector,
        poll_interval: float = 2.0,
        slow_interval: float = 30.0,
        ascii_mode: bool = False,
        alert_thresholds: Optional[AlertConfig] = None,
        history=None,
        ai_config: Optional[AIConfig] = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.ai_config = ai_config or AIConfig()
        self.alert_thresholds = alert_thresholds
        # Optional HistoryStore: per-minute samples + drift detection on every slow poll
        self.history = history
        self._last_sample_at = 0.0
        self._announced_offline_changes = False
        self.collector = collector
        self.poll_interval = poll_interval
        self.slow_interval = max(slow_interval, poll_interval)
        self._ascii_filter = AsciiFilter() if ascii_mode else None
        self._privilege_warning_shown = False
        self._current_theme_idx = 0

        # Polling state: one collection at a time, in a worker thread
        self._poll_in_flight = False
        self._last_slow_poll: Optional[float] = None
        self._failures = 0

        # Latest telemetry, used by modals and export
        self.telemetry: Optional[Telemetry] = None

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
                with VerticalScroll(classes="tab-scroll"):
                    yield self.top_processes_panel
            with TabPane("[3] Portlar", id="tab-ports"):
                with VerticalScroll(classes="tab-scroll"):
                    yield self.all_ports_table
            with TabPane("[4] Servisler", id="tab-services"):
                with VerticalScroll(classes="tab-scroll"):
                    yield self.services_table
            with TabPane("[5] Veritabanı", id="tab-databases"):
                with VerticalScroll(classes="tab-scroll"):
                    yield self.database_panel
            with TabPane("[6] Siteler", id="tab-websites"):
                with VerticalScroll(classes="tab-scroll"):
                    yield self.port_table
            with TabPane("[7] Yedekler", id="tab-backups"):
                with VerticalScroll(classes="tab-scroll"):
                    yield self.backup_detail_view
            with TabPane("[8] Loglar", id="tab-logs"):
                yield self.log_viewer
            with TabPane("[9] Güvenlik", id="tab-security"):
                with VerticalScroll(classes="tab-scroll"):
                    yield self.security_panel
            with TabPane("[0] Depolama", id="tab-storage"):
                with VerticalScroll(classes="tab-scroll"):
                    yield self.storage_panel
        yield Footer()

    def notify(self, message, *, markup: bool = False, **kwargs):
        # Messages often embed telemetry (domains, user names, paths); never parse them as markup
        return super().notify(message, markup=markup, **kwargs)

    def get_line_filters(self):
        filters = list(super().get_line_filters())
        if self._ascii_filter is not None:
            filters.append(self._ascii_filter)
        return filters

    def on_mount(self) -> None:
        self.search_input.can_focus = False
        self.set_focus(None)
        self.request_poll(force_slow=True)
        self.set_interval(self.poll_interval, self.request_poll)

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "search-input":
            self.port_table.filter_query = event.value

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "search-input":
            self.query_one("#search-bar").remove_class("visible")
            self.search_input.can_focus = False
            self._focus_active_tab()

    def on_tabbed_content_tab_activated(self, event: TabbedContent.TabActivated) -> None:
        if not self.search_input.has_focus:
            self._focus_active_tab()

    def _focus_active_tab(self) -> None:
        """Arrow keys / PgUp / PgDn scroll the active tab when its content is taller than the terminal."""
        pane = self.query_one(TabbedContent).active_pane
        scrolls = pane.query(".tab-scroll") if pane is not None else []
        self.set_focus(scrolls.first() if scrolls else None)

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
            self._focus_active_tab()
        else:
            search_bar.add_class("visible")
            self.search_input.can_focus = True
            self.search_input.focus()

    def action_find_port(self) -> None:
        self.push_screen(PortFinderModal(ports=self.telemetry.ports if self.telemetry else []))

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
        t = self.telemetry
        if t:
            self.push_screen(AlertsModal(snapshot=t.snapshot, ports=t.ports, routes=t.routes, storage=t.storage))

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
        if self._poll_in_flight:
            self.notify("Veriler zaten toplanıyor...", timeout=1.5)
            return
        self.request_poll(force_slow=True)
        self.notify("Tüm veriler yeniden toplanıyor...", title="Yenile", timeout=1.5)

    def action_export_report(self) -> None:
        """Exports full server audit markdown report to disk."""
        t = self.telemetry
        if not t:
            self.notify("⚠️ Veriler henüz yüklenmedi, lütfen bekleyin.", title="Rapor Hatası", severity="warning")
            return
        try:
            report_file = export_audit_report(
                t.snapshot, t.ports, t.routes, t.backups, t.containers,
                databases=t.databases, services=t.services, security=t.security, storage=t.storage,
                output_dir="audit-reports",
            )
        except Exception as e:
            log.exception("Rapor yazılamadı")
            self.notify(f"Rapor yazılırken hata oluştu: {e}", title="Hata", severity="error")
            return
        self.notify(
            f"PulseOps denetim raporu kaydedildi:\n{report_file}",
            title="⚡ PulseOps Raporu Oluşturuldu!",
            severity="information",
            timeout=5.0,
        )

    # --- polling ------------------------------------------------------------------------------

    def _logs_visible(self) -> bool:
        try:
            return self.query_one("#main-tabs", TabbedContent).active == "tab-logs"
        except Exception:
            return False

    def request_poll(self, force_slow: bool = False) -> None:
        """Starts one background collection unless one is still running (slow hosts never pile up)."""
        if self._poll_in_flight:
            return
        now = time.monotonic()
        include_slow = force_slow or self._last_slow_poll is None or now - self._last_slow_poll >= self.slow_interval
        include_logs = include_slow or self._logs_visible()
        self._poll_in_flight = True
        self.run_worker(
            partial(self._collect_in_thread, include_slow, include_logs),
            thread=True,
            group="poll",
            exit_on_error=False,
        )

    def _collect_in_thread(self, include_slow: bool, include_logs: bool) -> None:
        try:
            telemetry = self.collector.collect(include_slow=include_slow, include_logs=include_logs)
        except Exception as e:
            log.exception("Telemetri toplanamadı")
            self.call_from_thread(self._on_poll_failed, e)
            return
        changes, offline = self._record_history(telemetry, include_slow)
        self.call_from_thread(self._on_poll_done, telemetry, include_slow, changes, offline)

    def _record_history(self, t: Telemetry, include_slow: bool):
        """Runs in the poll thread. Returns (new changes, changes recorded while the TUI was closed)."""
        if self.history is None:
            return [], []
        from pulseops.history import host_key
        changes, offline = [], []
        try:
            if not self._announced_offline_changes:
                offline = [c for c in self.history.take_unreported(host_key(t), "tui") if c.severity != "INFO"]
            if include_slow:
                changes = self.history.detect_changes(t)
                self.history.take_unreported(host_key(t), "tui")  # what we show live is not "offline"
            if t.collected_at - self._last_sample_at >= 60:
                score, _ = calculate_audit_score(t.snapshot, t.ports, t.routes, security=t.security, storage=t.storage,
                                        containers=t.containers)
                self.history.record_sample(t, score, len(summarize_alerts(t, self.alert_thresholds)))
                self._last_sample_at = t.collected_at
        except Exception:
            log.exception("Geçmiş kaydedilemedi")
        return changes, offline

    def _on_poll_done(self, telemetry: Telemetry, include_slow: bool, changes=(), offline=()) -> None:
        self._poll_in_flight = False
        if not self._announced_offline_changes and self.history is not None:
            self._announced_offline_changes = True
            if offline:
                self.notify(
                    "\n".join(f"• {c.message}" for c in offline[:5]) + ("\n…" if len(offline) > 5 else "")
                    + "\n\nAyrıntılar için: h",
                    title=f"Son açılıştan beri {len(offline)} güvenlik değişikliği",
                    severity="warning",
                    timeout=15.0,
                )
        for change in changes:
            if change.severity != "INFO":
                self.notify(change.message, title="⚠ Güvenlik değişikliği (h)",
                            severity="error" if change.severity == "HIGH" else "warning", timeout=15.0)
        if include_slow:
            self._last_slow_poll = time.monotonic()
        if self._failures:
            log.info("Bağlantı yeniden kuruldu (%d başarısız denemeden sonra)", self._failures)
            self.notify("Veri akışı yeniden sağlandı.", title="Bağlantı", severity="information", timeout=4.0)
            self._failures = 0
            self.header_bar.error_message = ""
        try:
            self.apply_telemetry(telemetry)
        except Exception:
            log.exception("Telemetri arayüze uygulanamadı")

    def _on_poll_failed(self, error: Exception) -> None:
        self._poll_in_flight = False
        self._failures += 1
        message = str(error) or type(error).__name__
        self.header_bar.error_message = message
        if self._failures == 1:
            self.notify(
                f"{message}\n\nSon alınan veriler gösteriliyor; her {self.poll_interval:g} sn'de yeniden deneniyor.",
                title="Veri toplanamadı",
                severity="error",
                timeout=8.0,
            )

    def poll_data(self) -> None:
        """Synchronous full poll + apply (used by tests and scripts)."""
        self.apply_telemetry(self.collector.collect(include_slow=True, include_logs=True))

    def apply_telemetry(self, t: Telemetry) -> None:
        self.telemetry = t
        snapshot = t.snapshot

        privileges = t.privileges
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

        self.vitals_panel.snapshot = snapshot
        self.port_table.routes = t.routes
        self.port_table.ports = t.ports
        self.all_ports_table.ports = t.ports
        self.top_processes_panel.processes = snapshot.top_processes

        self.backup_panel.tasks = t.backups
        self.backup_detail_view.backup_data = t.backup_data
        self.service_panel.containers = t.containers
        self.services_table.services = t.services
        self.database_panel.databases = t.databases
        self.security_panel.containers = t.containers
        self.security_panel.security = t.security
        self.storage_panel.storage = t.storage
        if t.logs:
            self.log_viewer.logs = t.logs

        alerts = summarize_alerts(t, self.alert_thresholds)
        self.header_bar.alerts_count = len(alerts)
        self.alert_ticker.alerts_count = len(alerts)
        self.alert_ticker.alert_snippet = "  •  ".join(alerts[:3])

        score, grade = calculate_audit_score(snapshot, t.ports, t.routes, security=t.security, storage=t.storage,
                                        containers=t.containers)
        self.vitals_panel.health_score = score
        self.vitals_panel.health_grade = grade

        self.dashboard_status_bar.docker_count = len(t.containers)
        self.dashboard_status_bar.websites_count = len(t.routes)
        self.dashboard_status_bar.db_count = len(t.databases)
        self.dashboard_status_bar.ssl_warnings = sum(
            1 for r in t.routes if r.is_ssl and r.ssl_days_left is not None and r.ssl_days_left <= 7
        )
        self.dashboard_status_bar.alerts_count = len(alerts)

    def action_show_history(self) -> None:
        if self.history is None:
            self.notify("Geçmiş kapalı (demo modu veya [history] enabled = false).", timeout=3.0)
            return
        if not self.telemetry:
            self.notify("Veriler henüz yüklenmedi.", timeout=2.0)
            return
        from pulseops.history import host_key
        from pulseops.ui.modals.history_modal import HistoryModal
        self.push_screen(HistoryModal(self.history, host_key(self.telemetry), self.telemetry.snapshot.hostname))

    def action_ai_analysis(self) -> None:
        if not self.telemetry:
            self.notify("Veriler henüz yüklenmedi.", timeout=2.0)
            return
        from pulseops.ai import AIError, Conversation
        from pulseops.ui.modals.ai_modal import AIModal

        changes = []
        if self.history is not None:
            import time
            from pulseops.history import host_key
            try:
                changes = self.history.changes(host_key(self.telemetry), since=time.time() - 86400, limit=20)
            except Exception:
                log.exception("Geçmiş okunamadı")
        try:
            conversation = Conversation(self.ai_config, self.telemetry, changes)
        except AIError as e:
            self.notify(str(e), title="AI", severity="error", timeout=8.0)
            return
        self.push_screen(AIModal(conversation, self.ai_config.model, self.telemetry.snapshot.hostname))

    def on_unmount(self) -> None:
        try:
            self.collector.close()
        except Exception:
            log.exception("Collector kapatılamadı")

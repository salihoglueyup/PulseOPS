import os
import sys
import argparse

from version import __version__
from commands import SUBCOMMANDS, EXIT_UNKNOWN, add_connection_args, build_collector, build_subcommand_parsers
from logging_setup import get_logger, setup_logging
from pulseops_config import ConfigError, load_config

EPILOG = """komutlar:
  pulseops                      bu sunucuyu canlı izler (TUI)
  pulseops root@sunucu          uzak sunucuyu SSH ile izler (TUI)
  pulseops status [--json]      TUI açmadan özet yazdırır
  pulseops report [-f md|json]  denetim raporu üretir
  pulseops check                sağlık skoruna göre çıkış kodu (cron / monitoring)
  pulseops config [--init]      yapılandırmayı göster / şablon oluştur
  pulseops probe [--tier ...]   sunucuda çalışan salt-okunur betiği göster (denetim)
  pulseops history [--since]    kayıtlı trendler ve güvenlik değişiklikleri
  pulseops notify --test        bildirim kanallarını dene
  pulseops update | uninstall   kendini günceller / kaldırır
  pulseops version              sürüm bilgisi
"""


def build_tui_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pulseops",
        description="PulseOps (PulseTUI): Agentless Real-Time Server, Web & Infrastructure Observability TUI",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    add_connection_args(parser)
    parser.add_argument(
        "--interval",
        type=float,
        default=None,
        help="Hızlı metrik (CPU, RAM, port, süreç) yenileme aralığı, sn (varsayılan: 2). Yavaş SSH bağlantılarında artırın.",
    )
    parser.add_argument(
        "--slow-interval",
        type=float,
        default=None,
        help="Ağır kontrollerin (servis, docker, nginx, yedek) aralığı, sn (varsayılan: 30)",
    )
    parser.add_argument("--no-color", action="store_true", default=None, help="Renksiz çıktı (NO_COLOR ortam değişkeni de desteklenir)")
    parser.add_argument("--ascii", action="store_true", default=None, help="Emoji/Unicode desteklemeyen terminaller için yalnızca ASCII karakter kullanır")
    parser.add_argument("--no-mouse", action="store_true", default=None, help="Fare desteğini kapatır (tmux/screen'de metin seçimi için)")
    parser.add_argument("-V", "--version", action="version", version=f"pulseops {__version__}")
    return parser


def terminal_supports_unicode() -> bool:
    encoding = (getattr(sys.stdout, "encoding", None) or "").lower().replace("-", "")
    return encoding.startswith("utf")


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    log_path = setup_logging()
    log = get_logger("cli")

    is_subcommand = bool(argv) and argv[0] in SUBCOMMANDS
    try:
        config, config_files = load_config()
    except ConfigError as e:
        print(f"❌ Yapılandırma hatası: {e}", file=sys.stderr)
        sys.exit(EXIT_UNKNOWN if is_subcommand and argv[0] == "check" else 2)

    if is_subcommand:
        args = build_subcommand_parsers().parse_args(argv)
        args.config, args.config_files = config, config_files
        sys.exit(args.func(args))

    args = build_tui_parser().parse_args(argv)
    args.config = config
    general = config.general
    interval = max(args.interval if args.interval is not None else general.interval, 0.5)
    slow_interval = args.slow_interval if args.slow_interval is not None else general.slow_interval
    no_color = args.no_color or general.no_color
    ascii_mode = args.ascii or general.ascii or not terminal_supports_unicode()
    mouse = general.mouse and not args.no_mouse

    if no_color:
        # Textual reads NO_COLOR when the App is constructed
        os.environ["NO_COLOR"] = "1"

    collector = build_collector(args)
    log.info("PulseOps %s başlatıldı (%s), aralık %.1fs / %.0fs, yapılandırma: %s",
             __version__, type(collector).__name__, interval, slow_interval,
             ", ".join(map(str, config_files)) or "varsayılan")

    from ui.app import ServerTUIApp

    from collectors.base import DemoCollector

    history = None
    if config.history.enabled and not isinstance(collector, DemoCollector):
        from history import HistoryStore
        history = HistoryStore()

    app = ServerTUIApp(
        history=history,
        collector=collector,
        poll_interval=interval,
        slow_interval=slow_interval,
        ascii_mode=ascii_mode,
        alert_thresholds=config.alerts,
    )
    app.run(mouse=mouse)
    if app.return_code not in (None, 0) and log_path:
        print(f"PulseOps beklenmedik şekilde kapandı. Ayrıntılar: {log_path}", file=sys.stderr)


if __name__ == "__main__":
    main()

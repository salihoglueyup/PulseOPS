import sys
import argparse

from version import __version__
from commands import SUBCOMMANDS, EXIT_UNKNOWN, add_connection_args, build_collector, build_subcommand_parsers, launch_tui
from logging_setup import setup_logging
from pulseops_config import ConfigError, load_config

EPILOG = """komutlar:
  pulseops                      bu sunucuyu canlı izler (TUI)
  pulseops root@sunucu          uzak sunucuyu SSH ile izler (TUI)
  pulseops status [--json]      TUI açmadan özet yazdırır
  pulseops report [-f md|json]  denetim raporu üretir
  pulseops check [--all]        sağlık skoruna göre çıkış kodu (cron / monitoring), --all: tüm filo
  pulseops fleet [--group web]  filo görünümü: tüm sunucular tek ekranda
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


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    log_path = setup_logging()

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
    collector = build_collector(args)
    launch_tui(args, config, collector, log_path, config_files)


if __name__ == "__main__":
    main()

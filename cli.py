import os
import sys
import argparse

from version import __version__
from commands import SUBCOMMANDS, add_connection_args, build_collector, build_subcommand_parsers

EPILOG = """komutlar:
  pulseops                      bu sunucuyu canlı izler (TUI)
  pulseops root@sunucu          uzak sunucuyu SSH ile izler (TUI)
  pulseops status [--json]      TUI açmadan özet yazdırır
  pulseops report [-f md|json]  denetim raporu üretir
  pulseops check                sağlık skoruna göre çıkış kodu (cron / monitoring)
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
        default=1.5,
        help="Metrik yenileme aralığı, saniye (varsayılan: 1.5). Yavaş SSH bağlantılarında artırın.",
    )
    parser.add_argument("--no-color", action="store_true", help="Renksiz çıktı (NO_COLOR ortam değişkeni de desteklenir)")
    parser.add_argument("--ascii", action="store_true", help="Emoji/Unicode desteklemeyen terminaller için yalnızca ASCII karakter kullanır")
    parser.add_argument("--no-mouse", action="store_true", help="Fare desteğini kapatır (tmux/screen'de metin seçimi için)")
    parser.add_argument("-V", "--version", action="version", version=f"pulseops {__version__}")
    return parser


def terminal_supports_unicode() -> bool:
    encoding = (getattr(sys.stdout, "encoding", None) or "").lower().replace("-", "")
    return encoding.startswith("utf")


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv

    if argv and argv[0] in SUBCOMMANDS:
        args = build_subcommand_parsers().parse_args(argv)
        sys.exit(args.func(args))

    args = build_tui_parser().parse_args(argv)
    if args.interval < 0.5:
        args.interval = 0.5

    if args.no_color:
        # Textual reads NO_COLOR when the App is constructed
        os.environ["NO_COLOR"] = "1"

    collector = build_collector(args)

    from ui.app import ServerTUIApp

    app = ServerTUIApp(
        collector=collector,
        poll_interval=args.interval,
        ascii_mode=args.ascii or not terminal_supports_unicode(),
    )
    app.run(mouse=not args.no_mouse)


if __name__ == "__main__":
    main()

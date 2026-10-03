"""Shared CLI plumbing and non-interactive commands (status, report, check)."""
import sys
import json
import getpass
import argparse
from pathlib import Path

from rich.console import Console
from rich.table import Table

from collectors.base import BaseCollector, LocalLiveCollector, DemoCollector
from collectors.telemetry import collect_telemetry, summarize_alerts
from collectors.audit_exporter import calculate_audit_score, generate_audit_markdown
from models.telemetry import Telemetry
from models.services import ServiceState

# Nagios / monitoring plugin compatible exit codes
EXIT_OK, EXIT_WARNING, EXIT_CRITICAL, EXIT_UNKNOWN = 0, 1, 2, 3


def add_connection_args(parser: argparse.ArgumentParser) -> None:
    """Arguments that select which host is observed; shared by the TUI and every subcommand."""
    parser.add_argument(
        "target",
        nargs="?",
        help="Uzak sunucu hedefi (örn: root@192.168.1.100). Verilmezse bu makine izlenir.",
    )
    parser.add_argument("--demo", action="store_true", help="Simülasyon / Demo modunu başlatır (örnek verilerle)")
    parser.add_argument("--live", action="store_true", help="Bu makineyi izler (varsayılan)")
    parser.add_argument(
        "--ssh", "--host",
        dest="host",
        type=str,
        help="Uzak Linux sunucusuna SSH üzerinden bağlanır (örn: root@192.168.1.100)",
    )
    parser.add_argument("-u", "--user", type=str, default=None, help="SSH kullanıcı adı (varsayılan: root)")
    parser.add_argument("-p", "--port", type=int, default=22, help="SSH port numarası (varsayılan: 22)")
    parser.add_argument("-k", "--key", type=str, help="SSH özel anahtar dosyası yolu (örn: ~/.ssh/id_ed25519)")
    parser.add_argument("-P", "--password", type=str, help=argparse.SUPPRESS)


def build_collector(args: argparse.Namespace, interactive: bool = True) -> BaseCollector:
    """Creates the collector selected by the connection arguments. Exits the process on SSH failure."""
    ssh_target = args.host or args.target
    if ssh_target in ("demo", "mock"):
        args.demo, ssh_target = True, None
    elif ssh_target in ("live", "local"):
        args.live, ssh_target = True, None

    if not ssh_target:
        return DemoCollector() if args.demo else LocalLiveCollector()

    from collectors.ssh_collector import SSHCollector

    ssh_target = ssh_target.strip()
    if "@" in ssh_target:
        username, host = ssh_target.split("@", 1)
    else:
        username, host = (args.user or "root"), ssh_target
    if args.user:
        username = args.user

    password = args.password
    if not password and not args.key and interactive and sys.stdin.isatty():
        try:
            pwd_input = getpass.getpass(f"🔑 {username}@{host} için SSH Şifresi (Varsayılan anahtarı denemek için Enter): ")
            if pwd_input.strip():
                password = pwd_input.strip()
        except (KeyboardInterrupt, EOFError):
            print("\nİptal edildi.", file=sys.stderr)
            sys.exit(0)

    if interactive:
        print(f"🔗 Uzak Linux sunucusuna bağlanılıyor: {username}@{host}:{args.port}...", file=sys.stderr)
    collector = SSHCollector(host=host, username=username, port=args.port, key_filename=args.key, password=password)
    try:
        collector.test_connection()
    except Exception as e:
        print(f"❌ [HATA] {username}@{host}:{args.port} adresine SSH ile bağlanılamadı: {e}", file=sys.stderr)
        if interactive:
            print("💡 Olası nedenler:", file=sys.stderr)
            print(f"   1. {host}:{args.port} adresine erişim engellenmiş veya port kapalı olabilir.", file=sys.stderr)
            print(f"   2. '{username}' kullanıcısı için şifre veya anahtar reddedildi.", file=sys.stderr)
            print("   3. Sunucudaki güvenlik duvarı (UFW / iptables) bağlantıyı kısıtlıyor olabilir.", file=sys.stderr)
        sys.exit(EXIT_UNKNOWN)
    return collector


def _score(t: Telemetry) -> tuple[int, str]:
    return calculate_audit_score(t.snapshot, t.ports, t.routes, security=t.security, storage=t.storage)


def _telemetry_json(t: Telemetry) -> dict:
    score, grade = _score(t)
    data = t.model_dump(mode="json")
    data["score"] = score
    data["grade"] = grade
    data["alerts"] = summarize_alerts(t)
    return data


def _collect_or_exit(collector: BaseCollector) -> Telemetry:
    try:
        return collect_telemetry(collector)
    except Exception as e:
        print(f"❌ [HATA] Telemetri toplanamadı: {e}", file=sys.stderr)
        sys.exit(EXIT_UNKNOWN)


def render_status(t: Telemetry, console: Console) -> None:
    s = t.snapshot
    score, grade = _score(t)
    alerts = summarize_alerts(t)

    console.print(f"[bold]⚡ PulseOps[/bold]  {s.hostname}  ·  {s.os_name}  ·  çekirdek {s.kernel}  ·  uptime {s.uptime_human}")
    console.print(f"[bold]Sağlık skoru:[/bold] {score}/100  {grade}")
    console.print()

    vitals = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
    vitals.add_column("Kaynak")
    vitals.add_column("Kullanım", justify="right")
    vitals.add_column("Detay")
    load = ", ".join(f"{x:.2f}" for x in s.cpu.load_avg)
    vitals.add_row("CPU", f"%{s.cpu.total_percent:.1f}", f"{s.cpu.cores} çekirdek · load {load}")
    vitals.add_row("RAM", f"%{s.memory.percent:.1f}", f"{s.memory.used_gb:.1f} / {s.memory.total_gb:.1f} GB")
    vitals.add_row("Swap", f"%{s.memory.swap_percent:.1f}", "")
    for d in s.disks:
        vitals.add_row(f"Disk {d.mountpoint}", f"%{d.percent:.1f}", f"{d.used_gb:.1f} / {d.total_gb:.1f} GB")
    console.print(vitals)
    console.print()

    failed_services = [sv.name for sv in t.services if sv.state == ServiceState.FAILED]
    console.print(
        f"Portlar: {len(t.ports)}  ·  Siteler: {len(t.routes)}  ·  Konteynerler: {len(t.containers)}  ·  "
        f"Veritabanları: {len(t.databases)}  ·  Servisler: {len(t.services)} ({len(failed_services)} hatalı)"
    )
    console.print(f"Güvenlik duvarı: {s.firewall.summary}")
    console.print()

    limitations = t.privileges.limitations
    if limitations:
        console.print(f"[bold yellow]Kısıtlı erişim ({t.privileges.user}):[/bold yellow]")
        for item in limitations:
            console.print(f"  • {item}")
        console.print(f"  {t.privileges.hint}")
        console.print()

    if alerts:
        console.print(f"[bold red]Uyarılar ({len(alerts)}):[/bold red]")
        for a in alerts:
            console.print(f"  • {a}")
    else:
        console.print("[bold green]Aktif uyarı yok.[/bold green]")


def cmd_status(args: argparse.Namespace) -> int:
    t = _collect_or_exit(build_collector(args))
    if args.json:
        print(json.dumps(_telemetry_json(t), ensure_ascii=False, indent=2))
    else:
        render_status(t, Console())
    return EXIT_OK


def cmd_report(args: argparse.Namespace) -> int:
    t = _collect_or_exit(build_collector(args))
    if args.format == "json":
        content = json.dumps(_telemetry_json(t), ensure_ascii=False, indent=2)
    else:
        content = generate_audit_markdown(
            t.snapshot, t.ports, t.routes, t.backups, t.containers,
            databases=t.databases, services=t.services, security=t.security, storage=t.storage,
        )

    if args.output == "-":
        print(content)
        return EXIT_OK

    import time
    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)
    host = "".join(c for c in t.snapshot.hostname if c.isalnum() or c in ("-", "_")) or "server"
    ext = "json" if args.format == "json" else "md"
    path = out_dir / f"pulseops-audit-{host}-{time.strftime('%Y-%m-%d_%H%M%S')}.{ext}"
    path.write_text(content, encoding="utf-8")
    print(path)
    return EXIT_OK


def evaluate_check(score: int, warn: int, crit: int) -> int:
    if score < crit:
        return EXIT_CRITICAL
    if score < warn:
        return EXIT_WARNING
    return EXIT_OK


def cmd_check(args: argparse.Namespace) -> int:
    if args.crit > args.warn:
        print("❌ --crit değeri --warn değerinden büyük olamaz.", file=sys.stderr)
        return EXIT_UNKNOWN
    t = _collect_or_exit(build_collector(args, interactive=False))
    score, grade = _score(t)
    alerts = summarize_alerts(t)
    code = evaluate_check(score, args.warn, args.crit)
    label = {EXIT_OK: "OK", EXIT_WARNING: "WARNING", EXIT_CRITICAL: "CRITICAL"}[code]
    summary = f"; {'; '.join(alerts)}" if alerts else ""
    # Single line + perfdata, the format monitoring systems (Nagios, Icinga, Zabbix) expect
    print(f"PULSEOPS {label} - {t.snapshot.hostname} skor {score}/100 {grade}{summary} | score={score};{args.warn};{args.crit};0;100 alerts={len(alerts)}")
    return code


def build_subcommand_parsers() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pulseops", description="PulseOps etkileşimsiz komutlar")
    sub = parser.add_subparsers(dest="command", required=True)

    p_status = sub.add_parser("status", help="TUI açmadan tek ekranlık özet yazdırır")
    add_connection_args(p_status)
    p_status.add_argument("--json", action="store_true", help="Çıktıyı JSON olarak verir")
    p_status.set_defaults(func=cmd_status)

    p_report = sub.add_parser("report", help="Denetim raporu üretir")
    add_connection_args(p_report)
    p_report.add_argument("-f", "--format", choices=["md", "json"], default="md", help="Rapor biçimi (varsayılan: md)")
    p_report.add_argument("-o", "--output", default="audit-reports", help="Çıktı dizini; '-' ise stdout'a yazar")
    p_report.set_defaults(func=cmd_report)

    p_check = sub.add_parser(
        "check",
        help="Sağlık skoruna göre çıkış kodu döner (0 OK, 1 WARNING, 2 CRITICAL, 3 UNKNOWN)",
    )
    add_connection_args(p_check)
    p_check.add_argument("--warn", type=int, default=80, help="Bu skorun altı WARNING (varsayılan: 80)")
    p_check.add_argument("--crit", type=int, default=50, help="Bu skorun altı CRITICAL (varsayılan: 50)")
    p_check.set_defaults(func=cmd_check)

    from installer import add_installer_subcommands
    add_installer_subcommands(sub)
    return parser


SUBCOMMANDS = ("status", "report", "check", "update", "uninstall", "version")

"""Shared CLI plumbing and non-interactive commands (status, report, check)."""
import os
import sys
import json
import getpass
import argparse
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.table import Table

from collectors.base import BaseCollector, DemoCollector, create_local_collector
from collectors.telemetry import collect_telemetry, summarize_alerts
from collectors.audit_exporter import calculate_audit_score, generate_audit_markdown
from models.telemetry import Telemetry
from models.services import ServiceState
from pulseops_config import Config, ConfigError, init_user_config, render_config, user_config_path, SYSTEM_CONFIG

# Nagios / monitoring plugin compatible exit codes
EXIT_OK, EXIT_WARNING, EXIT_CRITICAL, EXIT_UNKNOWN = 0, 1, 2, 3


class _RemovedPasswordFlag(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        parser.error(
            f"{option_string} kaldırıldı: komut satırındaki şifre `ps` çıktısında ve shell geçmişinde görünür. "
            "Şifre gerekiyorsa PulseOps güvenli şekilde sorar; otomasyon için PULSEOPS_SSH_PASSWORD "
            "ortam değişkenini kullanın (tercihen SSH anahtarı)."
        )


def add_connection_args(parser: argparse.ArgumentParser) -> None:
    """Arguments that select which host is observed; shared by the TUI and every subcommand."""
    parser.add_argument(
        "target",
        nargs="?",
        help="Uzak sunucu: user@host[:port] veya ~/.ssh/config'teki bir Host adı. Verilmezse bu makine izlenir.",
    )
    parser.add_argument("--demo", action="store_true", help="Simülasyon / Demo modunu başlatır (örnek verilerle)")
    parser.add_argument("--live", action="store_true", help="Bu makineyi izler (varsayılan)")
    parser.add_argument("--ssh", "--host", dest="host", type=str, help="Uzak sunucu (target ile aynı)")
    parser.add_argument("-u", "--user", type=str, default=None, help="SSH kullanıcı adı (varsayılan: ~/.ssh/config, yoksa root)")
    parser.add_argument("-p", "--port", type=int, default=None, help="SSH portu (varsayılan: ~/.ssh/config, yoksa 22)")
    parser.add_argument("-k", "--key", type=str, help="SSH özel anahtarı (varsayılan: ~/.ssh/config, ssh-agent ve ~/.ssh/id_*)")
    parser.add_argument("-J", "--jump", type=str, default=None,
                        help="Atlama sunucusu (ProxyJump), örn: bastion veya user@bastion:2222,ikinci-hop")
    parser.add_argument("-P", "--password", nargs="?", action=_RemovedPasswordFlag, help=argparse.SUPPRESS)


def _ask_yes_no(question: str) -> bool:
    try:
        answer = input(question)
    except (KeyboardInterrupt, EOFError):
        print(file=sys.stderr)
        return False
    return answer.strip().lower() in ("e", "evet", "y", "yes")


def _confirm_host_key(host_entry: str, key_type: str, fp: str) -> bool:
    print(f"\n🔐 '{host_entry}' sunucusunun kimliği doğrulanamadı (known_hosts'ta kayıt yok).", file=sys.stderr)
    print(f"   {key_type} anahtar parmak izi: {fp}", file=sys.stderr)
    print("   Parmak izini sunucu yöneticinizden doğrulayın (sunucuda: ssh-keygen -lf /etc/ssh/ssh_host_*_key.pub).",
          file=sys.stderr)
    return _ask_yes_no("   Bağlanmaya devam edilsin ve anahtar ~/.ssh/known_hosts dosyasına eklensin mi? (evet/hayır): ")


def _getpass(prompt: str) -> Optional[str]:
    try:
        value = getpass.getpass(prompt)
    except (KeyboardInterrupt, EOFError):
        print("\nİptal edildi.", file=sys.stderr)
        sys.exit(EXIT_UNKNOWN)
    return value or None


def _fail(message: str) -> None:
    print(f"❌ [HATA] {message}", file=sys.stderr)
    sys.exit(EXIT_UNKNOWN)


def build_collector(args: argparse.Namespace, interactive: bool = True) -> BaseCollector:
    """Creates the collector selected by the connection arguments. Exits the process on SSH failure.

    SSH authentication follows OpenSSH: keys (command line, ~/.ssh/config, ssh-agent, ~/.ssh/id_*)
    first; a passphrase or password is only asked for when a key is encrypted or keys are rejected.
    """
    import paramiko
    from collectors.hostkeys import UnknownHostKeyError, describe_bad_host_key

    destination = args.host or args.target
    if destination in ("demo", "mock"):
        args.demo, destination = True, None
    elif destination in ("live", "local"):
        args.live, destination = True, None

    config = _config(args)
    use_sudo = config.general.use_sudo
    if not destination:
        return DemoCollector() if args.demo else create_local_collector(use_sudo=use_sudo)

    from collectors.ssh_collector import SSHCollector
    from collectors.transport import SSHTransport, TransportError, resolve_target

    can_prompt = interactive and sys.stdin.isatty()
    target = resolve_target(destination.strip(), username=args.user, port=args.port, key_filename=args.key,
                            proxy_jump=getattr(args, "jump", None))
    transport = SSHTransport(
        target,
        password=os.environ.get("PULSEOPS_SSH_PASSWORD") or None,
        host_key_mode=config.ssh.host_key_checking,
        confirm_host_key=_confirm_host_key if can_prompt else None,
    )
    via = f" (atlama: {target.proxy_jump})" if target.proxy_jump else ""
    if interactive:
        print(f"🔗 Bağlanılıyor: {target.label}{via}...", file=sys.stderr)

    for _ in range(4):
        try:
            transport.test_connection()
            break
        except paramiko.BadHostKeyException as e:
            _fail(describe_bad_host_key(e))
        except UnknownHostKeyError as e:
            _fail(str(e))
        except paramiko.PasswordRequiredException:
            if not can_prompt or transport.passphrase:
                _fail("SSH anahtarı parola korumalı. ssh-agent'a ekleyin (ssh-add) veya etkileşimli çalıştırın.")
            transport.passphrase = _getpass("🔑 SSH anahtar parolası: ")
        except paramiko.AuthenticationException:
            if not can_prompt or transport.password:
                _fail(f"{target.label}: kimlik doğrulaması reddedildi (anahtar/ssh-agent/şifre).")
            transport.password = _getpass(f"🔑 {target.label} için SSH şifresi: ")
        except (OSError, paramiko.SSHException, TransportError) as e:
            if "No authentication methods available" in str(e) and can_prompt and not transport.password:
                # No key and no agent: paramiko never reached the server's auth step
                transport.password = _getpass(f"🔑 {target.label} için SSH şifresi: ")
                continue
            print(f"❌ [HATA] {target.label}{via} adresine bağlanılamadı: {e}", file=sys.stderr)
            if interactive:
                print("💡 Olası nedenler: adres/port yanlış, sunucu kapalı veya bir güvenlik duvarı engelliyor.",
                      file=sys.stderr)
            sys.exit(EXIT_UNKNOWN)
    else:
        _fail("Kimlik doğrulaması tamamlanamadı.")

    transport.disable_prompts()
    return SSHCollector(transport, use_sudo=use_sudo)


def _score(t: Telemetry) -> tuple[int, str]:
    return calculate_audit_score(t.snapshot, t.ports, t.routes, security=t.security, storage=t.storage)


def _config(args: argparse.Namespace) -> Config:
    return getattr(args, "config", None) or Config()


def _telemetry_json(t: Telemetry, config: Config) -> dict:
    score, grade = _score(t)
    data = t.model_dump(mode="json")
    data["score"] = score
    data["grade"] = grade
    data["alerts"] = summarize_alerts(t, config.alerts)
    return data


def _collect_or_exit(collector: BaseCollector) -> Telemetry:
    try:
        return collect_telemetry(collector)
    except Exception as e:
        print(f"❌ [HATA] Telemetri toplanamadı: {e}", file=sys.stderr)
        sys.exit(EXIT_UNKNOWN)


def render_status(t: Telemetry, console: Console, config: Optional[Config] = None) -> None:
    s = t.snapshot
    score, grade = _score(t)
    alerts = summarize_alerts(t, (config or Config()).alerts)

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
        print(json.dumps(_telemetry_json(t, _config(args)), ensure_ascii=False, indent=2))
    else:
        render_status(t, Console(), _config(args))
    return EXIT_OK


def cmd_report(args: argparse.Namespace) -> int:
    t = _collect_or_exit(build_collector(args))
    if args.format == "json":
        content = json.dumps(_telemetry_json(t, _config(args)), ensure_ascii=False, indent=2)
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
    config = _config(args)
    args.warn = config.check.warn if args.warn is None else args.warn
    args.crit = config.check.crit if args.crit is None else args.crit
    if args.crit > args.warn:
        print("❌ --crit değeri --warn değerinden büyük olamaz.", file=sys.stderr)
        return EXIT_UNKNOWN
    t = _collect_or_exit(build_collector(args, interactive=False))
    score, grade = _score(t)
    alerts = summarize_alerts(t, config.alerts)
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
    p_check.add_argument("--warn", type=int, default=None, help="Bu skorun altı WARNING (varsayılan: config, yoksa 80)")
    p_check.add_argument("--crit", type=int, default=None, help="Bu skorun altı CRITICAL (varsayılan: config, yoksa 50)")
    p_check.set_defaults(func=cmd_check)

    p_config = sub.add_parser("config", help="Geçerli yapılandırmayı gösterir veya şablon oluşturur")
    p_config.add_argument("--init", action="store_true", help=f"Açıklamalı şablonu {user_config_path()} konumuna yazar")
    p_config.add_argument("--force", action="store_true", help="--init ile var olan dosyanın üzerine yazar")
    p_config.set_defaults(func=cmd_config)

    from installer import add_installer_subcommands
    add_installer_subcommands(sub)
    return parser


SUBCOMMANDS = ("status", "report", "check", "config", "update", "uninstall", "version")


def cmd_config(args: argparse.Namespace) -> int:
    if args.init:
        try:
            path = init_user_config(force=args.force)
        except ConfigError as e:
            print(f"❌ {e}", file=sys.stderr)
            return 1
        print(f"✓ Şablon oluşturuldu: {path}")
        return 0
    loaded = getattr(args, "config_files", [])
    print("# Okunan dosyalar: " + (", ".join(str(p) for p in loaded) if loaded else "yok (varsayılanlar)"))
    print(f"# Aranan konumlar: {SYSTEM_CONFIG}, {user_config_path()}")
    print()
    print(render_config(_config(args)), end="")
    return 0

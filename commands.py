"""Shared CLI plumbing and non-interactive commands (status, report, check)."""
import os
import sys
import json
import getpass
import argparse
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.markup import escape

from ui.safe import PlainTable

from collectors.base import BaseCollector, DemoCollector, create_local_collector, read_machine_id
from collectors.telemetry import collect_telemetry, summarize_alerts
from collectors.audit_exporter import calculate_audit_score, generate_audit_markdown
from models.telemetry import Telemetry
from models.services import ServiceState
from logging_setup import get_logger
from version import __version__
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


class CollectorError(Exception):
    """A host could not be connected to; the message is ready to show to the user."""


def build_collector(args: argparse.Namespace, interactive: bool = True) -> BaseCollector:
    """Like make_collector, but prints the error and exits (single-host commands and the TUI)."""
    try:
        return make_collector(args, interactive=interactive)
    except CollectorError as e:
        print(f"❌ [HATA] {e}", file=sys.stderr)
        if interactive and getattr(e, "hint", None):
            print(e.hint, file=sys.stderr)
        sys.exit(EXIT_UNKNOWN)


def make_collector(args: argparse.Namespace, interactive: bool = True) -> BaseCollector:
    """Creates and connects the collector selected by the connection arguments; raises CollectorError.

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
        if args.demo:
            return DemoCollector()
        collector = create_local_collector(use_sudo=use_sudo)
        collector.failed_login_threshold = config.alerts.ssh_failed_logins
        return collector

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
            raise CollectorError(describe_bad_host_key(e)) from e
        except UnknownHostKeyError as e:
            raise CollectorError(str(e)) from e
        except paramiko.PasswordRequiredException as e:
            if not can_prompt or transport.passphrase:
                raise CollectorError(
                    f"{target.label}: SSH anahtarı parola korumalı. ssh-agent'a ekleyin (ssh-add) veya etkileşimli çalıştırın."
                ) from e
            transport.passphrase = _getpass("🔑 SSH anahtar parolası: ")
        except paramiko.AuthenticationException as e:
            if not can_prompt or transport.password:
                raise CollectorError(f"{target.label}: kimlik doğrulaması reddedildi (anahtar/ssh-agent/şifre).") from e
            transport.password = _getpass(f"🔑 {target.label} için SSH şifresi: ")
        except (OSError, paramiko.SSHException, TransportError) as e:
            if "No authentication methods available" in str(e) and can_prompt and not transport.password:
                # No key and no agent: paramiko never reached the server's auth step
                transport.password = _getpass(f"🔑 {target.label} için SSH şifresi: ")
                continue
            if "No authentication methods available" in str(e):
                raise CollectorError(f"{target.label}: kullanılabilir SSH anahtarı yok (ssh-agent / ~/.ssh/config).") from e
            error = CollectorError(f"{target.label}{via} adresine bağlanılamadı: {e}")
            error.hint = "💡 Olası nedenler: adres/port yanlış, sunucu kapalı veya bir güvenlik duvarı engelliyor."
            raise error from e
    else:
        raise CollectorError(f"{target.label}: kimlik doğrulaması tamamlanamadı.")

    transport.disable_prompts()
    collector = SSHCollector(transport, use_sudo=use_sudo)
    collector.failed_login_threshold = config.alerts.ssh_failed_logins
    return collector


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
    """Plain-text status. Every telemetry value is escaped: hostnames, mounts and alerts come from the host."""
    s = t.snapshot
    score, grade = _score(t)
    alerts = summarize_alerts(t, (config or Config()).alerts)

    console.print(f"[bold]⚡ PulseOps[/bold]  {escape(s.hostname)}  ·  {escape(s.os_name)}  ·  "
                  f"çekirdek {escape(s.kernel)}  ·  uptime {s.uptime_human}")
    console.print(f"[bold]Sağlık skoru:[/bold] {score}/100  {escape(grade)}")
    console.print()

    vitals = PlainTable(show_header=True, header_style="bold", box=None, pad_edge=False)
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
    console.print(f"Güvenlik duvarı: {s.firewall.summary}", markup=False)
    sec = t.security
    f2b = ("kurulu değil" if not sec.fail2ban.installed else
           "durum okunamadı" if not sec.fail2ban.known else
           "ÇALIŞMIYOR" if sec.fail2ban.running is False else f"aktif, {sec.fail2ban.currently_banned} IP engelli")
    auth = (f"{sec.auth.failed_total} başarısız / {sec.auth.accepted} başarılı ({sec.auth.window})"
            if sec.auth.known else "okunamadı")
    console.print(f"SSH girişleri: {auth}  ·  fail2ban: {f2b}", markup=False)
    reboot = {True: "  ·  YENİDEN BAŞLATMA GEREKLİ", False: "", None: ""}[sec.updates.reboot_required]
    console.print(f"Güncellemeler: {sec.updates.summary}{reboot}  ·  Sertleştirme: {sec.hardening.summary}",
                  markup=False)
    console.print()

    limitations = t.privileges.limitations
    if limitations:
        console.print(f"[bold yellow]Kısıtlı erişim ({escape(t.privileges.user)}):[/bold yellow]")
        for item in limitations:
            console.print(f"  • {item}", markup=False)
        console.print(f"  {t.privileges.hint}", markup=False)
        console.print()

    if alerts:
        console.print(f"[bold red]Uyarılar ({len(alerts)}):[/bold red]")
        for a in alerts:
            console.print(f"  • {a}", markup=False)
    else:
        console.print("[bold green]Aktif uyarı yok.[/bold green]")


def _history_store(args: argparse.Namespace):
    """The local history store, or None (disabled in config, or demo data that must not pollute it)."""
    if args.demo or not _config(args).history.enabled:
        return None
    from history import HistoryStore
    return HistoryStore()


def _record_history(store, t: Telemetry, config: Config) -> list:
    """Stores a metric sample and runs drift detection. History problems never fail a command."""
    if store is None:
        return []
    try:
        score, _ = _score(t)
        store.record_sample(t, score, len(summarize_alerts(t, config.alerts)))
        return store.detect_changes(t)
    except Exception:
        get_logger("history").exception("Geçmiş kaydedilemedi")
        return []


def _recent_changes(store, t: Telemetry, hours: int = 24) -> list:
    if store is None:
        return []
    import time
    from history import host_key
    try:
        return store.changes(host_key(t), since=time.time() - hours * 3600, limit=20)
    except Exception:
        get_logger("history").exception("Geçmiş okunamadı")
        return []


def cmd_status(args: argparse.Namespace) -> int:
    t = _collect_or_exit(build_collector(args))
    store = _history_store(args)
    _record_history(store, t, _config(args))
    recent = _recent_changes(store, t)
    if args.json:
        data = _telemetry_json(t, _config(args))
        data["recent_changes"] = [c.model_dump() for c in recent]
        print(json.dumps(data, ensure_ascii=False, indent=2))
    else:
        console = Console()
        render_status(t, console, _config(args))
        if recent:
            console.print()
            console.print(f"[bold]Son 24 saatteki değişiklikler ({len(recent)}):[/bold]")
            for c in recent:
                console.print(f"  {_fmt_time(c.ts)}  [{c.severity}] {c.message}", markup=False)
    return EXIT_OK


def _fmt_time(ts: float) -> str:
    import time
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))


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


STATE_LABEL = {EXIT_OK: "OK", EXIT_WARNING: "WARNING", EXIT_CRITICAL: "CRITICAL", EXIT_UNKNOWN: "UNKNOWN"}
# Worst first when combining hosts: CRITICAL > UNKNOWN > WARNING > OK
SEVERITY_RANK = {EXIT_OK: 0, EXIT_WARNING: 1, EXIT_UNKNOWN: 2, EXIT_CRITICAL: 3}


def cmd_check(args: argparse.Namespace) -> int:
    config = _config(args)
    args.warn = config.check.warn if args.warn is None else args.warn
    args.crit = config.check.crit if args.crit is None else args.crit
    if args.crit > args.warn:
        print("❌ --crit değeri --warn değerinden büyük olamaz.", file=sys.stderr)
        return EXIT_UNKNOWN
    if getattr(args, "all", False) or getattr(args, "group", None):
        return _check_fleet(args)
    t = _collect_or_exit(build_collector(args, interactive=False))
    code, line = _check_telemetry(args, t)
    print(line)
    return code


def _check_telemetry(args: argparse.Namespace, t: Telemetry) -> tuple[int, str]:
    config = _config(args)
    score, grade = _score(t)
    alerts = summarize_alerts(t, config.alerts)
    code = evaluate_check(score, args.warn, args.crit)

    # Security drift since the previous `check` (whoever detected it: TUI, status or check)
    store = _history_store(args)
    _record_history(store, t, config)
    unreported = []
    if store is not None:
        from history import host_key
        try:
            unreported = store.take_unreported(host_key(t), "check")
        except Exception:
            get_logger("history").exception("Değişiklikler okunamadı")
    new_changes = [c for c in unreported if c.severity != "INFO"]
    if any(c.severity == "HIGH" for c in new_changes) and config.history.drift_exit != "none":
        code = max(code, EXIT_CRITICAL if config.history.drift_exit == "critical" else EXIT_WARNING)

    label = STATE_LABEL[code]
    _notify_check(args, store, t, label, score, alerts, unreported)
    summary = f"; {'; '.join(alerts)}" if alerts else ""
    if new_changes:
        summary += "; DEĞİŞİKLİK: " + "; ".join(c.message for c in new_changes)
    # Single line + perfdata, the format monitoring systems (Nagios, Icinga, Zabbix) expect
    line = (f"PULSEOPS {label} - {t.snapshot.hostname} skor {score}/100 {grade}{summary}"
            f" | score={score};{args.warn};{args.crit};0;100 alerts={len(alerts)} changes={len(new_changes)}")
    return code, line


def fleet_targets(config: Config, group: Optional[str] = None) -> list[str]:
    if group:
        if group not in config.fleet.groups:
            known = ", ".join(sorted(config.fleet.groups)) or "yok"
            raise CollectorError(f"'{group}' adında grup yok (tanımlı gruplar: {known})")
        return list(config.fleet.groups[group])
    seen: list[str] = []
    for target in config.fleet.hosts + [h for members in config.fleet.groups.values() for h in members]:
        if target not in seen:
            seen.append(target)
    return seen


def _target_args(args: argparse.Namespace, target: str) -> argparse.Namespace:
    one = argparse.Namespace(**vars(args))
    one.host, one.target, one.all, one.group = None, target, False, None
    one.demo = target in ("demo", "mock")
    return one


def _check_one_target(args: argparse.Namespace, target: str) -> tuple[int, str]:
    one = _target_args(args, target)
    try:
        t = collect_telemetry(make_collector(one, interactive=False))
    except Exception as e:  # unreachable host, auth failure, probe error...
        message = str(e) if isinstance(e, CollectorError) else f"{target}: {e}"
        _notify_unreachable(one, target, message)
        return EXIT_UNKNOWN, f"PULSEOPS UNKNOWN - {target}: {message} | score=;;;0;100"
    return _check_telemetry(one, t)


def _check_fleet(args: argparse.Namespace) -> int:
    from concurrent.futures import ThreadPoolExecutor

    config = _config(args)
    try:
        targets = fleet_targets(config, args.group)
    except CollectorError as e:
        print(f"❌ {e}", file=sys.stderr)
        return EXIT_UNKNOWN
    if not targets:
        print("Filoda sunucu yok: yapılandırmaya [fleet] hosts = [\"web01\", ...] ekleyin.", file=sys.stderr)
        return EXIT_UNKNOWN
    with ThreadPoolExecutor(max_workers=min(config.fleet.parallel, len(targets))) as pool:
        results = list(pool.map(lambda target: _check_one_target(args, target), targets))
    for _, line in results:
        print(line)
    counts = {label: sum(1 for code, _ in results if STATE_LABEL[code] == label) for label in STATE_LABEL.values()}
    print("PULSEOPS FLEET - " + ", ".join(f"{n} {label}" for label, n in counts.items() if n) + f" ({len(targets)} sunucu)")
    return max((code for code, _ in results), key=lambda c: SEVERITY_RANK[c])


def _notify_unreachable(args: argparse.Namespace, target: str, message: str) -> None:
    """An unreachable host is a state too (UNKNOWN): notify on the transition, and when it recovers."""
    store = _history_store(args)
    if store is None:
        return
    key = f"target:{target}"
    try:
        previous = store.get_meta(key, "check_state")
        store.set_meta(key, "check_state", "UNKNOWN")
    except Exception:
        get_logger("history").exception("check durumu kaydedilemedi")
        return
    config = _config(args)
    if config.notify.channels and config.notify.on_state_change and previous not in (None, "UNKNOWN"):
        from notify import Notification, dispatch
        for error in dispatch(config.notify, Notification(host=target, state="UNKNOWN", previous_state=previous,
                                                          alerts=[f"Erişilemiyor: {message}"])):
            print(f"⚠️  Bildirim gönderilemedi: {error}", file=sys.stderr)


def _notify_check(args, store, t: Telemetry, state: str, score: int, alerts: list, changes: list) -> None:
    """Sends a notification on a state transition or new security changes (never on a repeat)."""
    from notify import build_check_notification, dispatch

    config = _config(args)
    previous = None
    if store is not None:
        from history import host_key
        try:
            previous = store.get_meta(host_key(t), "check_state")
            target = getattr(args, "target", None)
            if target:
                # a host that was unreachable is tracked by its target name until it answers again
                if store.get_meta(f"target:{target}", "check_state") == "UNKNOWN":
                    previous = "UNKNOWN"
                store.set_meta(f"target:{target}", "check_state", state)
            store.set_meta(host_key(t), "check_state", state)
        except Exception:
            get_logger("history").exception("check durumu kaydedilemedi")
    if not config.notify.channels:
        return
    _warn_plaintext_secrets(args)
    n = build_check_notification(config.notify, t.snapshot.hostname, state, previous, score, alerts, changes)
    if n is None:
        return
    for error in dispatch(config.notify, n):
        print(f"⚠️  Bildirim gönderilemedi: {error}", file=sys.stderr)


def _warn_plaintext_secrets(args) -> None:
    """Literal tokens/passwords in a config file that other users can read are a leak waiting to happen."""
    import stat as stat_mod

    channels = _config(args).notify.channels
    secrets = [getattr(ch, f, "") for ch in channels for f in ("url", "bot_token", "password")]
    if not any(v and not v.startswith("env:") for v in secrets):
        return
    for path in getattr(args, "config_files", []):
        try:
            mode = path.stat().st_mode
        except OSError:
            continue
        if mode & (stat_mod.S_IRGRP | stat_mod.S_IROTH):
            print(f"⚠️  {path} başka kullanıcılar tarafından okunabiliyor ve bildirim sırları içeriyor: "
                  f"`chmod 600 {path}` veya sırlar için \"env:DEGISKEN\" kullanın.", file=sys.stderr)


def cmd_notify(args: argparse.Namespace) -> int:
    from notify import Notification, dispatch

    config = _config(args)
    if not config.notify.channels:
        print("Bildirim kanalı tanımlı değil. Örnekler için: pulseops config --init (veya pulseops config)")
        return EXIT_UNKNOWN
    _warn_plaintext_secrets(args)
    import socket
    errors = dispatch(config.notify, Notification(host=socket.gethostname(), state="OK", test=True))
    for ch in config.notify.channels:
        label = ch.name or ch.type
        failed = [e for e in errors if e.startswith(f"{label}:")]
        print(f"{'❌' if failed else '✅'} {label}" + (f": {failed[0].split(': ', 1)[1]}" if failed else ""))
    return EXIT_WARNING if errors else EXIT_OK


def terminal_supports_unicode() -> bool:
    encoding = (getattr(sys.stdout, "encoding", None) or "").lower().replace("-", "")
    return encoding.startswith("utf")


def _tui_options(args: argparse.Namespace, config: Config) -> dict:
    general = config.general
    interval = getattr(args, "interval", None)
    slow = getattr(args, "slow_interval", None)
    return {
        "interval": max(interval if interval is not None else general.interval, 0.5),
        "slow_interval": slow if slow is not None else general.slow_interval,
        "no_color": bool(getattr(args, "no_color", None)) or general.no_color,
        "ascii": bool(getattr(args, "ascii", None)) or general.ascii or not terminal_supports_unicode(),
        "mouse": general.mouse and not getattr(args, "no_mouse", None),
    }


def launch_tui(args: argparse.Namespace, config: Config, collector, log_path=None, config_files=()) -> int:
    """Runs the single-host TUI for an already connected collector."""
    from ui.app import ServerTUIApp

    opts = _tui_options(args, config)
    if opts["no_color"]:
        os.environ["NO_COLOR"] = "1"  # read by Textual when the App is constructed
    get_logger("cli").info("PulseOps %s başlatıldı (%s), aralık %.1fs / %.0fs, yapılandırma: %s",
                           __version__, type(collector).__name__, opts["interval"],
                           opts["slow_interval"], ", ".join(map(str, config_files)) or "varsayılan")
    history = None
    if config.history.enabled and not isinstance(collector, DemoCollector):
        from history import HistoryStore
        history = HistoryStore()
    if hasattr(collector, "defer_updates"):
        collector.defer_updates = True  # first screen at once; pending updates a slow tick later
    app = ServerTUIApp(
        history=history,
        collector=collector,
        poll_interval=opts["interval"],
        slow_interval=opts["slow_interval"],
        ascii_mode=opts["ascii"],
        alert_thresholds=config.alerts,
    )
    app.run(mouse=opts["mouse"])
    if app.return_code not in (None, 0) and log_path:
        print(f"PulseOps beklenmedik şekilde kapandı. Ayrıntılar: {log_path}", file=sys.stderr)
    return app.return_code or 0


def cmd_fleet(args: argparse.Namespace) -> int:
    """Fleet overview; Enter opens a host's full TUI, quitting it returns to the fleet."""
    from ui.fleet_app import FleetApp

    config = _config(args)
    try:
        targets = fleet_targets(config, args.group)
    except CollectorError as e:
        print(f"❌ {e}", file=sys.stderr)
        return EXIT_UNKNOWN
    if not targets:
        print("Filoda sunucu yok. Yapılandırmaya ekleyin (pulseops config):\n\n"
              "[fleet]\nhosts = [\"local\", \"web01\", \"deploy@10.0.0.5\"]\ngroups = { web = [\"web01\"] }",
              file=sys.stderr)
        return EXIT_UNKNOWN

    history = None
    if config.history.enabled:
        from history import HistoryStore
        history = HistoryStore()

    def connect(target: str):
        return make_collector(_target_args(args, target), interactive=False)

    opts = _tui_options(args, config)
    while True:
        fleet = FleetApp(targets, connect, config, history=history, ascii_mode=opts["ascii"],
                         interval=max(opts["interval"] * 5, 10.0))
        chosen = fleet.run(mouse=opts["mouse"])
        if not chosen:
            return EXIT_OK
        one = _target_args(args, chosen)
        try:
            collector = make_collector(one, interactive=True)
        except CollectorError as e:
            print(f"❌ {e}", file=sys.stderr)
            input("Filoya dönmek için Enter...")
            continue
        launch_tui(one, config, collector, config_files=getattr(args, "config_files", ()))


def _parse_since(value: str) -> float:
    import re
    import time
    m = re.fullmatch(r"(\d+)\s*([hdw])", value.strip().lower())
    if not m:
        raise argparse.ArgumentTypeError("süre biçimi: 6h, 24h, 7d, 2w")
    return time.time() - int(m.group(1)) * {"h": 3600, "d": 86400, "w": 604800}[m.group(2)]


def cmd_history(args: argparse.Namespace) -> int:
    """Shows stored trends and security changes without connecting to any host."""
    from history import HistoryStore
    from ui.widgets.sparkline import render_sparkline

    store = HistoryStore()
    hosts = store.hosts() if store.path.exists() else []
    if not hosts:
        print("Henüz geçmiş yok. `pulseops`, `pulseops status` veya cron ile `pulseops check` çalıştırıldıkça birikir.")
        return EXIT_OK
    if args.host:
        wanted = args.host.lower()
        matches = [h for h in hosts if h[1].lower() == wanted or h[0].startswith(wanted)]
    else:
        local_id = read_machine_id()
        matches = [h for h in hosts if h[0] == local_id] or hosts[:1]
    if len(matches) != 1:
        print("Sunucu belirsiz veya bulunamadı. Kayıtlı sunucular:")
        for host_id, name, last in hosts:
            print(f"  {name:30s} {host_id[:12]}  son görülme {_fmt_time(last)}")
        return EXIT_UNKNOWN
    host_id, hostname, last_seen = matches[0]
    since = args.since
    samples = store.samples(host_id, since)
    changes = store.changes(host_id, since=since, limit=500)

    if args.json:
        print(json.dumps({"host_id": host_id, "hostname": hostname, "samples": [x.model_dump() for x in samples],
                          "changes": [c.model_dump() for c in changes]}, ensure_ascii=False, indent=2))
        return EXIT_OK

    console = Console()
    console.print(f"[bold]⚡ {escape(hostname)}[/bold]  ({host_id[:12]})  ·  son görülme {_fmt_time(last_seen)}")
    if samples:
        table = PlainTable(box=None, pad_edge=False, header_style="bold")
        for col in ("Metrik", "Trend", "Min", "Ort", "Maks", "Son"):
            table.add_column(col, justify="left" if col in ("Metrik", "Trend") else "right")
        for label, attr, top in (("CPU %", "cpu", 100), ("RAM %", "mem", 100), ("Disk / %", "disk_root", 100),
                                 ("Load", "load1", None), ("Skor", "score", 100), ("Uyarı", "alerts", None)):
            values = [float(getattr(x, attr)) for x in samples]
            hi = top if top is not None else max(max(values), 1.0)
            table.add_row(label, render_sparkline(values, 0.0, hi, width=40),
                          f"{min(values):.1f}", f"{sum(values) / len(values):.1f}", f"{max(values):.1f}", f"{values[-1]:.1f}")
        console.print(f"{len(samples)} örnek, {_fmt_time(samples[0].ts)} → {_fmt_time(samples[-1].ts)}")
        console.print(table)
    else:
        console.print("Bu aralıkta metrik örneği yok.")
    console.print()
    if changes:
        console.print(f"[bold]Güvenlik değişiklikleri ({len(changes)}):[/bold]")
        for c in changes:
            console.print(f"  {_fmt_time(c.ts)}  [{c.severity}] {c.message}", markup=False)
    else:
        console.print("Bu aralıkta güvenlik değişikliği yok.")
    return EXIT_OK


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
    p_check.add_argument("--all", action="store_true", help="[fleet] içindeki tüm sunucuları paralel kontrol et")
    p_check.add_argument("--group", default=None, help="Yalnızca bu filo grubunu kontrol et")
    p_check.add_argument("--warn", type=int, default=None, help="Bu skorun altı WARNING (varsayılan: config, yoksa 80)")
    p_check.add_argument("--crit", type=int, default=None, help="Bu skorun altı CRITICAL (varsayılan: config, yoksa 50)")
    p_check.set_defaults(func=cmd_check)

    p_config = sub.add_parser("config", help="Geçerli yapılandırmayı gösterir veya şablon oluşturur")
    p_config.add_argument("--init", action="store_true", help=f"Açıklamalı şablonu {user_config_path()} konumuna yazar")
    p_config.add_argument("--force", action="store_true", help="--init ile var olan dosyanın üzerine yazar")
    p_config.set_defaults(func=cmd_config)

    p_history = sub.add_parser("history", help="Kayıtlı trendleri ve güvenlik değişikliklerini gösterir (bağlantı kurmaz)")
    p_history.add_argument("host", nargs="?", help="Hostname veya makine kimliği öneki (varsayılan: bu makine)")
    p_history.add_argument("--since", type=_parse_since, default="24h", help="Zaman aralığı: 6h, 24h, 7d, 2w (varsayılan: 24h)")
    p_history.add_argument("--json", action="store_true", help="JSON çıktı")
    p_history.set_defaults(func=cmd_history)

    p_fleet = sub.add_parser("fleet", help="Filo görünümü: [fleet] içindeki tüm sunucular tek ekranda")
    p_fleet.add_argument("--group", default=None, help="Yalnızca bu grup")
    p_fleet.add_argument("--ascii", action="store_true", default=None, help=argparse.SUPPRESS)
    p_fleet.add_argument("--no-mouse", action="store_true", default=None, help=argparse.SUPPRESS)
    for name in ("user", "port", "key", "jump", "host", "target", "password"):
        p_fleet.set_defaults(**{name: None})
    p_fleet.set_defaults(func=cmd_fleet, demo=False, live=False)

    p_notify = sub.add_parser("notify", help="Bildirim kanallarına deneme mesajı gönderir")
    p_notify.add_argument("--test", action="store_true", required=True, help="Her kanala deneme mesajı gönder")
    p_notify.set_defaults(func=cmd_notify)

    p_probe = sub.add_parser("probe", help="Sunucuda çalıştırılan salt-okunur betiği gösterir (denetim için)")
    p_probe.add_argument("--tier", choices=["fast", "slow", "logs", "all"], default="all",
                         help="fast: her 2 sn, slow: her 30 sn, logs: Loglar sekmesi açıkken (varsayılan: all)")
    p_probe.add_argument("--sudo", choices=["auto", "on", "off"], default="auto",
                         help="auto: ilk turdaki gibi `sudo -n true` ile tespit (varsayılan)")
    p_probe.set_defaults(func=cmd_probe)

    from installer import add_installer_subcommands
    add_installer_subcommands(sub)
    return parser


SUBCOMMANDS = ("status", "report", "check", "fleet", "history", "notify", "config", "probe", "update", "uninstall", "version")


def cmd_probe(args: argparse.Namespace) -> int:
    """Prints the exact read-only shell script PulseOps runs on a host, for review by auditors."""
    from collectors.probe import build_script

    tiers = {"fast": dict(fast=True), "slow": dict(fast=False, slow=True), "logs": dict(fast=False, logs=True),
             "all": dict(fast=True, slow=True, logs=True)}[args.tier]
    sudo = None if args.sudo == "auto" else args.sudo == "on"
    script, nonce = build_script(**tiers, sudo=sudo)
    print(script.replace(nonce, "<nonce>"), end="")
    return EXIT_OK


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

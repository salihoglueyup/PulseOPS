"""`pulseops schedule`: run `pulseops check` periodically from a systemd timer (an alternative to cron).

root  -> /etc/systemd/system/pulseops-check.{service,timer}
other -> ~/.config/systemd/user/pulseops-check.{service,timer} (systemctl --user)

The check's exit code (1 WARNING / 2 CRITICAL / 3 UNKNOWN) is a monitoring result, not a failure of
the unit, so the service treats all four as success; alerts go out through [notify].
"""
import argparse
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

UNIT = "pulseops-check"
DEFAULT_ARGS = "check"


def parse_interval(text: str) -> int:
    """'30s' / '5m' / '2h' / '300' -> seconds (minimum 60: the probe itself takes a few seconds)."""
    m = re.fullmatch(r"\s*(\d+)\s*([smh]?)\s*", text)
    if not m:
        raise ValueError(f"geçersiz aralık: {text!r} (örnek: 5m, 1h, 300)")
    seconds = int(m.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600}[m.group(2)]
    if seconds < 60:
        raise ValueError("aralık en az 60 saniye olmalı")
    return seconds


def _unit_escape(arg: str) -> str:
    """One ExecStart argument: systemd expands % specifiers and $ variables, so both are doubled."""
    return shlex.quote(arg).replace("%", "%%").replace("$", "$$")


def executable() -> Optional[str]:
    """Absolute path of the pulseops command that should run from the timer."""
    if getattr(sys, "frozen", False):
        return str(Path(sys.executable).resolve())
    found = shutil.which("pulseops")
    return str(Path(found).resolve()) if found else None


def render_units(exe: str, check_args: list[str], interval: int, system: bool) -> tuple[str, str]:
    command = " ".join(_unit_escape(a) for a in [exe, *check_args])
    hardening = (
        "# Read-only for the system; history (~/.local/share) and -o files stay writable\n"
        "ProtectSystem=full\nPrivateTmp=yes\n"
        if system else ""
    )
    service = f"""[Unit]
Description=PulseOps health and security check
Documentation=https://github.com/salihoglueyup/PulseOPS
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart={command}
# 1/2/3 are WARNING/CRITICAL/UNKNOWN results, not unit failures
SuccessExitStatus=0 1 2 3
Nice=10
IOSchedulingClass=idle
TimeoutStartSec=300
{hardening}"""
    timer = f"""[Unit]
Description=Run PulseOps check every {interval} seconds

[Timer]
OnBootSec=2min
OnUnitActiveSec={interval}s
RandomizedDelaySec=30s
AccuracySec=15s

[Install]
WantedBy=timers.target
"""
    return service, timer


def unit_dir(system: bool) -> Path:
    if system:
        return Path("/etc/systemd/system")
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "systemd" / "user"


def _systemctl(system: bool, *args: str) -> int:
    cmd = ["systemctl"] + ([] if system else ["--user"]) + list(args)
    try:
        return subprocess.call(cmd)
    except FileNotFoundError:
        print("❌ systemctl bulunamadı: bu sistem systemd kullanmıyor; cron kullanın (README).", file=sys.stderr)
        return 1


def _is_system(args: argparse.Namespace) -> bool:
    return not args.user and hasattr(os, "geteuid") and os.geteuid() == 0


def cmd_schedule(args: argparse.Namespace) -> int:
    system = _is_system(args)
    directory = unit_dir(system)
    service_path, timer_path = directory / f"{UNIT}.service", directory / f"{UNIT}.timer"

    if args.action == "remove":
        if not service_path.exists() and not timer_path.exists():
            print("Kurulu zamanlama yok.")
            return 0
        _systemctl(system, "disable", "--now", f"{UNIT}.timer")
        for path in (service_path, timer_path):
            path.unlink(missing_ok=True)
        _systemctl(system, "daemon-reload")
        print(f"✓ Zamanlama kaldırıldı ({directory})")
        return 0

    if args.action == "status":
        if not timer_path.exists():
            print("Kurulu zamanlama yok. Kurmak için: pulseops schedule install")
            return 1
        _systemctl(system, "list-timers", "--no-pager", f"{UNIT}.timer")
        # `systemctl status` exits 3 for an inactive oneshot between runs, which is the normal state
        _systemctl(system, "status", "--no-pager", "--lines=5", f"{UNIT}.service")
        return 0

    # install / show
    try:
        interval = parse_interval(args.every)
        check_args = shlex.split(args.args)
    except ValueError as e:
        print(f"❌ {e}", file=sys.stderr)
        return 2
    if not check_args or check_args[0] != "check":
        print("❌ --args bir `check` komutu olmalı (ör. \"check --all -f prometheus -o /var/lib/...\")", file=sys.stderr)
        return 2
    exe = executable()
    if not exe:
        print("❌ pulseops komutu PATH'te bulunamadı; önce install.sh ile kurun.", file=sys.stderr)
        return 1
    service, timer = render_units(exe, check_args, interval, system)

    if args.action == "show":
        print(f"# {service_path}\n{service}\n# {timer_path}\n{timer}", end="")
        return 0

    try:
        directory.mkdir(parents=True, exist_ok=True)
        service_path.write_text(service, encoding="utf-8")
        timer_path.write_text(timer, encoding="utf-8")
    except OSError as e:
        print(f"❌ {directory} yazılamadı: {e}", file=sys.stderr)
        return 1
    if _systemctl(system, "daemon-reload") != 0 or _systemctl(system, "enable", "--now", f"{UNIT}.timer") != 0:
        print(f"⚠️  Birimler yazıldı ({directory}) ama etkinleştirilemedi.", file=sys.stderr)
        return 1
    scope = "sistem" if system else "kullanıcı (oturum kapalıyken de çalışması için: loginctl enable-linger)"
    print(f"✓ Her {interval} sn'de `{' '.join(check_args)}` çalışacak ({scope} zamanlayıcısı, {directory})")
    print("  Durum: pulseops schedule status · Kaldırma: pulseops schedule remove")
    return 0


def add_schedule_subcommand(sub) -> None:
    p = sub.add_parser("schedule", help="`pulseops check`'i systemd zamanlayıcısıyla düzenli çalıştırır")
    p.add_argument("action", choices=["install", "show", "status", "remove"],
                   help="install: kur ve başlat · show: birimleri yalnızca göster · status · remove")
    p.add_argument("--every", default="5m", help="Çalışma aralığı: 5m, 1h, 300 (varsayılan: 5m, en az 60 sn)")
    p.add_argument("--args", default=DEFAULT_ARGS,
                   help='Çalıştırılacak check komutu (varsayılan: "check"), ör. "check --all -f prometheus -o FILE"')
    p.add_argument("--user", action="store_true", help="root olsa bile kullanıcı zamanlayıcısı kur (systemctl --user)")
    p.set_defaults(func=cmd_schedule)

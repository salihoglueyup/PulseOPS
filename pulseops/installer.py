"""Self-management commands: version, update, uninstall.

PulseOps can be installed three ways on Linux and each is updated/removed differently:
  * binary  - standalone PyInstaller executable downloaded by install.sh
  * venv    - isolated virtualenv in ~/.local/share/pulseops created by install.sh
  * pipx    - `pipx install git+...`
Anything else (e.g. `pip install -e .` in a dev checkout) is left alone.
"""
import os
import sys
import json
import shutil
import hashlib
import argparse
import subprocess
import tempfile
import urllib.request
from pathlib import Path
from typing import Optional

from pulseops.version import __version__

REPO = os.environ.get("PULSEOPS_REPO_SLUG", "salihoglueyup/PulseOPS")
BINARY_ASSET = "pulseops-linux-amd64"
VENV_INSTALL_DIR = Path.home() / ".local" / "share" / "pulseops"
LINK_DIRS = (Path("/usr/local/bin"), Path.home() / ".local" / "bin")
LINK_NAMES = ("pulseops", "pulsetui")


PACKAGE_BINARY = Path("/usr/bin/pulseops")  # where the .deb/.rpm installs it (install.sh never does)


def detect_install_mode(
    frozen: Optional[bool] = None,
    prefix: Optional[str] = None,
    venv_dir: Path = VENV_INSTALL_DIR,
    executable: Optional[str] = None,
) -> str:
    """Returns 'package', 'binary', 'venv', 'pipx' or 'source'."""
    frozen = getattr(sys, "frozen", False) if frozen is None else frozen
    if frozen:
        exe = Path(executable or sys.executable).resolve()
        return "package" if exe == PACKAGE_BINARY else "binary"
    prefix_path = Path(sys.prefix if prefix is None else prefix).resolve()
    if prefix_path == (venv_dir / "venv").resolve():
        return "venv"
    if "pipx" in prefix_path.parts and prefix_path.name == "pulseops":
        return "pipx"
    return "source"


def parse_version(tag: str) -> tuple[int, ...]:
    """'v1.2.10' -> (1, 2, 10). Non-numeric suffixes are ignored."""
    parts = []
    for chunk in tag.strip().lstrip("vV").split("."):
        digits = ""
        for c in chunk:
            if not c.isdigit():
                break
            digits += c
        if not digits:
            break
        parts.append(int(digits))
        if len(digits) != len(chunk):
            break
    return tuple(parts)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def verify_checksum(path: Path, checksum_text: str) -> bool:
    """Accepts both a bare hash and `sha256sum` output ('<hash>  <file>')."""
    expected = checksum_text.strip().split()[0].lower() if checksum_text.strip() else ""
    return bool(expected) and sha256_file(path) == expected


def find_links(target: Path, link_dirs=LINK_DIRS) -> list[Path]:
    """Symlinks named pulseops/pulsetui in link_dirs that point at target (or inside it, if a directory)."""
    target = target.resolve()
    found = []
    for d in link_dirs:
        for name in LINK_NAMES:
            link = d / name
            if not link.is_symlink():
                continue
            resolved = link.resolve()
            if resolved == target or target in resolved.parents:
                found.append(link)
    return found


def _http_get(url: str, timeout: float = 15.0) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": f"pulseops/{__version__}"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def latest_release_tag() -> str:
    data = json.loads(_http_get(f"https://api.github.com/repos/{REPO}/releases/latest"))
    return data["tag_name"]


def _confirm(question: str, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        print("Etkileşimsiz ortam: onay için --yes kullanın.", file=sys.stderr)
        return False
    return input(f"{question} [e/H]: ").strip().lower() in ("e", "evet", "y", "yes")


def _update_binary(exe: Path, force: bool) -> int:
    try:
        tag = latest_release_tag()
    except Exception as e:
        print(f"❌ Son sürüm bilgisi alınamadı: {e}", file=sys.stderr)
        return 1
    if not force and parse_version(tag) <= parse_version(__version__):
        print(f"✓ Zaten güncel: {__version__} (son sürüm {tag})")
        return 0
    if not os.access(exe.parent, os.W_OK):
        print(f"❌ {exe.parent} dizinine yazma izni yok. `sudo pulseops update` ile tekrar deneyin.", file=sys.stderr)
        return 1

    base = f"https://github.com/{REPO}/releases/download/{tag}"
    print(f"⬇️  {tag} indiriliyor...")
    fd, tmp_name = tempfile.mkstemp(prefix=".pulseops-update-", dir=exe.parent)
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(_http_get(f"{base}/{BINARY_ASSET}", timeout=120))
        checksum = _http_get(f"{base}/{BINARY_ASSET}.sha256").decode()
        if not verify_checksum(tmp, checksum):
            print("❌ SHA-256 doğrulaması başarısız, güncelleme iptal edildi.", file=sys.stderr)
            return 1
        tmp.chmod(0o755)
        os.replace(tmp, exe)
    except Exception as e:
        print(f"❌ Güncelleme başarısız: {e}", file=sys.stderr)
        return 1
    finally:
        tmp.unlink(missing_ok=True)
    print(f"✓ PulseOps {tag} sürümüne güncellendi.")
    return 0


def cmd_version(args: argparse.Namespace) -> int:
    print(f"pulseops {__version__} ({detect_install_mode()})")
    return 0


PACKAGE_UPDATE_HINT = """PulseOps paket yöneticisiyle kurulmuş; güncellemek için yeni paketi indirip kurun:
  Debian/Ubuntu:    sudo apt install ./pulseops_<sürüm>-1_amd64.deb
  RHEL/Alma/Fedora: sudo dnf install ./pulseops-<sürüm>-1.x86_64.rpm"""

PACKAGE_REMOVE_HINT = """PulseOps paket yöneticisiyle kurulmuş; kaldırmak için:
  Debian/Ubuntu:    sudo apt remove pulseops
  RHEL/Alma/Fedora: sudo dnf remove pulseops"""


def cmd_update(args: argparse.Namespace) -> int:
    mode = detect_install_mode()
    if mode == "package":
        print(PACKAGE_UPDATE_HINT, file=sys.stderr)
        print(f"Yeni sürümler: https://github.com/{REPO}/releases/latest", file=sys.stderr)
        return 1
    repo_url = f"git+https://github.com/{REPO}.git"
    if mode == "binary":
        return _update_binary(Path(sys.executable).resolve(), args.force)
    if mode == "venv":
        return subprocess.call([sys.executable, "-m", "pip", "install", "--upgrade", "--quiet", repo_url])
    if mode == "pipx":
        return subprocess.call(["pipx", "install", "--force", repo_url])
    print("Bu kurulum kaynak koddan yapılmış; `git pull` ile güncelleyin.", file=sys.stderr)
    return 1


def cmd_uninstall(args: argparse.Namespace) -> int:
    mode = detect_install_mode()
    if mode == "package":
        print(PACKAGE_REMOVE_HINT, file=sys.stderr)
        return 1
    if mode == "source":
        print("Bu kurulum kaynak koddan yapılmış; `pip uninstall pulseops` ile kaldırın.", file=sys.stderr)
        return 1

    if mode == "binary":
        target = Path(sys.executable).resolve()
    elif mode == "venv":
        target = VENV_INSTALL_DIR
    else:
        target = Path(sys.prefix).resolve()

    links = find_links(target)
    print("Kaldırılacaklar:")
    print(f"  • {target}" + (" (pipx)" if mode == "pipx" else ""))
    for link in links:
        print(f"  • {link} (kısayol)")
    if not _confirm("PulseOps kaldırılsın mı?", args.yes):
        print("İptal edildi.")
        return 1

    failed = False
    for link in links:
        try:
            link.unlink()
        except PermissionError:
            print(f"⚠️  {link} silinemedi (izin yok). `sudo rm {link}` çalıştırın.", file=sys.stderr)
            failed = True

    if mode == "binary":
        target.unlink()
    elif mode == "venv":
        shutil.rmtree(target)
    else:
        if subprocess.call(["pipx", "uninstall", "pulseops"]) != 0:
            failed = True

    print("✓ PulseOps kaldırıldı." if not failed else "PulseOps kaldırıldı, ancak bazı kısayollar elle silinmeli.")
    return 1 if failed else 0


def add_installer_subcommands(sub) -> None:
    p_version = sub.add_parser("version", help="Sürüm ve kurulum türünü gösterir")
    p_version.set_defaults(func=cmd_version)

    p_update = sub.add_parser("update", help="PulseOps'u en son sürüme günceller")
    p_update.add_argument("--force", action="store_true", help="Sürüm aynı olsa bile yeniden indirir")
    p_update.set_defaults(func=cmd_update)

    p_uninstall = sub.add_parser("uninstall", help="PulseOps'u bu sistemden kaldırır")
    p_uninstall.add_argument("-y", "--yes", action="store_true", help="Onay sormadan kaldırır")
    p_uninstall.set_defaults(func=cmd_uninstall)

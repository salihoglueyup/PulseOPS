import os
import shutil

from pulseops.models.privileges import PrivilegeInfo

def _docker_socket_accessible() -> bool:
    if os.environ.get("DOCKER_HOST"):
        return True
    sock = "/var/run/docker.sock"
    return os.path.exists(sock) and os.access(sock, os.R_OK | os.W_OK)


def collect_local_privileges() -> PrivilegeInfo:
    """Privileges of the current process. The local collector never uses sudo, so only root is elevated."""
    if not hasattr(os, "geteuid"):
        # Non-POSIX platform (e.g. a Windows dev machine): no uid model, report no limitations
        return PrivilegeInfo()
    import pwd

    uid = os.geteuid()
    try:
        user = pwd.getpwuid(uid).pw_name
    except KeyError:
        user = str(uid)
    docker_installed = shutil.which("docker") is not None
    return PrivilegeInfo(
        user=user,
        is_root=uid == 0,
        elevated=uid == 0,
        docker_installed=docker_installed,
        docker_access=docker_installed and (uid == 0 or _docker_socket_accessible()),
    )


def parse_privileges_section(text: str) -> PrivilegeInfo:
    """Parses the PRIV probe section. The probe falls back to `sudo -n`, so passwordless sudo counts as elevated."""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) < 2 or not lines[1].isdigit():
        # Unknown (old probe or failed command): assume full access rather than showing false warnings
        return PrivilegeInfo()
    user, uid = lines[0], int(lines[1])
    flags = set(lines[2:])
    is_root = uid == 0
    sudo_ok = "sudo_ok" in flags
    docker_installed = "docker_installed" in flags
    return PrivilegeInfo(
        user=user,
        is_root=is_root,
        elevated=is_root or sudo_ok,
        docker_installed=docker_installed,
        docker_access=docker_installed and (is_root or sudo_ok or "docker_ok" in flags),
    )


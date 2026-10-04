"""Storage analysis: Docker disk usage, filesystem health (inodes, read-only remounts), log bloat,
deleted-but-open files, largest directories, and data-driven cleanup advice.

Everything here parses probe output (see the DOCKER_DF, CONTAINERD_SZ and STORAGE probe sections);
nothing is estimated or made up: a value that could not be read stays empty/None.
"""
import json
import math
import re
import shutil
import subprocess
from typing import Optional

from pulseops.models.storage import (
    DeletedOpenFile, FileUsage, StorageItem, StorageOverview, human_bytes,
)

BUILDKIT_BLOAT_BYTES = 10 * 1024**3
MIN_DELETED_BYTES = 1024**2  # smaller deleted-but-open files (temp files, sockets' backing) are noise
_SIZE = re.compile(r"^\s*([0-9]+(?:\.[0-9]+)?)\s*([kKMGTP]?i?B?)\s*$")
# docker formats sizes with go-units HumanSize: decimal (1 GB = 1000^3)
_DECIMAL = {"": 1, "B": 1, "KB": 1e3, "kB": 1e3, "MB": 1e6, "GB": 1e9, "TB": 1e12, "PB": 1e15,
            "KIB": 1024, "MIB": 1024**2, "GIB": 1024**3, "TIB": 1024**4}


def parse_docker_size(text: str) -> int:
    """'1.324GB' / '12.5GB (99%)' / '0B' -> bytes; anything unreadable -> 0."""
    m = _SIZE.match(str(text).split("(")[0])
    if not m:
        return 0
    unit = m.group(2)
    factor = _DECIMAL.get(unit) or _DECIMAL.get(unit.upper())
    value = float(m.group(1)) * (factor or 0)
    return int(value) if math.isfinite(value) else 0


def _percent(text: str) -> float:
    m = re.search(r"\((\d+(?:\.\d+)?)%\)", str(text))
    return float(m.group(1)) if m else 0.0


def _int_or_none(value) -> Optional[int]:
    text = str(value).strip()
    return int(text) if text.isdecimal() else None


class StorageCollector:
    def parse_docker_df(self, text: str, containerd_sz_txt: str = "") -> StorageOverview:
        """`docker system df --format '{{json .}}'` (or the table form) and `du -sk <image store>`."""
        items: list[StorageItem] = []
        for line in text.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                data = json.loads(line)
            except ValueError:
                continue
            if not isinstance(data, dict):
                continue
            items.append(self._item(str(data.get("Type", "?")), data.get("TotalCount"), data.get("Active"),
                                    str(data.get("Size", "0B")), str(data.get("Reclaimable", "0B"))))
        if not items:  # older docker: plain table
            for line in text.splitlines():
                parts = line.split()
                if not parts or parts[0] == "TYPE":
                    continue
                if parts[:2] in (["Build", "Cache"], ["Local", "Volumes"]):
                    parts = [" ".join(parts[:2])] + parts[2:]
                if len(parts) >= 5:
                    items.append(self._item(parts[0], parts[1], parts[2], parts[3], " ".join(parts[4:])))

        buildkit = sum(i.total_bytes for i in items if "build" in i.name.lower())
        for i in items:
            i.is_critical = "build" in i.name.lower() and buildkit > BUILDKIT_BLOAT_BYTES

        containerd = None
        first = containerd_sz_txt.strip().split()[:1]
        if first and first[0].isdecimal():
            containerd = int(first[0]) * 1024
        return StorageOverview(items=items, buildkit_cache_bytes=buildkit, containerd_bytes=containerd,
                               is_cache_bloated=buildkit > BUILDKIT_BLOAT_BYTES)

    @staticmethod
    def _item(name, count, active, size, reclaimable) -> StorageItem:
        return StorageItem(name=name, total_bytes=parse_docker_size(size),
                           reclaimable_bytes=parse_docker_size(reclaimable),
                           reclaimable_percent=_percent(reclaimable),
                           count=_int_or_none(count), active=_int_or_none(active))

    def apply_storage_section(self, ov: StorageOverview, text: str) -> StorageOverview:
        """Merges the STORAGE probe section into an overview (returns a new one)."""
        ov = ov.model_copy(deep=True)
        blocks: dict[str, list[str]] = {}
        current = None
        for raw in text.splitlines():
            line = raw.rstrip()
            if line.startswith("#") and line[1:].split(" ")[0].replace("_", "").isupper():
                key, _, rest = line[1:].partition(" ")
                current = key
                blocks.setdefault(key, [])
                if rest:
                    blocks[key].append(rest)
            elif line.strip() and current is not None:
                blocks[current].append(line)
        if "INODES" not in blocks:
            return ov
        ov.known = True
        ov.complete = (blocks.get("SCOPE") or [""])[0] == "full"

        for line in blocks.get("INODES", [])[1:]:
            parts = line.split()
            if len(parts) >= 6 and parts[4].endswith("%") and parts[4][:-1].isdecimal():
                ov.inode_percent[" ".join(parts[5:])] = float(parts[4][:-1])
        ov.read_only_mounts = sorted(set(blocks.get("RO", [])))

        journal = " ".join(blocks.get("JOURNAL", []))
        m = re.search(r"take up ([0-9.]+)\s*([KMGTP]?)B?\b", journal)
        if m:
            value = float(m.group(1)) * {"": 1, "K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4, "P": 1024**5}[m.group(2)]
            ov.journal_bytes = int(value) if math.isfinite(value) else None

        varlog = blocks.get("VARLOG", [])
        ov.var_log_bytes = int(varlog[0]) * 1024 if varlog and varlog[0].isdecimal() else None
        ov.big_logs = self._size_path_list(blocks.get("BIGLOGS", []))
        ov.docker_logs = self._size_path_list(blocks.get("DOCKERLOGS", []))

        seen_inodes = set()
        for line in blocks.get("DELETED", []):
            parts = line.split(" ", 4)  # size inode pid comm path
            if len(parts) < 5 or not (parts[0].isdecimal() and parts[1].isdecimal() and parts[2].isdecimal()):
                continue
            path = parts[4].removesuffix(" (deleted)")
            if parts[1] in seen_inodes or path.startswith(("/memfd:", "/SYSV", "/dev/")):
                continue
            seen_inodes.add(parts[1])
            if int(parts[0]) >= MIN_DELETED_BYTES:
                ov.deleted_open.append(DeletedOpenFile(pid=int(parts[2]), process=parts[3], path=path,
                                                       bytes=int(parts[0])))
        ov.deleted_open.sort(key=lambda f: -f.bytes)
        ov.deleted_open = ov.deleted_open[:20]

        dirs = blocks.get("TOPDIRS", [])
        ov.top_dirs_partial = any(line.startswith("RC ") and line != "RC 0" for line in dirs)
        entries = self._size_path_list([line for line in dirs if not line.startswith("RC ")], unit=1024)
        ov.top_dirs = [e for e in entries if e.path != "/"][:12]
        return ov

    @staticmethod
    def _size_path_list(lines: list[str], unit: int = 1) -> list[FileUsage]:
        out = []
        for line in lines:
            size, _, path = line.strip().partition(" ") if "\t" not in line else line.strip().partition("\t")
            if size.isdecimal() and path.strip():
                out.append(FileUsage(path=path.strip(), bytes=int(size) * unit))
        return sorted(out, key=lambda f: -f.bytes)


def storage_recommendations(st: StorageOverview, disks: list) -> list[str]:
    """Advice derived only from what was measured."""
    recs: list[str] = []
    for mount in st.critical_read_only:
        recs.append(f"[DIKKAT] {mount} salt-okunur bağlanmış: dosya sistemi hatası olabilir. "
                    "`dmesg | tail` ve `journalctl -k` ile kontrol edin, gerekirse fsck planlayın.")
    for mount, pct in sorted(st.inode_percent.items(), key=lambda kv: -kv[1]):
        if pct >= 90:
            recs.append(f"[DIKKAT] {mount} inode'ları %{pct:.0f} dolu: disk boş görünse de yeni dosya oluşturulamaz. "
                        f"Çok küçük dosya biriken dizini bulun: `find {mount} -xdev -type d -size +1M`.")
    if st.forecast_days is not None and st.forecast_days < 30:
        recs.append(f"[UYARI] Bu hızla (%{st.growth_percent_per_day:.2f}/gün) kök disk yaklaşık "
                    f"{st.forecast_days:.0f} gün içinde dolacak.")
    if st.deleted_open_bytes >= 100 * 1024**2:
        top = st.deleted_open[0]
        recs.append(f"[FIRSAT] Silinmiş ama hâlâ açık dosyalar {human_bytes(st.deleted_open_bytes)} tutuyor "
                    f"(en büyüğü: {top.process} pid {top.pid}, {human_bytes(top.bytes)}). "
                    "Alan, süreç yeniden başlatılınca boşalır.")
    if st.docker_log_bytes >= 1024**3:
        recs.append(f"[FIRSAT] Docker konteyner logları {human_bytes(st.docker_log_bytes)}. Kalıcı çözüm: "
                    '/etc/docker/daemon.json → "log-opts": {"max-size": "50m", "max-file": "3"}.')
    if st.journal_bytes is not None and st.journal_bytes >= 2 * 1024**3:
        recs.append(f"[FIRSAT] journald {human_bytes(st.journal_bytes)} kullanıyor: "
                    "`journalctl --vacuum-size=500M`, kalıcı: journald.conf SystemMaxUse=500M.")
    if st.big_logs:
        biggest = st.big_logs[0]
        recs.append(f"[BILGI] En büyük log: {biggest.path} ({human_bytes(biggest.bytes)}). "
                    "logrotate yapılandırmasını kontrol edin.")
    if st.is_cache_bloated:
        recs.append(f"[DIKKAT] BuildKit önbelleği {st.buildkit_cache_human}: "
                    "`docker builder prune -f --keep-storage 10GB` (çalışan konteynerlere dokunmaz).")
    if st.docker_reclaimable_bytes >= 5 * 1024**3:
        recs.append(f"[FIRSAT] Docker'da {human_bytes(st.docker_reclaimable_bytes)} geri kazanılabilir: "
                    "`docker system df -v` ile inceleyin, `docker image prune -a` / `docker volume prune`.")
    if st.known and not st.complete:
        recs.append("[BILGI] Root olmadan büyük dosya, silinmiş-açık dosya ve dizin analizi eksik kalır "
                    "(`sudo pulseops`).")
    if not recs and (st.known or disks):
        recs.append("[GUVENLI] Depolama sağlıklı: inode, salt-okunur bağlama, log ve önbellek sorunu yok.")
    return recs


def disk_forecast(samples: list, min_hours: float = 6.0, min_samples: int = 12) -> tuple[Optional[float], Optional[float]]:
    """Least-squares trend of root disk usage -> (days until 100 %, % per day); (None, rate) when not growing."""
    points = [(s.ts, s.disk_root) for s in samples if s.disk_root]
    if len(points) < min_samples or points[-1][0] - points[0][0] < min_hours * 3600:
        return None, None
    n = len(points)
    mean_t = sum(t for t, _ in points) / n
    mean_d = sum(d for _, d in points) / n
    var = sum((t - mean_t) ** 2 for t, _ in points)
    if var == 0:
        return None, None
    slope_per_day = sum((t - mean_t) * (d - mean_d) for t, d in points) / var * 86400
    if slope_per_day <= 0.01:  # flat or shrinking (noise below 0.01 %/day)
        return None, round(slope_per_day, 3)
    current = points[-1][1]
    return max(0.0, (100.0 - current) / slope_per_day), round(slope_per_day, 3)


def apply_forecast(st: StorageOverview, samples: list, disks: Optional[list] = None) -> StorageOverview:
    """Adds the root disk fill forecast from history samples and refreshes the advice."""
    st = st.model_copy()
    st.forecast_days, st.growth_percent_per_day = disk_forecast(samples)
    st.recommendations = storage_recommendations(st, disks or [])
    return st


def collect_local_storage(root_path: str = "/") -> StorageOverview:
    """psutil-based fallback for non-Linux development machines (no probe)."""
    import psutil

    ov = StorageOverview()
    try:
        du = psutil.disk_usage(root_path)
        ov.root_used_gb, ov.root_total_gb, ov.root_percent = du.used / 1024**3, du.total / 1024**3, du.percent
    except Exception:
        pass
    if shutil.which("docker"):
        try:
            out = subprocess.run(["docker", "system", "df", "--format", "{{json .}}"],
                                 capture_output=True, text=True, timeout=4).stdout
            docker = StorageCollector().parse_docker_df(out)
            ov.items, ov.buildkit_cache_bytes, ov.is_cache_bloated = docker.items, docker.buildkit_cache_bytes, docker.is_cache_bloated
        except Exception:
            pass
    ov.recommendations = storage_recommendations(ov, [])
    return ov

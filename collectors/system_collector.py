import os
import time
import platform
from pathlib import Path
from typing import Optional
import psutil

from models.system import (
    CpuMetric,
    MemoryMetric,
    DiskPartition,
    NetworkRate,
    SystemSnapshot,
    ProcessInfo,
    DiskIoRate,
    FirewallStatus,
)
from collectors.firewall_collector import FirewallCollector

class SystemCollector:
    """Collects system-level hardware, memory, disk, and network rate metrics."""

    def __init__(self):
        self._last_net_time: float = time.time()
        self._last_net_io = psutil.net_io_counters(pernic=True)
        self._last_disk_time: float = time.time()
        self._last_disk_io = psutil.disk_io_counters()
        self.firewall_collector = FirewallCollector()
        self._proc_cache: dict[int, psutil.Process] = {}
        # prime cpu measurement
        psutil.cpu_percent(interval=None)
        try:
            for p in psutil.process_iter(['pid', 'name']):
                if p.pid != 0:
                    self._proc_cache[p.pid] = p
                    try:
                        p.cpu_percent()
                    except Exception:
                        pass
        except Exception:
            pass

    def _get_os_pretty_name(self) -> str:
        """Reads /etc/os-release on Linux or falls back to platform.system()."""
        os_release = Path("/etc/os-release")
        if os_release.exists():
            try:
                for line in os_release.read_text(encoding="utf-8").splitlines():
                    if line.startswith("PRETTY_NAME="):
                        return line.split("=", 1)[1].strip('"\'')
            except Exception:
                pass
        return f"{platform.system()} {platform.release()}"

    def _get_load_avg(self) -> tuple[float, float, float]:
        """Gets system load average, or (0.0, 0.0, 0.0) if unsupported (e.g. Windows)."""
        if hasattr(os, "getloadavg"):
            try:
                return os.getloadavg()
            except Exception:
                pass
        return (0.0, 0.0, 0.0)

    def collect_snapshot(self) -> SystemSnapshot:
        """Polls current system vitals and returns a typed SystemSnapshot."""
        now = time.time()
        
        # 1. CPU
        total_cpu = psutil.cpu_percent(interval=None)
        if total_cpu == 0.0:
            total_cpu = psutil.cpu_percent(interval=0.05)
        per_core = psutil.cpu_percent(interval=None, percpu=True)
        cores_count = psutil.cpu_count(logical=True) or len(per_core) or 1
        load_avg = self._get_load_avg()
        cpu = CpuMetric(
            cores=cores_count,
            total_percent=total_cpu,
            per_core_percent=per_core,
            load_avg=load_avg,
        )

        # 2. Memory & Swap
        vmem = psutil.virtual_memory()
        smem = psutil.swap_memory()
        memory = MemoryMetric(
            total_bytes=vmem.total,
            used_bytes=vmem.used,
            free_bytes=vmem.free,
            available_bytes=vmem.available,
            percent=vmem.percent,
            swap_total_bytes=smem.total,
            swap_used_bytes=smem.used,
            swap_percent=smem.percent,
        )

        # 3. Disks
        disks: list[DiskPartition] = []
        try:
            partitions = psutil.disk_partitions(all=False)
            seen_mounts = set()
            for part in partitions:
                if part.mountpoint in seen_mounts:
                    continue
                # Skip snap, loop, and docker overlay mounts to keep dashboard clean
                if any(ignored in part.mountpoint for ignored in ("/snap", "/docker", "/var/lib/docker")):
                    continue
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    disks.append(DiskPartition(
                        device=part.device,
                        mountpoint=part.mountpoint,
                        fstype=part.fstype,
                        total_bytes=usage.total,
                        used_bytes=usage.used,
                        free_bytes=usage.free,
                        percent=usage.percent,
                    ))
                    seen_mounts.add(part.mountpoint)
                except (PermissionError, OSError):
                    continue
        except Exception:
            pass

        # 4. Network Rate (RX / TX per second)
        net_rates: list[NetworkRate] = []
        current_net_io = psutil.net_io_counters(pernic=True)
        delta_time = max(now - self._last_net_time, 0.001)

        for nic, io in current_net_io.items():
            # Skip loopback
            if nic.lower() in ("lo", "loopback", "lo0"):
                continue
            prev_io = self._last_net_io.get(nic)
            if prev_io:
                rx_rate = max((io.bytes_recv - prev_io.bytes_recv) / delta_time, 0.0)
                tx_rate = max((io.bytes_sent - prev_io.bytes_sent) / delta_time, 0.0)
            else:
                rx_rate, tx_rate = 0.0, 0.0
            net_rates.append(NetworkRate(
                interface=nic,
                rx_bytes_sec=rx_rate,
                tx_bytes_sec=tx_rate,
            ))

        # Prioritize active adapters with current or cumulative traffic
        net_rates.sort(
            key=lambda x: (
                x.rx_bytes_sec + x.tx_bytes_sec,
                current_net_io[x.interface].bytes_recv + current_net_io[x.interface].bytes_sent if x.interface in current_net_io else 0
            ),
            reverse=True
        )

        self._last_net_time = now
        self._last_net_io = current_net_io

        # 5. Uptime
        boot_time = psutil.boot_time()
        uptime_sec = max(now - boot_time, 0.0)

        # 6. Top Processes (by CPU and Memory)
        top_procs: list[ProcessInfo] = []
        try:
            current_pids = set(psutil.pids())
            # Clean up terminated processes
            for pid in list(self._proc_cache.keys()):
                if pid not in current_pids:
                    del self._proc_cache[pid]

            # Add newly spawned processes
            for pid in current_pids:
                if pid not in self._proc_cache and pid != 0:
                    try:
                        p = psutil.Process(pid)
                        p.cpu_percent()
                        self._proc_cache[pid] = p
                    except Exception:
                        pass

            num_cores = psutil.cpu_count(logical=True) or 1
            procs = []
            for pid, p in list(self._proc_cache.items()):
                try:
                    p_name = p.name()
                    if pid == 0 or p_name.lower() in ("system idle process", "idle"):
                        continue
                    
                    raw_cpu = p.cpu_percent()
                    cpu_pct = round(raw_cpu / num_cores, 1) if raw_cpu > 0 else 0.0

                    mem_info = p.memory_info()
                    mem_bytes = mem_info.rss if mem_info else 0
                    mem_mb = round(mem_bytes / (1024 * 1024), 1)
                    mem_pct = round(p.memory_percent(), 1)
                    
                    username = ""
                    try:
                        username = p.username()
                    except Exception:
                        pass

                    procs.append(ProcessInfo(
                        pid=pid,
                        name=p_name or "unknown",
                        cpu_percent=cpu_pct,
                        memory_mb=mem_mb,
                        memory_percent=mem_pct,
                        username=username,
                    ))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    self._proc_cache.pop(pid, None)
                    continue

            # Prioritize processes by composite resource impact (CPU and Memory)
            procs.sort(key=lambda x: (x.cpu_percent * 2.0 + x.memory_percent * 3.0, x.cpu_percent, x.memory_mb), reverse=True)
            top_procs = procs[:30]
        except Exception:
            pass

        # 7. Disk I/O Rate
        disk_io_rate = DiskIoRate()
        try:
            curr_disk_io = psutil.disk_io_counters()
            if curr_disk_io and self._last_disk_io:
                delta_d = max(now - self._last_disk_time, 0.001)
                r_rate = max((curr_disk_io.read_bytes - self._last_disk_io.read_bytes) / delta_d, 0.0)
                w_rate = max((curr_disk_io.write_bytes - self._last_disk_io.write_bytes) / delta_d, 0.0)
                disk_io_rate = DiskIoRate(read_bytes_sec=r_rate, write_bytes_sec=w_rate)
            self._last_disk_time = now
            self._last_disk_io = curr_disk_io
        except Exception:
            pass

        # 8. Firewall
        firewall = self.firewall_collector.collect()

        return SystemSnapshot(
            hostname=platform.node() or "localhost",
            os_name=self._get_os_pretty_name(),
            kernel=platform.release() or "unknown",
            uptime_seconds=uptime_sec,
            cpu=cpu,
            memory=memory,
            disks=disks,
            network=net_rates,
            top_processes=top_procs,
            disk_io=disk_io_rate,
            firewall=firewall,
            timestamp=now,
        )

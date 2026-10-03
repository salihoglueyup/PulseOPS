import re
import shutil
import subprocess
import datetime
from pathlib import Path
from typing import Optional, Dict
from models.backup import (
    BackupTask,
    BackupStatus,
    BackupSnapshot,
    DeploymentState,
    BackupRetentionAudit,
    BackupData,
)

BACKUP_KEYWORDS = {
    "backup", "dump", "restic", "borg", "snapshot", "rsync", "duplicati", 
    "pg_dump", "mysqldump", "mariadb-dump", "tar", "rclone"
}

SNAPSHOT_REGEX = re.compile(r'store-(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})(\d{2})\.json')

class BackupCollector:
    """Discovers and checks backup tasks, snapshot archives, deployment SHAs, and retention health."""

    def is_backup_related(self, name: str) -> bool:
        lower = name.lower()
        return any(kw in lower for kw in BACKUP_KEYWORDS)

    def parse_timers_text(self, text: str) -> list[BackupTask]:
        """Parses output from `systemctl list-timers --all`."""
        tasks: list[BackupTask] = []
        lines = text.strip().splitlines()
        
        for line in lines:
            line_str = line.strip()
            if not line_str or line_str.startswith("NEXT") or "timers listed" in line_str:
                continue
            
            parts = line_str.split()
            if len(parts) < 6:
                continue
            
            timer_unit = None
            for part in parts:
                if part.endswith(".timer"):
                    timer_unit = part
                    break
                    
            if not timer_unit or not self.is_backup_related(timer_unit):
                continue
                
            last_run = None
            if "UTC" in line_str or "ago" in line_str:
                dates = re.findall(r'[A-Z][a-z]{2}\s+\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}', line_str)
                if len(dates) >= 2:
                    last_run = dates[1]
                elif len(dates) == 1:
                    last_run = dates[0]
            
            status = BackupStatus.SUCCESS if last_run else BackupStatus.UNKNOWN
            if "failed" in line_str.lower():
                status = BackupStatus.FAILED
                
            tasks.append(BackupTask(
                name=timer_unit,
                mechanism="systemd-timer",
                schedule="Zamanlanmış (systemd)",
                last_run=last_run or "Bilinmiyor",
                status=status,
                exit_code=0 if status == BackupStatus.SUCCESS else 1
            ))
            
        return tasks

    def parse_crontab_text(self, text: str) -> list[BackupTask]:
        """Parses crontab entries to find backup scripts."""
        tasks: list[BackupTask] = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
                
            if not self.is_backup_related(line):
                continue
                
            parts = line.split(maxsplit=5)
            if len(parts) >= 6:
                schedule = " ".join(parts[:5])
                cmd = parts[5]
            else:
                schedule = "Özel Cron"
                cmd = line
                
            script_name = cmd.split()[0]
            tasks.append(BackupTask(
                name=script_name,
                mechanism="cron",
                schedule=schedule,
                last_run="Cron Takvimi",
                status=BackupStatus.SUCCESS,
                target_path=cmd
            ))
            
        return tasks

    def parse_snapshot_files(
        self,
        filenames: list[str],
        file_sizes: Optional[Dict[str, int]] = None,
        now: Optional[datetime.datetime] = None
    ) -> list[BackupSnapshot]:
        """Parses snapshot filenames like store-20260929-160647.json into structured metadata."""
        if now is None:
            now = datetime.datetime.now()

        file_sizes = file_sizes or {}
        snapshots: list[BackupSnapshot] = []

        for name in filenames:
            name_clean = name.strip()
            match = SNAPSHOT_REGEX.match(name_clean)
            if not match:
                continue

            year, month, day, hour, minute, second = map(int, match.groups())
            try:
                dt = datetime.datetime(year, month, day, hour, minute, second)
            except ValueError:
                continue

            diff = now - dt
            age_days = diff.total_seconds() / 86400.0

            if age_days < 0.04:  # < 1 hour
                age_human = f"{int(diff.total_seconds() / 60)} dk önce"
            elif age_days < 1.0:
                age_human = f"{int(diff.total_seconds() / 3600)} saat önce"
            elif age_days < 2.0:
                age_human = f"Dün {dt.strftime('%H:%M')}"
            else:
                age_human = f"{int(age_days)} gün önce"

            size_b = file_sizes.get(name_clean, 245 * 1024)  # default realistic ~245KB
            if size_b < 1024 * 1024:
                size_human = f"{size_b / 1024:.1f} KB"
            else:
                size_human = f"{size_b / (1024 * 1024):.1f} MB"

            snapshots.append(BackupSnapshot(
                filename=name_clean,
                timestamp_str=dt.strftime("%Y-%m-%d %H:%M:%S"),
                age_days=round(age_days, 1),
                age_human=age_human,
                size_bytes=size_b,
                size_human=size_human,
                kind="JSON Store Snapshot",
                is_stale_warning=(age_days > 30.0)
            ))

        # Sort newest first
        snapshots.sort(key=lambda s: s.timestamp_str, reverse=True)
        return snapshots

    def audit_retention(self, snapshots: list[BackupSnapshot]) -> BackupRetentionAudit:
        """Audits snapshot disk usage, retention window, and generates cleanup advice."""
        if not snapshots:
            return BackupRetentionAudit(
                total_snapshots=0,
                total_size_human="0 MB",
                retention_status="YEDEK YOK",
                recommendation="Henüz sistemde kayıtlı store snapshot'ı bulunmuyor."
            )

        total_bytes = sum(s.size_bytes for s in snapshots)
        if total_bytes < 1024 * 1024:
            total_size_human = f"{total_bytes / 1024:.1f} KB"
        elif total_bytes < 1024 * 1024 * 1024:
            total_size_human = f"{total_bytes / (1024 * 1024):.1f} MB"
        else:
            total_size_human = f"{total_bytes / (1024 * 1024 * 1024):.2f} GB"

        oldest = snapshots[-1]
        newest = snapshots[0]

        # Calculate time span
        try:
            d_oldest = datetime.datetime.strptime(oldest.timestamp_str, "%Y-%m-%d %H:%M:%S")
            d_newest = datetime.datetime.strptime(newest.timestamp_str, "%Y-%m-%d %H:%M:%S")
            days_span = max((d_newest - d_oldest).days, 1)
        except Exception:
            days_span = 0

        stale_count = sum(1 for s in snapshots if s.is_stale_warning)

        if stale_count > 0:
            status = "⚠️ TEMİZLİK ÖNERİLİR"
            rec = f"{stale_count} adet snapshot 30 günden eski ({total_size_human} alan kaplıyor). 'find . -name \"store-*.json\" -mtime +30 -delete' ile temizlik yapabilirsiniz."
        elif newest.age_days > 3.0:
            status = "⚠️ GÜNCEL DEĞİL"
            rec = f"Son snapshot {newest.age_human} alınmış. Otomatik cron veya deploy tetikleyicisini kontrol edin."
        else:
            status = "SAĞLIKLI ✓"
            rec = f"Yedekler düzenli alınıyor. Toplam {len(snapshots)} snapshot ({total_size_human}) mevcut."

        return BackupRetentionAudit(
            total_snapshots=len(snapshots),
            total_size_human=total_size_human,
            oldest_snapshot_date=oldest.timestamp_str,
            newest_snapshot_date=newest.timestamp_str,
            days_span=days_span,
            files_older_than_30d=stale_count,
            retention_status=status,
            recommendation=rec
        )

    def parse_deployment_state(self, file_map: dict[str, str]) -> DeploymentState:
        """Extracts Git commit hashes from deployment SHA files."""
        last_sha = file_map.get("last-successful-deploy.sha", "").strip()[:10] or None
        prev_sha = file_map.get("previous-successful-deploy.sha", "").strip()[:10] or None
        return DeploymentState(
            last_deploy_sha=last_sha,
            prev_deploy_sha=prev_sha,
            last_deploy_time="Aktif" if last_sha else None
        )

    def collect_local(self) -> list[BackupTask]:
        """Runs local checks on Linux/Windows for timers/scheduled tasks."""
        tasks: list[BackupTask] = []
        
        # 1. Systemd timers
        if shutil.which("systemctl"):
            try:
                res = subprocess.run(
                    ["systemctl", "list-timers", "--all", "--no-pager"],
                    capture_output=True,
                    text=True,
                    timeout=3
                )
                if res.returncode == 0:
                    tasks.extend(self.parse_timers_text(res.stdout))
            except Exception:
                pass
                
        # 2. Crontab
        if shutil.which("crontab"):
            try:
                res = subprocess.run(
                    ["crontab", "-l"],
                    capture_output=True,
                    text=True,
                    timeout=3
                )
                if res.returncode == 0:
                    tasks.extend(self.parse_crontab_text(res.stdout))
            except Exception:
                pass

        # 3. Windows Task Scheduler
        if not tasks and shutil.which("schtasks"):
            try:
                res = subprocess.run(
                    ["schtasks", "/query", "/fo", "csv"],
                    capture_output=True,
                    text=True,
                    timeout=3
                )
                if res.returncode == 0:
                    for line in res.stdout.splitlines()[1:]:
                        parts = [p.strip('"') for p in line.strip().split('","')]
                        if len(parts) >= 3:
                            t_name = parts[0].lstrip("\\")
                            next_run = parts[1]
                            t_status = parts[2]
                            t_lower = t_name.lower()
                            # Skip non-backup app updaters
                            if any(ign in t_lower for ign in ("update", "updater", "nvidia", "google", "git", "edge", "discord")):
                                continue
                            if any(k in t_lower for k in ("backup", "yedek", "dump", "archive", "shadowcopy", "wbadmin", "restic", "borg", "robocopy", "snapshot")):
                                tasks.append(BackupTask(
                                    name=t_name[:24],
                                    mechanism="Windows Task",
                                    schedule=f"Sonraki: {next_run[:16]}" if next_run != "N/A" else "Zamanlanmış",
                                    last_run="Task Scheduler",
                                    status=BackupStatus.SUCCESS if t_status.lower() in ("ready", "running") else BackupStatus.UNKNOWN,
                                    exit_code=0
                                ))
                                if len(tasks) >= 4:
                                    break
            except Exception:
                pass
                
        return tasks

    def collect_local_snapshots(self) -> list[BackupSnapshot]:
        """Scans current project and backup subdirectories for store-*.json files."""
        found_files = []
        file_sizes = {}
        for root in [Path.cwd(), Path.cwd() / "backups", Path.cwd() / "store"]:
            if root.exists():
                for p in root.glob("store-*.json"):
                    found_files.append(p.name)
                    try:
                        file_sizes[p.name] = p.stat().st_size
                    except OSError:
                        pass
        return self.parse_snapshot_files(found_files, file_sizes)

    def collect_backup_data(self) -> BackupData:
        """Returns the full aggregated backup data for Tab 5."""
        tasks = self.collect_local()
        snapshots = self.collect_local_snapshots()
        retention = self.audit_retention(snapshots)
        
        # Check local sha files if any
        sha_map = {}
        for sha_name in ("last-successful-deploy.sha", "previous-successful-deploy.sha"):
            p = Path(sha_name)
            if p.exists():
                try:
                    sha_map[sha_name] = p.read_text(encoding="utf-8").strip()
                except Exception:
                    pass
        deployment = self.parse_deployment_state(sha_map)

        return BackupData(
            tasks=tasks,
            snapshots=snapshots,
            deployment=deployment,
            retention=retention,
        )


from pathlib import Path
from pulseops.collectors.backup_collector import BackupCollector
from pulseops.models.backup import BackupStatus

def test_parse_systemd_timers():
    fixture_path = Path("tests/fixtures/timers_output.txt")
    content = fixture_path.read_text(encoding="utf-8")
    
    collector = BackupCollector()
    tasks = collector.parse_timers_text(content)
    
    # Should identify db-backup.timer and restic-daily.timer (ignoring logrotate and tmpfiles)
    assert len(tasks) == 2
    
    t1 = next(t for t in tasks if t.name == "db-backup.timer")
    assert t1.mechanism == "systemd-timer"
    assert "Wed 2026-09-30 03:00:01" in t1.last_run
    assert t1.status == BackupStatus.SUCCESS

    t2 = next(t for t in tasks if t.name == "restic-daily.timer")
    assert t2.mechanism == "systemd-timer"
    assert "Wed 2026-09-30 06:00:02" in t2.last_run

def test_parse_crontab_entries():
    cron_text = """
    # m h  dom mon dow   command
    0 2 * * * /usr/bin/certbot renew --quiet
    30 3 * * * /root/scripts/pg_dump_backup.sh > /dev/null 2>&1
    0 * * * * /opt/scripts/healthcheck.sh
    15 4 * * 0 /usr/local/bin/borg-backup.sh /data /mnt/backup
    """
    collector = BackupCollector()
    tasks = collector.parse_crontab_text(cron_text)
    
    assert len(tasks) == 2
    names = [t.name for t in tasks]
    assert any("pg_dump_backup.sh" in n for n in names)
    assert any("borg-backup.sh" in n for n in names)

def test_parse_snapshot_files_and_retention():
    import datetime
    collector = BackupCollector()
    sample_files = [
        "store-20260929-160647.json",
        "store-20260925-134157.json",
        "store-20260824-145125.json", # > 30 days old
        "invalid-file.txt",
    ]
    ref_time = datetime.datetime(2026, 9, 30, 14, 0, 0)
    snapshots = collector.parse_snapshot_files(sample_files, now=ref_time)
    
    assert len(snapshots) == 3
    assert snapshots[0].filename == "store-20260929-160647.json"
    assert any(w in snapshots[0].age_human for w in ("saat", "Dün", "gün"))
    assert snapshots[0].is_stale_warning is False
    
    # Check 36-day-old file
    oldest = snapshots[-1]
    assert oldest.filename == "store-20260824-145125.json"
    assert oldest.is_stale_warning is True
    assert oldest.age_days > 35.0

    # Retention audit
    audit = collector.audit_retention(snapshots)
    assert audit.total_snapshots == 3
    assert audit.files_older_than_30d == 1
    assert "TEMİZLİK" in audit.retention_status
    assert "find" in audit.recommendation

def test_deployment_state_parsing():
    collector = BackupCollector()
    file_map = {
        "last-successful-deploy.sha": "8f2a1b9c3e4567\n",
        "previous-successful-deploy.sha": "4c9e7d3a1f9999\n",
    }
    deploy = collector.parse_deployment_state(file_map)
    assert deploy.last_deploy_sha == "8f2a1b9c3e"
    assert deploy.prev_deploy_sha == "4c9e7d3a1f"
    assert deploy.has_rollback_target is True

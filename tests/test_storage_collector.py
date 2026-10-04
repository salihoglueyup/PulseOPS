from pathlib import Path

import pytest

from pulseops.collectors.mock_collector import MockCollector
from pulseops.collectors.storage_collector import (
    StorageCollector, apply_forecast, disk_forecast, parse_docker_size, storage_recommendations,
)
from pulseops.history import Sample
from pulseops.models.storage import StorageOverview, human_bytes

TABULAR_DF_BLOATED = """
TYPE            TOTAL     ACTIVE    SIZE      RECLAIMABLE
Images          14        5         8.4GB     2.1GB (25%)
Containers      5         5         74.2MB    0B (0%)
Local Volumes   3         3         1.2GB     0B (0%)
Build Cache     42        0         128.3GB   128.3GB (100%)
"""

JSON_DF = (
    '{"Active":"1","Reclaimable":"1.312GB (99%)","Size":"1.324GB","TotalCount":"8","Type":"Images"}\n'
    '{"Active":"0","Reclaimable":"0B","Size":"0B","TotalCount":"0","Type":"Build Cache"}\n'
)

STORAGE_SECTION = (Path(__file__).parent / "fixtures" / "storage_section.txt").read_text()


def test_docker_sizes_are_decimal_like_docker_prints_them():
    assert parse_docker_size("1.324GB") == 1_324_000_000
    assert parse_docker_size("74.2MB") == 74_200_000
    assert parse_docker_size("1.312GB (99%)") == 1_312_000_000
    assert parse_docker_size("0B") == 0
    for bad in ("", "abc", "nanGB", "1e999GB", "²GB"):
        assert parse_docker_size(bad) == 0


def test_parse_docker_df_table_and_json():
    ov = StorageCollector().parse_docker_df(TABULAR_DF_BLOATED, "120586240\t/var/lib/docker/overlay2")
    assert ov.is_cache_bloated and ov.buildkit_cache_bytes == 128_300_000_000
    assert ov.containerd_bytes == 120586240 * 1024
    build = next(i for i in ov.items if i.name == "Build Cache")
    assert build.is_critical and build.reclaimable_percent == 100 and build.details == "0/42 aktif"

    js = StorageCollector().parse_docker_df(JSON_DF, "")
    assert [i.name for i in js.items] == ["Images", "Build Cache"] and not js.is_cache_bloated
    assert js.containerd_bytes is None and js.containerd_overlayfs_human == "-"


def test_storage_section_parsing():
    ov = StorageCollector().apply_storage_section(StorageOverview(), STORAGE_SECTION)
    assert ov.known and ov.complete
    assert ov.inode_percent == {"/": 96.0, "/data": 1.0}
    assert ov.read_only_mounts == ["/", "/data"] and ov.critical_read_only == ["/"]
    assert ov.journal_bytes == int(2.5 * 1024**3) and ov.var_log_bytes == 3145728 * 1024
    assert ov.big_logs[0].path == "/var/log/nginx/access.log"
    # Same inode held by two processes counts once; memfd is not a disk file
    assert [(f.pid, f.process, f.path) for f in ov.deleted_open] == [(501, "nginx", "/var/log/nginx/access.log.1")]
    assert ov.deleted_open_bytes == 209715200
    assert [d.path for d in ov.top_dirs] == ["/var", "/home"] and ov.top_dirs_partial  # du hit its time limit


def test_storage_section_without_root_and_missing():
    user = StorageCollector().apply_storage_section(StorageOverview(), "#INODES\nFilesystem Inodes\n#SCOPE user\n")
    assert user.known and not user.complete
    assert any("sudo pulseops" in r for r in storage_recommendations(user, []))
    assert not StorageCollector().apply_storage_section(StorageOverview(), "").known


def test_recommendations_are_derived_from_measurements():
    ov = StorageCollector().apply_storage_section(StorageOverview(), STORAGE_SECTION)
    recs = "\n".join(storage_recommendations(ov, []))
    assert "/ salt-okunur" in recs and "inode'ları %96" in recs
    assert "Silinmiş ama hâlâ açık" in recs and "nginx pid 501" in recs
    assert "log-opts" in recs and "vacuum-size" in recs
    assert "[GUVENLI]" not in recs
    clean = storage_recommendations(StorageOverview(known=True, complete=True), [])
    assert clean == ["[GUVENLI] Depolama sağlıklı: inode, salt-okunur bağlama, log ve önbellek sorunu yok."]


def sample(ts, disk):
    return Sample(ts=ts, cpu=0, mem=0, swap=0, load1=0, disk_root=disk, net_rx=0, net_tx=0, score=100, alerts=0)


def test_disk_forecast():
    day = 86400
    growing = [sample(i * 3600, 50 + i * 0.1) for i in range(48)]   # +2.4 %/day
    days, rate = disk_forecast(growing)
    assert rate == pytest.approx(2.4, abs=0.01)
    assert days == pytest.approx((100 - growing[-1].disk_root) / 2.4, rel=0.01)

    flat = [sample(i * 3600, 50.0) for i in range(48)]
    assert disk_forecast(flat) == (None, 0.0)
    assert disk_forecast(growing[:5]) == (None, None)                                   # too few samples
    assert disk_forecast([sample(i * 60, 50 + i) for i in range(30)]) == (None, None)   # < 6 hours

    st = apply_forecast(StorageOverview(known=True), [sample(i * day / 24, 90 + i * 0.1) for i in range(48)])
    assert st.forecast_days is not None and st.forecast_days < 7
    assert any("gün içinde dolacak" in r for r in st.recommendations)


def test_storage_alerts_and_score():
    from pulseops.collectors.audit_exporter import calculate_audit_score
    from pulseops.collectors.base import DemoCollector
    from pulseops.collectors.telemetry import collect_telemetry, summarize_alerts

    t = collect_telemetry(DemoCollector())
    base, _ = calculate_audit_score(t.snapshot, t.ports, t.routes, t.security, t.storage, t.containers)
    t.storage = StorageCollector().apply_storage_section(t.storage, STORAGE_SECTION)
    t.storage.forecast_days = 3.0
    alerts = summarize_alerts(t)
    for expected in ("/ salt-okunur bağlanmış (dosya sistemi hatası?)", "/ inode %96",
                     "Kök disk ~3 gün içinde dolacak", "Docker konteyner logları 2.0 GB"):
        assert expected in alerts
    score, _ = calculate_audit_score(t.snapshot, t.ports, t.routes, t.security, t.storage, t.containers)
    assert score == max(15, base - 40)


def test_human_bytes():
    assert human_bytes(0) == "0 B" and human_bytes(1536) == "1.5 KB" and human_bytes(None) == "?"
    assert human_bytes(3 * 1024**4) == "3.0 TB"


def test_demo_storage_and_panel_render():
    from pulseops.ui.widgets.storage_panel import StoragePanel

    st = MockCollector().get_storage()
    assert st.known and st.deleted_open and st.top_dirs and st.forecast_days == 46.0
    panel = StoragePanel()
    panel.storage = st
    assert "DEPOLAMA" in str(panel.render().title)

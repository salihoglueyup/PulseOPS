import pytest
from collectors.storage_collector import StorageCollector
from collectors.mock_collector import MockCollector
from models.storage import StorageOverview, StorageItem
from ui.widgets.storage_panel import StoragePanel

TABULAR_DF_BLOATED = """
TYPE            TOTAL     ACTIVE    SIZE      RECLAIMABLE
Images          14        5         8.4GB     2.1GB (25%)
Containers      5         5         74.2MB    0B (0%)
Local Volumes   3         3         1.2GB     0B (0%)
Build Cache     42        0         128.3GB   128.3GB (100%)
"""

TABULAR_DF_CLEAN = """
TYPE            TOTAL     ACTIVE    SIZE      RECLAIMABLE
Images          14        5         8.4GB     2.1GB (25%)
Containers      5         5         74.2MB    0B (0%)
Local Volumes   3         3         1.2GB     0B (0%)
Build Cache     12        2         1.5GB     500MB (33%)
"""

CONTAINERD_SZ_OUTPUT = "115G\t/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs"

def test_parse_docker_df_bloated():
    collector = StorageCollector()
    overview = collector.parse_docker_df(TABULAR_DF_BLOATED, CONTAINERD_SZ_OUTPUT)

    assert overview.is_cache_bloated is True
    assert "128.3GB" in overview.buildkit_cache_human
    assert overview.containerd_overlayfs_human == "115G"
    assert len(overview.items) == 4
    
    # Check that Build Cache item is marked as critical
    bc_item = next(it for it in overview.items if "build" in it.name.lower())
    assert bc_item.is_critical is True
    assert "128.3GB" in bc_item.total_human
    assert len(overview.snapshot_groups) > 0
    assert any("docker builder prune" in r for r in overview.recommendations)

def test_parse_docker_df_clean():
    collector = StorageCollector()
    overview = collector.parse_docker_df(TABULAR_DF_CLEAN, "6.7G\t/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs")

    assert overview.is_cache_bloated is False
    assert overview.containerd_overlayfs_human == "6.7G"
    bc_item = next(it for it in overview.items if "build" in it.name.lower())
    assert bc_item.is_critical is False
    assert any("dengeli" in r for r in overview.recommendations)

def test_mock_collector_storage():
    mock = MockCollector()
    storage = mock.get_storage()

    assert isinstance(storage, StorageOverview)
    assert storage.root_used_gb == 31.0
    assert storage.root_percent == 17.0
    assert storage.is_cache_bloated is False
    assert len(storage.items) >= 4
    assert len(storage.recommendations) >= 2

def test_storage_panel_render():
    panel = StoragePanel()
    mock = MockCollector()
    panel.storage = mock.get_storage()
    
    rendered = panel.render()
    assert rendered is not None
    assert "DEPOLAMA" in str(rendered.title)

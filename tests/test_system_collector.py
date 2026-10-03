import pytest
from collectors.system_collector import SystemCollector
from models.system import SystemSnapshot

def test_system_collector_local_snapshot():
    collector = SystemCollector()
    snapshot = collector.collect_snapshot()
    
    assert isinstance(snapshot, SystemSnapshot)
    assert len(snapshot.hostname) > 0
    assert snapshot.cpu.cores >= 1
    assert snapshot.memory.total_bytes > 0
    assert snapshot.memory.percent >= 0.0
    assert len(snapshot.disks) >= 1
    # Check uptime
    assert snapshot.uptime_seconds > 0

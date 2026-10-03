import pytest
from collectors.port_finder import find_available_ports
from models.ports import ListeningPort, PortExposure

def test_find_available_ports():
    used_ports = [
        ListeningPort(proto="tcp", ip="127.0.0.1", port=3000, process_name="node", exposure=PortExposure.SAFE_INTERNAL),
        ListeningPort(proto="tcp", ip="127.0.0.1", port=3001, process_name="node", exposure=PortExposure.SAFE_INTERNAL),
        ListeningPort(proto="tcp", ip="127.0.0.1", port=3002, process_name="node", exposure=PortExposure.SAFE_INTERNAL),
    ]
    
    free_ports = find_available_ports(used_ports, start_port=3000, end_port=3010, limit=3)
    assert len(free_ports) == 3
    # 3000, 3001, 3002 are busy, so first free should be 3003
    assert free_ports[0] == 3003
    assert free_ports[1] == 3004
    assert free_ports[2] == 3005

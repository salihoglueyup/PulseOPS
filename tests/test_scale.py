"""Large hosts: thousands of processes and listening ports, hundreds of containers and services."""
import json
import sys
import time

import pytest

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="needs a Linux probe corpus")

N_PROC, N_PORT, N_CT, N_SVC = 8000, 3000, 300, 1500


def big_host() -> dict[str, str]:
    procs0 = [f"{pid} {pid * 7} {pid % 5000} worker-{pid % 97}" for pid in range(1, N_PROC)]
    procs1 = [f"{pid} {pid * 7 + pid % 13} {pid % 5000} worker-{pid % 97}" for pid in range(1, N_PROC)]
    ports = ["#tcp", "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"]
    owners = ["#sockets"]
    for i in range(N_PORT):
        ip = "00000000" if i % 3 else "0100007F"
        ports.append(f"   {i}: {ip}:{1024 + i:04X} 00000000:0000 0A 00000000:00000000 00:00000000 00000000"
                     f"     0        0 {900000 + i} 1 0 100 0 0 10 0")
        owners.append(f"/proc/{1 + i % (N_PROC - 1)}/fd socket:[{900000 + i}]")
    docker = [json.dumps({"ID": f"{i:012x}", "Names": f"app-{i}", "Image": f"registry/app:{i}", "Status": "Up 2 hours",
                          "State": "running", "Ports": f"0.0.0.0:{20000 + i}->80/tcp"}) for i in range(N_CT)]
    services = ["  UNIT LOAD ACTIVE SUB DESCRIPTION"] + [
        f"  svc-{i:04d}.service loaded {'failed failed' if i % 50 == 49 else 'active running'} Service {i}"
        for i in range(N_SVC)
    ]
    return {"PROCSTAT0": "\n".join(procs0), "PROCSTAT": "\n".join(procs1),
            "PROCUSERS": "\n".join(f"{pid} user{pid % 50}" for pid in range(1, N_PROC)),
            "PORTS": "\n".join(ports), "PORT_OWNERS": "\n".join(owners), "DOCKER": "\n".join(docker),
            "SERVICES": "\n".join(services)}


@pytest.fixture(scope="module")
def telemetry():
    from collectors.probe_collector import ProbeCollector
    from test_fuzz_probe import FuzzTransport

    collector = ProbeCollector(FuzzTransport(big_host()))
    started = time.perf_counter()
    collector.collect()
    t = collector.collect(include_slow=False)
    return t, time.perf_counter() - started


def test_large_host_is_collected_quickly(telemetry):
    t, elapsed = telemetry
    assert elapsed < 5.0
    assert len(t.ports) == N_PORT and len(t.containers) == N_CT
    assert len(t.snapshot.top_processes) == 20


def test_failed_services_are_never_capped_away(telemetry):
    t, _ = telemetry
    from models.services import ServiceState

    failed = sorted(s.name for s in t.services if s.state == ServiceState.FAILED)
    assert failed == sorted(f"svc-{i:04d}.service" for i in range(N_SVC) if i % 50 == 49)
    assert len(t.services) <= 25 + len(failed) + 10  # still capped for display

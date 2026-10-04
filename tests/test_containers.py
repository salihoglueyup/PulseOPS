import os
import shutil
import subprocess
import uuid

import pytest

from collectors import probe_parsers as pp
from models.docker import ContainerSecurity


SAMPLE = (
    "/risky||true|host||[\"CAP_SYS_ADMIN\"]|0||/var/run/docker.sock>/var/run/docker.sock>true;|false\n"
    "/etc-mount|1000|false|bridge|host|null|7|unhealthy|/etc>/host/etc>false;/srv/data>/data>true;|false\n"
    "/tame|1000:1000|false|bridge||null|0|healthy||true\n"
    "garbage line\n"
)


def test_parse_docker_security_and_risks():
    sec = pp.parse_docker_security(SAMPLE)
    assert set(sec) == {"risky", "etc-mount", "tame"}
    risky = {(r.severity, r.text) for r in sec["risky"].risks}
    assert ("HIGH", "--privileged (host'a tam erişim)") in risky
    assert ("HIGH", "Docker soketi bağlı (/var/run/docker.sock): host'ta root") in risky
    assert ("HIGH", "Tehlikeli yetenek: SYS_ADMIN") in risky
    assert ("MEDIUM", "Host ağı (--network=host)") in risky
    etc = {(r.severity, r.text) for r in sec["etc-mount"].risks}
    assert etc == {("MEDIUM", "Host dizini bağlı: /etc -> /host/etc"), ("MEDIUM", "Host PID ad alanı (--pid=host)")}
    assert sec["etc-mount"].restart_count == 7 and sec["etc-mount"].health == "unhealthy"
    assert sec["tame"].risks == [] and sec["tame"].read_only_root
    assert ContainerSecurity(user="root").runs_as_root and not ContainerSecurity(user="1000:1000").runs_as_root


def test_container_alerts_score_and_drift():
    from collectors.audit_exporter import calculate_audit_score
    from collectors.base import DemoCollector
    from collectors.drift import HIGH, diff, fingerprint
    from collectors.telemetry import collect_telemetry, summarize_alerts

    t = collect_telemetry(DemoCollector())
    t.privileges.docker_access = True
    base = t.model_copy(deep=True)
    base_score, _ = calculate_audit_score(t.snapshot, t.ports, t.routes, t.security, t.storage, t.containers)
    sec = pp.parse_docker_security(SAMPLE)
    t.containers[0].name = "risky"
    t.containers[0].security = sec["risky"]
    t.containers[1].name = "etc-mount"
    t.containers[1].security = sec["etc-mount"]

    alerts = summarize_alerts(t)
    assert "Konteyner risky: --privileged (host'a tam erişim) (+2)" in alerts
    assert "Konteyner etc-mount sağlıksız (healthcheck)" in alerts
    assert "Konteyner etc-mount 7 kez yeniden başladı" in alerts
    score, _ = calculate_audit_score(t.snapshot, t.ports, t.routes, t.security, t.storage, t.containers)
    assert score == max(15, base_score - 10)
    changes = {(c.severity, c.message) for c in diff(fingerprint(base), fingerprint(t))}
    assert (HIGH, "Riskli konteyner: risky: --privileged (host'a tam erişim)") in changes

    # Without docker access nothing is compared: no false "risk removed"
    blind = t.model_copy(deep=True)
    blind.privileges.docker_access = False
    assert not [c for c in diff(fingerprint(t), fingerprint(blind)) if c.category == "container"]


@pytest.mark.skipif(os.environ.get("PULSEOPS_TEST_DOCKER") != "1" or not shutil.which("docker"),
                    reason="PULSEOPS_TEST_DOCKER=1 and a usable docker are needed")
def test_live_docker_containers():
    from collectors.probe_collector import ProbeCollector
    from collectors.transport import LocalTransport

    tag = uuid.uuid4().hex[:8]
    risky, tame = f"pulseops-risky-{tag}", f"pulseops-tame-{tag}"
    image = os.environ.get("PULSEOPS_TEST_DOCKER_IMAGE", "alpine:3.20")
    subprocess.run(["docker", "run", "-d", "--rm", "--name", risky, "--privileged", "-v",
                    "/var/run/docker.sock:/var/run/docker.sock", image, "sleep", "300"], check=True, capture_output=True)
    subprocess.run(["docker", "run", "-d", "--rm", "--name", tame, "--user", "1000", "--read-only", image,
                    "sleep", "300"], check=True, capture_output=True)
    try:
        t = ProbeCollector(LocalTransport()).collect()
        by_name = {c.name: c for c in t.containers}
        assert by_name[risky].security is not None and by_name[tame].security is not None
        high = [r.text for r in by_name[risky].security.risks if r.severity == "HIGH"]
        assert any("privileged" in r for r in high) and any("Docker soketi" in r for r in high)
        assert by_name[tame].security.risks == []
    finally:
        subprocess.run(["docker", "rm", "-f", risky, tame], capture_output=True)

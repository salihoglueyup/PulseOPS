"""Property-based fuzzing of everything that reads probe output.

Probe output comes from the observed server and must be treated as untrusted: a compromised or just
unusual host (old tools, foreign locale, truncated output, hostile process names) may print anything.
Whatever it prints, PulseOps must not crash: the only acceptable failure is a TransportError for
output that is missing its required sections.

The corpus is real probe output from the machine running the tests; Hypothesis mutates it section by
section (random text, dropped/duplicated lines, hostile tokens, truncation) and the whole pipeline runs
on the result: ProbeCollector (fast + slow + logs, two rounds for rates), alerts, drift fingerprint and
diff, `status` rendering, the JSON telemetry and the Markdown audit report.
"""
import io
import json
import re
import sys
from pathlib import Path

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import HealthCheck, given, settings, strategies as st  # noqa: E402
from rich.console import Console  # noqa: E402

from pulseops.collectors.audit_exporter import generate_audit_markdown  # noqa: E402
from pulseops.collectors.drift import diff, fingerprint  # noqa: E402
from pulseops.collectors.probe import SECTION_PREFIX, build_script, parse_sections  # noqa: E402
from pulseops.collectors.probe_collector import ProbeCollector  # noqa: E402
from pulseops.collectors.telemetry import summarize_alerts  # noqa: E402
from pulseops.collectors.transport import LocalTransport, TransportError  # noqa: E402
from pulseops.commands import _telemetry_json, render_status  # noqa: E402
from pulseops.config import Config  # noqa: E402

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="needs a Linux probe corpus")

HOSTILE_TOKENS = [
    "", "-1", "0", "-0", "nan", "NaN", "inf", "-inf", "1e309", "99999999999999999999999999", "0x1f", "1,5",
    "abc", ":", "::", "/", "*", "%", "=", "[bold red]x[/]", "[link=http://evil]y[/link]", "[/]", "\x1b[31m",
    "\x00", "\t", "ü", "İ", "🔥", "a" * 5000, "(sshd)", ") ", "'", '"', "\\", "$(id)", "users:((",
    "Failed password for", "from", "port",
]


def _real_sections() -> dict[str, str]:
    """One full probe run on this machine, split into sections (baseline included)."""
    script, nonce = build_script(fast=True, slow=True, logs=True, baseline=True, sudo=False)
    return parse_sections(LocalTransport().run(script, timeout=120), nonce)


# Realistic content for sections a CI runner / dev machine usually has empty
SAMPLES = {
    "SERVICES": (
        "  UNIT                     LOAD   ACTIVE SUB     DESCRIPTION\n"
        "  nginx.service            loaded active running A high performance web server\n"
        "  docker.service           loaded active running Docker Application Container Engine\n"
        "● postgresql.service       loaded failed failed  PostgreSQL RDBMS\n"
        "  redis-server.service     loaded inactive dead  Advanced key-value store\n"
        "  ssh.service              loaded active running OpenBSD Secure Shell server\n"
    ),
    "TIMERS": (Path(__file__).parent / "fixtures" / "timers_output.txt").read_text(),
    "NGINX": (Path(__file__).parent / "fixtures" / "nginx_sample.conf").read_text(),
    "FAIL2BAN": (
        "INSTALLED\nRUNNING\nStatus\n|- Number of jail:\t1\n`- Jail list:\tsshd\n#JAIL sshd\n"
        "Status for the jail: sshd\n|- Filter\n|  |- Currently failed:\t3\n|  |- Total failed:\t120\n"
        "`- Actions\n   |- Currently banned:\t2\n   |- Total banned:\t40\n   `- Banned IP list:\t203.0.113.5 198.51.100.7\n"
    ),
    "BACKUP_FILES": (
        "SNAP 120 ./backups/store-20261001-020000.json\nSNAP 7 /srv/app data/store-20261002-020000.json\n"
        "FILE:./last-successful-deploy.sha\na1b2c3d4e5f6\n"
    ),
    "DOCKER_SEC": ("/web|1000|false|bridge||[\"NET_ADMIN\"]|3|healthy|/srv/www>/var/www>true;|false\n"
                   "/priv||true|host|host|null|0||/var/run/docker.sock>/var/run/docker.sock>true;|false\n"),
    "CRONTAB": "0 2 * * * /usr/local/bin/backup.sh\n*/5 * * * * curl -s http://localhost/health\n",
    "AUTH": (
        "SOURCE journal\nFAILED 120\nINVALID 30\nACCEPTED 4\nACCEPTED_PASSWORD 1\n"
        "FIP 90 203.0.113.5\nFIP 60 198.51.100.7\nFUSER 70 root\nFUSER 20 admin\n"
        "ACC 2026-10-01T10:00:00+0000 publickey deploy 192.0.2.10\nACC 2026-10-02T11:00:00+0000 password root 192.0.2.11\n"
    ),
    "LOGS": (
        '203.0.113.5 - - [04/Oct/2026:06:00:00 +0000] "GET /[/] HTTP/1.1" 404 153 "-" "curl/8"\n'
        '198.51.100.7 - - [04/Oct/2026:06:00:01 +0000] "POST /login HTTP/1.1" 502 0 "-" "[link=x]y[/link]"\n'
    ),
}

CORPUS = _real_sections() if sys.platform.startswith("linux") else {}
for _name, _text in SAMPLES.items():
    if CORPUS and not CORPUS.get(_name, "").strip():
        CORPUS[_name] = _text

_NONCE = re.compile(re.escape(SECTION_PREFIX) + r":([0-9a-f]+):")
_NAMES = re.compile(re.escape(SECTION_PREFIX) + r":\{?[0-9a-f]+\}?:([A-Z0-9_]+)===")


class FuzzTransport:
    """Answers each probe script with the corpus, mutated by the current Hypothesis example."""

    name = "fuzz"

    def __init__(self, mutated: dict[str, str]):
        self.mutated = mutated

    def run(self, script: str, timeout: float) -> str:
        nonce = _NONCE.search(script).group(1)
        out = []
        for name in _NAMES.findall(script):
            out.append(f"{SECTION_PREFIX}:{nonce}:{name}===")
            if name != "END":
                out.append(self.mutated.get(name, CORPUS.get(name, "")))
        return "\n".join(out) + "\n"

    def close(self) -> None:
        pass


@st.composite
def mutated_text(draw, original: str) -> str:
    lines = original.splitlines() or [""]
    kind = draw(st.sampled_from(["keep", "random", "tokens", "drop", "dup", "truncate", "empty"]))
    if kind == "keep":
        return original
    if kind == "random":
        return draw(st.text(max_size=400))
    if kind == "empty":
        return ""
    if kind == "truncate":
        return original[: draw(st.integers(0, len(original)))]
    if kind == "drop":
        keep = draw(st.lists(st.booleans(), min_size=len(lines), max_size=len(lines)))
        return "\n".join(line for line, k in zip(lines, keep) if k)
    if kind == "dup":
        i = draw(st.integers(0, len(lines) - 1))
        return "\n".join(lines[: i + 1] + [lines[i]] * draw(st.integers(1, 50)) + lines[i + 1:])
    # tokens: replace a few whitespace-separated tokens with hostile values
    for _ in range(draw(st.integers(1, 6))):
        i = draw(st.integers(0, len(lines) - 1))
        parts = lines[i].split(" ")
        j = draw(st.integers(0, len(parts) - 1))
        parts[j] = draw(st.sampled_from(HOSTILE_TOKENS) | st.text(max_size=12))
        lines[i] = " ".join(parts)
    return "\n".join(lines)


@st.composite
def mutated_corpus(draw) -> dict[str, str]:
    names = sorted(CORPUS)
    chosen = draw(st.lists(st.sampled_from(names), min_size=1, max_size=6, unique=True)) if names else []
    return {name: draw(mutated_text(CORPUS[name])) for name in chosen}


def run_pipeline(mutated: dict[str, str]) -> None:
    collector = ProbeCollector(FuzzTransport(mutated))
    try:
        first = collector.collect(include_slow=True, include_logs=True)
        t = collector.collect(include_slow=False, include_logs=True)
    except TransportError:
        return  # required section missing/garbled: reported as a connection problem, by design

    summarize_alerts(t)
    diff(fingerprint(first), fingerprint(t))
    json.dumps(_telemetry_json(t, Config()), ensure_ascii=False)
    render_status(t, Console(file=io.StringIO(), width=100, force_terminal=True), Config())
    generate_audit_markdown(
        t.snapshot, t.ports, t.routes, t.backups, t.containers,
        databases=t.databases, services=t.services, security=t.security, storage=t.storage,
    )
    # Hard invariants regardless of input
    s = t.snapshot
    assert 0.0 <= s.cpu.total_percent <= 100.0
    assert all(0.0 <= c <= 100.0 for c in s.cpu.per_core_percent)
    assert 0.0 <= s.memory.percent <= 100.0
    assert all(0 <= p.port <= 65535 for p in t.ports)


def test_corpus_is_complete():
    assert {"UPTIME", "CPUSTAT", "PRIV", "DISK"} <= set(CORPUS)
    run_pipeline({})  # the unmodified corpus must go through cleanly


@settings(max_examples=int(__import__("os").environ.get("PULSEOPS_FUZZ_EXAMPLES", "150")), deadline=None,
          suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])
@given(mutated_corpus())
def test_probe_pipeline_never_crashes(mutated):
    run_pipeline(mutated)


def _random_mutation(rng, original: str) -> str:
    lines = original.splitlines() or [""]
    kind = rng.choice(["random", "tokens", "drop", "dup", "truncate"])
    if kind == "random":
        return "".join(rng.choice(HOSTILE_TOKENS + [" ", "\n", "x", "9"]) for _ in range(rng.randint(0, 60)))
    if kind == "truncate":
        return original[: rng.randint(0, len(original))]
    if kind == "drop":
        return "\n".join(line for line in lines if rng.random() < 0.5)
    if kind == "dup":
        i = rng.randrange(len(lines))
        return "\n".join(lines[: i + 1] + [lines[i]] * rng.randint(1, 200) + lines[i + 1:])
    for _ in range(rng.randint(1, 8)):
        i = rng.randrange(len(lines))
        parts = lines[i].split(" ")
        parts[rng.randrange(len(parts))] = rng.choice(HOSTILE_TOKENS)
        lines[i] = " ".join(parts)
    return "\n".join(lines)


@pytest.mark.asyncio
async def test_tui_renders_hostile_telemetry():
    """Mutated telemetry goes through every tab of the real TUI (widgets must not crash on it)."""
    import random

    from conftest import settle
    from pulseops.ui.app import ServerTUIApp

    rng = random.Random(1337)
    samples = []
    while len(samples) < 6:
        mutated = {name: _random_mutation(rng, CORPUS[name]) for name in rng.sample(sorted(CORPUS), 8)}
        collector = ProbeCollector(FuzzTransport(mutated))
        try:
            collector.collect()
            samples.append(collector.collect(include_slow=False))
        except TransportError:
            continue

    app = ServerTUIApp(collector=ProbeCollector(FuzzTransport({})), poll_interval=3600)
    async with app.run_test(size=(120, 40)) as pilot:
        await settle(pilot)
        for t in samples:
            app.apply_telemetry(t)
            for key in "1234567890":
                await pilot.press(key)
                await pilot.pause()
        await settle(pilot)
        assert app.is_running


EXHAUSTIVE_TOKENS = ["", "abc", "-1", "²", "nan", "inf", "1e999", "99999999999999999999999", "0x10", "=1", ":", "/",
                     "(", "[/]", "\x00", "ü"]


EXTRA_SAMPLES = {
    "SS": (Path(__file__).parent / "fixtures" / "ss_output.txt").read_text(),
    "DOCKER": ('{"ID":"abc","Names":"web","Image":"nginx:1","Status":"Up 2 hours","Ports":"0.0.0.0:8080->80/tcp, :::8080->80/tcp"}\n'),
    "DOCKER_DF": ('{"Type":"Images","TotalCount":"5","Active":"2","Size":"2.1GB","Reclaimable":"1.2GB (57%)"}\n'
                  '{"Type":"Build Cache","TotalCount":"40","Active":"0","Size":"12.5GB","Reclaimable":"12.5GB"}\n'),
    "CONTAINERD_SZ": "28G\t/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs\n",
    "SSHD_CONF": "#EFFECTIVE\nport 22\npermitrootlogin prohibit-password\npasswordauthentication yes\n",
}


def _section_parsers():
    from pulseops.collectors import probe_parsers as pp
    from pulseops.collectors.backup_collector import BackupCollector
    from pulseops.collectors.nginx_parser import NginxParser
    from pulseops.collectors.port_collector import PortCollector
    from pulseops.collectors.privilege_collector import parse_privileges_section
    from pulseops.collectors.security_collector import SecurityCollector
    from pulseops.collectors.service_collector import ServiceCollector
    from pulseops.collectors.storage_collector import StorageCollector

    return {
        "HOST": pp.parse_host, "UPTIME": pp.parse_uptime, "LOADAVG": pp.parse_loadavg, "SYSCONF": pp.parse_sysconf,
        "CPUSTAT": pp.parse_cpustat, "MEM": pp.parse_meminfo, "DISK": pp.parse_df, "DISKSTATS": pp.parse_diskstats,
        "NET": pp.parse_net_dev, "PROCSTAT": pp.parse_procstat, "PROCUSERS": pp.parse_procusers,
        "PORT_OWNERS": pp.parse_socket_owners, "PORTS": lambda s: pp.parse_proc_net(s, {}, {}),
        "FIREWALL": pp.parse_firewall, "BACKUP_FILES": pp.parse_backup_files, "FAIL2BAN": pp.parse_fail2ban,
        "AUTH": pp.parse_auth, "ACCESS": pp.parse_access, "UPDATES": lambda s: pp.parse_updates(s, 1e9),
        "HARDEN": pp.parse_hardening, "DOCKER_SEC": pp.parse_docker_security, "PRIV": parse_privileges_section,
        "NGINX": NginxParser().parse_config_text, "SERVICES": lambda s: ServiceCollector().parse_systemctl_units(s, ""),
        "UNIT_FILES": lambda s: ServiceCollector().parse_systemctl_units("", s),
        "TIMERS": BackupCollector().parse_timers_text, "CRONTAB": BackupCollector().parse_crontab_text,
        "DOCKER": ProbeCollector._parse_containers, "DOCKER_DF": lambda s: StorageCollector().parse_docker_df(s, ""),
        "CONTAINERD_SZ": lambda s: StorageCollector().parse_docker_df("", s),
        "SSHD_CONF": SecurityCollector().parse_sshd_config_text,
        "SS": PortCollector().parse_ss_text,
    }


def test_every_token_of_every_parser_input_survives_hostile_values():
    """Deterministic complement to the random fuzzer: each token, one at a time, gets each hostile value."""
    failures = []
    for name, parse in _section_parsers().items():
        sample = CORPUS.get(name) or SAMPLES.get(name) or EXTRA_SAMPLES.get(name, "")
        lines = sample.splitlines()[:60]
        for i, line in enumerate(lines):
            tokens = re.split(r"(\s+)", line)  # separators kept: tab-separated values get mutated too
            for j in range(0, len(tokens), 2):
                for bad in EXHAUSTIVE_TOKENS:
                    mutated = lines[:i] + ["".join(tokens[:j] + [bad] + tokens[j + 1:])] + lines[i + 1:]
                    try:
                        parse("\n".join(mutated))
                    except Exception as e:  # collect all, report together
                        failures.append(f"{name} line {i} token {j} -> {bad!r}: {type(e).__name__}: {e}")
    assert not failures, "\n".join(failures[:30]) + f"\n... {len(failures)} failures"

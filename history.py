"""Local history: per-minute metric samples and security drift events, per observed machine.

~/.local/share/pulseops/history.db (0600). Short-lived connections make it safe to use from the
TUI's poll thread and from a cron `pulseops check` at the same time.
"""
import json
import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Optional

from pydantic import BaseModel

from collectors.drift import Change, diff, fingerprint
from models.telemetry import Telemetry

SAMPLE_RETENTION_DAYS = 30
CHANGE_RETENTION_DAYS = 180

SCHEMA = """
CREATE TABLE IF NOT EXISTS hosts (
    host_id TEXT PRIMARY KEY, hostname TEXT NOT NULL, first_seen REAL NOT NULL, last_seen REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS samples (
    host_id TEXT NOT NULL, ts REAL NOT NULL, cpu REAL, mem REAL, swap REAL, load1 REAL,
    disk_root REAL, net_rx REAL, net_tx REAL, score INTEGER, alerts INTEGER
);
CREATE INDEX IF NOT EXISTS samples_host_ts ON samples (host_id, ts);
CREATE TABLE IF NOT EXISTS baselines (
    host_id TEXT PRIMARY KEY, ts REAL NOT NULL, fingerprint TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS changes (
    host_id TEXT NOT NULL, ts REAL NOT NULL, severity TEXT NOT NULL, category TEXT NOT NULL, message TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS changes_host_ts ON changes (host_id, ts);
CREATE TABLE IF NOT EXISTS meta (
    host_id TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY (host_id, key)
);
"""


def default_history_path() -> Path:
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "pulseops" / "history.db"


def host_key(t: Telemetry) -> str:
    """Machine identity; falls back to the hostname when /etc/machine-id is unavailable."""
    return t.machine_id or f"hostname:{t.snapshot.hostname}"


class StoredChange(BaseModel):
    ts: float
    severity: str
    category: str
    message: str


class Sample(BaseModel):
    ts: float
    cpu: float
    mem: float
    swap: float
    load1: float
    disk_root: float
    net_rx: float
    net_tx: float
    score: int
    alerts: int


class HistoryStore:
    def __init__(self, path: Optional[Path] = None):
        self.path = path or default_history_path()

    @contextmanager
    def _db(self):
        new = not self.path.exists()
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        conn = sqlite3.connect(self.path, timeout=10)
        try:
            if new:
                os.chmod(self.path, 0o600)
            conn.execute("PRAGMA busy_timeout = 10000")
            conn.executescript(SCHEMA)
            yield conn
            conn.commit()
        finally:
            conn.close()

    # --- writes ---------------------------------------------------------------------------------

    def record_sample(self, t: Telemetry, score: int, alerts: int, ts: Optional[float] = None) -> None:
        s = t.snapshot
        root = next((d for d in s.disks if d.mountpoint == "/"), s.disks[0] if s.disks else None)
        ts = ts or t.collected_at or time.time()
        with self._db() as db:
            self._touch_host(db, t, ts)
            db.execute(
                "INSERT INTO samples VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (host_key(t), ts, s.cpu.total_percent, s.memory.percent, s.memory.swap_percent, s.cpu.load_avg[0],
                 root.percent if root else None,
                 sum(n.rx_bytes_sec for n in s.network), sum(n.tx_bytes_sec for n in s.network), score, alerts),
            )
            db.execute("DELETE FROM samples WHERE ts < ?", (ts - SAMPLE_RETENTION_DAYS * 86400,))

    def detect_changes(self, t: Telemetry, ts: Optional[float] = None) -> list[Change]:
        """Compares t with the stored baseline, records the changes and makes t the new baseline.

        The first observation of a machine only establishes the baseline (no changes). Changes are
        stamped with the detection time, so consumers (`take_unreported`) never skip them.
        """
        ts = ts or time.time()
        key = host_key(t)
        current = fingerprint(t)
        with self._db() as db:
            # Same machine seen through several routes in parallel (local + SSH, fleet): one at a time
            db.execute("BEGIN IMMEDIATE")
            self._touch_host(db, t, ts)
            row = db.execute("SELECT fingerprint FROM baselines WHERE host_id = ?", (key,)).fetchone()
            changes = diff(json.loads(row[0]), current) if row else []
            if row:
                # Keep the last readable value of categories this run could not read
                previous = json.loads(row[0])
                current = {k: (v if v is not None else previous.get(k)) for k, v in current.items()}
            db.execute("INSERT OR REPLACE INTO baselines VALUES (?, ?, ?)", (key, ts, json.dumps(current)))
            db.executemany(
                "INSERT INTO changes VALUES (?, ?, ?, ?, ?)",
                [(key, ts, c.severity, c.category, c.message) for c in changes],
            )
            db.execute("DELETE FROM changes WHERE ts < ?", (ts - CHANGE_RETENTION_DAYS * 86400,))
        return changes

    def take_unreported(self, host_id: str, consumer: str, now: Optional[float] = None) -> list[StoredChange]:
        """Changes recorded (by any detector: TUI, status, check) since `consumer` last asked.

        The first call only marks the starting point, so a fresh install does not replay old history.
        """
        now = now or time.time()
        key = f"last_seen:{consumer}"
        with self._db() as db:
            row = db.execute("SELECT value FROM meta WHERE host_id = ? AND key = ?", (host_id, key)).fetchone()
            db.execute("INSERT OR REPLACE INTO meta VALUES (?, ?, ?)", (host_id, key, repr(now)))
        if row is None:
            return []
        return [c for c in self.changes(host_id, since=float(row[0])) if c.ts <= now][::-1]

    def get_meta(self, host_id: str, key: str) -> Optional[str]:
        with self._db() as db:
            row = db.execute("SELECT value FROM meta WHERE host_id = ? AND key = ?", (host_id, key)).fetchone()
        return row[0] if row else None

    def set_meta(self, host_id: str, key: str, value: str) -> None:
        with self._db() as db:
            db.execute("INSERT OR REPLACE INTO meta VALUES (?, ?, ?)", (host_id, key, value))

    def reset_baseline(self, host_id: str) -> None:
        with self._db() as db:
            db.execute("DELETE FROM baselines WHERE host_id = ?", (host_id,))

    @staticmethod
    def _touch_host(db, t: Telemetry, ts: float) -> None:
        db.execute(
            "INSERT INTO hosts VALUES (?, ?, ?, ?) ON CONFLICT(host_id) DO UPDATE SET hostname = excluded.hostname,"
            " last_seen = excluded.last_seen",
            (host_key(t), t.snapshot.hostname, ts, ts),
        )

    # --- reads ----------------------------------------------------------------------------------

    def changes(self, host_id: str, since: float = 0.0, limit: int = 200) -> list[StoredChange]:
        with self._db() as db:
            rows = db.execute(
                "SELECT ts, severity, category, message FROM changes WHERE host_id = ? AND ts > ?"
                " ORDER BY ts DESC LIMIT ?", (host_id, since, limit),
            ).fetchall()
        return [StoredChange(ts=r[0], severity=r[1], category=r[2], message=r[3]) for r in rows]

    def samples(self, host_id: str, since: float) -> list[Sample]:
        with self._db() as db:
            rows = db.execute(
                "SELECT ts, cpu, mem, swap, load1, disk_root, net_rx, net_tx, score, alerts FROM samples"
                " WHERE host_id = ? AND ts >= ? ORDER BY ts", (host_id, since),
            ).fetchall()
        fields = list(Sample.model_fields)
        return [Sample(**{k: (v if v is not None else 0) for k, v in zip(fields, r)}) for r in rows]

    def hosts(self) -> list[tuple[str, str, float]]:
        with self._db() as db:
            return db.execute("SELECT host_id, hostname, last_seen FROM hosts ORDER BY last_seen DESC").fetchall()

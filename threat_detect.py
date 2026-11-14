"""Log-driven threat detection for SysMonitor (stdlib only).

Turns raw log lines (sshd via journald, web access logs, SysMonitor's own
auth failures) into normalized :class:`LogEvent` objects, runs them through
sliding-window detectors in :class:`ThreatEngine`, and persists findings and
a learned login baseline in SQLite.

Everything except :func:`read_journal_sshd` and :class:`FileTailer` is pure,
so detectors are unit-tested with synthetic events and an injected clock.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import sqlite3
import subprocess
import time
from collections import OrderedDict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

# ── Event + finding types ──────────────────────────────────────────────────


@dataclass
class LogEvent:
    """One normalized log observation.

    Attributes:
        ts: Event time (epoch seconds).
        source: Origin, e.g. ``sshd``, ``nginx``, ``sysmon``.
        kind: ``login_fail``, ``login_ok``, or ``http``.
        ip: Source IP (normalized) or ``""`` when unknown.
        user: Account name for login events, else ``""``.
        status: HTTP status code for ``http`` events, else 0.
        path: Request path for ``http`` events.
        raw: Original line, truncated for storage.
    """

    ts: float
    source: str
    kind: str
    ip: str = ""
    user: str = ""
    status: int = 0
    path: str = ""
    raw: str = ""


@dataclass
class Finding:
    """A detector verdict about one IP (or user) over a time window."""

    ts: float
    detector: str
    severity: str  # info | warning | critical
    ip: str
    user: str
    message: str
    evidence: str = ""
    score: int = 0
    blockable: bool = False
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Return a JSON-serializable dict."""
        return asdict(self)


# ── IP helpers ─────────────────────────────────────────────────────────────


def normalize_ip(raw: str) -> str:
    """Return a canonical IP string, or ``""`` if ``raw`` isn't an IP.

    IPv4-mapped IPv6 (``::ffff:1.2.3.4``) collapses to plain IPv4 so the same
    host is never tracked twice.
    """
    try:
        addr = ipaddress.ip_address(raw.strip().strip("[]"))
    except ValueError:
        return ""
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return str(addr)


def parse_networks(spec: str) -> list:
    """Parse a comma-separated list of IPs/CIDRs, skipping invalid entries."""
    nets = []
    for part in (spec or "").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            continue
    return nets


def is_blockable_ip(ip: str, allowlist: list | None = None) -> bool:
    """True only for a globally-routable address outside the allowlist.

    Loopback, RFC1918/LAN, link-local, multicast, reserved and documentation
    ranges are never blockable: the monitor must not be able to lock the
    operator out of their own network.
    """
    ip = normalize_ip(ip)
    if not ip:
        return False
    addr = ipaddress.ip_address(ip)
    if not addr.is_global:
        return False
    return not any(
        addr in net for net in (allowlist or []) if net.version == addr.version
    )


# ── Parsers ────────────────────────────────────────────────────────────────

_RAW_MAX = 300
_SSH_PATTERNS = [
    (
        "login_fail",
        re.compile(
            r"Failed (?:password|publickey|keyboard-interactive/pam) for "
            r"(?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port"
        ),
    ),
    ("login_fail", re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>\S+)")),
    (
        "login_fail",
        re.compile(
            r"(?:Connection closed by|Disconnected from) authenticating user "
            r"(?P<user>\S+) (?P<ip>\S+) port"
        ),
    ),
    (
        "login_fail",
        re.compile(
            r"maximum authentication attempts exceeded for "
            r"(?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port"
        ),
    ),
    (
        "login_ok",
        re.compile(
            r"Accepted (?:password|publickey|keyboard-interactive/pam|"
            r"hostbased|gssapi\S*) for (?P<user>\S+) from (?P<ip>\S+) port"
        ),
    ),
]


def parse_sshd_message(message: str, ts: float) -> LogEvent | None:
    """Parse one sshd log message into a LogEvent, or None if irrelevant."""
    for kind, pattern in _SSH_PATTERNS:
        m = pattern.search(message)
        if m:
            ip = normalize_ip(m.group("ip"))
            if not ip:
                return None
            return LogEvent(
                ts=ts,
                source="sshd",
                kind=kind,
                ip=ip,
                user=m.group("user"),
                raw=message[:_RAW_MAX],
            )
    return None


# nginx/apache "combined": ip - user [time] "METHOD path PROTO" status size ...
_ACCESS_RE = re.compile(
    r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "
    r'"(?P<method>[A-Z]+) (?P<path>\S*)[^"]*" (?P<status>\d{3}) '
)


def parse_access_line(line: str, source: str = "nginx") -> LogEvent | None:
    """Parse one combined-format access-log line into an ``http`` event."""
    m = _ACCESS_RE.match(line)
    if not m:
        return None
    ip = normalize_ip(m.group("ip"))
    if not ip:
        return None
    try:
        ts = datetime.strptime(m.group("time"), "%d/%b/%Y:%H:%M:%S %z").timestamp()
    except ValueError:
        ts = time.time()
    return LogEvent(
        ts=ts,
        source=source,
        kind="http",
        ip=ip,
        status=int(m.group("status")),
        path=m.group("path")[:200],
        raw=line[:_RAW_MAX],
    )


# ── Baseline (learned known-good logins) ───────────────────────────────────


class Baseline:
    """Learned set of normal login sources, accounts and hours.

    Attributes:
        ips: Source IPs that have logged in successfully before.
        users: Accounts that have logged in successfully before.
        hours: Hours-of-day (0-23) with at least one successful login.
        logins: Total successful logins observed.
    """

    def __init__(self) -> None:
        self.ips: set = set()
        self.users: set = set()
        self.hours: set = set()
        self.logins = 0

    def add(self, ev: LogEvent) -> None:
        """Fold one successful login into the baseline."""
        self.ips.add(ev.ip)
        self.users.add(ev.user)
        self.hours.add(datetime.fromtimestamp(ev.ts).hour)
        self.logins += 1


# ── Detection engine ───────────────────────────────────────────────────────

_PROBE_RE = re.compile(
    r"(?:\.env|\.git/|wp-login|wp-admin|xmlrpc\.php|phpmyadmin|/etc/passwd|"
    r"\.\./|cgi-bin|boaform|/actuator|/vendor/phpunit|\.aws/|id_rsa|"
    r"/admin\.php|/shell|eval-stdin|setup\.cgi)",
    re.IGNORECASE,
)


@dataclass
class Thresholds:
    """Detector tuning. Defaults suit a small self-hosted LAN server."""

    brute_fails: int = 6
    brute_window: float = 120.0
    spray_users: int = 4
    spray_window: float = 300.0
    dist_ips: int = 5
    dist_window: float = 600.0
    success_after_fails: int = 3
    success_window: float = 600.0
    burst_requests: int = 100
    burst_window: float = 10.0
    scan_errors: int = 8
    scan_window: float = 60.0
    probe_hits: int = 3
    metronome_requests: int = 12
    metronome_cv: float = 0.1
    metronome_max_mean: float = 5.0
    cooldown: float = 600.0
    odd_hour_min_logins: int = 10
    max_tracked_ips: int = 5000


class ThreatEngine:
    """Sliding-window detectors over a stream of LogEvents.

    Args:
        thresholds: Detector tuning.
        baseline: Learned login baseline (mutated as logins are seen).
        allowlist: Networks never flagged as ``blockable``.
        learning: While True, baseline detectors only learn (emit ``info``).
        clock: Injectable time source for tests.
    """

    def __init__(
        self,
        thresholds: Thresholds | None = None,
        baseline: Baseline | None = None,
        allowlist: list | None = None,
        learning: bool = True,
        clock=time.time,
    ) -> None:
        self.t = thresholds or Thresholds()
        self.baseline = baseline or Baseline()
        self.allowlist = allowlist or []
        self.learning = learning
        self._clock = clock
        self._fails: OrderedDict = OrderedDict()  # ip -> deque[(ts, user)]
        self._user_fails: OrderedDict = OrderedDict()  # user -> deque[(ts, ip)]
        self._http: OrderedDict = OrderedDict()  # ip -> deque[(ts, status, path)]
        self._cooldown: dict = {}  # (detector, key) -> last emit ts

    # -- bookkeeping --------------------------------------------------------

    def _track(self, table: OrderedDict, key: str) -> deque:
        """Fetch/create a window deque, evicting the least-recently-used key."""
        q = table.get(key)
        if q is None:
            q = table[key] = deque()
            while len(table) > self.t.max_tracked_ips:
                table.popitem(last=False)
        else:
            table.move_to_end(key)
        return q

    @staticmethod
    def _trim(q: deque, horizon: float) -> None:
        while q and q[0][0] < horizon:
            q.popleft()

    def _emit(self, out: list, key: tuple, f: Finding) -> None:
        """Append a finding unless the same (detector, key) fired recently."""
        last = self._cooldown.get(key)
        if last is not None and f.ts - last < self.t.cooldown:
            return
        self._cooldown[key] = f.ts
        if len(self._cooldown) > 4 * self.t.max_tracked_ips:
            cutoff = f.ts - self.t.cooldown
            self._cooldown = {k: v for k, v in self._cooldown.items() if v >= cutoff}
        out.append(f)

    def _blockable(self, ip: str) -> bool:
        return is_blockable_ip(ip, self.allowlist)

    # -- ingestion ----------------------------------------------------------

    def ingest(self, ev: LogEvent, seed: bool = False) -> list:
        """Feed one event; return any new findings.

        Args:
            ev: The event.
            seed: Backfill mode: successful logins update the baseline but no
                detectors run, so history never produces alerts.
        """
        if seed:
            if ev.kind == "login_ok":
                self.baseline.add(ev)
            return []
        out: list = []
        if ev.kind == "login_fail":
            self._on_fail(ev, out)
        elif ev.kind == "login_ok":
            self._on_success(ev, out)
        elif ev.kind == "http":
            self._on_http(ev, out)
        return out

    def _on_fail(self, ev: LogEvent, out: list) -> None:
        t = self.t
        if not ev.ip:
            return
        q = self._track(self._fails, ev.ip)
        q.append((ev.ts, ev.user))
        self._trim(q, ev.ts - max(t.brute_window, t.spray_window, t.success_window))
        recent = [u for ts, u in q if ts >= ev.ts - t.brute_window]
        if len(recent) >= t.brute_fails:
            self._emit(
                out,
                ("brute_force", ev.ip),
                Finding(
                    ts=ev.ts,
                    detector="brute_force",
                    severity="warning",
                    ip=ev.ip,
                    user=ev.user,
                    score=min(100, 40 + 5 * len(recent)),
                    message=f"Brute force: {len(recent)} failed logins from {ev.ip} "
                    f"in {int(t.brute_window)}s",
                    evidence=ev.raw,
                    blockable=self._blockable(ev.ip),
                ),
            )
        users = {u for ts, u in q if ts >= ev.ts - t.spray_window}
        if len(users) >= t.spray_users:
            self._emit(
                out,
                ("password_spray", ev.ip),
                Finding(
                    ts=ev.ts,
                    detector="password_spray",
                    severity="warning",
                    ip=ev.ip,
                    user=ev.user,
                    score=70,
                    message=f"Password spraying: {len(users)} different accounts "
                    f"tried from {ev.ip} in {int(t.spray_window)}s",
                    evidence=", ".join(sorted(users))[:_RAW_MAX],
                    blockable=self._blockable(ev.ip),
                ),
            )
        if ev.user:
            uq = self._track(self._user_fails, ev.user)
            uq.append((ev.ts, ev.ip))
            self._trim(uq, ev.ts - t.dist_window)
            ips = {i for _, i in uq}
            if len(ips) >= t.dist_ips:
                self._emit(
                    out,
                    ("distributed", ev.user),
                    Finding(
                        ts=ev.ts,
                        detector="distributed_attack",
                        severity="warning",
                        ip="",
                        user=ev.user,
                        score=65,
                        message=f"Distributed attack: account '{ev.user}' targeted "
                        f"from {len(ips)} IPs in {int(t.dist_window)}s",
                        evidence=", ".join(sorted(ips))[:_RAW_MAX],
                        blockable=False,
                    ),
                )

    def _on_success(self, ev: LogEvent, out: list) -> None:
        t, b = self.t, self.baseline
        # Success right after a run of failures from the same IP.
        q = self._fails.get(ev.ip)
        if q:
            n = sum(1 for ts, _ in q if ts >= ev.ts - t.success_window)
            if n >= t.success_after_fails:
                self._emit(
                    out,
                    ("success_after_fail", ev.ip),
                    Finding(
                        ts=ev.ts,
                        detector="success_after_failures",
                        severity="critical",
                        ip=ev.ip,
                        user=ev.user,
                        score=95,
                        message=f"Login succeeded for '{ev.user}' from {ev.ip} after "
                        f"{n} failures — possible compromised credentials",
                        evidence=ev.raw,
                        blockable=False,
                    ),
                )
        if ev.user == "root":
            self._emit(
                out,
                ("root_login", ev.ip),
                Finding(
                    ts=ev.ts,
                    detector="root_login",
                    severity="critical",
                    ip=ev.ip,
                    user="root",
                    score=90,
                    message=f"Remote root login from {ev.ip}",
                    evidence=ev.raw,
                ),
            )
        new_ip = ev.ip not in b.ips
        new_user = ev.user not in b.users
        odd_hour = (
            b.logins >= t.odd_hour_min_logins
            and datetime.fromtimestamp(ev.ts).hour not in b.hours
        )
        if new_ip or new_user or odd_hour:
            reasons = []
            if new_ip:
                reasons.append(f"new source {ev.ip}")
            if new_user:
                reasons.append(f"first login for '{ev.user}'")
            if odd_hour:
                reasons.append("unusual hour")
            sev = "info" if self.learning else "warning"
            self._emit(
                out,
                ("new_login", ev.ip, ev.user),
                Finding(
                    ts=ev.ts,
                    detector="new_login_pattern",
                    severity=sev,
                    ip=ev.ip,
                    user=ev.user,
                    score=35 if self.learning else 60,
                    message=f"Login for '{ev.user}' from {ev.ip}: "
                    + ", ".join(reasons)
                    + (" (learning)" if self.learning else ""),
                    evidence=ev.raw,
                ),
            )
        b.add(ev)

    def _on_http(self, ev: LogEvent, out: list) -> None:
        t = self.t
        q = self._track(self._http, ev.ip)
        q.append((ev.ts, ev.status, ev.path))
        self._trim(q, ev.ts - max(t.scan_window, t.burst_window, 120.0))
        blockable = self._blockable(ev.ip)
        burst = sum(1 for ts, _, _ in q if ts >= ev.ts - t.burst_window)
        if burst >= t.burst_requests:
            self._emit(
                out,
                ("http_burst", ev.ip),
                Finding(
                    ts=ev.ts,
                    detector="request_burst",
                    severity="warning",
                    ip=ev.ip,
                    user="",
                    score=60,
                    message=f"Request burst: {burst} requests from {ev.ip} in "
                    f"{int(t.burst_window)}s",
                    evidence=ev.raw,
                    blockable=blockable,
                ),
            )
        window = [(s, p) for ts, s, p in q if ts >= ev.ts - t.scan_window]
        errors = sum(1 for s, _ in window if s in (401, 403, 404))
        probes = {p.split("?")[0] for _, p in window if _PROBE_RE.search(p)}
        if len(probes) >= t.probe_hits or errors >= t.scan_errors:
            why = (
                f"{len(probes)} probe paths"
                if len(probes) >= t.probe_hits
                else f"{errors} client errors"
            )
            self._emit(
                out,
                ("http_scan", ev.ip),
                Finding(
                    ts=ev.ts,
                    detector="web_scan",
                    severity="warning",
                    ip=ev.ip,
                    user="",
                    score=75,
                    message=f"Web scanning from {ev.ip}: {why} in {int(t.scan_window)}s",
                    evidence=", ".join(sorted(probes))[:_RAW_MAX] or ev.raw,
                    blockable=blockable,
                ),
            )
        # Metronome timing is only meaningful for public clients: LAN pollers
        # (dashboards, health checks) are legitimately periodic.
        if blockable and len(q) >= t.metronome_requests:
            times = [ts for ts, _, _ in list(q)[-t.metronome_requests :]]
            gaps = [b - a for a, b in zip(times, times[1:])]
            mean = sum(gaps) / len(gaps)
            if 0 < mean <= t.metronome_max_mean:
                var = sum((g - mean) ** 2 for g in gaps) / len(gaps)
                if (var**0.5) / mean < t.metronome_cv:
                    self._emit(
                        out,
                        ("http_metronome", ev.ip),
                        Finding(
                            ts=ev.ts,
                            detector="bot_timing",
                            severity="info",
                            ip=ev.ip,
                            user="",
                            score=40,
                            message=f"Bot-like timing from {ev.ip}: {len(gaps) + 1} "
                            f"requests every {mean:.1f}s (±{(var**0.5):.2f}s)",
                            evidence=ev.raw,
                            blockable=False,
                        ),
                    )


# ── Persistence ────────────────────────────────────────────────────────────

_SCHEMA = [
    "CREATE TABLE IF NOT EXISTS security_events ("
    "id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, "
    "detector TEXT NOT NULL, severity TEXT NOT NULL, ip TEXT NOT NULL, "
    "username TEXT NOT NULL, message TEXT NOT NULL, evidence TEXT NOT NULL, "
    "score INTEGER NOT NULL, blockable INTEGER NOT NULL)",
    "CREATE INDEX IF NOT EXISTS idx_secev_ts ON security_events(ts)",
    "CREATE INDEX IF NOT EXISTS idx_secev_ip ON security_events(ip, ts)",
    "CREATE TABLE IF NOT EXISTS threat_baseline ("
    "kind TEXT NOT NULL, value TEXT NOT NULL, first_seen INTEGER NOT NULL, "
    "PRIMARY KEY (kind, value))",
    "CREATE TABLE IF NOT EXISTS threat_meta (key TEXT PRIMARY KEY, value TEXT)",
]


def open_db(path: str) -> sqlite3.Connection:
    """Open the threat DB (same file as metrics history), creating tables."""
    conn = sqlite3.connect(path, timeout=5)
    for stmt in _SCHEMA:
        conn.execute(stmt)
    return conn


def record_finding(conn: sqlite3.Connection, f: Finding) -> int:
    """Insert one finding. Returns its row id."""
    with conn:
        cur = conn.execute(
            "INSERT INTO security_events (ts, detector, severity, ip, username, "
            "message, evidence, score, blockable) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                int(f.ts),
                f.detector,
                f.severity,
                f.ip,
                f.user,
                f.message,
                f.evidence,
                f.score,
                1 if f.blockable else 0,
            ),
        )
    return int(cur.lastrowid)


def query_findings(
    conn: sqlite3.Connection,
    since: float = 0,
    ip: str = "",
    min_severity: str = "info",
    limit: int = 200,
) -> list:
    """Return findings newest-first, optionally filtered."""
    rank = {"info": 0, "warning": 1, "critical": 2}
    allowed = [s for s, r in rank.items() if r >= rank.get(min_severity, 0)]
    sql = (
        "SELECT id, ts, detector, severity, ip, username, message, evidence, "
        "score, blockable FROM security_events WHERE ts >= ? "
        f"AND severity IN ({','.join('?' * len(allowed))})"
    )
    args: list = [int(since), *allowed]
    if ip:
        sql += " AND ip = ?"
        args.append(ip)
    sql += " ORDER BY ts DESC, id DESC LIMIT ?"
    args.append(max(1, min(limit, 1000)))
    cols = (
        "id",
        "ts",
        "detector",
        "severity",
        "ip",
        "user",
        "message",
        "evidence",
        "score",
        "blockable",
    )
    rows = [dict(zip(cols, r)) for r in conn.execute(sql, args)]
    for r in rows:
        r["blockable"] = bool(r["blockable"])
    return rows


def top_offenders(conn: sqlite3.Connection, since: float, limit: int = 10) -> list:
    """Return IPs ranked by finding count and peak score since ``since``."""
    cur = conn.execute(
        "SELECT ip, COUNT(*), MAX(score), MAX(ts) FROM security_events "
        "WHERE ts >= ? AND ip != '' GROUP BY ip ORDER BY MAX(score) DESC, "
        "COUNT(*) DESC LIMIT ?",
        (int(since), limit),
    )
    return [
        {"ip": r[0], "count": r[1], "max_score": r[2], "last_ts": r[3]} for r in cur
    ]


def prune_findings(
    conn: sqlite3.Connection, days: float, now: float | None = None
) -> int:
    """Delete findings older than ``days``. Returns rows removed."""
    cutoff = int((now if now is not None else time.time()) - days * 86400)
    with conn:
        return conn.execute(
            "DELETE FROM security_events WHERE ts < ?", (cutoff,)
        ).rowcount


def load_baseline(conn: sqlite3.Connection) -> Baseline:
    """Rebuild the Baseline from the DB."""
    b = Baseline()
    for kind, value in conn.execute("SELECT kind, value FROM threat_baseline"):
        if kind == "ip":
            b.ips.add(value)
        elif kind == "user":
            b.users.add(value)
        elif kind == "hour":
            b.hours.add(int(value))
    row = conn.execute("SELECT value FROM threat_meta WHERE key='logins'").fetchone()
    b.logins = int(row[0]) if row else 0
    return b


def save_baseline(
    conn: sqlite3.Connection, b: Baseline, now: float | None = None
) -> None:
    """Persist the Baseline (idempotent upserts)."""
    ts = int(now if now is not None else time.time())
    rows = (
        [("ip", v, ts) for v in b.ips]
        + [("user", v, ts) for v in b.users]
        + [("hour", str(v), ts) for v in b.hours]
    )
    with conn:
        conn.executemany(
            "INSERT OR IGNORE INTO threat_baseline (kind, value, first_seen) "
            "VALUES (?,?,?)",
            rows,
        )
        conn.execute(
            "INSERT OR REPLACE INTO threat_meta (key, value) VALUES ('logins', ?)",
            (str(b.logins),),
        )


def learning_state(
    conn: sqlite3.Connection, learning_days: float, now: float | None = None
) -> tuple:
    """Return ``(learning, learning_ends_ts)``; stamps first-run on first call."""
    now = now if now is not None else time.time()
    row = conn.execute("SELECT value FROM threat_meta WHERE key='started'").fetchone()
    if row is None:
        with conn:
            conn.execute(
                "INSERT INTO threat_meta (key, value) VALUES ('started', ?)",
                (str(int(now)),),
            )
        started = now
    else:
        started = float(row[0])
    ends = started + learning_days * 86400
    return now < ends, ends


# ── Log sources ────────────────────────────────────────────────────────────


def read_journal_sshd(
    cursor_file: str,
    backfill: bool = False,
    timeout: int = 20,
    errors: list | None = None,
) -> list:
    """Read new sshd events from journald, resuming from a cursor file.

    Args:
        cursor_file: Writable path where journalctl keeps its cursor.
        backfill: First-run mode: read the last 30 days instead of 1 hour.
        timeout: Subprocess timeout in seconds.
        errors: Optional list; a human-readable problem (missing journalctl,
            no journal permission) is appended so callers can surface it.

    Returns:
        List of LogEvent (oldest first). Empty if journalctl is unavailable or
        the service user lacks journal access.
    """
    since = "-30d" if backfill else "-1h"
    cmd = [
        "journalctl",
        "-t",
        "sshd",
        "-t",
        "sshd-session",
        "-o",
        "json",
        "--no-pager",
        f"--since={since}",
        f"--cursor-file={cursor_file}",
    ]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        if errors is not None:
            errors.append(f"journalctl failed: {exc}")
        return []
    if errors is not None and "insufficient permissions" in res.stderr.lower():
        errors.append(
            "no journal access: add the service user to the systemd-journal group"
        )
    events = []
    for line in res.stdout.splitlines():
        try:
            rec = json.loads(line)
            msg = rec.get("MESSAGE")
            if not isinstance(msg, str):
                continue
            ts = int(rec["__REALTIME_TIMESTAMP"]) / 1_000_000
        except (ValueError, KeyError, TypeError):
            continue
        ev = parse_sshd_message(msg, ts)
        if ev:
            events.append(ev)
    return events


class FileTailer:
    """Incrementally read new lines from a log file, surviving rotation.

    Starts at end-of-file on first open (no historical replay). Rotation is
    detected by inode change, truncation, or a changed file head (a rotated
    file can reuse an inode and already be larger than the old offset).
    """

    _HEAD = 64

    def __init__(self, path: str) -> None:
        self.path = path
        self._inode: int | None = None
        self._pos = 0
        self._head = b""

    def _head_changed(self, fh) -> bool:
        fh.seek(0)
        cur = fh.read(self._HEAD)
        n = min(len(cur), len(self._head))
        changed = cur[:n] != self._head[:n]
        if len(cur) > len(self._head):
            self._head = cur
        return changed

    def read_new(self, max_bytes: int = 4_000_000) -> list:
        """Return complete new lines since the last call (may be empty)."""
        try:
            st = os.stat(self.path)
            fh = open(self.path, "rb")
        except OSError:
            return []
        with fh:
            if self._inode is None:
                self._inode, self._pos = st.st_ino, st.st_size
                fh.seek(0)
                self._head = fh.read(self._HEAD)
                return []
            rotated = st.st_ino != self._inode or st.st_size < self._pos
            if not rotated and self._head_changed(fh):
                rotated = True
            if rotated:
                self._inode, self._pos = st.st_ino, 0
                fh.seek(0)
                self._head = fh.read(self._HEAD)
            if st.st_size == self._pos:
                return []
            fh.seek(self._pos)
            data = fh.read(max_bytes)
        end = data.rfind(b"\n")
        if end < 0:
            return []
        self._pos += end + 1
        return data[: end + 1].decode("utf-8", "replace").splitlines()


def resolve_state_dir(db_path: str) -> Path:
    """Directory for cursor files: alongside the threat DB."""
    return Path(db_path).parent

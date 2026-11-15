"""IP blocking policy for SysMonitor (stdlib only).

Decides *whether* an address may be blocked and records every decision; the
actual enforcement is delegated to the root helper ``sysmon-block`` (an
nftables set), never done in-process.

Modes (``SYSMONITOR_BLOCK_MODE``):
    off      never blocks, records nothing
    dry-run  records "would block" decisions, enforces nothing
    manual   blocks only on explicit operator action (API / signed ntfy link)
    auto     additionally blocks high-confidence findings automatically
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

import threat_detect as td

MODES = ("off", "dry-run", "manual", "auto")
# Detectors precise enough to block without a human in the loop.
AUTO_DETECTORS = frozenset({"brute_force", "password_spray", "web_scan"})
TTL_LADDER = (3600, 86400, 604800)  # 1h, 24h, 7d for repeat offenders
APPROVAL_TTL = 3600
QUARANTINE_DEFAULT_MIN = 15
QUARANTINE_MAX_MIN = 60
QUARANTINE_CONFIRM = "QUARANTINE"
_DRYRUN_COOLDOWN = 600.0


class BlockRefused(Exception):
    """A block was refused by policy; ``str(exc)`` is the human reason."""


@dataclass
class Settings:
    """Blocker configuration."""

    mode: str = "off"
    helper: str = "/usr/local/sbin/sysmon-block"
    max_active: int = 200
    max_per_hour: int = 10
    min_score: int = 60
    allowlist: list = field(default_factory=list)


_SCHEMA = [
    "CREATE TABLE IF NOT EXISTS ip_blocks ("
    "id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL, ts INTEGER NOT NULL, "
    "ttl INTEGER NOT NULL, expires INTEGER NOT NULL, mode TEXT NOT NULL, "
    "source TEXT NOT NULL, detector TEXT NOT NULL, reason TEXT NOT NULL, "
    "status TEXT NOT NULL, removed_ts INTEGER, removed_by TEXT)",
    "CREATE INDEX IF NOT EXISTS idx_ipblocks_ip ON ip_blocks(ip, ts)",
]


def open_db(path: str) -> sqlite3.Connection:
    """Open the shared DB and ensure the ip_blocks table exists."""
    conn = td.open_db(path)
    for stmt in _SCHEMA:
        conn.execute(stmt)
    return conn


# ── Signed one-tap approval links ──────────────────────────────────────────


def load_or_create_secret(path: Path) -> bytes:
    """Return the HMAC key, creating a random 0600 key file on first use."""
    try:
        data = path.read_bytes()
        if len(data) >= 16:
            return data
    except OSError:
        pass
    key = secrets.token_bytes(32)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(key)
    path.chmod(0o600)
    return key


def sign_approval(key: bytes, ip: str, exp: int) -> str:
    """HMAC over (ip, expiry): scoped to one address and time-limited."""
    return hmac.new(key, f"block:{ip}:{exp}".encode(), hashlib.sha256).hexdigest()


def verify_approval(
    key: bytes, ip: str, exp: int, sig: str, now: float | None = None
) -> bool:
    """Constant-time check of a signed approval; False if expired or forged."""
    if (now if now is not None else time.time()) > exp:
        return False
    return hmac.compare_digest(sign_approval(key, ip, exp), sig or "")


# ── Manager ────────────────────────────────────────────────────────────────


class BlockManager:
    """Applies the blocking policy and records an audit trail.

    Args:
        db_path: Shared SQLite DB.
        settings: Mode, helper path, caps, allowlist.
        known_ips: Callable returning IPs that have logged in successfully
            (never auto-blocked: guards the operator's own remote address).
        runner: subprocess.run-compatible callable (injected in tests).
        clock: Time source.
        log: ``log(message, level)`` callback for the event log.
    """

    def __init__(
        self,
        db_path,
        settings,
        known_ips=lambda: set(),
        runner=subprocess.run,
        clock=time.time,
        log=lambda msg, level="info": None,
    ) -> None:
        self.db_path = db_path
        self.s = settings
        self.known_ips = known_ips
        self._run = runner
        self._clock = clock
        self._log = log

    # -- helper bridge ------------------------------------------------------

    def _helper(self, *args: str) -> dict:
        try:
            res = self._run(
                ["sudo", "-n", self.s.helper, *args],
                capture_output=True,
                text=True,
                timeout=20,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise BlockRefused(f"blocker helper unavailable: {exc}") from exc
        try:
            out = json.loads(res.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            out = {"ok": False, "error": (res.stderr or "no output").strip()[:200]}
        if res.returncode != 0 or not out.get("ok"):
            raise BlockRefused(f"helper refused: {out.get('error', 'unknown error')}")
        return out

    def init_helper(self) -> None:
        """Create/restore the nft table (manual and auto modes only)."""
        if self.s.mode in ("manual", "auto"):
            self._helper("init")

    # -- queries ------------------------------------------------------------

    def _conn(self) -> sqlite3.Connection:
        return open_db(self.db_path)

    def _expire_stale(self, conn: sqlite3.Connection) -> None:
        with conn:
            conn.execute(
                "UPDATE ip_blocks SET status='expired' WHERE status='active' AND expires <= ?",
                (int(self._clock()),),
            )

    def active(self) -> list:
        """Currently-enforced blocks, newest first."""
        conn = self._conn()
        try:
            self._expire_stale(conn)
            return self._rows(conn, "status='active'", (), 500)
        finally:
            conn.close()

    def history(self, limit: int = 100) -> list:
        """Every recorded decision (blocks, would-blocks, removals), newest first."""
        conn = self._conn()
        try:
            self._expire_stale(conn)
            return self._rows(conn, "1=1", (), limit)
        finally:
            conn.close()

    @staticmethod
    def _rows(conn, where: str, args: tuple, limit: int) -> list:
        cur = conn.execute(
            "SELECT id, ip, ts, ttl, expires, mode, source, detector, reason, status, "
            f"removed_ts, removed_by FROM ip_blocks WHERE {where} "
            "ORDER BY id DESC LIMIT ?",
            (*args, max(1, min(limit, 1000))),
        )
        cols = (
            "id",
            "ip",
            "ts",
            "ttl",
            "expires",
            "mode",
            "source",
            "detector",
            "reason",
            "status",
            "removed_ts",
            "removed_by",
        )
        return [dict(zip(cols, r)) for r in cur]

    def _offences(self, conn, ip: str) -> int:
        return conn.execute(
            "SELECT COUNT(*) FROM ip_blocks WHERE ip=? AND status IN "
            "('active','expired')",
            (ip,),  # operator removals = false positives
        ).fetchone()[0]

    # -- policy -------------------------------------------------------------

    def _check_allowed(self, conn, ip: str, force: bool) -> str:
        norm = td.normalize_ip(ip)
        if not norm:
            raise BlockRefused(f"not an IP address: {ip!r}")
        if not td.is_blockable_ip(norm, self.s.allowlist):
            raise BlockRefused(
                f"{norm} is not a blockable public address (LAN/allowlisted)"
            )
        if not force and norm in self.known_ips():
            raise BlockRefused(
                f"{norm} has logged in successfully before (known source)"
            )
        n_active = conn.execute(
            "SELECT COUNT(*) FROM ip_blocks WHERE status='active' AND expires > ?",
            (int(self._clock()),),
        ).fetchone()[0]
        if n_active >= self.s.max_active:
            raise BlockRefused(f"active block cap reached ({self.s.max_active})")
        return norm

    def _rate_ok(self, conn) -> bool:
        n = conn.execute(
            "SELECT COUNT(*) FROM ip_blocks WHERE source='auto' AND ts > ? "
            "AND status IN ('active','expired','removed')",
            (int(self._clock()) - 3600,),
        ).fetchone()[0]
        return n < self.s.max_per_hour

    def block(
        self,
        ip: str,
        reason: str,
        source: str = "manual",
        ttl: int | None = None,
        detector: str = "",
        force: bool = False,
    ) -> dict:
        """Block one address now (manual/auto modes).

        Raises:
            BlockRefused: policy or helper refused; nothing was enforced.
        """
        if self.s.mode not in ("manual", "auto"):
            raise BlockRefused(f"blocking is disabled (mode: {self.s.mode})")
        conn = self._conn()
        try:
            self._expire_stale(conn)
            norm = self._check_allowed(conn, ip, force)
            ladder_ttl = TTL_LADDER[
                min(self._offences(conn, norm), len(TTL_LADDER) - 1)
            ]
            ttl = int(ttl) if ttl else ladder_ttl
            self._helper("add", norm, str(ttl))
            now = int(self._clock())
            with conn:
                cur = conn.execute(
                    "INSERT INTO ip_blocks (ip, ts, ttl, expires, mode, source, detector, "
                    "reason, status) VALUES (?,?,?,?,?,?,?,?, 'active')",
                    (
                        norm,
                        now,
                        ttl,
                        now + ttl,
                        self.s.mode,
                        source,
                        detector,
                        reason[:300],
                    ),
                )
            self._log(f"BLOCKED {norm} for {ttl}s ({source}: {reason})", "warning")
            return {"id": cur.lastrowid, "ip": norm, "ttl": ttl, "expires": now + ttl}
        finally:
            conn.close()

    def unblock(self, ip: str, by: str = "manual") -> dict:
        """Remove a block (works in any mode so an operator can always undo)."""
        norm = td.normalize_ip(ip)
        if not norm:
            raise BlockRefused(f"not an IP address: {ip!r}")
        self._helper("del", norm)
        conn = self._conn()
        try:
            with conn:
                conn.execute(
                    "UPDATE ip_blocks SET status='removed', removed_ts=?, removed_by=? "
                    "WHERE ip=? AND status='active'",
                    (int(self._clock()), by, norm),
                )
        finally:
            conn.close()
        self._log(f"UNBLOCKED {norm} by {by}", "info")
        return {"ip": norm}

    def flush(self, by: str = "manual") -> int:
        """Remove every block. Returns how many were active."""
        self._helper("flush")
        conn = self._conn()
        try:
            with conn:
                n = conn.execute(
                    "UPDATE ip_blocks SET status='removed', removed_ts=?, removed_by=? "
                    "WHERE status='active'",
                    (int(self._clock()), by),
                ).rowcount
        finally:
            conn.close()
        self._log(f"FLUSHED all blocks ({n}) by {by}", "warning")
        return n

    # -- finding hook -------------------------------------------------------

    def handle_finding(self, f) -> dict:
        """Apply policy to one finding.

        Returns:
            ``{"action": ...}`` where action is ``blocked``, ``would_block``,
            ``proposed`` (blockable, awaiting an operator), or ``none``;
            ``reason`` explains refusals.
        """
        if self.s.mode == "off" or not f.blockable or not f.ip:
            return {"action": "none"}
        eligible = f.detector in AUTO_DETECTORS and f.score >= self.s.min_score
        if self.s.mode == "manual" or (self.s.mode == "auto" and not eligible):
            return {"action": "proposed"}
        if self.s.mode == "dry-run":
            return self._record_dry_run(f, eligible)
        conn = self._conn()
        try:
            if not self._rate_ok(conn):
                return {"action": "proposed", "reason": "auto-block rate limit reached"}
        finally:
            conn.close()
        try:
            res = self.block(f.ip, f.message, source="auto", detector=f.detector)
        except BlockRefused as exc:
            return {"action": "proposed", "reason": str(exc)}
        return {"action": "blocked", "ttl": res["ttl"]}

    def _record_dry_run(self, f, eligible: bool) -> dict:
        if not eligible:
            return {"action": "none"}
        conn = self._conn()
        try:
            try:
                self._check_allowed(conn, f.ip, force=False)
            except BlockRefused as exc:
                return {"action": "none", "reason": str(exc)}
            now = int(self._clock())
            seen = conn.execute(
                "SELECT 1 FROM ip_blocks WHERE ip=? AND status='would_block' AND ts > ?",
                (f.ip, now - int(_DRYRUN_COOLDOWN)),
            ).fetchone()
            if not seen:
                ttl = TTL_LADDER[min(self._offences(conn, f.ip), len(TTL_LADDER) - 1)]
                with conn:
                    conn.execute(
                        "INSERT INTO ip_blocks (ip, ts, ttl, expires, mode, source, detector, "
                        "reason, status) VALUES (?,?,?,?,?,?,?,?, 'would_block')",
                        (
                            f.ip,
                            now,
                            ttl,
                            now + ttl,
                            "dry-run",
                            "auto",
                            f.detector,
                            f.message[:300],
                        ),
                    )
            return {"action": "would_block"}
        finally:
            conn.close()

    # -- outbound quarantine (manual only) ----------------------------------

    def quarantine_status(self) -> dict:
        """Current quarantine state from the helper (never raises)."""
        try:
            out = self._helper("quarantine", "status")
        except BlockRefused as exc:
            return {"available": False, "active": False, "error": str(exc)}
        return {
            "available": True,
            "active": bool(out.get("active")),
            "until": out.get("until"),
            "remaining": out.get("remaining"),
        }

    def quarantine_start(self, minutes: int | None = None, by: str = "manual") -> dict:
        """Cut outbound internet (LAN + SSH kept) for a bounded time.

        The helper arms a root-owned auto-revert timer first and refuses to
        engage without it. There is intentionally no automatic caller.

        Raises:
            BlockRefused: invalid duration, or the helper refused.
        """
        minutes = QUARANTINE_DEFAULT_MIN if minutes is None else int(minutes)
        if not 1 <= minutes <= QUARANTINE_MAX_MIN:
            raise BlockRefused(f"minutes must be between 1 and {QUARANTINE_MAX_MIN}")
        out = self._helper("quarantine", "on", str(minutes * 60))
        self._log(f"QUARANTINE engaged for {minutes} min by {by}", "error")
        return {"active": True, "until": out.get("until"), "minutes": minutes}

    def quarantine_release(self, by: str = "manual") -> dict:
        """Restore internet immediately."""
        self._helper("quarantine", "off")
        self._log(f"QUARANTINE released by {by}", "success")
        return {"active": False}

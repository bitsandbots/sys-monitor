#!/usr/bin/env python3
"""
hiddenscope v2.0.0 — Hidden endpoint & connection detector
MIT License — CoreConduit Consulting (https://coreconduit.com)

Vendored into SysMonitor unmodified as `hiddenscope_scanner.py` so the node
agent can import its detection logic directly (stdlib only — no extra
dependency). SysMonitor calls `_connections()`, `_listeners()`,
`score_connection()`, `SUSPICIOUS_PORTS`, and `AllowList` from
`sys_monitor.py`'s "Security Monitoring" section to power the dashboard's
Security tab and alert card. This file also remains fully usable standalone
as the original `hiddenscope` CLI (`python3 hiddenscope_scanner.py live`,
`scan`, `watch`, `report`, etc.) — nothing below this note has been changed.

Subcommands:
  live       Active TCP/UDP connections with process mapping
  listeners  Bound/listening sockets
  scan       Static scan: bytes + source patterns with false-positive reduction
  deps       Dependency manifest scan (package.json, requirements.txt, …)
  watch      Continuous delta monitoring with cooldown, allowlist, state filters
  baseline   Capture or diff a connection snapshot
  report     Full system snapshot (connections + listeners + findings)

Global flags:
  --json           Machine-readable JSON output
  --severity       Minimum severity to surface  info|low|medium|high|critical
  --no-color       Disable ANSI colour
  --whitelist FILE Load a JSON allowlist (procs, ports, networks, url_domains)

Watch flags:
  --interval N     Poll interval in seconds (default: 5)
  --cooldown N     Suppress re-alerting same (proc,addr) for N seconds (default: 60)
  --public-only    Only alert on external connections
  --states LIST    Comma-separated TCP states to watch (default: ESTABLISHED,SYN_SENT)
  --ignore-proc    Comma-separated process names to suppress
  --ignore-port    Comma-separated ports to suppress
  --ignore-ip      Comma-separated IPs or CIDRs to suppress
  --log FILE       Append NDJSON alert log
  --show-closed    Also report closed connections

Scan flags:
  --max-size MB    Skip files > N MB (default: 10)
  --skip-dir NAME  Additional directory name to exclude (repeatable)
  --no-fp-filter   Disable automatic false-positive reduction heuristics

Exit codes:  0=clean  1=findings at/above --severity  2=error
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import math
import re
import socket
import subprocess
import sys
import textwrap
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Set, Tuple

# ── Optional enhanced deps ────────────────────────────────────────────────────
try:
    import psutil

    HAS_PSUTIL = True
except ImportError:  # pragma: no cover
    psutil = None  # type: ignore[assignment]
    HAS_PSUTIL = False

# ── ANSI colour (degrades with --no-color or non-TTY) ────────────────────────
_ANSI: Dict[str, str] = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "green": "\033[32m",
    "cyan": "\033[36m",
    "blue": "\033[34m",
    "yellow": "\033[33m",
    "red": "\033[31m",
    "bred": "\033[1;31m",
    "magenta": "\033[35m",
}
_USE_COLOR: bool = sys.stdout.isatty()


def _c(key: str, text: str) -> str:
    return f"{_ANSI.get(key,'')}{text}{_ANSI['reset']}" if _USE_COLOR else text


def _err(msg: str) -> None:
    print(f"  ERROR: {msg}", file=sys.stderr)


# ── Version / identity ────────────────────────────────────────────────────────
VERSION = "1.0.0"
PROG = "hiddenscope"

# ── Severity ──────────────────────────────────────────────────────────────────
SEV_LEVELS = ["info", "low", "medium", "high", "critical"]
SEV_COLOR = {
    "info": "cyan",
    "low": "blue",
    "medium": "yellow",
    "high": "red",
    "critical": "bred",
}
SEV_ICONS = {
    "info": "[i]",
    "low": "[~]",
    "medium": "[!]",
    "high": "[!!]",
    "critical": "[CRIT]",
}


def _sev(s: str) -> int:
    return SEV_LEVELS.index(s) if s in SEV_LEVELS else 0


def _sev_down(s: str, steps: int = 1) -> str:
    return SEV_LEVELS[max(0, _sev(s) - steps)]


# ── Known C2 / backdoor ports ─────────────────────────────────────────────────
SUSPICIOUS_PORTS: Dict[int, str] = {
    23: "Telnet",
    1234: "Common C2",
    1337: "l33t/C2",
    4444: "Metasploit",
    4445: "Metasploit alt",
    5555: "Android ADB/C2",
    6666: "IRC/C2",
    6667: "IRC",
    8888: "Jupyter/C2",
    9001: "Tor ORPort",
    9050: "Tor SOCKS",
    9051: "Tor control",
    12345: "NetBus",
    31337: "Back Orifice",
    65535: "Max-port/suspicious",
}

# ── RFC1918 / loopback / link-local ──────────────────────────────────────────
_PRIV_PFX = (
    "10.",
    "192.168.",
    "127.",
    "169.254.",
    "::1",
    "fe80:",
    "fc00:",
    "fd",
    "0.0.0.0",
    "::",
)


def is_private(addr: Optional[str]) -> bool:
    if not addr or addr in ("-", "*", ""):
        return True
    addr = addr.strip()
    if any(addr.startswith(p) for p in _PRIV_PFX):
        return True
    if addr.startswith("172."):
        try:
            return 16 <= int(addr.split(".")[1]) <= 31
        except (IndexError, ValueError):
            pass
    return False


def _parse_addr(s: str) -> Tuple[Optional[str], Optional[int]]:
    """Split 'ip:port' or '[ipv6]:port' → (ip, port)."""
    if not s or s in ("-", "*"):
        return None, None
    m = re.match(r"^\[([^\]]+)\]:(\d+)$", s)
    if m:
        return m.group(1), int(m.group(2))
    if ":" in s:
        ip, _, p = s.rpartition(":")
        try:
            return ip or None, int(p)
        except ValueError:
            pass
    return s or None, None


# ═══════════════════════════════════════════════════════════════════════════════
# FALSE-POSITIVE REDUCTION CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════

# Documentation/reserved IP networks — never generate a finding for these
_DOC_NET_STRS = [
    "192.0.2.0/24",  # TEST-NET-1     (RFC 5737)
    "198.51.100.0/24",  # TEST-NET-2     (RFC 5737)
    "203.0.113.0/24",  # TEST-NET-3     (RFC 5737)
    "198.18.0.0/15",  # Benchmarking   (RFC 2544)
    "100.64.0.0/10",  # CGNAT shared   (RFC 6598)
    "240.0.0.0/4",  # Reserved class E
    "224.0.0.0/4",  # Multicast
]
_DOC_NETWORKS = [ipaddress.ip_network(s) for s in _DOC_NET_STRS]

# Lock / generated files — skip URL and IP patterns (massive false-positive source)
_SKIP_URL_SCAN_FILES: Set[str] = {
    "package-lock.json",
    "yarn.lock",
    "Cargo.lock",
    "poetry.lock",
    "Pipfile.lock",
    "composer.lock",
    "Gemfile.lock",
    "shrinkwrap.json",
    "npm-shrinkwrap.json",
}

# URL domains that are documentation / testing / standards — downgrade severity
_BENIGN_DOMAINS: Set[str] = {
    "example.com",
    "example.org",
    "example.net",
    "test.com",
    "localhost",
    "httpbin.org",
    "schema.org",
    "json-schema.org",
    "w3.org",
    "iana.org",
    "ietf.org",
    "rfc-editor.org",
    "docs.python.org",
    "docs.rs",
    "pkg.go.dev",
    "developer.mozilla.org",
    "developer.apple.com",
    "docs.github.com",
    "docs.aws.amazon.com",
}

# Path fragments that indicate test / fixture / example directories
_TEST_DIR_NAMES: Set[str] = {
    "test",
    "tests",
    "spec",
    "specs",
    "__tests__",
    "fixture",
    "fixtures",
    "testdata",
    "test_data",
    "example",
    "examples",
    "demo",
    "demos",
    "mock",
    "mocks",
    "stub",
    "stubs",
    "__snapshots__",
    "doc",
    "docs",
    "documentation",
}

# Common placeholder credential values → downgrade from high to low
_CRED_PLACEHOLDERS: Set[str] = {
    "changeme",
    "password",
    "secret",
    "example",
    "your_key_here",
    "insert_key_here",
    "replace_me",
    "placeholder",
    "my_password",
    "test_password",
    "fake_password",
    "dummy_password",
    "dummy",
    "your-api-key",
    "your_api_key",
    "api_key_here",
    "samplekey",
    "your-secret",
    "your_secret",
    "xxxxxxxx",
    "12345678",
    "abcdefgh",
    "null",
    "none",
    "undefined",
    "empty",
    "blank",
    "todo",
    "fixme",
    "<api_key>",
    "<password>",
    "<secret>",
    "<token>",
    "enter_key_here",
    "paste_key_here",
    "add_key_here",
}

# High-priority patterns: always scan even in lock/generated files
_ALWAYS_SCAN_DESCS: Set[str] = {
    "Embedded SSH/TLS private key",
    "AWS access key ID",
    "GitHub personal/OAuth token",
    "Hardcoded credential",
    "Bash /dev/tcp reverse-shell path",
    "Netcat reverse/bind shell invocation",
    "bash -c/-i shell spawn",
    "Obfuscated eval/exec (base64-wrapped)",
}


# ═══════════════════════════════════════════════════════════════════════════════
# FALSE-POSITIVE REDUCTION HELPERS
# ═══════════════════════════════════════════════════════════════════════════════


def _entropy(s: str) -> float:
    """Shannon entropy in bits per character. Minimum 0.0."""
    if len(s) < 2:
        return 0.0
    freq: Dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def _is_placeholder_cred(value: str) -> bool:
    """
    Heuristic: is this credential value a documentation placeholder?
    True  → downgrade severity (probably not a real secret)
    False → keep severity (probably a real secret)
    """
    v = value.strip("\"' \t").lower()
    if v in _CRED_PLACEHOLDERS:
        return True
    if len(v) < 5:
        return True
    if _entropy(v) < 2.2:  # very low entropy = repetitive / dictionary
        return True
    if len(set(v)) <= 3:  # e.g. "xxxxxxxx", "12121212"  # pragma: no cover
        return True  # unreachable: ≤3 unique chars → entropy < log₂(3) < 2.2 (caught above)
    # All digits (version number, etc.)
    if re.match(r"^\d+$", v):
        return True
    return False


def _ip_is_documentation(ip_str: str) -> bool:
    """Return True if the IP is in a documentation/reserved range."""
    try:
        addr = ipaddress.ip_address(ip_str.strip())
        return any(addr in net for net in _DOC_NETWORKS)
    except ValueError:
        return True  # malformed → don't generate a finding


def _extract_url_domain(raw: bytes) -> str:
    """Pull the hostname from a URL byte string."""
    try:
        from urllib.parse import urlparse

        domain = urlparse(raw.decode("utf-8", errors="replace")).netloc.lower()
        return domain.split(":")[0].lstrip("www.")
    except Exception:  # pragma: no cover
        return ""


def _domain_is_benign(domain: str, extra: Set[str]) -> bool:
    if not domain:
        return False
    all_benign = _BENIGN_DOMAINS | extra
    return any(domain == d or domain.endswith("." + d) for d in all_benign)


def _is_comment_line(text: str, pos: int) -> bool:
    """Return True if the text position pos falls on a commented-out line."""
    line_start = text.rfind("\n", 0, pos) + 1
    prefix = text[line_start:pos].lstrip()
    return prefix.startswith(("#", "//", "--", "* ", "/*", "<!--", "rem "))


def _byte_is_comment_line(data: bytes, pos: int) -> bool:
    """Return True if byte position pos falls on a commented-out line."""
    line_start = data.rfind(b"\n", 0, pos) + 1
    prefix = data[line_start:pos].lstrip()
    return prefix.startswith((b"#", b"//", b"--", b"* ", b"/*", b"<!--", b"rem "))


def _in_test_path(path: Path) -> bool:
    return bool({p.lower() for p in path.parts} & _TEST_DIR_NAMES)


# ═══════════════════════════════════════════════════════════════════════════════
# FINDING
# ═══════════════════════════════════════════════════════════════════════════════
class Finding:
    __slots__ = (
        "category",
        "severity",
        "description",
        "detail",
        "source",
        "line",
        "ts",
        "suppressed_by",
    )

    def __init__(
        self,
        category: str,
        severity: str,
        description: str,
        detail: str = "",
        source: str = "",
        line: int = 0,
        suppressed_by: str = "",
    ):
        self.category, self.severity = category, severity
        self.description, self.detail = description, detail
        self.source, self.line = source, line
        self.ts = datetime.now(timezone.utc).isoformat()
        self.suppressed_by = suppressed_by  # non-empty → was downgraded

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "ts": self.ts,
            "category": self.category,
            "severity": self.severity,
            "description": self.description,
            "detail": self.detail,
            "source": self.source,
            "line": self.line,
        }
        if self.suppressed_by:
            d["fp_note"] = self.suppressed_by
        return d

    def __str__(self) -> str:
        col = SEV_COLOR.get(self.severity, "reset")
        icon = _c(col, SEV_ICONS.get(self.severity, "[?]"))
        tag = _c(col, f"[{self.severity.upper():8s}]")
        src = (
            f" ({self.source}:{self.line})"
            if self.source and self.line
            else (f" ({self.source})" if self.source else "")
        )
        fp = (
            _c("dim", f"  [fp-reduced: {self.suppressed_by}]")
            if self.suppressed_by
            else ""
        )
        out = f"  {icon} {tag} {self.description}{src}{fp}"
        if self.detail:
            trunc = (self.detail[:117] + "…") if len(self.detail) > 120 else self.detail
            out += f"\n             → {_c('dim', trunc)}"
        return out


# ═══════════════════════════════════════════════════════════════════════════════
# ALLOWLIST
# ═══════════════════════════════════════════════════════════════════════════════
ConnDict = Dict[str, Any]


class AllowList:
    """
    Suppression rules loaded from --whitelist FILE and/or CLI flags.

    JSON schema (all fields optional):
    {
      "procs":       ["chrome", "slack"],       // process names (case-insensitive)
      "ports":       [80, 443, 53],             // ports to suppress in live/watch
      "networks":    ["10.0.0.0/8", "1.2.3.4"],// IPs / CIDRs to suppress
      "url_domains": ["example.com"],           // extra domains for scan URL FP
      "scan_dirs":   ["vendor", "generated"]    // extra dirs to skip in scan
    }
    """

    def __init__(self) -> None:
        self.procs: Set[str] = set()
        self.ports: Set[int] = set()
        self.networks: List[Any] = []  # ipaddress.IPv4Network / IPv6Network
        self.url_domains: Set[str] = set()
        self.scan_dirs: Set[str] = set()

    # ── Factory ───────────────────────────────────────────────────────────────
    @classmethod
    def from_file(cls, path: Path) -> "AllowList":
        data = json.loads(path.read_text())
        al = cls()
        al.procs = {p.lower() for p in data.get("procs", [])}
        al.ports = set(int(p) for p in data.get("ports", []))
        al.url_domains = {d.lstrip(".").lower() for d in data.get("url_domains", [])}
        al.scan_dirs = set(data.get("scan_dirs", []))
        for net_str in data.get("networks", []):
            try:
                al.networks.append(ipaddress.ip_network(net_str, strict=False))
            except ValueError:
                _err(f"[whitelist] invalid network: {net_str!r}")
        return al

    def merge_args(self, args: argparse.Namespace) -> None:
        """Pull in any per-command --ignore-* flags."""
        for spec in (getattr(args, "ignore_proc", None) or "").split(","):
            s = spec.strip().lower()
            if s:
                self.procs.add(s)
        for spec in (getattr(args, "ignore_port", None) or "").split(","):
            s = spec.strip()
            if s.isdigit():
                self.ports.add(int(s))
        for spec in (getattr(args, "ignore_ip", None) or "").split(","):
            s = spec.strip()
            if not s:
                continue
            try:
                net_str = s if "/" in s else s + "/32"
                self.networks.append(ipaddress.ip_network(net_str, strict=False))
            except ValueError:
                _err(f"invalid IP/CIDR: {s!r}")
        for d in getattr(args, "skip_dir", None) or []:
            self.scan_dirs.add(d)

    # ── Matchers ──────────────────────────────────────────────────────────────
    def suppresses_conn(self, conn: ConnDict) -> Optional[str]:
        """Return reason string if this connection should be suppressed, else None."""
        proc = (conn.get("proc") or "").lower()
        rport = conn.get("rport") or 0
        rip = conn.get("rip") or ""

        if proc and proc in self.procs:
            return f"proc '{proc}' in allowlist"
        if rport and rport in self.ports:
            return f"port {rport} in allowlist"
        if rip and self._ip_allowed(rip):
            return f"IP {rip} in allowlist network"
        return None

    def _ip_allowed(self, ip_str: str) -> bool:
        if not self.networks:
            return False
        try:
            addr = ipaddress.ip_address(ip_str)
            return any(addr in net for net in self.networks)
        except ValueError:
            return False


# ═══════════════════════════════════════════════════════════════════════════════
# ALERT TRACKER  (watch cooldown / deduplication)
# ═══════════════════════════════════════════════════════════════════════════════
class AlertTracker:
    """
    Prevents re-alerting on the same (proc, remote_addr) within a cooldown window.
    Key = f"{proc}|{raddr}"
    """

    def __init__(self, cooldown: float = 60.0) -> None:
        self.cooldown = cooldown
        self._seen: Dict[str, float] = {}

    def should_alert(self, key: str) -> bool:
        """Return True if alert is allowed now, and record the timestamp."""
        now = time.time()
        last = self._seen.get(key)
        if last is None or (now - last) >= self.cooldown:
            self._seen[key] = now
            return True
        return False

    def remaining(self, key: str) -> float:
        """Seconds remaining in cooldown (0 if not in cooldown)."""
        last = self._seen.get(key)
        if last is None:
            return 0.0
        remaining = self.cooldown - (time.time() - last)
        return max(0.0, remaining)

    def purge(self, active_keys: Set[str]) -> None:
        """Remove stale entries for closed connections."""
        for k in [k for k in self._seen if k not in active_keys]:
            del self._seen[k]


# ═══════════════════════════════════════════════════════════════════════════════
# DETECTION PATTERNS
# Tuple: (compiled_bytes_re, description, severity, skip_in_lock_files)
# ═══════════════════════════════════════════════════════════════════════════════
BYTE_PATTERNS: List[Tuple[re.Pattern, str, str, bool]] = [
    # ── Credentials / keys ────────────────────────────────────────────────────
    (
        re.compile(rb"-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----"),
        "Embedded SSH/TLS private key",
        "critical",
        False,
    ),
    (
        re.compile(rb"(?:AKIA|AIPA|AIFA|AIUA)[0-9A-Z]{16}"),
        "AWS access key ID",
        "high",
        False,
    ),
    (
        re.compile(rb"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}"),
        "GitHub personal/OAuth token",
        "high",
        False,
    ),
    (
        re.compile(
            rb"(?:password|passwd|secret|api[_\-]?key|auth[_\-]?token|private[_\-]?key)"
            rb'\s*[=:]\s*["\'][^"\']{8,}["\']',
            re.IGNORECASE,
        ),
        "Hardcoded credential",
        "high",
        False,
    ),
    # ── Reverse shell indicators ──────────────────────────────────────────────
    (
        re.compile(rb'/dev/tcp/[^\s"\'<>\x00-\x1f]{5,}'),
        "Bash /dev/tcp reverse-shell path",
        "critical",
        False,
    ),
    (
        re.compile(
            rb"(?:nc|ncat|netcat)\s+(?:-[el]+\s+)?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+\d+",
            re.IGNORECASE,
        ),
        "Netcat reverse/bind shell invocation",
        "critical",
        False,
    ),
    (
        re.compile(rb'bash\s+-[ic]\s+["\']?(?:/bin/|sh\b|bash\b)', re.IGNORECASE),
        "bash -c/-i shell spawn",
        "critical",
        False,
    ),
    # ── Obfuscated execution ──────────────────────────────────────────────────
    (
        re.compile(
            rb"(?:eval|exec)\s*\(\s*"
            rb"(?:base64_decode|base64\.b64decode|atob|Buffer\.from)\s*\(",
            re.IGNORECASE,
        ),
        "Obfuscated eval/exec (base64-wrapped)",
        "critical",
        False,
    ),
    # ── Dynamic DNS / tunnel domains ─────────────────────────────────────────
    (
        re.compile(
            rb"[a-z0-9\-]+\."
            rb"(?:duckdns|ddns(?:king)?|no\-ip|freedns|dynu|changeip|zapto"
            rb"|hopto|mooo|servebeer|sytes|ngrok|localxpose|serveo|pagekite"
            rb"|bore\.pub|trycloudflare|tailscale)\."
            rb"(?:org|net|com|io|me)",
            re.IGNORECASE,
        ),
        "Dynamic DNS / tunnel service domain",
        "medium",
        True,
    ),
    # ── Hardcoded public IPv4 ─────────────────────────────────────────────────
    # Note: subject to documentation-IP and version-string FP reduction
    (
        re.compile(
            rb"\b(?!(?:0|10|127|172\.(?:1[6-9]|2\d|3[01])|192\.168|169\.254|255)\.)"
            rb"(?:\d{1,3}\.){3}\d{1,3}\b"
        ),
        "Hardcoded public IPv4 address",
        "medium",
        True,
    ),
    # ── Remote URLs ───────────────────────────────────────────────────────────
    (
        re.compile(
            rb"https?://(?!(?:localhost|127\.0\.0\.1|0\.0\.0\.0)[/:])"
            rb'[^\s\'"<>\x00-\x1f]{12,}',
            re.IGNORECASE,
        ),
        "Hardcoded HTTP/S URL",
        "low",
        True,
    ),
    (
        re.compile(rb'wss?://[^\s\'"<>\x00-\x1f]{5,}', re.IGNORECASE),
        "Hardcoded WebSocket URL",
        "low",
        True,
    ),
    # ── Known telemetry / analytics SaaS ─────────────────────────────────────
    (
        re.compile(
            rb"(?:sentry\.io|segment\.(?:io|com)|mixpanel\.com|amplitude\.com"
            rb"|heap\.io|datadoghq?\.com|newrelic\.com|rollbar\.com"
            rb"|bugsnag\.com|honeybadger\.io)",
            re.IGNORECASE,
        ),
        "Known analytics/error-tracking SaaS endpoint",
        "info",
        True,
    ),
    # ── Phone-home keywords ───────────────────────────────────────────────────
    (
        re.compile(
            rb"(?:phone[_\-]?home|call[_\-]?home|ping[_\-]?home|telemetry|beacon)",
            re.IGNORECASE,
        ),
        "Phone-home/telemetry keyword",
        "info",
        False,
    ),
]

# Source-code (text mode) patterns
SOURCE_PATTERNS: List[Tuple[re.Pattern, str, str]] = [
    (
        re.compile(r"import\s+(?:pty|tty)\b"),
        "PTY/TTY import — reverse shell indicator",
        "medium",
    ),
    (
        re.compile(r'__import__\s*\(\s*["\'](?:subprocess|os|socket|pty)["\']'),
        "Dynamic import of system/socket module",
        "medium",
    ),
    (
        re.compile(
            r"exec\s*\(\s*(?:compile|__import__|open|urllib|requests)\b", re.IGNORECASE
        ),
        "exec() wrapping stdlib call",
        "high",
    ),
    (
        re.compile(
            r'os\s*\.\s*(?:system|popen)\s*\(["\'](?:bash|sh|cmd|powershell)',
            re.IGNORECASE,
        ),
        "Shell invocation via os.system/popen",
        "medium",
    ),
    (
        re.compile(
            r'subprocess\s*\.\s*(?:call|run|Popen)\s*\(\s*["\'](?:bash|sh)',
            re.IGNORECASE,
        ),
        "Shell invocation via subprocess",
        "medium",
    ),
    (
        re.compile(
            r"socket\s*\.\s*(?:connect|bind)\s*\(\s*\(.*?\d{1,5}\s*\)\s*\)", re.DOTALL
        ),
        "Raw socket connect/bind",
        "low",
    ),
]

# Extension / filename sets
_SKIP_EXTS: Set[str] = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".bmp",
    ".ico",
    ".webp",
    ".avif",
    ".mp3",
    ".mp4",
    ".wav",
    ".ogg",
    ".flac",
    ".m4a",
    ".zip",
    ".tar",
    ".gz",
    ".bz2",
    ".xz",
    ".7z",
    ".rar",
    ".deb",
    ".rpm",
    ".ttf",
    ".woff",
    ".woff2",
    ".otf",
    ".eot",
    ".pdf",
    ".pyc",
    ".class",
    ".o",
    ".a",
}
_TEXT_EXTS: Set[str] = {
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".mjs",
    ".cjs",
    ".sh",
    ".bash",
    ".zsh",
    ".fish",
    ".ksh",
    ".rb",
    ".go",
    ".rs",
    ".c",
    ".cc",
    ".cpp",
    ".h",
    ".hpp",
    ".java",
    ".kt",
    ".php",
    ".lua",
    ".pl",
    ".yaml",
    ".yml",
    ".toml",
    ".json",
    ".xml",
    ".ini",
    ".cfg",
    ".env",
    ".conf",
    ".config",
    ".properties",
    ".tf",
    ".hcl",
    ".html",
    ".htm",
    ".css",
    ".sql",
}
_TEXT_NAMES: Set[str] = {"Makefile", "Dockerfile", "Procfile", "Gemfile", ".env"}
_SKIP_DIRS: Set[str] = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "venv",
    "env",
    ".venv",
    ".direnv",
    "dist",
    "build",
    ".next",
    ".nuxt",
    "vendor",
    "third_party",
}


# ═══════════════════════════════════════════════════════════════════════════════
# LIVE SYSTEM ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════
def _proc_info(pid: Optional[int]) -> Tuple[str, str, str]:
    if pid is None or not HAS_PSUTIL or psutil is None:
        return "?", "", ""
    try:
        p = psutil.Process(pid)
        return p.name(), p.exe(), " ".join(p.cmdline()[:6])
    except Exception:
        return "?", "", ""


def get_connections_psutil() -> List[ConnDict]:
    assert psutil is not None
    rows: List[ConnDict] = []
    for c in psutil.net_connections(kind="inet"):
        name, exe, cmd = _proc_info(c.pid)
        laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "-"
        raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "-"
        rows.append(
            {
                "pid": c.pid,
                "proc": name,
                "exe": exe,
                "cmdline": cmd,
                "status": c.status or "?",
                "laddr": laddr,
                "raddr": raddr,
                "rip": c.raddr.ip if c.raddr else None,
                "rport": c.raddr.port if c.raddr else None,
                "family": "IPv6" if c.family == socket.AF_INET6 else "IPv4",
            }
        )
    return rows


def get_connections_ss() -> List[ConnDict]:
    rows: List[ConnDict] = []
    try:
        raw = subprocess.check_output(
            ["ss", "-tnpH"], stderr=subprocess.DEVNULL, text=True
        )
    except FileNotFoundError:
        try:
            raw = subprocess.check_output(
                ["netstat", "-tnp", "--program"], stderr=subprocess.DEVNULL, text=True
            )
        except Exception:
            return rows
    except subprocess.CalledProcessError:
        return rows

    for line in raw.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        status, laddr, raddr = parts[0], parts[3], parts[4]
        pid_blk = parts[5] if len(parts) > 5 else ""
        pid, pname = None, "?"
        m = re.search(r"pid=(\d+)", pid_blk)
        if m:
            pid = int(m.group(1))
        m2 = re.search(r'"([^"]+)"', pid_blk)
        if m2:
            pname = m2.group(1)
        rip, rport = _parse_addr(raddr)
        rows.append(
            {
                "pid": pid,
                "proc": pname,
                "exe": "",
                "cmdline": "",
                "status": status,
                "laddr": laddr,
                "raddr": raddr,
                "rip": rip,
                "rport": rport,
                "family": "IPv6" if "[" in laddr else "IPv4",
            }
        )
    return rows


def get_listeners_psutil() -> List[ConnDict]:
    assert psutil is not None
    rows: List[ConnDict] = []
    for c in psutil.net_connections(kind="inet"):
        if c.status != "LISTEN":
            continue
        name, exe, _ = _proc_info(c.pid)
        rows.append(
            {
                "pid": c.pid,
                "proc": name,
                "exe": exe,
                "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "-",
                "port": c.laddr.port if c.laddr else None,
                "iface": c.laddr.ip if c.laddr else None,
            }
        )
    return rows


def get_listeners_ss() -> List[ConnDict]:
    rows: List[ConnDict] = []
    try:
        raw = subprocess.check_output(
            ["ss", "-tlnpH"], stderr=subprocess.DEVNULL, text=True
        )
    except Exception:
        return rows
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        laddr = parts[3]
        pid_blk = parts[5] if len(parts) > 5 else ""
        pid, pname = None, "?"
        m = re.search(r"pid=(\d+)", pid_blk)
        if m:
            pid = int(m.group(1))
        m2 = re.search(r'"([^"]+)"', pid_blk)
        if m2:
            pname = m2.group(1)
        ip, port = _parse_addr(laddr)
        rows.append(
            {
                "pid": pid,
                "proc": pname,
                "exe": "",
                "laddr": laddr,
                "port": port,
                "iface": ip,
            }
        )
    return rows


def _connections() -> List[ConnDict]:
    return get_connections_psutil() if HAS_PSUTIL else get_connections_ss()


def _listeners() -> List[ConnDict]:
    return get_listeners_psutil() if HAS_PSUTIL else get_listeners_ss()


def score_connection(c: ConnDict, al: Optional[AllowList] = None) -> Optional[Finding]:
    """
    Return a Finding if the connection looks suspicious.
    Returns None for private addresses or allowlisted entries.
    """
    rip, rport = c.get("rip"), c.get("rport")
    proc, exe, pid = c.get("proc", "?"), c.get("exe", ""), c.get("pid")

    if not rip or is_private(rip):
        return None
    if al:
        reason = al.suppresses_conn(c)
        if reason:
            return None  # explicitly allowed

    if rport and rport in SUSPICIOUS_PORTS:
        return Finding(
            "live.suspicious_port",
            "high",
            f"Connection to known-suspicious port {rport} ({SUSPICIOUS_PORTS[rport]})",
            detail=f"PID {pid} [{proc}] → {rip}:{rport}",
            source=exe or proc,
        )

    if exe and re.match(r"^/(?:tmp|dev/shm|var/tmp|run/user/\d+)", exe):
        return Finding(
            "live.suspicious_exe",
            "high",
            "External connection from process in suspicious filesystem path",
            detail=f"PID {pid} [{proc}] @ {exe} → {rip}:{rport}",
            source=exe,
        )

    return Finding(
        "live.external",
        "info",
        "Active external connection",
        detail=f"PID {pid} [{proc}] → {rip}:{rport}  [{c.get('status','?')}]",
        source=exe or proc,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# STATIC SCANNER
# ═══════════════════════════════════════════════════════════════════════════════
_DEFAULT_MAX_MB = 10


def scan_file(
    path: Path,
    min_sev: str = "info",
    max_bytes: int = _DEFAULT_MAX_MB * 1024 * 1024,
    al: Optional[AllowList] = None,
    fp_filter: bool = True,
    extra_source_patterns: Optional[List[Tuple[re.Pattern, str, str]]] = None,
) -> List[Finding]:
    """
    Scan a single file for suspicious byte and source patterns.

    fp_filter=True applies heuristics that downgrade or suppress known
    false-positive patterns (documentation IPs, placeholder credentials,
    benign URL domains, commented lines, test-directory context).
    """
    al = al or AllowList()
    suffix = path.suffix.lower()
    name = path.name

    if suffix in _SKIP_EXTS:
        return []
    try:
        sz = path.stat().st_size
    except OSError:
        return []
    if sz > max_bytes or sz == 0:
        return []
    try:
        data = path.read_bytes()
    except (PermissionError, OSError):
        return []

    # Lock/generated files: only run high-priority patterns
    skip_noise = fp_filter and (name in _SKIP_URL_SCAN_FILES)

    # Test/fixture/example path context: downgrade medium+ findings by one level
    in_test = fp_filter and _in_test_path(path)

    findings: List[Finding] = []
    seen: Set[Tuple[str, str]] = set()
    threshold = _sev(min_sev)

    # ── Byte patterns ─────────────────────────────────────────────────────────
    for pat, desc, sev, skip_in_locks in BYTE_PATTERNS:
        if skip_noise and skip_in_locks and desc not in _ALWAYS_SCAN_DESCS:
            continue
        if _sev(sev) < threshold:
            continue

        for m in pat.finditer(data):
            raw = m.group(0)[:120]
            try:
                detail = raw.decode("utf-8", errors="replace")
            except Exception:  # pragma: no cover
                detail = repr(raw)

            effective_sev = sev
            fp_notes: List[str] = []

            if fp_filter:
                # ── Documentation IP filter ───────────────────────────────
                if "IPv4" in desc:
                    ip_str = detail.strip()
                    if _ip_is_documentation(ip_str):
                        continue  # RFC 5737 / reserved — skip entirely
                    # Sanity-check: octets must all be 0-255
                    octets = ip_str.split(".")
                    if len(octets) != 4:
                        continue  # pragma: no cover
                    try:
                        if not all(0 <= int(o) <= 255 for o in octets):
                            continue  # pragma: no cover
                    except ValueError:  # pragma: no cover
                        continue

                # ── URL benign-domain filter ──────────────────────────────
                if "URL" in desc or "WebSocket" in desc:
                    domain = _extract_url_domain(raw)
                    if _domain_is_benign(domain, al.url_domains):
                        if threshold <= _sev("info"):
                            effective_sev = "info"
                            fp_notes.append(f"benign domain: {domain}")
                        else:
                            continue

                # ── Credential placeholder filter ─────────────────────────
                if desc in ("Hardcoded credential",):
                    m2 = re.search(rb'[=:]\s*["\']([^"\']{4,})["\']', raw)
                    if m2:
                        val = m2.group(1).decode("utf-8", errors="replace")
                        if _is_placeholder_cred(val):
                            effective_sev = _sev_down(effective_sev, 2)
                            fp_notes.append(
                                f"likely placeholder (entropy={_entropy(val):.1f})"
                            )

                # ── Test-directory context ────────────────────────────────
                if in_test and _sev(effective_sev) >= _sev("medium"):
                    effective_sev = _sev_down(effective_sev)
                    fp_notes.append("in test/fixture path")

                # ── Commented-line downgrade (byte mode) ──────────────────
                # Byte patterns have no language awareness; a commented-out
                # reverse shell is still worth noting but not critical.
                if _byte_is_comment_line(data, m.start()):
                    if _sev(effective_sev) > _sev("info"):
                        effective_sev = _sev_down(effective_sev)
                    fp_notes.append("match on commented line")

            if _sev(effective_sev) < threshold:
                continue

            key = (desc, detail[:60])
            if key in seen:
                continue
            seen.add(key)

            lineno = data[: m.start()].count(b"\n") + 1
            findings.append(
                Finding(
                    "static.bytes",
                    effective_sev,
                    desc,
                    detail=detail,
                    source=str(path),
                    line=lineno,
                    suppressed_by="; ".join(fp_notes),
                )
            )

    # ── Source patterns (text mode) ───────────────────────────────────────────
    if suffix in _TEXT_EXTS or name in _TEXT_NAMES:
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:  # pragma: no cover
            text = ""

        for pat, desc, sev in list(SOURCE_PATTERNS) + list(extra_source_patterns or []):
            if _sev(sev) < threshold:
                continue
            for m in pat.finditer(text):
                if fp_filter and _is_comment_line(text, m.start()):
                    continue  # commented-out code → skip

                effective_sev = sev
                fp_notes = []

                if fp_filter and in_test and _sev(effective_sev) >= _sev("medium"):
                    effective_sev = _sev_down(effective_sev)
                    fp_notes.append("in test/fixture path")

                if _sev(effective_sev) < threshold:
                    continue

                detail = m.group(0)[:120]
                key = (desc, detail[:60])
                if key in seen:
                    continue
                seen.add(key)

                lineno = text[: m.start()].count("\n") + 1
                findings.append(
                    Finding(
                        "static.source",
                        effective_sev,
                        desc,
                        detail=detail,
                        source=str(path),
                        line=lineno,
                        suppressed_by="; ".join(fp_notes),
                    )
                )

    return findings


def scan_tree(
    root: Path,
    min_sev: str = "info",
    max_mb: int = _DEFAULT_MAX_MB,
    quiet: bool = False,
    al: Optional[AllowList] = None,
    fp_filter: bool = True,
    extra_source_patterns: Optional[List[Tuple[re.Pattern, str, str]]] = None,
) -> Generator[Finding, None, None]:
    al = al or AllowList()
    skip_dirs = _SKIP_DIRS | al.scan_dirs
    max_bytes = max_mb * 1024 * 1024
    count = 0
    for fpath in sorted(root.rglob("*")):
        if not fpath.is_file() or fpath.is_symlink():
            continue
        if any(part in skip_dirs for part in fpath.parts):
            continue
        try:
            if fpath.stat().st_size > max_bytes:
                continue
        except OSError:
            continue
        count += 1
        if not quiet and count % 200 == 0:
            print(f"\r  scanning… {count} files", end="", file=sys.stderr)
        yield from scan_file(
            fpath,
            min_sev=min_sev,
            max_bytes=max_bytes,
            al=al,
            fp_filter=fp_filter,
            extra_source_patterns=extra_source_patterns,
        )
    if not quiet and count >= 200:
        print(f"\r  scanned {count} files.          ", file=sys.stderr)


# ═══════════════════════════════════════════════════════════════════════════════
# DEPENDENCY MANIFEST SCANNER
# ═══════════════════════════════════════════════════════════════════════════════
_DEP_MANIFESTS: Set[str] = {
    "package.json",
    "package-lock.json",
    "requirements.txt",
    "requirements-dev.txt",
    "requirements_dev.txt",
    "Pipfile",
    "Pipfile.lock",
    "pyproject.toml",
    "setup.cfg",
    "setup.py",
    "Gemfile",
    "Cargo.toml",
}


def scan_deps(path: Path) -> List[Finding]:
    findings: List[Finding] = []
    fname = path.name
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings

    # ── pip / requirements.txt / Pipfile ─────────────────────────────────────
    if re.match(r"requirements.*\.txt$", fname, re.I) or fname == "Pipfile":
        for i, raw_line in enumerate(text.splitlines(), 1):
            line = raw_line.strip()
            if not line or line.startswith(("#", "[")):
                continue
            if re.match(r"^-e\s+(?:git|hg|svn|bzr)\+", line, re.I):
                findings.append(
                    Finding(
                        "deps.vcs_editable",
                        "medium",
                        "Editable VCS install (verify source integrity)",
                        detail=line,
                        source=str(path),
                        line=i,
                    )
                )
            elif re.match(r"^(?:git|hg|svn)\+", line, re.I):
                findings.append(
                    Finding(
                        "deps.vcs_direct",
                        "medium",
                        "Direct VCS URL dependency",
                        detail=line,
                        source=str(path),
                        line=i,
                    )
                )
            elif re.match(r"^https?://", line, re.I):
                findings.append(
                    Finding(
                        "deps.url_direct",
                        "medium",
                        "Direct URL dependency (bypasses PyPI integrity checks)",
                        detail=line,
                        source=str(path),
                        line=i,
                    )
                )

    # ── pyproject.toml / setup ────────────────────────────────────────────────
    if fname in ("pyproject.toml", "setup.cfg", "setup.py"):
        for i, line in enumerate(text.splitlines(), 1):
            if re.search(r"dependency[_\-]?links?\s*=", line, re.I):
                findings.append(
                    Finding(
                        "deps.dependency_links",
                        "medium",
                        "dependency_links bypasses PyPI index integrity",
                        detail=line.strip(),
                        source=str(path),
                        line=i,
                    )
                )

    # ── npm package.json (by name or content shape) ───────────────────────────
    _is_npm = fname == "package.json"
    if not _is_npm and fname.endswith(".json"):
        try:
            _probe = json.loads(text)
            if isinstance(_probe, dict) and (
                "scripts" in _probe
                or "dependencies" in _probe
                or "devDependencies" in _probe
            ):
                _is_npm = True
        except json.JSONDecodeError:
            pass

    if _is_npm:
        try:
            pkg = json.loads(text)
        except json.JSONDecodeError:
            return findings

        for sname, sval in (pkg.get("scripts") or {}).items():
            if re.search(r"(?:post|pre)install", sname, re.I) and isinstance(sval, str):
                if re.search(
                    r"(?:curl|wget|fetch|http|nc\b|bash\s+-[ic]|python\s+-c|node\s+-e)",
                    sval,
                    re.I,
                ):
                    findings.append(
                        Finding(
                            "deps.npm_postinstall_network",
                            "high",
                            f"npm '{sname}' script contains network/shell invocation",
                            detail=f"{sname}: {sval[:200]}",
                            source=str(path),
                        )
                    )

        for section in (
            "dependencies",
            "devDependencies",
            "optionalDependencies",
            "peerDependencies",
        ):
            for dep, ver in (pkg.get(section) or {}).items():
                if isinstance(ver, str) and re.match(
                    r"(?:git\+|github:|gitlab:|bitbucket:|https?://|file:)", ver, re.I
                ):
                    findings.append(
                        Finding(
                            "deps.npm_nonregistry",
                            "medium",
                            "npm dep sourced outside the registry",
                            detail=f"{section}/{dep}: {ver}",
                            source=str(path),
                        )
                    )

    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# BASELINE
# ═══════════════════════════════════════════════════════════════════════════════
def baseline_capture(outfile: Path) -> Dict[str, Any]:
    snap: Dict[str, Any] = {
        "tool": PROG,
        "version": VERSION,
        "captured": datetime.now(timezone.utc).isoformat(),
        "hostname": socket.gethostname(),
        "connections": _connections(),
        "listeners": _listeners(),
    }
    outfile.write_text(json.dumps(snap, indent=2))
    return snap


def baseline_diff(saved_path: Path, al: Optional[AllowList] = None) -> List[Finding]:
    al = al or AllowList()
    try:
        saved = json.loads(saved_path.read_text())
    except Exception as exc:
        return [Finding("baseline.error", "critical", f"Cannot parse baseline: {exc}")]

    cur_conns = _connections()
    cur_lstrs = _listeners()

    saved_r = {
        c["raddr"]
        for c in saved.get("connections", [])
        if c.get("raddr") and c["raddr"] not in ("-", "")
    }
    saved_l = {l["laddr"] for l in saved.get("listeners", []) if l.get("laddr")}
    cur_r = {
        c["raddr"] for c in cur_conns if c.get("raddr") and c["raddr"] not in ("-", "")
    }
    cur_l = {l["laddr"] for l in cur_lstrs if l.get("laddr")}

    findings: List[Finding] = []

    for addr in cur_l - saved_l:
        _, port = _parse_addr(addr)
        sev = "high" if port and port in SUSPICIOUS_PORTS else "medium"
        findings.append(
            Finding(
                "baseline.new_listener",
                sev,
                "New listening socket appeared since baseline",
                detail=addr,
            )
        )

    for addr in saved_l - cur_l:
        findings.append(
            Finding(
                "baseline.closed_listener",
                "info",
                "Listening socket closed since baseline",
                detail=addr,
            )
        )

    for addr in cur_r - saved_r:
        ip, port = _parse_addr(addr)
        if ip and not is_private(ip):
            procs = [c for c in cur_conns if c.get("raddr") == addr]
            # Check allowlist
            dummy_conn: ConnDict = {
                "rip": ip,
                "rport": port,
                "proc": procs[0]["proc"] if procs else "",
                "pid": None,
            }
            if al.suppresses_conn(dummy_conn):
                continue
            sev = "high" if port and port in SUSPICIOUS_PORTS else "medium"
            pstr = ", ".join(f"PID {c['pid']} [{c['proc']}]" for c in procs) or "?"
            findings.append(
                Finding(
                    "baseline.new_external",
                    sev,
                    "New external connection not in baseline",
                    detail=f"{addr} via {pstr}",
                )
            )

    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# OUTPUT HELPERS
# ═══════════════════════════════════════════════════════════════════════════════
def _hdr(text: str) -> None:
    print(f"\n  {_c('bold', text)}")
    print(f"  {'─' * len(text)}")


def print_findings(
    findings: List[Finding], as_json: bool = False, min_sev: str = "info"
) -> None:
    threshold = _sev(min_sev)
    filtered = [f for f in findings if _sev(f.severity) >= threshold]
    if as_json:
        print(json.dumps([f.to_dict() for f in filtered], indent=2))
        return
    if not filtered:
        print(_c("green", "  ✓ No findings above threshold."))
        return
    for f in filtered:
        print(str(f))


def print_connections(
    conns: List[ConnDict],
    al: Optional[AllowList] = None,
    proc_filter: Optional[str] = None,
    pid_filter: Optional[int] = None,
) -> None:
    al = al or AllowList()
    if proc_filter:
        conns = [
            c for c in conns if proc_filter.lower() in (c.get("proc") or "").lower()
        ]
    if pid_filter is not None:
        conns = [c for c in conns if c.get("pid") == pid_filter]

    ext = [c for c in conns if c.get("rip") and not is_private(c["rip"])]
    loc = [c for c in conns if c.get("rip") and is_private(c["rip"])]
    ext_kept = [c for c in ext if not al.suppresses_conn(c)]
    ext_supp = [c for c in ext if al.suppresses_conn(c)]

    _hdr(f"External connections ({len(ext_kept)} shown, {len(ext_supp)} allowlisted)")
    if not ext_kept:
        print(_c("green", "  None (or all allowlisted)."))
    for c in ext_kept:
        c2tag = (
            f"  {_c('bred', '*** C2: ' + SUSPICIOUS_PORTS[c['rport']] + ' ***')}"
            if c.get("rport") in SUSPICIOUS_PORTS
            else ""
        )
        print(
            f"  PID {str(c.get('pid','?')):>6}  {(c.get('proc') or '?'):<20}  "
            f"{(c.get('laddr') or '?'):<25} → {_c('yellow', c.get('raddr') or '?'):<34}"
            f"[{c.get('status','?')}]{c2tag}"
        )

    if ext_supp:
        print(
            f"\n  {_c('dim', f'  Allowlisted external ({len(ext_supp)}):')}  "
            + _c(
                "dim",
                ", ".join(c.get("raddr", "?") for c in ext_supp[:6])
                + ("…" if len(ext_supp) > 6 else ""),
            )
        )

    _hdr(f"Internal connections ({len(loc)})")
    if not loc:
        print(_c("dim", "  None."))
    for c in loc:
        print(
            f"  PID {str(c.get('pid','?')):>6}  {(c.get('proc') or '?'):<20}  "
            f"{(c.get('laddr') or '?'):<25} → {(c.get('raddr') or '?'):<34}"
            f"[{c.get('status','?')}]"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# COMMAND HANDLERS
# ═══════════════════════════════════════════════════════════════════════════════
def cmd_live(args: argparse.Namespace, al: AllowList) -> int:
    conns = _connections()
    findings = [f for f in (score_connection(c, al) for c in conns) if f]

    if args.json:
        print(
            json.dumps(
                {"connections": conns, "findings": [f.to_dict() for f in findings]},
                indent=2,
            )
        )
    else:
        print_connections(
            conns,
            al=al,
            proc_filter=getattr(args, "proc", None),
            pid_filter=getattr(args, "pid", None),
        )
        if findings:
            _hdr(f"Scored findings ({len(findings)})")
            print_findings(findings, min_sev=args.severity)

    threshold = _sev(args.severity)
    return 1 if any(_sev(f.severity) >= threshold for f in findings) else 0


def cmd_listeners(args: argparse.Namespace, _al: AllowList) -> int:
    listeners = _listeners()
    if args.json:
        print(json.dumps(listeners, indent=2))
        return 0

    _hdr(f"Listening sockets ({len(listeners)})")
    for l in sorted(listeners, key=lambda x: x.get("port") or 0):
        port = l.get("port")
        iface = l.get("iface") or "?"
        all_if = iface in ("0.0.0.0", "::", "", "*")
        c2tag = (
            f"  {_c('bred', '*** ' + SUSPICIOUS_PORTS[port] + ' ***')}"
            if port in SUSPICIOUS_PORTS
            else ""
        )
        iftag = (
            f"  {_c('yellow', '[ALL INTERFACES]')}"
            if all_if
            else _c("dim", f"  [{iface}]")
        )
        print(
            f"  :{str(port or '?'):<7}  {(l.get('proc') or '?'):<22}  "
            f"PID {l.get('pid','?')}{iftag}{c2tag}"
        )
    return 0


def load_rules_file(
    path: Path,
) -> List[Tuple[re.Pattern, str, str]]:
    """Load custom source-mode detection rules from a JSON file.

    Rules file format — JSON array of objects:
        [{"pattern": "REGEX", "description": "Label", "severity": "high"}, ...]

    severity must be one of: critical, high, medium, low, info.

    Args:
        path: Path to JSON rules file.

    Returns:
        List of (compiled_re, description, severity) tuples ready to pass
        as extra_source_patterns to scan_file().

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the file is not valid JSON or a rule has missing keys.
    """
    if not path.exists():
        raise FileNotFoundError(f"rules file not found: {path}")
    try:
        rules = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise ValueError(f"rules file is not valid JSON: {exc}") from exc
    if not isinstance(rules, list):
        raise ValueError("rules file must be a JSON array")

    compiled: List[Tuple[re.Pattern, str, str]] = []
    for i, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise ValueError(f"rule[{i}] must be an object")
        try:
            pat = re.compile(rule["pattern"])
            desc = rule["description"]
            sev = rule.get("severity", "medium")
        except KeyError as exc:
            raise ValueError(f"rule[{i}] missing required field: {exc}") from exc
        except re.error as exc:
            raise ValueError(f"rule[{i}] invalid regex: {exc}") from exc
        compiled.append((pat, desc, sev))
    return compiled


def cmd_scan(args: argparse.Namespace, al: AllowList) -> int:
    target = Path(args.path)
    fp_filter = not getattr(args, "no_fp_filter", False)

    if not target.exists():
        _err(f"path not found: {target}")
        return 2

    max_mb = getattr(args, "max_size", _DEFAULT_MAX_MB)
    max_bytes = max_mb * 1024 * 1024

    extra_source_patterns: List[Tuple[re.Pattern, str, str]] = []
    if getattr(args, "rules_file", None):
        try:
            extra_source_patterns = load_rules_file(Path(args.rules_file))
        except (FileNotFoundError, ValueError) as exc:
            _err(f"--rules-file: {exc}")
            return 2

    findings: List[Finding] = []

    if target.is_file():
        findings = scan_file(
            target,
            min_sev=args.severity,
            max_bytes=max_bytes,
            al=al,
            fp_filter=fp_filter,
            extra_source_patterns=extra_source_patterns,
        )
        findings += scan_deps(target)
    else:
        quiet = args.json
        skip_dirs = _SKIP_DIRS | al.scan_dirs

        # Collect candidate files first so we can emit progress percentages
        candidate_files: List[Path] = []
        for fpath in sorted(target.rglob("*")):
            if not fpath.is_file() or fpath.is_symlink():
                continue
            if any(part in skip_dirs for part in fpath.parts):
                continue
            try:
                if fpath.stat().st_size > max_bytes:
                    continue
            except OSError:
                continue
            candidate_files.append(fpath)

        total = len(candidate_files)
        for idx, fpath in enumerate(candidate_files, start=1):
            for f in scan_file(
                fpath,
                min_sev=args.severity,
                max_bytes=max_bytes,
                al=al,
                fp_filter=fp_filter,
                extra_source_patterns=extra_source_patterns,
            ):
                findings.append(f)

            if args.json and total > 0 and idx % max(1, total // 20) == 0:
                print(
                    json.dumps(
                        {
                            "type": "progress",
                            "current": idx,
                            "total": total,
                            "percent": int(idx / total * 100),
                        }
                    ),
                    flush=True,
                )
            elif not quiet and not args.json and idx % 200 == 0:
                print(f"\r  scanning… {idx} files", end="", file=sys.stderr)

        if not quiet and not args.json and total >= 200:
            print(f"\r  scanned {total} files.          ", file=sys.stderr)

        for mname in _DEP_MANIFESTS:
            for mp in target.rglob(mname):
                if not any(p in skip_dirs for p in mp.parts):
                    findings += scan_deps(mp)

    threshold = _sev(args.severity)
    above = [f for f in findings if _sev(f.severity) >= threshold]
    fp_reduced = sum(1 for f in findings if f.suppressed_by)

    if args.json:
        print(
            json.dumps(
                {
                    "target": str(target),
                    "fp_filter": fp_filter,
                    "findings": [f.to_dict() for f in above],
                },
                indent=2,
            )
        )
    else:
        note = (
            f"  {_c('dim', f'({fp_reduced} downgraded by FP filter)')}"
            if fp_reduced
            else ""
        )
        _hdr(
            f"Scan: {target}  →  {len(above)} finding(s) at/above '{args.severity}'{note}"
        )
        print_findings(findings, min_sev=args.severity)

    return 1 if above else 0


def cmd_deps(args: argparse.Namespace, al: AllowList) -> int:
    target = Path(args.path)
    if not target.exists():
        _err(f"path not found: {target}")
        return 2

    manifests: List[Path] = (
        [target]
        if target.is_file()
        else [
            mp
            for mname in _DEP_MANIFESTS
            for mp in target.rglob(mname)
            if not any(p in (_SKIP_DIRS | al.scan_dirs) for p in mp.parts)
        ]
    )

    findings: List[Finding] = []
    for m in manifests:
        findings += scan_deps(m)

    threshold = _sev(args.severity)
    above = [f for f in findings if _sev(f.severity) >= threshold]

    if args.json:
        print(
            json.dumps(
                {
                    "manifests": [str(m) for m in manifests],
                    "findings": [f.to_dict() for f in above],
                },
                indent=2,
            )
        )
    else:
        _hdr(f"Dep scan: {len(manifests)} manifest(s)  →  {len(above)} finding(s)")
        print_findings(findings, min_sev=args.severity)

    return 1 if above else 0


def cmd_watch(args: argparse.Namespace, al: AllowList) -> int:  # pragma: no cover
    interval = getattr(args, "interval", 5.0)
    show_closed = getattr(args, "show_closed", False)
    public_only = getattr(args, "public_only", False)
    cooldown_s = getattr(args, "cooldown", 60.0)
    log_path = getattr(args, "log", None)
    states_raw = (getattr(args, "states", "ESTABLISHED,SYN_SENT") or "").strip()
    watch_states: Set[str] = (
        {s.strip().upper() for s in states_raw.split(",") if s.strip()}
        if states_raw
        else set()
    )

    tracker = AlertTracker(cooldown=cooldown_s) if cooldown_s > 0 else None
    log_fh = open(log_path, "a") if log_path else None

    def _log(event: Dict) -> None:
        if log_fh:
            log_fh.write(json.dumps(event) + "\n")
            log_fh.flush()

    # ── Print watch config ────────────────────────────────────────────────────
    _hdr(f"Connection watcher  v{VERSION}")
    config_lines = [
        f"interval={interval}s",
        f"cooldown={cooldown_s}s",
    ]
    if watch_states:
        config_lines.append(f"states={','.join(sorted(watch_states))}")
    if public_only:
        config_lines.append("public-only")
    print(f"  Config: {' | '.join(config_lines)}")
    if al.procs:
        print(f"  Ignoring procs:    {', '.join(sorted(al.procs))}")
    if al.ports:
        print(f"  Ignoring ports:    {', '.join(str(p) for p in sorted(al.ports))}")
    if al.networks:
        print(f"  Ignoring networks: {len(al.networks)} rule(s)")
    if log_path:
        print(f"  Logging to:        {log_path}")

    # ── Seed ─────────────────────────────────────────────────────────────────
    prev: Dict[str, ConnDict] = {
        c["raddr"]: c
        for c in _connections()
        if c.get("raddr") and c["raddr"] not in ("-", "")
    }
    print(f"\n  Seeded with {len(prev)} existing connection(s). Watching…\n")
    _log(
        {
            "event": "watch_start",
            "ts": datetime.now(timezone.utc).isoformat(),
            "seeded": len(prev),
            "config": {
                "interval": interval,
                "cooldown": cooldown_s,
                "states": list(watch_states),
                "public_only": public_only,
            },
        }
    )

    try:
        while True:
            time.sleep(interval)
            cur: Dict[str, ConnDict] = {
                c["raddr"]: c
                for c in _connections()
                if c.get("raddr") and c["raddr"] not in ("-", "")
            }
            ts_iso = datetime.now(timezone.utc).isoformat()
            ts_fmt = datetime.now().strftime("%H:%M:%S")

            # ── New connections ───────────────────────────────────────────
            for addr in set(cur) - set(prev):
                c = cur[addr]

                # State filter
                state = (c.get("status") or "").upper()
                if watch_states and state and state not in watch_states:
                    _log(
                        {
                            "event": "skip_state",
                            "ts": ts_iso,
                            "addr": addr,
                            "state": state,
                        }
                    )
                    continue

                # Public-only filter
                rip = c.get("rip")
                is_ext = bool(rip and not is_private(rip))
                if public_only and not is_ext:
                    continue

                # Allowlist suppression
                sup_reason = al.suppresses_conn(c)
                if sup_reason:
                    _log(
                        {
                            "event": "suppressed",
                            "ts": ts_iso,
                            "addr": addr,
                            "reason": sup_reason,
                            **{k: c.get(k) for k in ("pid", "proc", "rip", "rport")},
                        }
                    )
                    continue

                # Cooldown deduplication
                ck_key = f"{(c.get('proc') or '?')}|{addr}"
                if tracker and not tracker.should_alert(ck_key):
                    rem = tracker.remaining(ck_key)
                    _log(
                        {
                            "event": "cooldown",
                            "ts": ts_iso,
                            "addr": addr,
                            "remaining_s": round(rem, 1),
                        }
                    )
                    continue

                # Classify + format output
                rport = c.get("rport") or 0
                c2name = SUSPICIOUS_PORTS.get(rport, "")
                if c2name:
                    sev = "high"
                    flag = _c("bred", f" [!!!C2: {c2name}!!!]")
                elif is_ext:
                    sev = "medium"
                    flag = _c("yellow", " [PUBLIC]")
                else:
                    sev = "info"
                    flag = ""

                print(
                    f"  [{ts_fmt}] +CONN{flag}  "
                    f"PID {str(c.get('pid','?')):<6} "
                    f"[{(c.get('proc','?') or '?'):<18}]"
                    f"  → {addr:<35} [{state}]"
                )

                _log(
                    {
                        "event": "new_conn",
                        "ts": ts_iso,
                        "severity": sev,
                        "addr": addr,
                        "state": state,
                        "is_external": is_ext,
                        "c2_port": c2name or None,
                        **{k: c.get(k) for k in ("pid", "proc", "exe", "rip", "rport")},
                    }
                )

            # ── Closed connections ────────────────────────────────────────
            if show_closed:
                for addr in set(prev) - set(cur):
                    c = prev[addr]
                    print(
                        f"  [{ts_fmt}] -GONE   "
                        f"PID {str(c.get('pid','?')):<6} "
                        f"[{(c.get('proc','?') or '?'):<18}]  → {addr}"
                    )
                    _log(
                        {
                            "event": "closed",
                            "ts": ts_iso,
                            "addr": addr,
                            **{k: c.get(k) for k in ("pid", "proc", "rip", "rport")},
                        }
                    )

            if tracker:
                tracker.purge(set(cur))

            prev = cur

    except KeyboardInterrupt:
        if log_fh:
            log_fh.close()
        print("\n  Watch stopped.")

    return 0


def cmd_baseline(args: argparse.Namespace, al: AllowList) -> int:
    action = args.action

    if action == "capture":
        outpath = Path(getattr(args, "output", "baseline.json"))
        snap = baseline_capture(outpath)
        print(f"  Baseline captured → {outpath}")
        print(
            f"  Connections: {len(snap['connections'])}  "
            f"Listeners: {len(snap['listeners'])}"
        )
        return 0

    if action == "diff":
        inpath = Path(getattr(args, "input", "baseline.json"))
        if not inpath.exists():
            _err(f"baseline not found: {inpath}")
            return 2
        findings = baseline_diff(inpath, al=al)
        threshold = _sev(args.severity)
        above = [f for f in findings if _sev(f.severity) >= threshold]
        if args.json:
            print(json.dumps([f.to_dict() for f in above], indent=2))
        else:
            _hdr(f"Baseline diff vs {inpath}  →  {len(above)} change(s)")
            print_findings(findings, min_sev=args.severity)
        return 1 if above else 0

    _err(f"unknown action '{action}'")
    return 2


def cmd_report(args: argparse.Namespace, al: AllowList) -> int:
    conns = _connections()
    listeners = _listeners()
    findings = [f for f in (score_connection(c, al) for c in conns) if f]

    report: Dict[str, Any] = {
        "tool": PROG,
        "version": VERSION,
        "hostname": socket.gethostname(),
        "generated": datetime.now(timezone.utc).isoformat(),
        "psutil": HAS_PSUTIL,
        "connections": conns,
        "listeners": listeners,
        "findings": [f.to_dict() for f in findings],
        "summary": {
            "total_connections": len(conns),
            "external_connections": sum(
                1 for c in conns if c.get("rip") and not is_private(c["rip"])
            ),
            "allowlisted": sum(
                1
                for c in conns
                if c.get("rip") and not is_private(c["rip"]) and al.suppresses_conn(c)
            ),
            "total_listeners": len(listeners),
            "findings_by_severity": {
                s: sum(1 for f in findings if f.severity == s) for s in SEV_LEVELS
            },
        },
    }

    threshold = _sev(args.severity)
    code = 1 if any(_sev(f.severity) >= threshold for f in findings) else 0

    if args.json:
        print(json.dumps(report, indent=2))
        return code

    s = report["summary"]
    print(
        f"\n  {_c('bold', 'hiddenscope report')} "
        f"| {report['hostname']} | {report['generated']}"
    )
    print(
        f"  Connections: {s['total_connections']}  "
        f"External: {_c('yellow', str(s['external_connections']))}  "
        f"Allowlisted: {_c('dim', str(s['allowlisted']))}  "
        f"Listeners: {s['total_listeners']}"
    )
    sev_str = "  ".join(
        f"{sv}: {_c(SEV_COLOR.get(sv,'reset'), str(cnt))}"
        for sv, cnt in s["findings_by_severity"].items()
        if cnt
    )
    print(f"  Findings:    {sev_str or _c('green', 'none')}")

    print_connections(conns, al=al)

    _hdr(f"Listeners ({len(listeners)})")
    for l in sorted(listeners, key=lambda x: x.get("port") or 0):
        port = l.get("port")
        iface = l.get("iface") or "?"
        all_if = iface in ("0.0.0.0", "::", "", "*")
        c2tag = (
            f"  {_c('bred', '*** ' + SUSPICIOUS_PORTS[port] + ' ***')}"
            if port in SUSPICIOUS_PORTS
            else ""
        )
        print(
            f"  :{str(port or '?'):<7}  {(l.get('proc') or '?'):<22}  "
            f"{'[ALL]' if all_if else f'[{iface}]'}{c2tag}"
        )

    if findings:
        _hdr(f"Live findings ({len(findings)})")
        print_findings(findings, min_sev=args.severity)

    return code


# ═══════════════════════════════════════════════════════════════════════════════
# ARGUMENT PARSER
# ═══════════════════════════════════════════════════════════════════════════════
def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=PROG,
        description=f"hiddenscope v{VERSION} — Hidden endpoint & connection detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(f"""\
            exit codes:  0=clean  1=findings  2=error

            examples:
              {PROG} live
              {PROG} --whitelist allow.json live --severity medium
              {PROG} live --ignore-proc chrome,slack --ignore-port 80,443
              {PROG} listeners
              {PROG} scan /opt/myapp
              {PROG} scan /opt/myapp --severity high --no-fp-filter
              {PROG} deps /opt/myapp
              {PROG} watch --interval 3 --cooldown 120 --public-only
              {PROG} watch --ignore-port 80,443,53 --log /var/log/hiddenscope.ndjson
              {PROG} baseline capture -o pre.json
              {PROG} baseline diff -i pre.json --whitelist allow.json
              {PROG} report --json | jq '.summary'

            whitelist file schema (all fields optional):
              {{
                "procs":       ["chrome", "slack", "systemd-resolved"],
                "ports":       [80, 443, 53, 123],
                "networks":    ["10.0.0.0/8", "172.16.0.0/12"],
                "url_domains": ["internal.corp.example"],
                "scan_dirs":   ["vendor", "generated"]
              }}
        """),
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    p.add_argument("--json", action="store_true", help="JSON output")
    p.add_argument(
        "--severity",
        default="info",
        choices=SEV_LEVELS,
        help="Minimum severity to surface (default: info)",
    )
    p.add_argument("--no-color", action="store_true", help="Disable ANSI colour")
    p.add_argument(
        "--whitelist",
        metavar="FILE",
        help="JSON allowlist file (procs, ports, networks, url_domains)",
    )

    sub = p.add_subparsers(dest="command", required=True)

    # live
    sp = sub.add_parser("live", help="Active TCP/UDP connections with process mapping")
    sp.add_argument("--proc", metavar="NAME", help="Filter display by process name")
    sp.add_argument("--pid", type=int, help="Filter display by PID")
    sp.add_argument("--ignore-proc", metavar="LIST", help="Suppress procs (csv)")
    sp.add_argument("--ignore-port", metavar="LIST", help="Suppress ports (csv)")
    sp.add_argument("--ignore-ip", metavar="LIST", help="Suppress IPs/CIDRs (csv)")

    # listeners
    sub.add_parser("listeners", help="Bound/listening sockets")

    # scan
    sp = sub.add_parser("scan", help="Static scan: bytes + source patterns")
    sp.add_argument("path")
    sp.add_argument(
        "--max-size",
        type=int,
        default=_DEFAULT_MAX_MB,
        metavar="MB",
        help=f"Skip files > N MB (default: {_DEFAULT_MAX_MB})",
    )
    sp.add_argument(
        "--skip-dir",
        action="append",
        metavar="NAME",
        default=[],
        help="Additional directory name to skip (repeatable)",
    )
    sp.add_argument(
        "--no-fp-filter",
        action="store_true",
        help="Disable automatic false-positive reduction heuristics",
    )
    sp.add_argument(
        "--rules-file",
        metavar="FILE",
        default=None,
        help="JSON file with custom detection rules [{pattern, description, severity}]",
    )

    # deps
    sp = sub.add_parser("deps", help="Dependency manifest scan")
    sp.add_argument("path")

    # watch
    sp = sub.add_parser("watch", help="Continuous delta-based connection monitoring")
    sp.add_argument(
        "--interval",
        type=float,
        default=5.0,
        metavar="SEC",
        help="Poll interval in seconds (default: 5)",
    )
    sp.add_argument(
        "--cooldown",
        type=float,
        default=60.0,
        metavar="SEC",
        help="Re-alert suppression window in seconds (default: 60, 0=off)",
    )
    sp.add_argument(
        "--public-only",
        action="store_true",
        help="Only alert on external (non-RFC1918) connections",
    )
    sp.add_argument(
        "--states",
        default="ESTABLISHED,SYN_SENT",
        metavar="LIST",
        help="Comma-separated TCP states to watch "
        "(default: ESTABLISHED,SYN_SENT, empty=all)",
    )
    sp.add_argument(
        "--ignore-proc", metavar="LIST", help="Suppress process names (csv)"
    )
    sp.add_argument("--ignore-port", metavar="LIST", help="Suppress ports (csv)")
    sp.add_argument("--ignore-ip", metavar="LIST", help="Suppress IPs/CIDRs (csv)")
    sp.add_argument("--log", metavar="FILE", help="Append NDJSON event log")
    sp.add_argument(
        "--show-closed",
        action="store_true",
        help="Also report connections that close between polls",
    )

    # baseline
    bl = sub.add_parser("baseline", help="Capture or diff a connection baseline")
    bls = bl.add_subparsers(dest="action", required=True)
    cap = bls.add_parser("capture", help="Snapshot current state to JSON")
    cap.add_argument("-o", "--output", default="baseline.json", metavar="FILE")
    dif = bls.add_parser("diff", help="Diff current state vs saved baseline")
    dif.add_argument("-i", "--input", default="baseline.json", metavar="FILE")
    dif.add_argument(
        "--ignore-proc", metavar="LIST", help="Suppress process names (csv)"
    )
    dif.add_argument("--ignore-port", metavar="LIST", help="Suppress ports (csv)")
    dif.add_argument("--ignore-ip", metavar="LIST", help="Suppress IPs/CIDRs (csv)")

    # report
    sub.add_parser(
        "report", help="Full system snapshot (connections + listeners + findings)"
    )

    return p


# ═══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════
_CMD_MAP = {
    "live": cmd_live,
    "listeners": cmd_listeners,
    "scan": cmd_scan,
    "deps": cmd_deps,
    "watch": cmd_watch,
    "baseline": cmd_baseline,
    "report": cmd_report,
}


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    global _USE_COLOR
    if getattr(args, "no_color", False):
        _USE_COLOR = False

    # Build allowlist: file → then merge any per-command flags
    al = AllowList()
    wl_path = getattr(args, "whitelist", None)
    if wl_path:
        try:
            al = AllowList.from_file(Path(wl_path))
        except Exception as exc:
            _err(f"cannot load whitelist {wl_path!r}: {exc}")
            return 2
    al.merge_args(args)

    if (
        not HAS_PSUTIL
        and not args.json
        and args.command in ("live", "listeners", "report")
    ):
        print(
            "  [note] psutil not installed — process info unavailable for other users.\n"
            "         pip install psutil  for richer output.\n",
            file=sys.stderr,
        )

    handler = _CMD_MAP.get(args.command)
    if not handler:
        parser.print_help()
        return 2

    return handler(args, al)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

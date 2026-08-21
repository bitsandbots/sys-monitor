"""hiddenscope_scanner.py: OS-parsing (ss/psutil), baseline capture/diff,
and the CLI command layer.

OS-parsing functions touch the real system through exactly two seams --
subprocess.check_output() (the `ss`-based path) and psutil (the
`psutil`-based path) -- so every test here mocks at one of those two
seams rather than shelling out or reading the real process table.
Baseline and CLI tests mock at hs._connections()/hs._listeners(), the
same higher-level seam already used by sys_monitor.py's glue tests.
"""
import json
import subprocess

import pytest

import hiddenscope_scanner as hs


def _last_json_value(text):
    """Decode the last whitespace-separated JSON value in `text`.

    cmd_scan's --json mode can interleave single-line progress objects
    before its final pretty-printed result object -- json.loads() on the
    raw blob fails, so this walks all top-level values and keeps the last.
    """
    dec = json.JSONDecoder()
    idx, n, last = 0, len(text), None
    while idx < n:
        while idx < n and text[idx].isspace():
            idx += 1
        if idx >= n:
            break
        last, idx = dec.raw_decode(text, idx)
    return last


# ── get_connections_ss / get_listeners_ss (subprocess seam) ──────────────


def test_get_connections_ss_parses_ss_output(monkeypatch):
    raw = (
        'ESTAB 0 0 192.168.1.5:52344 93.184.216.34:443 users:(("curl",pid=1234,fd=5))\n'
        "ESTAB 0 0 192.168.1.5:22 10.0.0.9:51000\n"
    )
    monkeypatch.setattr(subprocess, "check_output", lambda *a, **k: raw)

    rows = hs.get_connections_ss()

    assert len(rows) == 2
    assert rows[0]["pid"] == 1234
    assert rows[0]["proc"] == "curl"
    assert rows[0]["raddr"] == "93.184.216.34:443"
    assert rows[0]["rip"] == "93.184.216.34"
    assert rows[0]["rport"] == 443
    # No users:(( ) blob -> pid/proc stay unknown, row is still kept
    assert rows[1]["pid"] is None
    assert rows[1]["proc"] == "?"


def test_get_connections_ss_falls_back_to_netstat_when_ss_missing(monkeypatch):
    calls = []

    def fake_check_output(cmd, **kwargs):
        calls.append(cmd[0])
        if cmd[0] == "ss":
            raise FileNotFoundError()
        return 'ESTAB 0 0 10.0.0.1:80 10.0.0.2:9999 users:(("nginx",pid=9,fd=1))\n'

    monkeypatch.setattr(subprocess, "check_output", fake_check_output)

    rows = hs.get_connections_ss()

    assert calls == ["ss", "netstat"]
    assert len(rows) == 1
    assert rows[0]["proc"] == "nginx"


def test_get_connections_ss_returns_empty_when_both_tools_fail(monkeypatch):
    def fake_check_output(cmd, **kwargs):
        raise FileNotFoundError()

    monkeypatch.setattr(subprocess, "check_output", fake_check_output)

    assert hs.get_connections_ss() == []


def test_get_connections_ss_returns_empty_on_called_process_error(monkeypatch):
    def fake_check_output(cmd, **kwargs):
        raise subprocess.CalledProcessError(1, cmd)

    monkeypatch.setattr(subprocess, "check_output", fake_check_output)

    assert hs.get_connections_ss() == []


def test_get_connections_ss_skips_short_lines(monkeypatch):
    monkeypatch.setattr(subprocess, "check_output", lambda *a, **k: "State Recv-Q\ngarbage\n")

    assert hs.get_connections_ss() == []


def test_get_listeners_ss_parses_listening_sockets(monkeypatch):
    raw = 'LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=567,fd=3))\n'
    monkeypatch.setattr(subprocess, "check_output", lambda *a, **k: raw)

    rows = hs.get_listeners_ss()

    assert len(rows) == 1
    assert rows[0]["port"] == 22
    assert rows[0]["proc"] == "sshd"
    assert rows[0]["pid"] == 567
    assert rows[0]["iface"] == "0.0.0.0"


def test_get_listeners_ss_returns_empty_on_any_failure(monkeypatch):
    def fake_check_output(cmd, **kwargs):
        raise OSError("no ss binary")

    monkeypatch.setattr(subprocess, "check_output", fake_check_output)

    assert hs.get_listeners_ss() == []


# ── get_connections_psutil / get_listeners_psutil (psutil seam) ──────────


class _FakeAddr:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port


class _FakeConn:
    def __init__(self, pid, laddr, raddr, status, family=None):
        self.pid = pid
        self.laddr = laddr
        self.raddr = raddr
        self.status = status
        self.family = family or hs.socket.AF_INET


class _FakeProcess:
    def __init__(self, name, exe, cmdline):
        self._name = name
        self._exe = exe
        self._cmdline = cmdline

    def name(self):
        return self._name

    def exe(self):
        return self._exe

    def cmdline(self):
        return self._cmdline


@pytest.fixture
def fake_psutil(monkeypatch):
    """Installs a fake psutil module on hs.psutil with a controllable
    connection list, without requiring the real psutil package."""

    class _FakePsutilModule:
        def __init__(self):
            self.conns = []

        def net_connections(self, kind="inet"):
            return self.conns

        def Process(self, pid):
            procs = {1234: _FakeProcess("curl", "/usr/bin/curl", ["curl", "-s", "url"])}
            if pid not in procs:
                raise Exception(f"no such process {pid}")
            return procs[pid]

    fake = _FakePsutilModule()
    monkeypatch.setattr(hs, "psutil", fake)
    monkeypatch.setattr(hs, "HAS_PSUTIL", True)
    return fake


def test_get_connections_psutil_maps_fields(fake_psutil):
    fake_psutil.conns = [
        _FakeConn(1234, _FakeAddr("192.168.1.5", 52344), _FakeAddr("93.184.216.34", 443), "ESTABLISHED"),
        _FakeConn(None, _FakeAddr("0.0.0.0", 8585), None, "LISTEN"),
    ]

    rows = hs.get_connections_psutil()

    assert len(rows) == 2
    assert rows[0]["proc"] == "curl"
    assert rows[0]["exe"] == "/usr/bin/curl"
    assert rows[0]["raddr"] == "93.184.216.34:443"
    assert rows[0]["rip"] == "93.184.216.34"
    assert rows[1]["raddr"] == "-"
    assert rows[1]["rip"] is None


def test_get_connections_psutil_unknown_pid_degrades_gracefully(fake_psutil):
    fake_psutil.conns = [
        _FakeConn(9999, _FakeAddr("10.0.0.1", 80), _FakeAddr("10.0.0.2", 1000), "ESTABLISHED"),
    ]

    rows = hs.get_connections_psutil()

    assert rows[0]["proc"] == "?"
    assert rows[0]["exe"] == ""


def test_get_listeners_psutil_filters_to_listen_status_only(fake_psutil):
    fake_psutil.conns = [
        _FakeConn(1234, _FakeAddr("0.0.0.0", 8585), None, "LISTEN"),
        _FakeConn(1234, _FakeAddr("192.168.1.5", 52344), _FakeAddr("93.184.216.34", 443), "ESTABLISHED"),
    ]

    rows = hs.get_listeners_psutil()

    assert len(rows) == 1
    assert rows[0]["port"] == 8585
    assert rows[0]["proc"] == "curl"


# ── _connections() / _listeners() dispatch ────────────────────────────────


def test_connections_dispatches_to_psutil_when_available(monkeypatch):
    monkeypatch.setattr(hs, "HAS_PSUTIL", True)
    monkeypatch.setattr(hs, "get_connections_psutil", lambda: ["psutil-path"])
    monkeypatch.setattr(hs, "get_connections_ss", lambda: ["ss-path"])

    assert hs._connections() == ["psutil-path"]


def test_connections_dispatches_to_ss_when_psutil_unavailable(monkeypatch):
    monkeypatch.setattr(hs, "HAS_PSUTIL", False)
    monkeypatch.setattr(hs, "get_connections_psutil", lambda: ["psutil-path"])
    monkeypatch.setattr(hs, "get_connections_ss", lambda: ["ss-path"])

    assert hs._connections() == ["ss-path"]


# ── baseline_capture / baseline_diff ──────────────────────────────────────


@pytest.fixture
def stub_live(monkeypatch):
    """Returns a function that stubs hs._connections()/hs._listeners()
    with canned rows, the same seam sys_monitor.py's glue tests mock."""

    def _use(connections=None, listeners=None):
        monkeypatch.setattr(hs, "_connections", lambda: connections or [])
        monkeypatch.setattr(hs, "_listeners", lambda: listeners or [])

    return _use


def test_baseline_capture_writes_snapshot_and_returns_it(tmp_path, stub_live):
    stub_live(
        connections=[{"raddr": "93.184.216.34:443"}],
        listeners=[{"laddr": "0.0.0.0:22"}],
    )
    outfile = tmp_path / "baseline.json"

    snap = hs.baseline_capture(outfile)

    assert outfile.exists()
    on_disk = json.loads(outfile.read_text())
    assert on_disk["connections"] == snap["connections"]
    assert len(snap["connections"]) == 1
    assert len(snap["listeners"]) == 1
    assert snap["tool"] == hs.PROG


def test_baseline_diff_unparseable_file_returns_error_finding(tmp_path, stub_live):
    stub_live()
    bad = tmp_path / "baseline.json"
    bad.write_text("not json")

    findings = hs.baseline_diff(bad)

    assert len(findings) == 1
    assert findings[0].category == "baseline.error"
    assert findings[0].severity == "critical"


def test_baseline_diff_flags_new_listener(tmp_path, stub_live):
    saved = tmp_path / "baseline.json"
    saved.write_text(json.dumps({"connections": [], "listeners": []}))
    stub_live(listeners=[{"laddr": "0.0.0.0:22"}])

    findings = hs.baseline_diff(saved)

    new = [f for f in findings if f.category == "baseline.new_listener"]
    assert len(new) == 1
    assert new[0].detail == "0.0.0.0:22"
    assert new[0].severity == "medium"


def test_baseline_diff_new_listener_on_suspicious_port_is_high(tmp_path, stub_live):
    port = next(iter(hs.SUSPICIOUS_PORTS))
    saved = tmp_path / "baseline.json"
    saved.write_text(json.dumps({"connections": [], "listeners": []}))
    stub_live(listeners=[{"laddr": f"0.0.0.0:{port}"}])

    findings = hs.baseline_diff(saved)

    assert findings[0].severity == "high"


def test_baseline_diff_flags_closed_listener(tmp_path, stub_live):
    saved = tmp_path / "baseline.json"
    saved.write_text(json.dumps({"connections": [], "listeners": [{"laddr": "0.0.0.0:22"}]}))
    stub_live(listeners=[])

    findings = hs.baseline_diff(saved)

    closed = [f for f in findings if f.category == "baseline.closed_listener"]
    assert len(closed) == 1
    assert closed[0].severity == "info"


def test_baseline_diff_flags_new_external_connection(tmp_path, stub_live):
    saved = tmp_path / "baseline.json"
    saved.write_text(json.dumps({"connections": [], "listeners": []}))
    stub_live(connections=[{"raddr": "93.184.216.34:443", "rip": "93.184.216.34", "rport": 443, "pid": 1, "proc": "curl"}])

    findings = hs.baseline_diff(saved)

    new_ext = [f for f in findings if f.category == "baseline.new_external"]
    assert len(new_ext) == 1
    assert "93.184.216.34:443" in new_ext[0].detail


def test_baseline_diff_skips_private_new_connections(tmp_path, stub_live):
    saved = tmp_path / "baseline.json"
    saved.write_text(json.dumps({"connections": [], "listeners": []}))
    stub_live(connections=[{"raddr": "10.0.0.5:443", "rip": "10.0.0.5", "rport": 443, "pid": 1, "proc": "x"}])

    findings = hs.baseline_diff(saved)

    assert [f for f in findings if f.category == "baseline.new_external"] == []


def test_baseline_diff_respects_allowlist(tmp_path, stub_live):
    saved = tmp_path / "baseline.json"
    saved.write_text(json.dumps({"connections": [], "listeners": []}))
    stub_live(connections=[{"raddr": "93.184.216.34:443", "rip": "93.184.216.34", "rport": 443, "pid": 1, "proc": "curl"}])
    al = hs.AllowList()
    al.procs = {"curl"}

    findings = hs.baseline_diff(saved, al=al)

    assert [f for f in findings if f.category == "baseline.new_external"] == []


# ── CLI commands ───────────────────────────────────────────────────────────


@pytest.fixture
def parser():
    return hs._build_parser()


def test_cmd_live_json_reports_findings(capsys, parser, stub_live):
    stub_live(connections=[{"rip": "93.184.216.34", "rport": 1337, "pid": 1, "proc": "x", "raddr": "93.184.216.34:1337"}])
    args = parser.parse_args(["--json", "live"])

    code = hs.cmd_live(args, hs.AllowList())

    out = json.loads(capsys.readouterr().out)
    assert out["connections"][0]["rport"] == 1337
    assert len(out["findings"]) == 1
    assert code == 1  # a finding at/above default "info" threshold


def test_cmd_live_no_findings_exits_zero(capsys, parser, stub_live):
    stub_live(connections=[])
    args = parser.parse_args(["--json", "live"])

    code = hs.cmd_live(args, hs.AllowList())

    assert code == 0


def test_cmd_listeners_json(capsys, parser, stub_live):
    stub_live(listeners=[{"port": 22, "proc": "sshd", "pid": 1, "laddr": "0.0.0.0:22", "iface": "0.0.0.0"}])
    args = parser.parse_args(["--json", "listeners"])

    code = hs.cmd_listeners(args, hs.AllowList())

    out = json.loads(capsys.readouterr().out)
    assert out[0]["port"] == 22
    assert code == 0


def test_cmd_baseline_capture(tmp_path, capsys, parser, stub_live):
    stub_live(connections=[], listeners=[{"laddr": "0.0.0.0:22"}])
    outfile = tmp_path / "out.json"
    args = parser.parse_args(["baseline", "capture", "-o", str(outfile)])

    code = hs.cmd_baseline(args, hs.AllowList())

    assert code == 0
    assert outfile.exists()


def test_cmd_baseline_diff_missing_file_errors(tmp_path, capsys, parser):
    missing = tmp_path / "nope.json"
    args = parser.parse_args(["baseline", "diff", "-i", str(missing)])

    code = hs.cmd_baseline(args, hs.AllowList())

    assert code == 2


def test_cmd_baseline_diff_reports_changes(tmp_path, capsys, parser, stub_live):
    saved = tmp_path / "baseline.json"
    saved.write_text(json.dumps({"connections": [], "listeners": []}))
    stub_live(listeners=[{"laddr": "0.0.0.0:22"}])
    args = parser.parse_args(["--json", "baseline", "diff", "-i", str(saved)])

    code = hs.cmd_baseline(args, hs.AllowList())

    out = json.loads(capsys.readouterr().out)
    assert len(out) == 1
    assert code == 1


def test_cmd_baseline_unknown_action_errors(parser):
    args = parser.parse_args(["baseline", "capture"])
    args.action = "bogus"

    assert hs.cmd_baseline(args, hs.AllowList()) == 2


def test_cmd_report_json_structure(capsys, parser, stub_live):
    stub_live(
        connections=[{"rip": "93.184.216.34", "rport": 1337, "pid": 1, "proc": "x", "raddr": "93.184.216.34:1337"}],
        listeners=[{"port": 22, "proc": "sshd", "pid": 1, "laddr": "0.0.0.0:22", "iface": "0.0.0.0"}],
    )
    args = parser.parse_args(["--json", "report"])

    code = hs.cmd_report(args, hs.AllowList())

    out = json.loads(capsys.readouterr().out)
    assert out["summary"]["total_connections"] == 1
    assert out["summary"]["total_listeners"] == 1
    assert out["summary"]["external_connections"] == 1
    assert len(out["findings"]) == 1
    assert code == 1


def test_cmd_scan_path_not_found(capsys, parser):
    args = parser.parse_args(["--json", "scan", "/no/such/path"])

    assert hs.cmd_scan(args, hs.AllowList()) == 2


def test_cmd_scan_single_file_reports_findings(tmp_path, capsys, parser):
    target = tmp_path / "id_rsa"
    target.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----\n")
    args = parser.parse_args(["--json", "scan", str(target)])

    code = hs.cmd_scan(args, hs.AllowList())

    out = json.loads(capsys.readouterr().out)
    assert any(f["description"] == "Embedded SSH/TLS private key" for f in out["findings"])
    assert code == 1


def test_cmd_scan_directory_walks_tree(tmp_path, capsys, parser):
    (tmp_path / "safe.txt").write_text("hello world\n")
    (tmp_path / "id_rsa").write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----\n")
    args = parser.parse_args(["--json", "scan", str(tmp_path)])

    code = hs.cmd_scan(args, hs.AllowList())

    out = _last_json_value(capsys.readouterr().out)
    assert any("id_rsa" in f["source"] for f in out["findings"])
    assert code == 1


def test_cmd_deps_path_not_found(parser):
    args = parser.parse_args(["--json", "deps", "/no/such/path"])

    assert hs.cmd_deps(args, hs.AllowList()) == 2


def test_cmd_deps_finds_manifests_in_tree(tmp_path, capsys, parser):
    (tmp_path / "requirements.txt").write_text("git+https://github.com/foo/baz.git\n")
    args = parser.parse_args(["--json", "deps", str(tmp_path)])

    code = hs.cmd_deps(args, hs.AllowList())

    out = json.loads(capsys.readouterr().out)
    assert len(out["manifests"]) == 1
    assert code == 1


# ── main() dispatch ────────────────────────────────────────────────────────


def test_main_dispatches_to_matching_command(monkeypatch):
    monkeypatch.setattr(hs.sys, "argv", ["hiddenscope", "listeners"])
    # _CMD_MAP captures a reference to cmd_listeners at import time, so the
    # dispatch table entry -- not the module attribute -- has to be patched.
    monkeypatch.setitem(hs._CMD_MAP, "listeners", lambda args, al: 42)

    assert hs.main() == 42


def test_main_whitelist_load_failure_returns_error(monkeypatch, tmp_path):
    bad = tmp_path / "allow.json"
    bad.write_text("not json")
    monkeypatch.setattr(hs.sys, "argv", ["hiddenscope", "--whitelist", str(bad), "listeners"])

    assert hs.main() == 2

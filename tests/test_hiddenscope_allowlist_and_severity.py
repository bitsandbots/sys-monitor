"""hiddenscope_scanner.py: allowlist matching and severity scoring.

Covers gap-analysis item 4's own stated scope for the vendored scanner --
"allowlist matching and severity scoring are untested" -- not the whole
file. File/dependency scanning, live connection/listener OS-parsing,
baseline diff, and the CLI are separate, larger, deliberately out of
scope here (see TESTING_STRATEGY.md).

Everything tested here is a pure function/class -- no I/O, no
subprocess, no network -- so none of it needs mocking.
"""
import ipaddress

import hiddenscope_scanner as hs


# ── is_private ──────────────────────────────────────────────────────────


def test_is_private_rfc1918_and_loopback():
    assert hs.is_private("10.1.2.3") is True
    assert hs.is_private("192.168.1.1") is True
    assert hs.is_private("127.0.0.1") is True
    assert hs.is_private("169.254.1.1") is True
    assert hs.is_private("::1") is True
    assert hs.is_private("fe80::1") is True


def test_is_private_172_range_boundary():
    """172.16.0.0/12 is private (172.16.x-172.31.x); 172.15.x and 172.32.x
    are not, even though they share the "172." prefix."""
    assert hs.is_private("172.16.0.1") is True
    assert hs.is_private("172.31.255.255") is True
    assert hs.is_private("172.15.255.255") is False
    assert hs.is_private("172.32.0.1") is False


def test_is_private_empty_and_placeholder_addresses():
    assert hs.is_private("") is True
    assert hs.is_private(None) is True
    assert hs.is_private("-") is True
    assert hs.is_private("*") is True


def test_is_private_public_ip_is_not_private():
    assert hs.is_private("8.8.8.8") is False
    assert hs.is_private("93.184.216.34") is False


# ── AllowList.suppresses_conn ───────────────────────────────────────────


def test_allowlist_suppresses_by_proc_case_insensitive():
    al = hs.AllowList()
    al.procs.add("chrome")
    conn = {"proc": "Chrome", "rport": 443, "rip": "8.8.8.8"}
    assert al.suppresses_conn(conn) is not None


def test_allowlist_suppresses_by_port():
    al = hs.AllowList()
    al.ports.add(4444)
    conn = {"proc": "x", "rport": 4444, "rip": "8.8.8.8"}
    assert al.suppresses_conn(conn) is not None


def test_allowlist_suppresses_by_network():
    al = hs.AllowList()
    al.networks.append(ipaddress.ip_network("1.2.3.0/24"))
    conn = {"proc": "x", "rport": 443, "rip": "1.2.3.4"}
    assert al.suppresses_conn(conn) is not None


def test_allowlist_no_match_returns_none():
    al = hs.AllowList()
    al.procs.add("chrome")
    conn = {"proc": "firefox", "rport": 443, "rip": "8.8.8.8"}
    assert al.suppresses_conn(conn) is None


def test_allowlist_empty_never_suppresses():
    al = hs.AllowList()
    conn = {"proc": "anything", "rport": 4444, "rip": "8.8.8.8"}
    assert al.suppresses_conn(conn) is None


# ── AllowList.from_file ─────────────────────────────────────────────────


def test_allowlist_from_file_round_trip(tmp_path):
    path = tmp_path / "allowlist.json"
    path.write_text(
        '{"procs": ["Chrome"], "ports": [443, 8080], '
        '"networks": ["10.0.0.0/8"], "url_domains": ["Example.com"]}'
    )

    al = hs.AllowList.from_file(path)

    assert al.procs == {"chrome"}
    assert al.ports == {443, 8080}
    assert al.url_domains == {"example.com"}
    assert len(al.networks) == 1
    assert al.networks[0] == ipaddress.ip_network("10.0.0.0/8")


def test_allowlist_from_file_skips_invalid_network(tmp_path, capsys):
    path = tmp_path / "allowlist.json"
    path.write_text('{"networks": ["not-a-network", "10.0.0.0/8"]}')

    al = hs.AllowList.from_file(path)  # must not raise

    assert len(al.networks) == 1
    assert al.networks[0] == ipaddress.ip_network("10.0.0.0/8")
    assert "invalid network" in capsys.readouterr().err


# ── _sev / _sev_down ────────────────────────────────────────────────────


def test_sev_ordering():
    assert hs._sev("info") < hs._sev("low") < hs._sev("medium") < hs._sev("high") < hs._sev("critical")


def test_sev_unknown_defaults_to_info():
    assert hs._sev("not-a-real-severity") == hs._sev("info") == 0


def test_sev_down_steps_and_floors_at_info():
    assert hs._sev_down("high", 1) == "medium"
    assert hs._sev_down("low", 5) == "info"  # floors, never goes negative/raises


# ── score_connection ─────────────────────────────────────────────────────


def test_score_connection_private_ip_is_not_scored():
    conn = {"rip": "192.168.1.1", "rport": 4444, "proc": "x", "pid": 1}
    assert hs.score_connection(conn) is None


def test_score_connection_allowlisted_is_not_scored():
    al = hs.AllowList()
    al.ports.add(4444)
    conn = {"rip": "8.8.8.8", "rport": 4444, "proc": "x", "pid": 1}
    assert hs.score_connection(conn, al) is None


def test_score_connection_suspicious_port_is_high():
    conn = {"rip": "8.8.8.8", "rport": 4444, "proc": "nc", "pid": 1, "exe": "/usr/bin/nc"}
    finding = hs.score_connection(conn)
    assert finding is not None
    assert finding.severity == "high"
    assert finding.category == "live.suspicious_port"


def test_score_connection_suspicious_exe_path_is_high():
    conn = {
        "rip": "8.8.8.8",
        "rport": 9999,
        "proc": "evil",
        "pid": 1,
        "exe": "/tmp/.hidden/evil",
    }
    finding = hs.score_connection(conn)
    assert finding is not None
    assert finding.severity == "high"
    assert finding.category == "live.suspicious_exe"


def test_score_connection_plain_external_is_info():
    conn = {
        "rip": "93.184.216.34",
        "rport": 443,
        "proc": "curl",
        "pid": 1,
        "exe": "/usr/bin/curl",
        "status": "ESTABLISHED",
    }
    finding = hs.score_connection(conn)
    assert finding is not None
    assert finding.severity == "info"
    assert finding.category == "live.external"


def test_finding_to_dict_shape():
    conn = {"rip": "8.8.8.8", "rport": 4444, "proc": "x", "pid": 1}
    finding = hs.score_connection(conn)
    d = finding.to_dict()
    assert set(d.keys()) >= {"ts", "category", "severity", "description", "detail", "source", "line"}
    assert d["severity"] == "high"

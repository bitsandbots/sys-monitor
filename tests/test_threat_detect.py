"""Tests for threat_detect: parsers, detectors, persistence, tailer."""

from datetime import datetime

import pytest

import threat_detect as td

PUB = "8.8.8.8"  # globally routable (TEST-NET ranges are not "global")
PUB2 = "1.1.1.1"
LAN = "192.168.0.50"
T0 = 1_800_000_000.0


def fail(ip=PUB, user="HARNESS_bob", ts=T0):
    return td.LogEvent(ts=ts, source="sshd", kind="login_fail", ip=ip, user=user)


def ok(ip=PUB, user="HARNESS_bob", ts=T0):
    return td.LogEvent(ts=ts, source="sshd", kind="login_ok", ip=ip, user=user)


def http(ip=PUB, status=200, path="/", ts=T0):
    return td.LogEvent(
        ts=ts, source="nginx", kind="http", ip=ip, status=status, path=path
    )


def feed(engine, events):
    out = []
    for ev in events:
        out += engine.ingest(ev)
    return out


def names(findings):
    return [f.detector for f in findings]


# ── IP helpers ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "ip,expected",
    [
        (PUB, True),
        ("192.168.0.1", False),
        ("10.0.0.5", False),
        ("172.19.0.1", False),
        ("127.0.0.1", False),
        ("169.254.1.1", False),
        ("::1", False),
        ("203.0.113.9", False),
        ("not-an-ip", False),
        ("::ffff:8.8.8.8", True),
    ],
)
def test_is_blockable_ip(ip, expected):
    assert td.is_blockable_ip(ip) is expected


def test_allowlist_overrides_public_ip():
    allow = td.parse_networks("8.8.8.0/24, garbage, ")
    assert len(allow) == 1
    assert td.is_blockable_ip(PUB, allow) is False
    assert td.is_blockable_ip(PUB2, allow) is True


# ── Parsers ────────────────────────────────────────────────────────────────


def test_parse_sshd_failed_password_invalid_user():
    ev = td.parse_sshd_message(
        "Failed password for invalid user admin from 8.8.8.8 port 4242 ssh2", T0
    )
    assert (ev.kind, ev.user, ev.ip) == ("login_fail", "admin", PUB)


def test_parse_sshd_accepted_publickey():
    ev = td.parse_sshd_message(
        "Accepted publickey for corecond from 192.168.0.169 port 5555 ssh2: RSA SHA256:x",
        T0,
    )
    assert (ev.kind, ev.user, ev.ip) == ("login_ok", "corecond", "192.168.0.169")


def test_parse_sshd_preauth_disconnect_counts_as_fail():
    ev = td.parse_sshd_message(
        "Connection closed by authenticating user root 8.8.8.8 port 22 [preauth]", T0
    )
    assert ev.kind == "login_fail" and ev.user == "root"


def test_parse_sshd_ignores_noise():
    assert td.parse_sshd_message("Server listening on 0.0.0.0 port 2222.", T0) is None
    assert (
        td.parse_sshd_message("Failed password for x from not-an-ip port 1", T0) is None
    )


def test_parse_access_line_combined():
    line = (
        '8.8.8.8 - - [14/Nov/2026:10:00:01 +0000] "GET /.env HTTP/1.1" 404 153 '
        '"-" "curl/8.0"'
    )
    ev = td.parse_access_line(line)
    assert (ev.ip, ev.status, ev.path, ev.kind) == (PUB, 404, "/.env", "http")
    assert (
        ev.ts
        == datetime.strptime(
            "14/Nov/2026 10:00:01 +0000", "%d/%b/%Y %H:%M:%S %z"
        ).timestamp()
    )


def test_parse_access_line_garbage():
    assert td.parse_access_line("not a log line") is None


# ── SSH detectors ──────────────────────────────────────────────────────────


def test_brute_force_fires_once_then_cools_down():
    e = td.ThreatEngine(learning=False)
    out = feed(e, [fail(ts=T0 + i) for i in range(12)])
    assert names(out).count("brute_force") == 1
    f = next(x for x in out if x.detector == "brute_force")
    assert f.blockable is True and f.ip == PUB


def test_brute_force_below_threshold_is_quiet():
    e = td.ThreatEngine(learning=False)
    assert feed(e, [fail(ts=T0 + i) for i in range(5)]) == []


def test_brute_force_window_expires():
    e = td.ThreatEngine(learning=False)
    out = feed(e, [fail(ts=T0 + i * 60) for i in range(10)])  # 1/min: never 6 in 120s
    assert "brute_force" not in names(out)


def test_brute_force_from_lan_not_blockable():
    e = td.ThreatEngine(learning=False)
    out = feed(e, [fail(ip=LAN, ts=T0 + i) for i in range(8)])
    f = next(x for x in out if x.detector == "brute_force")
    assert f.blockable is False


def test_password_spray_many_users_one_ip():
    e = td.ThreatEngine(learning=False)
    out = feed(e, [fail(user=f"HARNESS_u{i}", ts=T0 + i * 10) for i in range(5)])
    assert "password_spray" in names(out)


def test_distributed_attack_many_ips_one_user():
    e = td.ThreatEngine(learning=False)
    ips = ["8.8.8.8", "1.1.1.1", "9.9.9.9", "8.8.4.4", "208.67.222.222"]
    out = feed(e, [fail(ip=ip, user="root", ts=T0 + i) for i, ip in enumerate(ips)])
    f = next(x for x in out if x.detector == "distributed_attack")
    assert f.blockable is False and f.user == "root"


def test_success_after_failures_is_critical_and_not_blockable():
    e = td.ThreatEngine(learning=False)
    out = feed(e, [fail(ts=T0 + i) for i in range(3)] + [ok(ts=T0 + 5)])
    f = next(x for x in out if x.detector == "success_after_failures")
    assert f.severity == "critical" and f.blockable is False


def test_root_login_is_critical():
    e = td.ThreatEngine(learning=False)
    out = e.ingest(ok(ip=LAN, user="root"))
    assert any(f.detector == "root_login" and f.severity == "critical" for f in out)


# ── Baseline / learning ────────────────────────────────────────────────────


def test_learning_mode_emits_info_and_learns():
    e = td.ThreatEngine(learning=True)
    out = e.ingest(ok())
    assert [f.severity for f in out] == ["info"]
    assert PUB in e.baseline.ips
    assert e.ingest(ok(ts=T0 + 5000)) == []  # known now


def test_new_source_warns_after_learning():
    b = td.Baseline()
    b.add(ok(ip=LAN))
    e = td.ThreatEngine(baseline=b, learning=False)
    out = e.ingest(ok(ip=PUB))
    assert out and out[0].severity == "warning" and "new source" in out[0].message


def test_known_login_is_quiet():
    b = td.Baseline()
    b.add(ok(ip=LAN))
    e = td.ThreatEngine(baseline=b, learning=False)
    assert e.ingest(ok(ip=LAN)) == []


def test_unusual_hour_flagged_only_with_enough_history():
    b = td.Baseline()
    hour = datetime.fromtimestamp(T0).hour
    for i in range(12):
        b.add(ok(ip=LAN, ts=T0 + i))
    e = td.ThreatEngine(baseline=b, learning=False)
    odd_ts = T0 + 6 * 3600
    assert datetime.fromtimestamp(odd_ts).hour != hour
    out = e.ingest(ok(ip=LAN, ts=odd_ts))
    assert out and "unusual hour" in out[0].message
    # Too little history: no hour-based finding.
    b2 = td.Baseline()
    b2.add(ok(ip=LAN))
    e2 = td.ThreatEngine(baseline=b2, learning=False)
    assert e2.ingest(ok(ip=LAN, ts=odd_ts)) == []


def test_seed_mode_learns_without_detecting():
    e = td.ThreatEngine(learning=False)
    for i in range(10):
        assert e.ingest(fail(ts=T0 + i), seed=True) == []
    assert e.ingest(ok(), seed=True) == []
    assert PUB in e.baseline.ips


# ── HTTP detectors ─────────────────────────────────────────────────────────


def test_request_burst():
    e = td.ThreatEngine(learning=False)
    out = feed(e, [http(ts=T0 + i * 0.05) for i in range(120)])
    assert "request_burst" in names(out)


def test_web_scan_by_probe_paths():
    e = td.ThreatEngine(learning=False)
    paths = ["/.env", "/wp-login.php", "/.git/config"]
    out = feed(e, [http(status=404, path=p, ts=T0 + i) for i, p in enumerate(paths)])
    f = next(x for x in out if x.detector == "web_scan")
    assert f.blockable is True and "probe" in f.message


def test_web_scan_by_error_ratio():
    e = td.ThreatEngine(learning=False)
    out = feed(e, [http(status=404, path=f"/x{i}", ts=T0 + i) for i in range(9)])
    assert "web_scan" in names(out)


def test_normal_browsing_is_quiet():
    e = td.ThreatEngine(learning=False)
    gaps = [1, 7, 2, 11, 3, 5, 1, 9, 4, 6] * 3
    t, evs = T0, []
    for i, g in enumerate(gaps):
        t += g
        evs.append(http(status=200, path=f"/page{i}", ts=t))
    assert feed(e, evs) == []


def test_metronome_only_for_public_ips():
    pub = td.ThreatEngine(learning=False)
    out = feed(pub, [http(ts=T0 + i * 2.0) for i in range(14)])
    f = next(x for x in out if x.detector == "bot_timing")
    assert f.severity == "info" and f.blockable is False
    lan = td.ThreatEngine(learning=False)
    assert feed(lan, [http(ip=LAN, ts=T0 + i * 2.0) for i in range(14)]) == []


def test_irregular_traffic_not_metronome():
    e = td.ThreatEngine(learning=False)
    gaps = [1, 4, 2, 5, 1, 3, 4, 1, 5, 2, 4, 1, 3]
    t, evs = T0, []
    for g in gaps:
        t += g
        evs.append(http(ts=t))
    assert "bot_timing" not in names(feed(e, evs))


def test_tracked_ip_table_is_bounded():
    e = td.ThreatEngine(thresholds=td.Thresholds(max_tracked_ips=50), learning=False)
    for i in range(500):
        e.ingest(fail(ip=f"8.{i % 250}.{i // 250}.9", ts=T0 + i))
    assert len(e._fails) <= 50


# ── Persistence ────────────────────────────────────────────────────────────


@pytest.fixture
def conn(tmp_path):
    c = td.open_db(str(tmp_path / "HARNESS_metrics.db"))
    yield c
    c.close()


def _finding(ts=T0, sev="warning", ip=PUB, score=50):
    return td.Finding(
        ts=ts,
        detector="brute_force",
        severity=sev,
        ip=ip,
        user="u",
        message="m",
        score=score,
        blockable=True,
    )


def test_record_and_query_findings(conn):
    td.record_finding(conn, _finding(ts=T0, sev="info"))
    td.record_finding(conn, _finding(ts=T0 + 10, sev="critical", ip=PUB2))
    rows = td.query_findings(conn, since=T0 - 1)
    assert [r["ip"] for r in rows] == [PUB2, PUB]  # newest first
    assert rows[0]["blockable"] is True
    assert len(td.query_findings(conn, min_severity="warning")) == 1
    assert len(td.query_findings(conn, ip=PUB)) == 1


def test_query_uses_bound_parameters(conn):
    td.record_finding(conn, _finding())
    # An injection attempt in the ip filter must match nothing, not everything.
    assert td.query_findings(conn, ip="x' OR '1'='1") == []


def test_prune_and_top_offenders(conn):
    td.record_finding(conn, _finding(ts=T0 - 40 * 86400))
    td.record_finding(conn, _finding(ts=T0, score=80))
    td.record_finding(conn, _finding(ts=T0 + 1, ip=PUB2, score=20))
    assert td.prune_findings(conn, 30, now=T0) == 1
    top = td.top_offenders(conn, since=T0 - 5)
    assert [t["ip"] for t in top] == [PUB, PUB2]


def test_baseline_roundtrip(conn):
    b = td.Baseline()
    b.add(ok(ip=LAN, user="corecond"))
    td.save_baseline(conn, b)
    td.save_baseline(conn, b)  # idempotent
    b2 = td.load_baseline(conn)
    assert b2.ips == {LAN} and b2.users == {"corecond"} and b2.logins == 1
    assert b2.hours == b.hours


def test_learning_state_window(conn):
    learning, ends = td.learning_state(conn, 7, now=T0)
    assert learning is True and ends == T0 + 7 * 86400
    assert td.learning_state(conn, 7, now=T0 + 8 * 86400)[0] is False
    assert td.learning_state(conn, 7, now=T0 + 1)[1] == ends  # start is stamped once


# ── FileTailer ─────────────────────────────────────────────────────────────


def test_tailer_reads_only_new_complete_lines(tmp_path):
    p = tmp_path / "HARNESS_access.log"
    p.write_text("old line\n")
    t = td.FileTailer(str(p))
    assert t.read_new() == []  # starts at EOF
    with open(p, "a") as fh:
        fh.write("one\ntwo\npartial")
    assert t.read_new() == ["one", "two"]
    with open(p, "a") as fh:
        fh.write(" done\n")
    assert t.read_new() == ["partial done"]
    assert t.read_new() == []


def test_tailer_survives_rotation_and_missing_file(tmp_path):
    p = tmp_path / "HARNESS_access.log"
    t = td.FileTailer(str(p))
    assert t.read_new() == []  # missing
    p.write_text("a\n")
    t.read_new()
    p.unlink()
    p.write_text("fresh\n")  # new inode
    assert t.read_new() == ["fresh"]

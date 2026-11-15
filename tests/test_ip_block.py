"""Tests for the sysmon-block helper and the ip_block policy manager."""

import importlib.machinery
import importlib.util
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

import ip_block as ib
import threat_detect as td

PUB, PUB2, LAN = "8.8.8.8", "1.1.1.1", "192.168.0.50"
T0 = 1_800_000_000


def _load_helper():
    path = Path(__file__).parent.parent / "contrib" / "sysmon-block"
    loader = importlib.machinery.SourceFileLoader("sysmon_block", str(path))
    spec = importlib.util.spec_from_loader("sysmon_block", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


helper = _load_helper()


class FakeNft:
    """Records nft argv; `table_exists` toggles list-table success."""

    def __init__(self, table_exists=True, fail_add=False):
        self.calls, self.table_exists, self.fail_add = [], table_exists, fail_add

    def __call__(self, argv, input=None, capture_output=True, text=True, timeout=0):
        self.calls.append((argv, input))
        rc, out = 0, ""
        if argv[:3] == ["nft", "list", "table"] and not self.table_exists:
            rc = 1
        if argv[:3] == ["nft", "add", "element"] and self.fail_add:
            rc = 1
        return SimpleNamespace(returncode=rc, stdout=out, stderr="boom" if rc else "")


@pytest.fixture
def hstate(tmp_path, monkeypatch):
    monkeypatch.setattr(helper, "STATE_FILE", tmp_path / "state" / "state.json")
    monkeypatch.setattr(helper, "ALLOWLIST_FILE", tmp_path / "allow")
    return tmp_path


# ── helper: validation ─────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "bad",
    [
        LAN,
        "10.1.2.3",
        "127.0.0.1",
        "169.254.1.1",
        "::1",
        "fe80::1",
        "0.0.0.0",
        "203.0.113.5",
        "224.0.0.1",
        "239.1.1.1",
        "ff02::1",
        "240.0.0.1",
        "nope",
        "",
        "8.8.8.8/24",
        "8.8.8.8; rm -rf /",
    ],
)
def test_helper_refuses_non_public_or_garbage(bad):
    with pytest.raises(helper.Refused):
        helper.validate_ip(bad)


def test_helper_accepts_public_and_normalizes_mapped_v6():
    assert helper.validate_ip(PUB) == PUB
    assert helper.validate_ip("::ffff:8.8.8.8") == PUB
    assert helper.validate_ip("2001:4860:4860::8888") == "2001:4860:4860::8888"


def test_helper_allowlist_blocks_public_ip(hstate):
    (hstate / "allow").write_text("# office\n8.8.8.0/24  # dns\nbad line\n")
    with pytest.raises(helper.Refused, match="allowlisted"):
        helper.validate_ip(PUB, helper.load_allowlist())
    assert helper.validate_ip(PUB2, helper.load_allowlist()) == PUB2


@pytest.mark.parametrize("ttl", ["0", "59", "-5", "99999999", "abc", "1.5", ""])
def test_helper_ttl_bounds(ttl):
    with pytest.raises(helper.Refused):
        helper.validate_ttl(ttl)
    assert helper.validate_ttl("3600") == 3600


# ── helper: commands ───────────────────────────────────────────────────────


def test_helper_add_creates_table_and_persists(hstate):
    run = FakeNft(table_exists=False)
    out = helper.cmd_add(PUB, "3600", run=run, now=lambda: T0)
    assert out == {"ok": True, "ip": PUB, "ttl": 3600}
    argvs = [c[0] for c in run.calls]
    assert ["nft", "-f", "-"] in argvs  # table created from ruleset
    assert [
        "nft",
        "add",
        "element",
        "inet",
        "sysmon",
        "blocklist4",
        f"{{ {PUB} timeout 3600s }}",
    ] in argvs
    assert helper.read_state()[PUB] == T0 + 3600
    assert oct(helper.STATE_FILE.stat().st_mode & 0o777) == "0o600"


def test_helper_add_ipv6_uses_v6_set(hstate):
    run = FakeNft()
    helper.cmd_add("2001:4860:4860::8888", "600", run=run, now=lambda: T0)
    assert any("blocklist6" in c[0] for c in run.calls)


def test_helper_add_refuses_lan_without_touching_nft(hstate):
    run = FakeNft()
    with pytest.raises(helper.Refused):
        helper.cmd_add(LAN, "3600", run=run)
    assert run.calls == []


def test_helper_add_nft_failure_not_persisted(hstate):
    with pytest.raises(helper.NftError):
        helper.cmd_add(PUB, "3600", run=FakeNft(fail_add=True), now=lambda: T0)
    assert helper.read_state() == {}


def test_helper_del_and_flush(hstate):
    helper.write_state({PUB: T0 + 99, PUB2: T0 + 99})
    helper.cmd_del(PUB, run=FakeNft())
    assert list(helper.read_state()) == [PUB2]
    helper.cmd_flush(run=FakeNft())
    assert helper.read_state() == {}


def test_helper_init_restores_only_unexpired_valid(hstate):
    helper.write_state({PUB: T0 + 500, PUB2: T0 - 10, LAN: T0 + 500})
    run = FakeNft()
    out = helper.cmd_init(run=run, now=lambda: T0)
    assert out["restored"] == 1
    adds = [c[0][-1] for c in run.calls if c[0][:3] == ["nft", "add", "element"]]
    assert adds == [f"{{ {PUB} timeout 500s }}"] or adds == [f"{{ {PUB} timeout 60s }}"]
    assert list(helper.read_state()) == [PUB]


def test_helper_main_usage_and_root_guard(hstate, monkeypatch, capsys):
    monkeypatch.delenv("SYSMON_BLOCK_ALLOW_NONROOT", raising=False)
    monkeypatch.setattr(helper.os, "geteuid", lambda: 1000)
    assert helper.main(["list"]) == 2
    monkeypatch.setenv("SYSMON_BLOCK_ALLOW_NONROOT", "1")
    assert helper.main(["add", PUB]) == 2  # missing ttl
    assert helper.main(["frobnicate"]) == 2
    assert helper.main(["add", LAN, "3600"]) == 2
    assert "not a public address" in capsys.readouterr().out


# ── manager ────────────────────────────────────────────────────────────────


class FakeHelper:
    def __init__(self):
        self.calls, self.fail = [], False

    def __call__(self, argv, capture_output=True, text=True, timeout=0):
        self.calls.append(argv[3:])  # strip sudo -n <helper>
        if self.fail:
            return SimpleNamespace(
                returncode=2, stdout='{"ok": false, "error": "nope"}', stderr=""
            )
        return SimpleNamespace(returncode=0, stdout='{"ok": true}', stderr="")


class Clock:
    def __init__(self, t=T0):
        self.t = t

    def __call__(self):
        return self.t


def make(tmp_path, mode="auto", known=(), **kw):
    fake, clock, logs = FakeHelper(), Clock(), []
    settings = ib.Settings(mode=mode, **kw)
    mgr = ib.BlockManager(
        str(tmp_path / "HARNESS_metrics.db"),
        settings,
        known_ips=lambda: set(known),
        runner=fake,
        clock=clock,
        log=lambda m, lvl="info": logs.append(m),
    )
    return mgr, fake, clock, logs


def finding(ip=PUB, detector="brute_force", score=70, blockable=True):
    return td.Finding(
        ts=T0,
        detector=detector,
        severity="warning",
        ip=ip,
        user="u",
        message=f"{detector} from {ip}",
        score=score,
        blockable=blockable,
    )


def test_auto_blocks_high_confidence_finding(tmp_path):
    mgr, fake, _, logs = make(tmp_path)
    res = mgr.handle_finding(finding())
    assert res == {"action": "blocked", "ttl": 3600}
    assert fake.calls == [["add", PUB, "3600"]]
    assert mgr.active()[0]["ip"] == PUB and any("BLOCKED" in m for m in logs)


def test_ttl_escalates_for_repeat_offender(tmp_path):
    mgr, fake, clock, _ = make(tmp_path)
    ttls = []
    for _ in range(4):
        ttls.append(mgr.block(PUB, "r")["ttl"])
        clock.t += 10_000_000  # let the previous block expire
    assert ttls == [3600, 86400, 604800, 604800]


def test_operator_removal_does_not_escalate(tmp_path):
    mgr, _, _, _ = make(tmp_path)
    mgr.block(PUB, "r")
    mgr.unblock(PUB)
    assert mgr.block(PUB, "r")["ttl"] == 3600


@pytest.mark.parametrize("mode", ["off", "dry-run", "manual"])
def test_block_refused_unless_manual_or_auto(tmp_path, mode):
    mgr, fake, _, _ = make(tmp_path, mode=mode)
    if mode == "manual":
        assert mgr.block(PUB, "r")["ip"] == PUB
        return
    with pytest.raises(ib.BlockRefused, match="disabled"):
        mgr.block(PUB, "r")
    assert fake.calls == []


def test_lan_and_allowlisted_never_blocked(tmp_path):
    mgr, fake, _, _ = make(tmp_path, allowlist=td.parse_networks("1.1.1.0/24"))
    for ip in (LAN, "127.0.0.1", PUB2):
        with pytest.raises(ib.BlockRefused):
            mgr.block(ip, "r")
    assert fake.calls == []


def test_known_login_source_not_auto_blocked_but_manual_can_force(tmp_path):
    mgr, fake, _, _ = make(tmp_path, known={PUB})
    res = mgr.handle_finding(finding())
    assert res["action"] == "proposed" and "known source" in res["reason"]
    assert fake.calls == []
    assert mgr.block(PUB, "operator says so", force=True)["ip"] == PUB


def test_only_high_confidence_detectors_auto_block(tmp_path):
    mgr, fake, _, _ = make(tmp_path)
    assert mgr.handle_finding(finding(detector="request_burst"))["action"] == "proposed"
    assert mgr.handle_finding(finding(score=10))["action"] == "proposed"
    assert mgr.handle_finding(finding(blockable=False))["action"] == "none"
    assert fake.calls == []


def test_manual_mode_only_proposes(tmp_path):
    mgr, fake, _, _ = make(tmp_path, mode="manual")
    assert mgr.handle_finding(finding())["action"] == "proposed"
    assert fake.calls == []


def test_dry_run_records_once_and_enforces_nothing(tmp_path):
    mgr, fake, clock, _ = make(tmp_path, mode="dry-run")
    assert mgr.handle_finding(finding())["action"] == "would_block"
    assert mgr.handle_finding(finding())["action"] == "would_block"
    rows = [h for h in mgr.history() if h["status"] == "would_block"]
    assert len(rows) == 1 and mgr.active() == [] and fake.calls == []
    clock.t += 700  # cooldown passed
    mgr.handle_finding(finding())
    assert len([h for h in mgr.history() if h["status"] == "would_block"]) == 2


def test_off_mode_does_nothing(tmp_path):
    mgr, fake, _, _ = make(tmp_path, mode="off")
    assert mgr.handle_finding(finding())["action"] == "none"
    assert mgr.history() == [] and fake.calls == []


def test_auto_rate_limit(tmp_path):
    mgr, fake, _, _ = make(tmp_path, max_per_hour=2)
    ips = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
    results = [mgr.handle_finding(finding(ip=i))["action"] for i in ips]
    assert results == ["blocked", "blocked", "proposed"]


def test_active_cap(tmp_path):
    mgr, _, _, _ = make(tmp_path, max_active=1)
    mgr.block(PUB, "r")
    with pytest.raises(ib.BlockRefused, match="cap"):
        mgr.block(PUB2, "r")


def test_helper_failure_means_nothing_recorded(tmp_path):
    mgr, fake, _, _ = make(tmp_path)
    fake.fail = True
    res = mgr.handle_finding(finding())
    assert res["action"] == "proposed" and "nope" in res["reason"]
    assert mgr.history() == []


def test_helper_missing_binary_is_a_refusal_not_a_crash(tmp_path):
    mgr, _, _, _ = make(tmp_path)

    def boom(*a, **k):
        raise FileNotFoundError("sudo")

    mgr._run = boom
    with pytest.raises(ib.BlockRefused, match="unavailable"):
        mgr.block(PUB, "r")


def test_expiry_and_unblock_flush(tmp_path):
    mgr, fake, clock, _ = make(tmp_path)
    mgr.block(PUB, "r")
    mgr.block(PUB2, "r")
    mgr.unblock(PUB, by="cory")
    assert [b["ip"] for b in mgr.active()] == [PUB2]
    assert fake.calls[-1] == ["del", PUB]
    clock.t += 4000
    assert mgr.active() == []  # 1h TTL elapsed
    mgr.block(PUB, "r")
    assert mgr.flush() == 1


def test_init_helper_only_in_enforcing_modes(tmp_path):
    for mode, expect in (("off", 0), ("dry-run", 0), ("manual", 1), ("auto", 1)):
        mgr, fake, _, _ = make(tmp_path, mode=mode)
        mgr.init_helper()
        assert len(fake.calls) == expect


def test_sql_injection_in_ip_is_just_an_invalid_ip(tmp_path):
    mgr, fake, _, _ = make(tmp_path)
    with pytest.raises(ib.BlockRefused):
        mgr.block("8.8.8.8' OR '1'='1", "r")
    with pytest.raises(ib.BlockRefused):
        mgr.unblock("1.1.1.1'; DROP TABLE ip_blocks;--")
    assert fake.calls == []


# ── approvals ──────────────────────────────────────────────────────────────


def test_approval_roundtrip_and_tamper(tmp_path):
    key = ib.load_or_create_secret(tmp_path / "k" / "approval.key")
    assert key == ib.load_or_create_secret(tmp_path / "k" / "approval.key")
    assert oct((tmp_path / "k" / "approval.key").stat().st_mode & 0o777) == "0o600"
    exp = T0 + 100
    sig = ib.sign_approval(key, PUB, exp)
    assert ib.verify_approval(key, PUB, exp, sig, now=T0)
    assert not ib.verify_approval(key, PUB2, exp, sig, now=T0)  # other IP
    assert not ib.verify_approval(key, PUB, exp + 1, sig, now=T0)  # altered expiry
    assert not ib.verify_approval(key, PUB, exp, sig, now=exp + 1)  # expired
    assert not ib.verify_approval(key, PUB, exp, "", now=T0)

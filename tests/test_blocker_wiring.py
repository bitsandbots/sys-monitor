"""Integration tests: blocker wired into the threat poller and /api/blocks."""

import time
from types import SimpleNamespace

import pytest

import ip_block as ib
import sys_monitor
import threat_detect as td

PUB, LAN = "8.8.8.8", "192.168.0.50"


class FakeHelper:
    def __init__(self):
        self.calls = []

    def __call__(self, argv, **kw):
        self.calls.append(argv[3:])
        return SimpleNamespace(returncode=0, stdout='{"ok": true}', stderr="")


@pytest.fixture
def blk(monkeypatch, tmp_path):
    sys_monitor.CONFIG.update(
        history_db=str(tmp_path / "HARNESS_metrics.db"),
        threat_enabled=True,
        threat_access_logs=[],
        threat_allowlist="",
        block_mode="off",  # init without touching the real helper
        public_url="http://HARNESS.invalid:8585",
        threat_notify_per_hour=50,
        config_token="",
    )
    sent = []
    monkeypatch.setattr(sys_monitor, "_send_alert", lambda *a, **k: sent.append((a, k)))
    monkeypatch.setattr(sys_monitor._td, "read_journal_sshd", lambda *a, **k: [])
    sys_monitor._threat_feed.clear()
    sys_monitor._threat_notified.clear()
    sys_monitor._threat_init()
    fake = FakeHelper()
    sys_monitor._blocker._run = fake
    sys_monitor._blocker.s.mode = "auto"
    yield SimpleNamespace(sent=sent, fake=fake)
    sys_monitor._threat_engine = None
    sys_monitor._blocker = None


def _fails(n, ip=PUB):
    t = time.time()
    return [
        td.LogEvent(ts=t + i, source="sshd", kind="login_fail", ip=ip, user="HARNESS_x")
        for i in range(n)
    ]


def test_auto_mode_blocks_and_says_so(blk, monkeypatch):
    monkeypatch.setattr(sys_monitor, "_threat_collect_events", lambda: _fails(8))
    sys_monitor._threat_poll_once()
    assert ["add", PUB, "3600"] in blk.fake.calls
    args, kwargs = blk.sent[0]
    assert "BLOCKED for 1h" in args[3] and kwargs["actions"] == ""


def test_dry_run_annotates_and_never_calls_helper(blk, monkeypatch):
    sys_monitor._blocker.s.mode = "dry-run"
    monkeypatch.setattr(sys_monitor, "_threat_collect_events", lambda: _fails(8))
    sys_monitor._threat_poll_once()
    assert blk.fake.calls == []
    assert "would block (dry-run)" in blk.sent[0][0][3]


def test_manual_mode_attaches_signed_one_tap_action(blk, monkeypatch):
    sys_monitor._blocker.s.mode = "manual"
    sys_monitor.CONFIG["block_mode"] = "manual"
    monkeypatch.setattr(sys_monitor, "_threat_collect_events", lambda: _fails(8))
    sys_monitor._threat_poll_once()
    args, kwargs = blk.sent[0]
    assert blk.fake.calls == []
    act = kwargs["actions"]
    assert act.startswith(
        f"http, Block {PUB}, http://HARNESS.invalid:8585/api/blocks/approve?"
    )
    assert "method=POST" in act and "sig=" in act


def test_no_action_without_public_url(blk):
    sys_monitor.CONFIG["public_url"] = ""
    assert sys_monitor._approval_action(PUB) == ""


def test_blocks_api_lifecycle(blk, node_client):
    r = node_client.post("/api/blocks", json={"ip": PUB, "reason": "HARNESS test"})
    assert r.status_code == 200 and r.get_json()["ttl"] == 3600
    data = node_client.get("/api/blocks").get_json()
    assert data["mode"] == "auto" and [b["ip"] for b in data["active"]] == [PUB]
    assert node_client.delete(f"/api/blocks/{PUB}").get_json()["success"]
    assert node_client.get("/api/blocks").get_json()["active"] == []
    node_client.post("/api/blocks", json={"ip": PUB})
    assert node_client.post("/api/blocks/flush").get_json()["removed"] == 1


def test_blocks_api_rejects_lan_and_garbage(blk, node_client):
    for body in ({"ip": LAN}, {"ip": "nope"}, {}, {"ip": PUB, "ttl": "abc"}):
        r = node_client.post("/api/blocks", json=body)
        assert r.status_code == 400 and r.get_json()["success"] is False
    assert blk.fake.calls == []


def test_blocks_mutations_honor_config_token(blk, node_client):
    sys_monitor.CONFIG["config_token"] = "HARNESS_cfg"
    assert node_client.post("/api/blocks", json={"ip": PUB}).status_code == 401
    ok = node_client.post(
        "/api/blocks", json={"ip": PUB}, headers={"X-Config-Token": "HARNESS_cfg"}
    )
    assert ok.status_code == 200


def test_blocks_api_when_disabled(node_client):
    sys_monitor._blocker = None
    assert node_client.get("/api/blocks").get_json()["enabled"] is False
    assert node_client.post("/api/blocks", json={"ip": PUB}).status_code == 503


def _approval(ip=PUB, offset=600, key=None):
    exp = int(time.time()) + offset
    return exp, ib.sign_approval(key or sys_monitor._approval_key, ip, exp)


def test_approve_valid_link_blocks(blk, node_client):
    exp, sig = _approval()
    r = node_client.post(f"/api/blocks/approve?ip={PUB}&exp={exp}&sig={sig}")
    assert r.status_code == 200 and ["add", PUB, "3600"] in blk.fake.calls


@pytest.mark.parametrize("case", ["forged", "other_ip", "expired", "no_sig", "bad_exp"])
def test_approve_rejects_bad_links(blk, node_client, case):
    exp, sig = _approval()
    url = {
        "forged": f"/api/blocks/approve?ip={PUB}&exp={exp}&sig={'0' * 64}",
        "other_ip": f"/api/blocks/approve?ip=1.1.1.1&exp={exp}&sig={sig}",
        "expired": "/api/blocks/approve?ip={}&exp={}&sig={}".format(
            PUB, *_approval(offset=-5)[0:1], _approval(offset=-5)[1]
        ),
        "no_sig": f"/api/blocks/approve?ip={PUB}&exp={exp}",
        "bad_exp": f"/api/blocks/approve?ip={PUB}&exp=abc&sig={sig}",
    }[case]
    assert node_client.post(url).status_code in (400, 403)
    assert blk.fake.calls == []


def test_approve_cannot_block_lan_even_when_signed(blk, node_client):
    exp, sig = _approval(ip=LAN)
    r = node_client.post(f"/api/blocks/approve?ip={LAN}&exp={exp}&sig={sig}")
    assert r.status_code == 400 and blk.fake.calls == []


def test_approve_is_post_only(blk, node_client):
    exp, sig = _approval()
    assert (
        node_client.get(f"/api/blocks/approve?ip={PUB}&exp={exp}&sig={sig}").status_code
        == 405
    )

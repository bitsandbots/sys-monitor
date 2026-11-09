"""Security webhook payload detail + re-alert on new findings."""
import sys_monitor_hub as hub


def _setup(monkeypatch):
    hub.HUB_CONFIG["alert_webhook_url"] = "http://example.invalid/hook"
    nid, _ = hub._add_node("10.0.0.5", 8585, label="HARNESS_n")
    hub._nodes[nid]["_alert_state"]["online"] = True
    sent = []
    monkeypatch.setattr(hub, "_send_webhook", lambda event, node, msg, detail=None: sent.append((event, detail)))
    return nid, sent


def F(detail, sev="high"):
    return {"category": "live.suspicious_port", "severity": sev, "description": "d", "detail": detail, "ts": "x"}


def sec(*findings):
    return {"actionable_count": len(findings), "actionable_findings": list(findings)}


def test_first_alert_carries_finding_detail(monkeypatch):
    nid, sent = _setup(monkeypatch)
    hub._check_alerts(nid, True, security=sec(F("pid 1 → 8.8.8.8:4444")))
    event, detail = sent[0]
    assert event == "security_alert"
    assert detail["findings"] == [
        {"category": "live.suspicious_port", "severity": "high", "description": "d", "detail": "pid 1 → 8.8.8.8:4444"}
    ]


def test_same_findings_do_not_realert(monkeypatch):
    nid, sent = _setup(monkeypatch)
    hub._check_alerts(nid, True, security=sec(F("a")))
    hub._check_alerts(nid, True, security=sec(F("a")))
    assert len(sent) == 1


def test_new_finding_while_alerting_realerts_with_only_the_new_one(monkeypatch):
    nid, sent = _setup(monkeypatch)
    hub._check_alerts(nid, True, security=sec(F("a")))
    hub._check_alerts(nid, True, security=sec(F("a"), F("b")))
    assert [e for e, _ in sent] == ["security_alert", "security_alert"]
    assert [f["detail"] for f in sent[1][1]["findings"]] == ["b"]


def test_recovery_fires_once_then_new_alert_works_again(monkeypatch):
    nid, sent = _setup(monkeypatch)
    hub._check_alerts(nid, True, security=sec(F("a")))
    hub._check_alerts(nid, True, security=sec())
    hub._check_alerts(nid, True, security=sec())
    hub._check_alerts(nid, True, security=sec(F("a")))
    assert [e for e, _ in sent] == ["security_alert", "security_recovered", "security_alert"]


def test_count_without_finding_list_still_alerts_once(monkeypatch):
    """Older nodes don't send actionable_findings."""
    nid, sent = _setup(monkeypatch)
    for _ in range(2):
        hub._check_alerts(nid, True, security={"actionable_count": 2})
    assert len(sent) == 1 and sent[0][1]["findings"] == []

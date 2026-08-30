"""kill_process, control_service, system_power -- the three
highest-blast-radius endpoints in the node agent. Unlike the rest of this
module, they don't go through the _run()/_read_file() seams: they call
os.kill() / subprocess.run() directly. Every test here mocks those two
callables explicitly so a bug in this file can never actually kill a
process, restart a service, or reboot the host it runs on. See the
"never hit destructive routes unmocked" lesson this suite follows.
"""
import subprocess

import sys_monitor


class FakeCompleted:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _no_real_kill(monkeypatch):
    def fail(*a, **k):
        raise AssertionError("os.kill must be mocked in this test")

    monkeypatch.setattr(sys_monitor.os, "kill", fail)


def _no_real_run(monkeypatch):
    def fail(*a, **k):
        raise AssertionError("subprocess.run must be mocked in this test")

    monkeypatch.setattr(sys_monitor.subprocess, "run", fail)


# ── kill_process() ──────────────────────────────────────────────────────


def test_kill_process_refuses_pid_1(monkeypatch):
    _no_real_kill(monkeypatch)
    result = sys_monitor.kill_process(1)
    assert result == {"success": False, "error": "Refusing to signal PID <= 1"}


def test_kill_process_refuses_disallowed_signal(monkeypatch):
    _no_real_kill(monkeypatch)
    result = sys_monitor.kill_process(1234, sig=1)
    assert result["success"] is False
    assert "not allowed" in result["error"]


def test_kill_process_success(monkeypatch):
    calls = []
    monkeypatch.setattr(sys_monitor.os, "kill", lambda pid, sig: calls.append((pid, sig)))
    result = sys_monitor.kill_process(1234, sig=15)
    assert result == {"success": True, "pid": 1234, "signal": 15}
    assert calls == [(1234, 15)]


def test_kill_process_not_found(monkeypatch):
    def raise_lookup(pid, sig):
        raise ProcessLookupError

    monkeypatch.setattr(sys_monitor.os, "kill", raise_lookup)
    result = sys_monitor.kill_process(99999)
    assert result["success"] is False
    assert "not found" in result["error"]


def test_kill_process_permission_denied_falls_back_to_sudo(monkeypatch):
    def raise_permission(pid, sig):
        raise PermissionError

    monkeypatch.setattr(sys_monitor.os, "kill", raise_permission)
    monkeypatch.setattr(
        sys_monitor.subprocess, "run",
        lambda cmd, **k: FakeCompleted(returncode=0) if cmd[:2] == ["sudo", "kill"] else (_ for _ in ()).throw(AssertionError(cmd)),
    )
    result = sys_monitor.kill_process(1234, sig=9)
    assert result == {"success": True, "pid": 1234, "signal": 9, "stderr": ""}


def test_kill_process_permission_denied_sudo_fails(monkeypatch):
    monkeypatch.setattr(sys_monitor.os, "kill", lambda pid, sig: (_ for _ in ()).throw(PermissionError))
    monkeypatch.setattr(
        sys_monitor.subprocess, "run",
        lambda cmd, **k: FakeCompleted(returncode=1, stderr="not permitted"),
    )
    result = sys_monitor.kill_process(1234)
    assert result["success"] is False
    assert result["stderr"] == "not permitted"


# ── control_service() ───────────────────────────────────────────────────


def test_control_service_rejects_unwhitelisted_service(monkeypatch):
    _no_real_run(monkeypatch)
    sys_monitor.CONFIG["services"] = ["nginx"]
    result = sys_monitor.control_service("evil-unit", "restart")
    assert result["success"] is False
    assert "not in allowed list" in result["error"]


def test_control_service_rejects_invalid_action(monkeypatch):
    _no_real_run(monkeypatch)
    sys_monitor.CONFIG["services"] = ["nginx"]
    result = sys_monitor.control_service("nginx", "erase-disk")
    assert result["success"] is False
    assert "Invalid action" in result["error"]


def test_control_service_success(monkeypatch):
    sys_monitor.CONFIG["services"] = ["nginx"]
    calls = []

    def fake_run(cmd, **k):
        calls.append(cmd)
        return FakeCompleted(returncode=0)

    monkeypatch.setattr(sys_monitor.subprocess, "run", fake_run)
    result = sys_monitor.control_service("nginx", "restart")
    assert result == {"success": True, "service": "nginx", "action": "restart", "stderr": ""}
    assert calls == [["sudo", "systemctl", "restart", "nginx"]]


def test_control_service_systemctl_failure(monkeypatch):
    sys_monitor.CONFIG["services"] = ["nginx"]
    monkeypatch.setattr(
        sys_monitor.subprocess, "run",
        lambda cmd, **k: FakeCompleted(returncode=1, stderr="Unit not found"),
    )
    result = sys_monitor.control_service("nginx", "stop")
    assert result["success"] is False
    assert result["stderr"] == "Unit not found"


def test_control_service_timeout(monkeypatch):
    sys_monitor.CONFIG["services"] = ["nginx"]

    def raise_timeout(cmd, **k):
        raise subprocess.TimeoutExpired(cmd, 30)

    monkeypatch.setattr(sys_monitor.subprocess, "run", raise_timeout)
    result = sys_monitor.control_service("nginx", "restart")
    assert result["success"] is False
    assert "Timeout" in result["error"]


# ── system_power() ──────────────────────────────────────────────────────


def test_system_power_rejects_invalid_action(monkeypatch):
    _no_real_run(monkeypatch)
    result = sys_monitor.system_power("erase-disk")
    assert result == {"success": False, "error": "Invalid power action"}


def test_system_power_reboot_success(monkeypatch):
    calls = []

    def fake_run(cmd, **k):
        calls.append(cmd)
        return FakeCompleted(returncode=0)

    monkeypatch.setattr(sys_monitor.subprocess, "run", fake_run)
    result = sys_monitor.system_power("reboot")
    assert result == {"success": True, "action": "reboot", "stderr": ""}
    assert calls == [["sudo", "reboot"]]


def test_system_power_reports_failure_not_false_success(monkeypatch):
    """Regression guard for the 2026-08-25 fix: a failed sudo command
    must not be reported as a successful reboot/shutdown."""
    monkeypatch.setattr(
        sys_monitor.subprocess, "run",
        lambda cmd, **k: FakeCompleted(returncode=1, stderr="sudo: a password is required"),
    )
    result = sys_monitor.system_power("shutdown")
    assert result["success"] is False
    assert result["stderr"] == "sudo: a password is required"


def test_system_power_timeout(monkeypatch):
    def raise_timeout(cmd, **k):
        raise subprocess.TimeoutExpired(cmd, 10)

    monkeypatch.setattr(sys_monitor.subprocess, "run", raise_timeout)
    result = sys_monitor.system_power("reboot")
    assert result["success"] is False
    assert "Timeout" in result["error"]


# ── Routes ───────────────────────────────────────────────────────────────


def test_route_kill_process_success(node_client, monkeypatch):
    monkeypatch.setattr(sys_monitor, "kill_process", lambda pid, sig: {"success": True, "pid": pid, "signal": sig})
    resp = node_client.delete("/api/processes/1234?signal=15")
    assert resp.status_code == 200
    assert resp.get_json()["success"] is True


def test_route_kill_process_failure_returns_400(node_client, monkeypatch):
    monkeypatch.setattr(sys_monitor, "kill_process", lambda pid, sig: {"success": False, "error": "not found"})
    resp = node_client.delete("/api/processes/1234")
    assert resp.status_code == 400


def test_route_service_control_rejects_unwhitelisted(node_client, monkeypatch):
    _no_real_run(monkeypatch)
    sys_monitor.CONFIG["services"] = []
    resp = node_client.post("/api/services/evil-unit/restart")
    assert resp.status_code == 400
    assert resp.get_json()["success"] is False


def test_route_service_control_success(node_client, monkeypatch):
    sys_monitor.CONFIG["services"] = ["nginx"]
    monkeypatch.setattr(sys_monitor.subprocess, "run", lambda cmd, **k: FakeCompleted(returncode=0))
    resp = node_client.post("/api/services/nginx/restart")
    assert resp.status_code == 200
    assert resp.get_json()["success"] is True


def test_route_power_rejects_unknown_action(node_client, monkeypatch):
    _no_real_run(monkeypatch)
    resp = node_client.post("/api/power/erase-disk")
    assert resp.status_code == 400


def test_route_power_success(node_client, monkeypatch):
    monkeypatch.setattr(sys_monitor.subprocess, "run", lambda cmd, **k: FakeCompleted(returncode=0))
    resp = node_client.post("/api/power/reboot")
    assert resp.status_code == 200
    assert resp.get_json()["success"] is True


def test_route_power_surfaces_false_success_fix(node_client, monkeypatch):
    """Route-level regression guard mirroring the unit-level one above."""
    monkeypatch.setattr(
        sys_monitor.subprocess, "run",
        lambda cmd, **k: FakeCompleted(returncode=1, stderr="sudo: a password is required"),
    )
    resp = node_client.post("/api/power/shutdown")
    assert resp.get_json()["success"] is False

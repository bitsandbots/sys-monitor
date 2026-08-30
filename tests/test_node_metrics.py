"""Unit tests for node-agent metric functions that had zero coverage:
get_storage, get_network, get_top_processes, get_services,
get_open_ports, get_services_with_ports, get_critical_services_status,
get_system_stability, get_power_status, get_temperature_status,
get_cpu_temperature, get_system_errors, log_event/get_log.

Uses the same proc_files/run_stub seams as test_proc_parsing.py.
"""
import sys_monitor


# ── get_cpu_temperature / get_temperature_status ────────────────────────


def test_get_cpu_temperature_parses_value(monkeypatch):
    monkeypatch.setattr(sys_monitor, "_read_file", lambda path, default="": "45123" if "thermal_zone0" in path else default)
    assert sys_monitor.get_cpu_temperature() == 45.1


def test_get_cpu_temperature_missing_file_returns_zero(monkeypatch):
    monkeypatch.setattr(sys_monitor, "_read_file", lambda path, default="": default)
    assert sys_monitor.get_cpu_temperature() == 0.0


def test_temperature_status_normal(monkeypatch):
    monkeypatch.setattr(sys_monitor, "get_cpu_temperature", lambda: 50.0)
    monkeypatch.setattr(sys_monitor, "_run", lambda cmd, timeout=5: "")
    status = sys_monitor.get_temperature_status()
    assert status["level"] == "normal"
    assert status["throttled_status"] is None


def test_temperature_status_throttling_with_vcgencmd(monkeypatch):
    monkeypatch.setattr(sys_monitor, "get_cpu_temperature", lambda: 90.0)
    monkeypatch.setattr(sys_monitor, "_run", lambda cmd, timeout=5: "throttled=0x50005")
    status = sys_monitor.get_temperature_status()
    assert status["level"] == "throttling"
    assert status["throttled_status"]["undervoltage_now"] is True


# ── get_power_status ─────────────────────────────────────────────────────


def test_power_status_unavailable_on_non_pi(run_stub):
    run_stub({})  # vcgencmd not found -> _run returns ""
    status = sys_monitor.get_power_status()
    assert status == {
        "available": False,
        "undervoltage_occurred": False,
        "frequency_capped_occurred": False,
        "throttled_now": False,
    }


def test_power_status_available_on_pi(run_stub):
    run_stub({"vcgencmd get_throttled": "throttled=0x1"})
    status = sys_monitor.get_power_status()
    assert status["available"] is True
    assert status["undervoltage_occurred"] is True
    assert status["throttled_now"] is False


# ── get_critical_services_status / get_system_stability ────────────────


def test_critical_services_all_active(run_stub):
    run_stub({"is-active": "active"})
    assert sys_monitor.get_critical_services_status() == []


def test_critical_services_reports_failed(monkeypatch):
    def fake_run(cmd, timeout=5):
        if "cron" in cmd:
            return "failed"
        return "active"

    monkeypatch.setattr(sys_monitor, "_run", fake_run)
    failed = sys_monitor.get_critical_services_status()
    assert {"name": "cron", "state": "failed", "critical": True} in failed


def test_system_stability_detects_oom(run_stub):
    run_stub({"out of memory": "kernel: Out of memory: Killed process 123"})
    result = sys_monitor.get_system_stability()
    assert result["stable"] is False
    assert result["issues"][0]["type"] == "oom"


def test_system_stability_clean(run_stub):
    run_stub({})
    result = sys_monitor.get_system_stability()
    assert result == {"stable": True, "issues": []}


def test_system_stability_detects_restart_loop(monkeypatch):
    def fake_run(cmd, timeout=5):
        if "restart job" in cmd:
            return "12"
        return ""

    monkeypatch.setattr(sys_monitor, "_run", fake_run)
    result = sys_monitor.get_system_stability()
    assert result["stable"] is False
    assert result["issues"][0]["type"] == "restart_loop"


# ── get_storage ──────────────────────────────────────────────────────────


def test_get_storage_parses_df_output(run_stub):
    df_output = (
        "Source Target Size Used Avail Use% Fstype\n"
        "/dev/sda1 / 100000M 40000M 60000M 40% ext4\n"
    )
    run_stub({"df -BM": df_output})
    devices = sys_monitor.get_storage()
    assert devices == [
        {
            "device": "/dev/sda1",
            "mount": "/",
            "total_mb": 100000,
            "used_mb": 40000,
            "avail_mb": 60000,
            "percent": 40,
            "fstype": "ext4",
        }
    ]


def test_get_storage_excludes_snap_mounts(run_stub):
    df_output = (
        "Source Target Size Used Avail Use% Fstype\n"
        "/dev/loop0 /snap/core/1 100M 50M 50M 50% squashfs\n"
    )
    run_stub({"df -BM": df_output})
    assert sys_monitor.get_storage() == []


# ── get_network ───────────────────────────────────────────────────────────


def test_get_network_no_sys_class_net(monkeypatch, tmp_path):
    monkeypatch.setattr(sys_monitor, "Path", lambda p: tmp_path / "does-not-exist")
    assert sys_monitor.get_network() == {"interfaces": [], "rates": {}}


def test_get_network_reports_interfaces(monkeypatch, tmp_path):
    (tmp_path / "lo").mkdir()
    (tmp_path / "eth0").mkdir()
    real_path = sys_monitor.Path

    def fake_path(p):
        return tmp_path if p == "/sys/class/net" else real_path(p)

    monkeypatch.setattr(sys_monitor, "Path", fake_path)
    monkeypatch.setattr(
        sys_monitor, "_read_file",
        lambda path, default="": {
            "/sys/class/net/eth0/operstate": "up",
            "/sys/class/net/eth0/address": "aa:bb:cc:dd:ee:ff",
            "/sys/class/net/eth0/statistics/rx_bytes": "2048",
            "/sys/class/net/eth0/statistics/tx_bytes": "1024",
        }.get(path, default),
    )
    monkeypatch.setattr(sys_monitor, "_run", lambda cmd, timeout=5: "192.168.1.50" if "eth0" in cmd else "")
    sys_monitor._net_prev.clear()
    sys_monitor._net_prev_time = 0.0

    result = sys_monitor.get_network()
    names = [i["name"] for i in result["interfaces"]]
    assert names == ["eth0"]
    assert result["interfaces"][0]["ip"] == "192.168.1.50"
    assert result["interfaces"][0]["rx_bytes"] == 2048
    assert "eth0" in result["rates"]


# ── get_top_processes ────────────────────────────────────────────────────


def test_get_top_processes_parses_ps_output(run_stub):
    ps_output = (
        "USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND\n"
        "root 42 12.5 3.2 1000 2000 ? S 10:00 0:01 /usr/bin/python3 app.py\n"
    )
    run_stub({"ps aux": ps_output})
    procs = sys_monitor.get_top_processes(limit=5)
    assert procs == [
        {"user": "root", "pid": 42, "cpu": 12.5, "mem": 3.2, "command": "/usr/bin/python3 app.py"}
    ]


# ── get_services / get_open_ports / get_services_with_ports ─────────────


def test_get_services_reports_active_and_enabled(monkeypatch, run_stub):
    sys_monitor.CONFIG["services"] = ["nginx"]
    run_stub({"is-active": "active", "is-enabled": "enabled", "show": "Web server"})
    services = sys_monitor.get_services()
    assert services == [
        {
            "name": "nginx",
            "active": True,
            "active_state": "active",
            "enabled": True,
            "enabled_state": "enabled",
            "description": "Web server",
        }
    ]


def test_get_open_ports_parses_ss_output(run_stub):
    ss_output = "Netid State Recv-Q Send-Q Local-Address:Port Peer-Address:Port\ntcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"
    run_stub({"ss -tuln": ss_output})
    assert sys_monitor.get_open_ports() == [{"port": 22, "protocol": "tcp", "address": "0.0.0.0"}]


def test_get_open_ports_excludes_ephemeral_range(run_stub):
    ss_output = "Netid State Recv-Q Send-Q Local-Address:Port Peer-Address:Port\ntcp LISTEN 0 128 0.0.0.0:60000 0.0.0.0:*\n"
    run_stub({"ss -tuln": ss_output})
    assert sys_monitor.get_open_ports() == []


def test_get_services_with_ports_matches_known_service(monkeypatch):
    monkeypatch.setattr(sys_monitor, "get_services", lambda: [{"name": "nginx", "active": True}])
    monkeypatch.setattr(sys_monitor, "get_open_ports", lambda: [{"port": 80, "protocol": "tcp", "address": "*"}])
    result = sys_monitor.get_services_with_ports()
    matched = [r for r in result if r.get("name") == "nginx"]
    assert matched and matched[0]["known"] is True and matched[0]["port"] == 80


# ── get_system_errors ─────────────────────────────────────────────────────


def test_get_system_errors_parses_json_lines(run_stub):
    import json as _json

    line = _json.dumps(
        {
            "__REALTIME_TIMESTAMP": "1700000000000000",
            "_SYSTEMD_UNIT": "nginx.service",
            "MESSAGE": "worker process exited",
            "PRIORITY": "3",
        }
    )
    run_stub({"journalctl -p err": line})
    errors = sys_monitor.get_system_errors(limit=10)
    assert errors[0]["unit"] == "nginx.service"
    assert errors[0]["msg"] == "worker process exited"


def test_get_system_errors_empty_output(run_stub):
    run_stub({})
    assert sys_monitor.get_system_errors() == []


# ── log_event / get_log ───────────────────────────────────────────────────


def test_log_event_and_get_log_round_trip():
    sys_monitor._event_log.clear()
    sys_monitor.log_event("something happened", "warning")
    entries = sys_monitor.get_log(limit=10)
    assert entries[-1]["msg"] == "something happened"
    assert entries[-1]["level"] == "warning"


def test_log_event_caps_at_log_max():
    sys_monitor._event_log.clear()
    for i in range(sys_monitor.LOG_MAX + 10):
        sys_monitor.log_event(f"event {i}")
    assert len(sys_monitor._event_log) == sys_monitor.LOG_MAX
    assert sys_monitor._event_log[-1]["msg"] == f"event {sys_monitor.LOG_MAX + 9}"

"""Tests for the SQLite metrics history."""
import sqlite3

import pytest

import sys_monitor


@pytest.fixture(autouse=True)
def history_db(tmp_path):
    prev = sys_monitor.CONFIG["history_db"]
    sys_monitor.CONFIG["history_db"] = str(tmp_path / "HARNESS_metrics.db")
    sys_monitor.CONFIG["history_days"] = 7
    yield
    sys_monitor.CONFIG["history_db"] = prev


def test_record_and_query_roundtrip():
    sys_monitor._history_record({"cpu_percent": 10.0, "mem_percent": 40.0}, now=1000)
    sys_monitor._history_record({"cpu_percent": 30.0}, now=1060)
    out = sys_monitor.get_history("cpu_percent", "1h", now=1100)
    assert out["metric"] == "cpu_percent"
    assert sorted(sys_monitor.get_history_metrics()) == ["cpu_percent", "mem_percent"]
    # 1h range -> 7s buckets, so the two samples stay separate
    assert [p[1] for p in out["points"]] == [10.0, 30.0]


def test_downsampling_averages_within_bucket():
    # 7d range -> bucket 1209s; two samples inside one bucket average
    sys_monitor._history_record({"x": 10.0}, now=1_000_000)
    sys_monitor._history_record({"x": 20.0}, now=1_000_060)
    pts = sys_monitor.get_history("x", "7d", now=1_000_100)["points"]
    assert len(pts) == 1 and pts[0][1] == 15.0


def test_range_filters_old_samples():
    sys_monitor._history_record({"x": 1.0}, now=1000)
    sys_monitor._history_record({"x": 2.0}, now=10_000)
    pts = sys_monitor.get_history("x", "1h", now=10_100)["points"]
    assert [p[1] for p in pts] == [2.0]


def test_prune_removes_only_old_rows():
    sys_monitor._history_record({"x": 1.0}, now=1000)
    sys_monitor._history_record({"x": 2.0}, now=1_000_000)
    assert sys_monitor._history_prune(now=1_000_000) == 1
    conn = sqlite3.connect(sys_monitor.CONFIG["history_db"])
    assert conn.execute("SELECT COUNT(*) FROM samples").fetchone()[0] == 1


def test_metric_name_is_parameterized():
    sys_monitor._history_record({"x": 1.0}, now=1000)
    evil = "x' OR '1'='1"
    assert sys_monitor.get_history(evil, "1h", now=1100)["points"] == []
    assert len(sys_monitor.get_history_metrics()) == 1  # table intact


def test_bad_range_raises():
    with pytest.raises(ValueError):
        sys_monitor.get_history("x", "30d")


def test_collect_sample_degrades_without_gpu(monkeypatch, run_stub):
    run_stub({})
    s = sys_monitor._collect_history_sample()
    assert "cpu_percent" in s and "mem_percent" in s
    assert not any(k.startswith("gpu_") for k in s)


def test_collect_sample_includes_gpu(monkeypatch):
    monkeypatch.setattr(
        sys_monitor, "get_gpu",
        lambda: {"available": True, "processes": [], "gpus": [
            {"index": 0, "util_percent": 5.0, "mem_percent": 50.0, "temp_c": None, "power_w": 7.0}]},
    )
    s = sys_monitor._collect_history_sample()
    assert s["gpu_util_percent:0"] == 5.0
    assert "gpu_temp_c:0" not in s


def test_history_routes(node_client):
    sys_monitor._history_record({"cpu_percent": 12.0})
    assert node_client.get("/api/history").get_json()["metrics"] == ["cpu_percent"]
    d = node_client.get("/api/history?metric=cpu_percent&range=1h").get_json()
    assert d["enabled"] and d["points"][0][1] == 12.0
    assert node_client.get("/api/history?metric=x&range=bogus").status_code == 400


def test_history_route_disabled(node_client):
    sys_monitor.CONFIG["history_db"] = ""
    assert node_client.get("/api/history").get_json() == {"enabled": False, "points": []}


def test_start_history_disabled_without_path():
    sys_monitor.CONFIG["history_db"] = ""
    assert sys_monitor.start_history() is False

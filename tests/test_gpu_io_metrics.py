"""Tests for GPU (nvidia-smi), disk I/O and NIC error metrics."""
import sys_monitor

SMI_GPU = "0, NVIDIA GeForce RTX 5070, 12, 6978, 12227, 30, 5.18, 250.00"
SMI_APPS = (
    "GPU-abc, 111, /usr/bin/small, 100\n"
    "GPU-abc, 3735779, /usr/local/lib/ollama/llama-server, 6936"
)


def test_get_gpu_parses_gpu_and_sorts_processes(run_stub):
    run_stub({"--query-gpu": SMI_GPU, "--query-compute-apps": SMI_APPS})
    g = sys_monitor.get_gpu()
    assert g["available"] is True
    gpu = g["gpus"][0]
    assert gpu["name"] == "NVIDIA GeForce RTX 5070"
    assert gpu["util_percent"] == 12.0
    assert gpu["mem_used_mb"] == 6978.0
    assert gpu["mem_percent"] == 57.1
    assert gpu["power_limit_w"] == 250.0
    assert [p["pid"] for p in g["processes"]] == [3735779, 111]


def test_get_gpu_unavailable_when_nvidia_smi_missing(run_stub):
    run_stub({})
    assert sys_monitor.get_gpu() == {"available": False, "gpus": [], "processes": []}


def test_get_gpu_handles_na_fields(run_stub):
    run_stub({"--query-gpu": "0, GPU X, [N/A], [N/A], 8000, [N/A], [N/A], [N/A]"})
    gpu = sys_monitor.get_gpu()["gpus"][0]
    assert gpu["util_percent"] is None
    assert gpu["mem_percent"] is None
    assert gpu["temp_c"] is None


def test_parse_diskstats_skips_partitions_and_virtual(proc_files):
    from tests.conftest import FIXTURES_DIR

    text = (FIXTURES_DIR / "diskstats_nvme_sata.txt").read_text()
    assert set(sys_monitor._parse_diskstats(text)) == {"nvme0n1", "sda"}


def test_get_disk_io_computes_rates(monkeypatch):
    sys_monitor._disk_prev.clear()
    sys_monitor._disk_prev_time = 0.0
    snaps = iter(
        [
            " 259 0 nvme0n1 100 0 1000 0 200 0 2000 0 0 0 0 0 0 0 0",
            " 259 0 nvme0n1 200 0 3000 0 300 0 6000 0 0 500 0 0 0 0 0",
        ]
    )
    monkeypatch.setattr(sys_monitor, "_read_file", lambda p, d="": next(snaps))
    clock = iter([100.0, 102.0])
    monkeypatch.setattr(sys_monitor.time, "time", lambda: next(clock))

    first = sys_monitor.get_disk_io()["disks"]["nvme0n1"]
    assert first["read_bps"] == 0
    d = sys_monitor.get_disk_io()["disks"]["nvme0n1"]
    assert d["read_bps"] == 2000 * 512 // 2
    assert d["write_bps"] == 4000 * 512 // 2
    assert d["read_iops"] == 50.0
    assert d["busy_percent"] == 25.0


def test_gpu_and_diskio_routes(node_client, run_stub, monkeypatch):
    run_stub({"--query-gpu": SMI_GPU})
    monkeypatch.setattr(sys_monitor, "_read_file", lambda p, d="": d)
    assert node_client.get("/api/gpu").get_json()["available"] is True
    assert node_client.get("/api/diskio").get_json() == {"disks": {}}

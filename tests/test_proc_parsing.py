"""Unit tests for /proc parsing and hardware detection.

Covers gap-analysis items 1 (CPU/memory/uptime parsing) and 8
(Pi vs. generic-PC /proc fixtures) -- see TESTING_STRATEGY.md.
"""
import sys_monitor


def test_get_cpu_usage_differential_sampling(proc_files):
    """First call always returns 0.0 (no previous sample yet). Second
    call, against a later /proc/stat snapshot, computes the real delta."""
    proc_files({"/proc/stat": "common/stat_sample1.txt", "/proc/loadavg": "common/loadavg.txt"})
    first = sys_monitor.get_cpu_usage()
    assert first["usage"] == 0.0
    assert first["cores"] == [0.0, 0.0]

    proc_files({"/proc/stat": "common/stat_sample2.txt", "/proc/loadavg": "common/loadavg.txt"})
    second = sys_monitor.get_cpu_usage()

    # sample1 -> sample2: total delta 1000, idle delta 600 => 40.0% used
    assert second["usage"] == 40.0
    assert second["cores"] == [40.0, 40.0]
    assert second["core_count"] == 2
    assert second["load_avg"] == [0.5, 0.3, 0.1]


def test_get_cpu_usage_ignores_non_cpu_lines(proc_files):
    """intr/ctxt/btime/processes lines in /proc/stat must not be mistaken
    for CPU lines (they don't start with 'cpu')."""
    proc_files({"/proc/stat": "common/stat_sample1.txt", "/proc/loadavg": "common/loadavg.txt"})
    parsed = sys_monitor._parse_proc_stat()
    assert set(parsed.keys()) == {"cpu", "cpu0", "cpu1"}


def test_get_memory_parses_meminfo(proc_files):
    proc_files({"/proc/meminfo": "common/meminfo.txt"})
    mem = sys_monitor.get_memory()

    assert mem["total_mb"] == 10240.0
    assert mem["free_mb"] == 2048.0
    assert mem["available_mb"] == 6144.0
    assert mem["buffers_mb"] == 1024.0
    assert mem["cached_mb"] == 2048.0
    assert mem["swap_total_mb"] == 2048.0
    assert mem["swap_used_mb"] == 1024.0
    # used = total - free - buffers - cached = 5120.0 MB; percent = 50.0
    assert mem["used_mb"] == 5120.0
    assert mem["percent"] == 50.0


def test_get_uptime_parses_and_formats(proc_files):
    proc_files({"/proc/uptime": "common/uptime.txt"})
    up = sys_monitor.get_uptime()

    assert up["seconds"] == 93784
    assert up["days"] == 1
    assert up["hours"] == 2
    assert up["minutes"] == 3
    assert up["formatted"] == "1d 2h 3m"


def test_get_uptime_missing_file_returns_unknown(proc_files):
    proc_files({})  # /proc/uptime unmapped -> _read_file returns default ""
    up = sys_monitor.get_uptime()
    assert up == {"seconds": 0, "formatted": "unknown", "days": 0, "hours": 0, "minutes": 0}


def test_detect_system_generic_pc(proc_files, run_stub):
    """No device-tree model, no Pi-style cpuinfo fields -> falls back to
    DMI identity and is_raspberry_pi is False, per CLAUDE.md's stated
    invariant that Pi-only fields degrade to None/empty on generic Linux."""
    proc_files(
        {
            "/proc/cpuinfo": "generic-pc/cpuinfo.txt",
            "/sys/devices/virtual/dmi/id/sys_vendor": "generic-pc/dmi_sys_vendor.txt",
            "/sys/devices/virtual/dmi/id/product_name": "generic-pc/dmi_product_name.txt",
        }
    )
    run_stub({})  # uname/hostname/etc run for real (harmless, unasserted); no vcgencmd needed

    info = sys_monitor.detect_system()

    assert info["is_raspberry_pi"] is False
    assert info["platform"] == "linux"
    assert info["model"] == "Dell Inc. OptiPlex 7090"
    assert info["soc"] == ""
    assert info["gpu_mb"] is None
    assert info["cpu_model"] == "Intel(R) Core(TM) i7-10700 CPU @ 2.90GHz"
    assert info["cpu_vendor"] == "GenuineIntel"


def test_detect_system_raspberry_pi(proc_files, run_stub):
    """Real device-tree model + Pi-style cpuinfo (Hardware/Revision/Serial)
    -> is_raspberry_pi True, SoC decoded from the revision code, GPU split
    read via vcgencmd (item 8's Pi branch)."""
    proc_files(
        {
            "/proc/device-tree/model": "raspberry-pi-5/device_tree_model.txt",
            "/proc/cpuinfo": "raspberry-pi-5/cpuinfo.txt",
        }
    )
    # _run() is stubbed at the whole-command level, so this is the value
    # after the real command's own `| grep -oP '\d+'` would already have
    # extracted it -- not raw vcgencmd output ("gpu=76M").
    run_stub({"vcgencmd get_mem gpu": "76"})

    info = sys_monitor.detect_system()

    assert info["is_raspberry_pi"] is True
    assert info["platform"] == "raspberry_pi"
    assert info["model"] == "Raspberry Pi 5 Model B Rev 1.1"
    assert info["revision"] == "d04171"
    assert info["soc"] == "BCM2712"
    assert info["gpu_mb"] == 76
    # Serial is truncated to the last 8 chars in _BOOT_INFO -- never the
    # full identifier -- and this fixture's serial is a placeholder, not a
    # real device's.
    assert info["serial"] == "12345678"

"""Service units and the opt-in non-root installer.

Neither can be started here (no root, no systemd), so this pins the properties
that matter: the hub runs unprivileged and hardened, and the generated sudoers
is exact-match and never grants a bare `systemctl`.
"""

import configparser
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
INSTALLER = ROOT / "contrib" / "install-nonroot.sh"


def _unit(path: Path) -> dict:
    """Parse a unit into {key: [values]} (keys repeat, e.g. Environment=)."""
    cp = configparser.RawConfigParser(strict=False, delimiters=("=",))
    cp.optionxform = str
    out: dict = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("["):
            continue
        key, _, val = line.partition("=")
        out.setdefault(key, []).append(val)
    return out


def _sudoers(*services: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(INSTALLER), "--print-sudoers", *services],
        capture_output=True,
        text=True,
        timeout=20,
    )


# ── hub unit ────────────────────────────────────────────────────────────


def test_hub_unit_is_unprivileged_and_hardened():
    u = _unit(ROOT / "hub" / "sys-monitor-hub.service")
    assert u["User"] != ["root"] and u["User"] == ["sys-monitor-hub"]
    assert u["NoNewPrivileges"] == ["true"]
    assert u["ProtectSystem"] == ["strict"]
    assert u["StateDirectory"] == ["sys-monitor-hub"]
    assert "SYSHUB_NODES_FILE=/var/lib/sys-monitor-hub/hub_nodes.json" in u["Environment"]


def test_install_script_creates_hub_user_and_migrates_registry():
    text = (ROOT / "install.sh").read_text()
    assert 'HUB_USER="sys-monitor-hub"' in text
    assert "useradd --system" in text
    assert "hub_nodes.json" in text and "-m 0600" in text


# ── non-root drop-in ────────────────────────────────────────────────────


def test_nonroot_dropin_confines_writes_to_the_state_dir():
    u = _unit(ROOT / "contrib" / "sys-monitor-nonroot.conf")
    assert u["User"] != ["root"]
    assert u["NoNewPrivileges"] == ["false"]  # sudo needs setuid
    assert "" in u["ReadWritePaths"]  # resets the base unit's /opt/sys-monitor
    env = " ".join(u["Environment"])
    for name in ("SYSMONITOR_SERVICES_FILE", "HIDDENSCOPE_ALLOWLIST_FILE", "HIDDENSCOPE_BASELINE_FILE"):
        assert f"{name}=/var/lib/sys-monitor/" in env


# ── generated sudoers ───────────────────────────────────────────────────


def test_sudoers_is_one_exact_line_per_action_and_service():
    r = _sudoers("ssh", "nginx")
    assert r.returncode == 0, r.stderr
    lines = [ln.split("NOPASSWD: ")[1] for ln in r.stdout.splitlines() if "NOPASSWD" in ln]
    sysctl = [ln for ln in lines if ln.split()[0].endswith("/systemctl")]
    assert len(sysctl) == 2 * 5
    for ln in sysctl:
        assert len(ln.split()) == 3  # <path> <action> <service>
        assert "*" not in ln
    assert sum("*" in ln for ln in lines) == 2  # only kill -9/-15 <pid>
    assert any(ln.endswith("shutdown -h now") for ln in lines)


def test_sudoers_never_grants_a_command_with_open_arguments():
    """reboot/shutdown are symlinks to systemctl on systemd hosts and sudo
    matches by file identity, so a bare path would allow any systemctl command."""
    r = _sudoers("ssh")
    cmds = [ln.split("NOPASSWD: ")[1] for ln in r.stdout.splitlines() if "NOPASSWD" in ln]
    for c in cmds:
        parts = c.split(None, 1)
        assert len(parts) == 2, f"bare command grants every argument: {c!r}"
    assert any(c.endswith('/reboot ""') for c in cmds)


@pytest.mark.parametrize("bad", ["x; id", "a b", "$(id)", "../x", "a,b", ""])
def test_sudoers_rejects_hostile_service_names(bad):
    r = _sudoers("ssh", bad)
    assert r.returncode != 0
    assert "invalid service name" in r.stderr


def test_sudoers_escapes_special_characters():
    r = _sudoers("svc:one")
    assert r.returncode == 0, r.stderr
    assert "systemctl start svc\\:one" in r.stdout


@pytest.mark.skipif(shutil.which("visudo") is None, reason="visudo not installed")
def test_generated_sudoers_passes_visudo(tmp_path):
    f = tmp_path / "HARNESS_sudoers"
    f.write_text(_sudoers("ssh", "svc:one", "getty@tty1.service").stdout)
    r = subprocess.run(["visudo", "-cf", str(f)], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr

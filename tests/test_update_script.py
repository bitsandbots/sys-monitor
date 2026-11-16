"""update.sh runs as root and executes a downloaded installer, so its trust
decisions are tested with a stub ``curl`` on PATH (no network, no root: --check
stops before anything is installed)."""

import json
import os
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
SCRIPT = ROOT / "update.sh"


def _run(tmp_path: Path, release: dict, *flags: str) -> subprocess.CompletedProcess:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    payload = tmp_path / "HARNESS_release.json"
    payload.write_text(json.dumps(release))
    curl = bindir / "curl"
    curl.write_text(f'#!/bin/sh\ncat "{payload}"\n')
    curl.chmod(curl.stat().st_mode | stat.S_IXUSR)
    env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}"}
    return subprocess.run(
        ["bash", str(SCRIPT), "--check", *flags],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )


ASSET = {"name": "sys-monitor-9.9.9.tar.gz", "browser_download_url": "http://HARNESS.invalid/a.tgz"}
SHA = {"name": "sys-monitor-9.9.9.tar.gz.sha256", "browser_download_url": "http://HARNESS.invalid/a.sha"}


def test_release_without_assets_is_refused_by_default(tmp_path):
    r = _run(tmp_path, {"tag_name": "v9.9.9", "assets": []})
    assert r.returncode != 0
    assert "--no-verify" in r.stdout + r.stderr


def test_release_without_assets_needs_explicit_no_verify(tmp_path):
    r = _run(tmp_path, {"tag_name": "v9.9.9", "assets": []}, "--no-verify")
    assert r.returncode == 0, r.stdout + r.stderr


def test_release_with_verifiable_assets_passes(tmp_path):
    r = _run(tmp_path, {"tag_name": "v9.9.9", "assets": [ASSET, SHA]})
    assert r.returncode == 0, r.stdout + r.stderr


def test_work_dir_is_not_predictable():
    text = SCRIPT.read_text()
    assert "$$" not in text.split("WORK_DIR=", 1)[1].splitlines()[0]
    assert "mktemp -d" in text

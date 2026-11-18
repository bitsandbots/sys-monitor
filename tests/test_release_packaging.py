"""Every first-party module sys_monitor.py imports must ship in the release
tarball and be copied by install.sh, or the feature silently disables."""

import ast
from pathlib import Path

ROOT = Path(__file__).parent.parent


def _local_imports() -> set[str]:
    tree = ast.parse((ROOT / "sys_monitor.py").read_text())
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module.split(".")[0])
    return {n for n in names if (ROOT / f"{n}.py").is_file()}


def test_local_modules_are_detected() -> None:
    assert {"ip_block", "threat_detect"} <= _local_imports()


def test_release_and_install_ship_every_local_module() -> None:
    release = (ROOT / "release.sh").read_text()
    install = (ROOT / "install.sh").read_text()
    for mod in _local_imports():
        assert f"  {mod}.py\n" in release, f"release.sh omits {mod}.py"
        assert f"{mod}.py" in install, f"install.sh never copies {mod}.py"

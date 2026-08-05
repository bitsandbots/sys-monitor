# Release Guide

SysMonitor uses `release.sh` to manage versioning, packaging, and tagging. Run it from the repo root on your dev machine.

---

## Versioning

SysMonitor follows [Semantic Versioning](https://semver.org/):

- **PATCH** (`2.0.x`) — bug fixes, docs, non-breaking internal changes
- **MINOR** (`2.x.0`) — new features, backward-compatible
- **MAJOR** (`x.0.0`) — breaking changes to API or config

The canonical version lives in `sys_monitor.py`:

```python
VERSION = "2.0.0"
```

`release.sh` reads and writes this constant. `hub/sys_monitor_hub.py` mirrors it.

---

## Creating a Release

### Dry run first

```bash
./release.sh 2.1.0 --dry-run
```

Shows exactly what would change — no files modified, no tags created.

### Cut the release

```bash
./release.sh 2.1.0
```

This will:
1. Validate the working tree is clean
2. Bump `VERSION = "2.1.0"` in `sys_monitor.py` and `hub/sys_monitor_hub.py`
3. Commit the bump: `chore: bump version to 2.1.0`
4. Create an annotated git tag: `v2.1.0`
5. Build `dist/sys-monitor-2.1.0.tar.gz`
6. Generate `dist/sys-monitor-2.1.0.sha256`

### Package current version (no bump)

```bash
./release.sh
```

Packages whatever `VERSION` is currently in `sys_monitor.py` without bumping or tagging.

---

## Release Contents

`hiddenscope_scanner.py` (the vendored security scanner) is included in `release.sh`'s `RELEASE_FILES` array alongside `sys_monitor.py`, so every release tarball ships with security monitoring built in — no separate packaging step needed.

The tarball includes:

```
sys-monitor-2.1.0/
├── sys_monitor.py
├── hiddenscope_scanner.py
├── requirements.txt
├── templates/index.html
├── sys-monitor.service
├── install.sh
├── .env.example
├── README.md
└── hub/
    ├── sys_monitor_hub.py
    ├── requirements.txt
    ├── templates/hub.html
    ├── sys-monitor-hub.service
    └── HUB_README.md
```

---

## Publishing the Release

After `release.sh` runs:

```bash
# Push the commit and tag
git push origin main && git push origin v2.1.0
```

Then on GitHub:
1. Go to **Releases → Draft a new release**
2. Select tag `v2.1.0`
3. Upload `dist/sys-monitor-2.1.0.tar.gz`
4. Upload `dist/sys-monitor-2.1.0.sha256`
5. Publish

---

## Install from a Release

On the target system:

```bash
curl -LO https://github.com/bitsandbots/sys-monitor/releases/download/v2.1.0/sys-monitor-2.1.0.tar.gz
sha256sum -c sys-monitor-2.1.0.sha256
tar -xzf sys-monitor-2.1.0.tar.gz
cd sys-monitor-2.1.0 && sudo ./install.sh
```

---

## `dist/` is Gitignored

Built artifacts (`dist/`) are excluded from the repo by `.gitignore`. Only upload tarballs to GitHub Releases — never commit them.

#!/usr/bin/env python3
"""fleet-watchdog.py - alert when a registered node goes silent.

sys_monitor_hub.py already polls every registered node (ping, every
poll_interval seconds) and tracks online/last_seen in-memory, exposed via
GET /api/fleet. This script adds the missing piece: a periodic check that
turns "online: false" into a visible ALERT line, so a unit that powered off
but never came back (e.g. stuck at BIOS setup - see the 2026-08-09 fleet
boot incident) is caught within minutes instead of being noticed only when
someone opens the dashboard.

Earlier boot-health-watchdog.py polled a GET /api/nodes endpoint that
doesn't exist on this hub (/api/nodes is POST/PUT/DELETE only; the actual
node list is GET /api/fleet) - this replaces it with the real API.

Usage:
  python3 fleet-watchdog.py [--hub URL] [--stale SECONDS] [--once]
"""
import argparse, json, os, time, urllib.request
from datetime import datetime, timezone

DEFAULT_HUB = os.environ.get("SYSHUB_URL", "http://127.0.0.1:8686")


def fetch_json(url):
    with urllib.request.urlopen(url, timeout=10) as r:
        return json.load(r)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hub", default=DEFAULT_HUB)
    ap.add_argument("--stale", type=int, default=600,
                     help="alert if a node has been offline for >N seconds (default 600)")
    ap.add_argument("--once", action="store_true", help="single pass, no loop")
    args = ap.parse_args()

    def check():
        try:
            fleet = fetch_json(args.hub + "/api/fleet")
        except Exception as e:
            print(f"fleet-watchdog: hub unreachable at {args.hub}: {e}", flush=True)
            return

        now = time.time()
        for node in fleet.get("nodes", []):
            if node.get("online"):
                continue
            label = node.get("label") or node.get("host")
            last = node.get("last_seen")
            age = (now - last) if last else None
            if age is not None and age < args.stale:
                continue  # just went offline, within the poll jitter window
            ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            age_str = f"{age/60:.1f} min" if age is not None else "never seen"
            print(f"ALERT [{ts}] {label}: offline for {age_str} "
                  f"(stale threshold {args.stale}s) - check if stuck at BIOS/POST", flush=True)

    if args.once:
        check()
        return
    while True:
        try:
            check()
        except Exception as e:
            print("fleet-watchdog: error:", e, flush=True)
        time.sleep(min(args.stale, 60))


if __name__ == "__main__":
    main()

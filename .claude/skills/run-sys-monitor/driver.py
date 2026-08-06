#!/usr/bin/env python3
"""REPL driver for browser-testing SysMonitor (node agent + Fleet Hub).

No chromium-cli in this environment — this is the fallback: Python
Playwright driving the system Chromium binary at /usr/bin/chromium.

Reads one command per line from stdin. Screenshots land in
screenshots/ next to this file (created on first use).

Commands:
  nav <url>                        navigate, waits for networkidle
  wait-for text=<substring>        poll (up to 10s) for visible text
  wait-for sel=<css>               poll (up to 10s) for a visible selector
  screenshot [name]                full-page screenshot -> screenshots/<name>.png
  screenshot-el <css> [name]       crop to one element
  click <css>                      click a selector
  fill <css> <text...>             fill an input (goes through Playwright's
                                    input pipeline, so React/controlled
                                    inputs see the change)
  press <key>                      e.g. Enter, Escape
  eval <js>                        page.evaluate, prints the JSON result
  dom-order <parent-css>           prints id/class of each direct child,
                                    in DOM order — use this to verify card
                                    reordering instead of eyeballing a
                                    screenshot
  console-errors                   prints every console.error seen so far
  quit                             close the browser and exit

Usage:
  python3 driver.py <<'EOF'
  nav http://localhost:8599
  wait-for sel=#panel-overview
  screenshot overview
  console-errors
  quit
  EOF
"""
import json
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

SCREEN_DIR = Path(__file__).parent / "screenshots"
CHROMIUM_PATH = "/usr/bin/chromium"


def main():
    SCREEN_DIR.mkdir(exist_ok=True)
    console_errors = []

    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path=CHROMIUM_PATH, args=["--no-sandbox"])
        page = browser.new_page(viewport={"width": 1280, "height": 1600})
        page.on(
            "console",
            lambda msg: console_errors.append(msg.text) if msg.type == "error" else None,
        )

        for raw in sys.stdin:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            cmd, *rest = line.split(" ", 1)
            arg = rest[0] if rest else ""

            try:
                if cmd == "nav":
                    page.goto(arg, wait_until="networkidle", timeout=20000)
                    print(f"OK nav {arg}")

                elif cmd == "wait-for":
                    if arg.startswith("text="):
                        page.get_by_text(arg[5:]).first.wait_for(state="visible", timeout=10000)
                    elif arg.startswith("sel="):
                        page.wait_for_selector(arg[4:], state="visible", timeout=10000)
                    else:
                        print(f"ERR wait-for needs text= or sel= prefix, got: {arg}")
                        continue
                    print(f"OK wait-for {arg}")

                elif cmd == "screenshot":
                    name = arg or "screenshot"
                    out = SCREEN_DIR / f"{name}.png"
                    page.screenshot(path=str(out), full_page=True)
                    print(f"OK screenshot {out}")

                elif cmd == "screenshot-el":
                    sel, _, name = arg.partition(" ")
                    name = name or "element"
                    out = SCREEN_DIR / f"{name}.png"
                    page.locator(sel).screenshot(path=str(out))
                    print(f"OK screenshot-el {out}")

                elif cmd == "click":
                    page.click(arg, timeout=10000)
                    print(f"OK click {arg}")

                elif cmd == "fill":
                    sel, _, text = arg.partition(" ")
                    page.fill(sel, text, timeout=10000)
                    print(f"OK fill {sel}")

                elif cmd == "press":
                    page.keyboard.press(arg)
                    print(f"OK press {arg}")

                elif cmd == "eval":
                    result = page.evaluate(arg)
                    print(f"OK eval {json.dumps(result)}")

                elif cmd == "dom-order":
                    order = page.eval_on_selector_all(
                        f"{arg} > *",
                        "els => els.map(e => e.id || ('.' + e.className))",
                    )
                    print(f"OK dom-order {json.dumps(order)}")

                elif cmd == "console-errors":
                    print(f"OK console-errors {json.dumps(console_errors)}")

                elif cmd == "quit":
                    break

                else:
                    print(f"ERR unknown command: {cmd}")

            except Exception as e:
                print(f"ERR {cmd}: {e}")

        browser.close()


if __name__ == "__main__":
    main()

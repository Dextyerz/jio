#!/usr/bin/env python3
"""notify_freshlinks.py — push freshlinks to Telegram as they appear.

Tails data/notify.log (written by freshlink_daemon.py) and forwards every line
to the operator's Telegram chat through the Hermes CLI.  Lines are consumed
from a byte-offset file so a restart never re-sends old links.

Usage:
    python3 notify_freshlinks.py            # tail forever
    python3 notify_freshlinks.py --once     # drain and exit
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

DATA = Path(__file__).resolve().parent / "data"
NOTIFY = DATA / "notify.log"
OFFSET = DATA / "notify.offset"
TG_CHAT_ID = "5096026302"


def send(text: str) -> None:
    subprocess.run(
        ["hermes", "send", "-t", f"telegram:{TG_CHAT_ID}", text],
        capture_output=True, timeout=60,
    )


def drain() -> int:
    if not NOTIFY.exists():
        return 0
    off = int(OFFSET.read_text()) if OFFSET.exists() else 0
    size = NOTIFY.stat().st_size
    if size < off:  # log rotated/truncated
        off = 0
    if size == off:
        return 0
    with NOTIFY.open("r") as fh:
        fh.seek(off)
        chunk = fh.read()
        OFFSET.write_text(str(fh.tell()))
    n = 0
    for line in chunk.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
            send(rec.get("text", line))
        except ValueError:
            send(line)
        n += 1
    return n


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--interval", type=int, default=10)
    args = ap.parse_args()

    if args.once:
        print(f"sent {drain()} notification(s)")
        return
    while True:
        try:
            drain()
        except Exception:
            pass
        time.sleep(args.interval)


if __name__ == "__main__":
    main()

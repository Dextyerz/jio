#!/usr/bin/env python3
"""Scan every device on every panel and build a number -> device map.

Each panel is an SMS-forwarding app on a physical phone that may carry
several SIMs, so a single device's smsData contains messages from many
numbers.  The correct lookup is therefore: for a given number, which
device(s) have recently received an SMS addressed to it.
"""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36"
PANELS = {
    "rtx-c9": "https://rtx-c9-default-rtdb.asia-southeast1.firebasedatabase.app",
    "rtx-c11": "https://rtx-c11-default-rtdb.asia-southeast1.firebasedatabase.app",
    "rtx-c3": "https://rtx-c3-default-rtdb.firebaseio.com",
    "rtx-c13": "https://rtx-c13-default-rtdb.asia-southeast1.firebasedatabase.app",
}
DATA = Path(__file__).resolve().parent / "data"
OUT = DATA / "num2dev.json"


def get(url: str, tries: int = 4):
    for i in range(tries):
        try:
            r = requests.get(url, headers={"User-Agent": UA}, timeout=45)
            if r.status_code == 200:
                return r.json()
        except requests.RequestException:
            pass
        time.sleep(0.7 * (i + 1))
    return None


def numbers_of(payload: dict) -> dict[str, str]:
    out: dict[str, str] = {}
    for v in (payload or {}).values():
        if not isinstance(v, dict):
            continue
        info = v.get("info") or ""
        if "Number :" not in info:
            continue
        num = info.split("Number :")[-1].strip().replace("+91", "")[-10:]
        if len(num) == 10 and num.isdigit():
            t = v.get("time", "")
            if num not in out or t > out[num]:
                out[num] = t
    return out


def scan_device(panel: str, dev: str) -> list[tuple[str, str, str, str]]:
    payload = get(f"{PANELS[panel]}/data/{dev}/smsData.json"
                  f"?orderBy=%22%24key%22&limitToLast=40")
    return [(num, panel, dev, t) for num, t in numbers_of(payload).items()]


def main() -> None:
    allmap: dict[str, list[dict]] = {}
    for panel in PANELS:
        shallow = get(f"{PANELS[panel]}/data.json?shallow=true")
        if not shallow:
            print(f"[!] {panel} unreachable")
            continue
        devs = list(shallow.keys())
        print(f"[*] {panel}: {len(devs)} devices", flush=True)
        rows: list[tuple[str, str, str, str]] = []
        with ThreadPoolExecutor(max_workers=24) as ex:
            futs = {ex.submit(scan_device, panel, d): d for d in devs}
            for f in as_completed(futs):
                try:
                    rows.extend(f.result())
                except Exception:
                    pass
        for num, pn, dev, t in rows:
            allmap.setdefault(num, []).append(
                {"panel": pn, "device": dev, "last_sms": t})
        print(f"[*] {panel}: {len(rows)} number sightings", flush=True)

    for num, lst in allmap.items():
        lst.sort(key=lambda e: e["last_sms"], reverse=True)

    DATA.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(allmap, indent=1))
    print(f"[*] {len(allmap)} distinct numbers -> {OUT}")

    live = {n: v for n, v in allmap.items() if v and v[0]["last_sms"]}
    fresh = sorted(live.items(), key=lambda kv: kv[1][0]["last_sms"], reverse=True)
    print(f"[*] {len(fresh)} numbers with any SMS")
    for n, v in fresh[:15]:
        print(f"    {n}  {v[0]['panel']:8s} {v[0]['last_sms']}  "
              f"({len(v)} device{'s' if len(v) > 1 else ''})")


if __name__ == "__main__":
    main()

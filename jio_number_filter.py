#!/usr/bin/env python3
"""jio_number_filter.py — keep only the Jio SIMs from the rtx family.

/users gives every live SIM; /data/<dev>/smsData carries an `info` string
("Operator : JIO 4G , Number : 919380026414") that names the operator.  A
number is Jio when any SMS on its device says so, otherwise it is dropped
(jio.com answers INVALID_JIONUMBER_ERROR for non-Jio numbers).

Writes data/brutal_jio_numbers.json: {mobile: {panel, device, sim, name}}.
"""

from __future__ import annotations

import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import requests

DATA = Path(__file__).resolve().parent / "data"
UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

PANELS = {
    "rtx-c9": "https://rtx-c9-default-rtdb.asia-southeast1.firebasedatabase.app",
    "rtx-c11": "https://rtx-c11-default-rtdb.asia-southeast1.firebasedatabase.app",
    "rtx-c3": "https://rtx-c3-default-rtdb.firebaseio.com",
}
MOB = re.compile(r"[6-9]\d{9}")


def live_sims() -> dict[str, dict]:
    out: dict[str, dict] = {}
    for tag, base in PANELS.items():
        try:
            u = requests.get(f"{base}/users.json", headers={"User-Agent": UA},
                             timeout=90).json()
        except (requests.RequestException, ValueError):
            continue
        for dev, v in (u or {}).items():
            if not isinstance(v, dict):
                continue
            for slot in ("Sim1", "Sim2"):
                n = (v.get(slot) or "").replace("+91", "").replace(" ", "").strip()
                if MOB.fullmatch(n):
                    out[n] = {"panel": tag, "device": dev, "sim": slot,
                              "name": v.get("device_name", "")}
    return out


def operator_of(mobile: str, meta: dict) -> str:
    base = PANELS[meta["panel"]]
    try:
        r = requests.get(
            f"{base}/data/{meta['device']}/smsData.json?orderBy=%22%24key%22&limitToLast=25",
            headers={"User-Agent": UA}, timeout=45)
        if r.status_code != 200:
            return "?"
        for v in (r.json() or {}).values():
            if not isinstance(v, dict):
                continue
            info = (v.get("info") or "").upper()
            if mobile not in info.replace("+91", ""):
                continue
            m = re.search(r"OPERATOR\s*:\s*([A-Z0-9 ]+)", info)
            if m:
                return m.group(1).strip()
    except (requests.RequestException, ValueError):
        pass
    return "?"


def main() -> int:
    sims = live_sims()
    print(f"live SIMs: {len(sims)}", flush=True)

    def job(item):
        m, meta = item
        return m, operator_of(m, meta)

    ops: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=16) as ex:
        for m, op in ex.map(job, sims.items()):
            ops[m] = op

    jio = {m: sims[m] for m, op in ops.items() if "JIO" in op.upper()}
    from collections import Counter
    print("operators:", Counter((o.split() or ["?"])[0] for o in ops.values()))
    print(f"Jio SIMs: {len(jio)}")
    DATA.mkdir(parents=True, exist_ok=True)
    (DATA / "brutal_jio_numbers.json").write_text(json.dumps(jio, indent=1))
    for m, meta in list(jio.items())[:12]:
        print(f"  {m}  {meta['panel']:8s} {meta['name'][:22]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

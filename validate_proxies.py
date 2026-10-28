#!/usr/bin/env python3
"""validate_proxies.py — keep only exits that can actually reach www.jio.com.

The free pool decays fast: most entries are dead, SOCKS entries lack the
requests[socks] dependency, and a handful are IP-banned by Jio.  This script
probes every candidate against the Jio sendOtp endpoint with a dummy number and
writes the survivors (with their measured latency) to data/proxies_live.json.

Usage:
    python3 validate_proxies.py [--workers 60] [--limit 0]
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import sys
import time
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent))

from farm import SEND_OTP_URL, jio_session, load_proxies

OUT = Path(__file__).resolve().parent / "data" / "proxies_live.json"
# a number that is guaranteed NOT to be Jio, so the probe never burns a real OTP
PROBE_MOBILE = "9999999999"


def probe(px: str) -> dict | None:
    if px.startswith("socks"):
        return None
    t0 = time.monotonic()
    try:
        s = jio_session(px)
        r = s.post(SEND_OTP_URL,
                   json={"mobileNumber": PROBE_MOBILE, "loginFlowType": "MOBILE",
                         "alternateNumber": ""}, timeout=12)
        ms = (time.monotonic() - t0) * 1000
        if r.status_code >= 500:
            return None
        body = r.text[:200].lower()
        # a live exit answers with a Jio business error, not a transport failure
        if "invalid_jionumber" in body or "captcha" in body or "locked" in body \
                or r.status_code == 200:
            return {"proxy": px, "ms": round(ms)}
    except Exception:
        return None
    return None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=60)
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    pool = load_proxies()
    if args.limit:
        pool = pool[:args.limit]
    print(f"probing {len(pool)} exits ...", flush=True)

    live: list[dict] = []
    with cf.ThreadPoolExecutor(args.workers) as ex:
        for i, res in enumerate(ex.map(probe, pool)):
            if res:
                live.append(res)
                print(f"  LIVE {res['proxy']:34s} {res['ms']:6.0f} ms", flush=True)
            if (i + 1) % 50 == 0:
                print(f"  ...{i + 1}/{len(pool)} probed, {len(live)} live", flush=True)

    live.sort(key=lambda e: e["ms"])
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(live, indent=1))
    print(f"\n{len(live)} live exits -> {OUT}")


if __name__ == "__main__":
    main()

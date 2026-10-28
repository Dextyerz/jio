#!/usr/bin/env python3
"""Discover live Jio SMS panels on public Firebase RTDB.

The known panels share a naming scheme (rtx-c<N>-default-rtdb) and two
different host suffixes. Probe the whole space in parallel and keep every
endpoint that answers with a readable database, then report the device
counts so the harvester can rank them.
"""
import asyncio
import json
import sys
from pathlib import Path

import aiohttp

DATA = Path(__file__).resolve().parent / "data"
OUT = DATA / "panels.json"

SUFFIXES = (
    "asia-southeast1.firebasedatabase.app",
    "firebaseio.com",
)
PREFIXES = ("rtx-c", "rtx-", "jio-", "sms-", "otp-", "rtx", "rtdb-", "c")
MAX_N = 40

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")


def targets() -> list[str]:
    out = []
    for p in PREFIXES:
        for n in range(1, MAX_N + 1):
            for s in SUFFIXES:
                out.append(f"https://{p}{n}-default-rtdb.{s}")
    return out


async def probe(session: aiohttp.ClientSession, url: str) -> dict | None:
    """Return panel info if the endpoint exposes a non-empty database."""
    try:
        async with session.get(f"{url}/.json?shallow=true",
                               timeout=aiohttp.ClientTimeout(total=12)) as r:
            if r.status != 200:
                return None
            d = await r.json(content_type=None)
            if not isinstance(d, dict) or not d:
                return None
            return {"url": url, "top_keys": list(d.keys())[:20],
                    "keys": len(d)}
    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
        return None


async def main() -> int:
    urls = targets()
    print(f"[*] probing {len(urls)} candidate endpoints", flush=True)
    conn = aiohttp.TCPConnector(limit=60, ssl=False)
    found: list[dict] = []
    async with aiohttp.ClientSession(connector=conn,
                                     headers={"User-Agent": UA}) as s:
        sem = asyncio.Semaphore(60)

        async def guarded(u: str) -> None:
            async with sem:
                r = await probe(s, u)
                if r:
                    found.append(r)
                    print(f"[LIVE] {u} keys={r['keys']}", flush=True)

        await asyncio.gather(*[asyncio.create_task(guarded(u)) for u in urls])

    found.sort(key=lambda x: x["url"])
    OUT.write_text(json.dumps(found, indent=1))
    print(f"[*] {len(found)} live panels -> {OUT}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

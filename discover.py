#!/usr/bin/env python3
"""Panel discovery for the Jio/Gemini farm.

Harvests candidate Firebase Realtime Database URLs from:
  * the two upstream panel lists (jioscan/panels.txt, arxpays script)
  * GitHub commit search (unauthenticated, many query variants)
  * search engines

Writes every unique candidate to panels_all.txt (url|key).
Alive/open panels are decided later by scan.py.
"""

from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path

from curl_cffi import requests

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "data"
OUT.mkdir(exist_ok=True)
CANDIDATES = OUT / "panels_all.txt"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36")

RTDB_RE = re.compile(
    r"https://[a-z0-9\-]+(?:-default-rtdb)?(?:\.asia-southeast1)?"
    r"\.(?:firebaseio\.com|firebasedatabase\.app)"
)

SEED_FILES = [
    Path("/home/ubuntu/.hermes/cache/scratch/jioscan/panels.txt"),
    Path("/home/ubuntu/.hermes/cache/documents/doc_723d04365caf_arxpays jio.py"),
    Path("/home/ubuntu/.hermes/cache/scratch/signupbot"),
]

GH_QUERIES = [
    '"default-rtdb.firebaseio.com"',
    '"firebaseio.com" panel',
    '"default-rtdb" clients',
    '"firebasedatabase.app" clients',
    'firebaseio "clients" "messages"',
    '"firebaseio.com" "getNumber"',
    'rat panel firebaseio',
    'apk panel firebaseio',
    '"firebaseio.com" sms',
    '"default-rtdb.firebaseio.com" messages',
]

ENGINE_QUERIES = [
    '"default-rtdb.firebaseio.com" panel',
    'firebaseio.com netlify panel apk',
    '"firebasedatabase.app" clients.json',
    'firebase panel sms apk netlify',
]


def load_seeds() -> dict[str, str]:
    panels: dict[str, str] = {}
    for p in SEED_FILES:
        if p.is_dir():
            files = list(p.rglob("*"))
        elif p.exists():
            files = [p]
        else:
            continue
        for f in files:
            if not f.is_file():
                continue
            try:
                text = f.read_text(errors="ignore")
            except Exception:
                continue
            for line in text.splitlines():
                if "firebase" not in line:
                    continue
                parts = line.strip().split("|", 1)
                m = RTDB_RE.search(parts[0])
                if m:
                    key = parts[1].strip() if len(parts) > 1 else ""
                    panels.setdefault(m.group(0), key)
    return panels


def gh_commits(panels: dict[str, str]) -> None:
    for q in GH_QUERIES:
        for page in (1, 2, 3):
            url = (f"https://api.github.com/search/commits?q={requests.utils.quote(q)}"
                   f"&per_page=100&page={page}")
            try:
                r = requests.get(url, impersonate="chrome110", timeout=25,
                                 headers={"User-Agent": UA, "Accept": "application/vnd.github+json"})
                if r.status_code != 200:
                    break
                items = r.json().get("items", [])
            except Exception:
                break
            if not items:
                break
            for it in items:
                for m in RTDB_RE.finditer(json.dumps(it)):
                    panels.setdefault(m.group(0), "")
            time.sleep(1)


def engines(panels: dict[str, str]) -> None:
    bases = ["https://www.bing.com/search?q=", "https://lite.duckduckgo.com/lite/?q=",
             "https://search.brave.com/search?q="]
    for q in ENGINE_QUERIES:
        for b in bases:
            try:
                r = requests.get(b + requests.utils.quote(q), impersonate="chrome110",
                                 timeout=20, headers={"User-Agent": UA})
            except Exception:
                continue
            for m in RTDB_RE.finditer(r.text):
                panels.setdefault(m.group(0), "")


def main() -> None:
    existing: dict[str, str] = {}
    if CANDIDATES.exists():
        for line in CANDIDATES.read_text().splitlines():
            if "|" in line:
                u, k = line.split("|", 1)
                existing[u] = k
    panels = load_seeds()
    print(f"[seed] {len(panels)} panels", flush=True)
    gh_commits(panels)
    print(f"[github] {len(panels)} panels", flush=True)
    engines(panels)
    print(f"[engines] {len(panels)} panels", flush=True)

    merged = {**existing, **panels}
    with CANDIDATES.open("w") as fh:
        for u, k in sorted(merged.items()):
            fh.write(f"{u}|{k}\n")
    print(f"[done] total unique candidates: {len(merged)} -> {CANDIDATES}")


if __name__ == "__main__":
    main()

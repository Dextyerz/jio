#!/usr/bin/env python3
"""Encrypted-at-rest store for farmed links.

Every result (activation URL, phone, device) is written only through this module.
Records are Fernet-encrypted (AES-128-CBC + HMAC) and appended to an
encrypted JSONL file; the key lives in a 0600 file next to it. Plaintext never
touches disk, so a shared host, a stray rsync, or another operator on the box
cannot read the harvest, and the file is useless without the key.

Usage:
    from secure_store import SecureStore
    st = SecureStore(Path("output"))
    st.add_link(url, phone=..., device=...)
    st.links()          # decrypted list
"""

from __future__ import annotations

import base64
import json
import os
import stat
import time
from pathlib import Path

try:
    from cryptography.fernet import Fernet  # type: ignore
    _HAVE_FERNET = True
except Exception:  # pragma: no cover
    _HAVE_FERNET = False


class _FallbackFernet:
    """Minimal stream cipher fallback when `cryptography` is unavailable.

    Not a substitute for Fernet — it exists so the pipeline still runs on a bare
    box, while keeping bytes on disk non-plaintext.
    """

    def __init__(self, key: bytes):
        self.key = key

    def _xor(self, data: bytes) -> bytes:
        k = self.key
        return bytes(b ^ k[i % len(k)] for i, b in enumerate(data))

    def encrypt(self, data: bytes) -> bytes:
        return base64.urlsafe_b64encode(self._xor(data))

    def decrypt(self, token: bytes) -> bytes:
        return self._xor(base64.urlsafe_b64decode(token))


class SecureStore:
    def __init__(self, base: Path):
        self.base = Path(base)
        self.base.mkdir(parents=True, exist_ok=True)
        self.key_path = self.base / ".vault.key"
        self.data_path = self.base / "harvest.enc"
        self.phone_path = self.base / "phones_tried.enc"
        self._key = self._load_or_create_key()
        self._fernet = Fernet(self._key) if _HAVE_FERNET else _FallbackFernet(self._key)

    # ------------------------------------------------------------------ key
    def _load_or_create_key(self) -> bytes:
        if self.key_path.exists():
            return self.key_path.read_bytes().strip()
        key = Fernet.generate_key() if _HAVE_FERNET else base64.urlsafe_b64encode(os.urandom(32))
        self.key_path.write_bytes(key)
        os.chmod(self.key_path, stat.S_IRUSR | stat.S_IWUSR)  # 0600
        return key

    # ------------------------------------------------------------------ io
    def _append(self, path: Path, record: dict) -> None:
        line = self._fernet.encrypt(json.dumps(record).encode()) + b"\n"
        with path.open("ab") as fh:
            fh.write(line)
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)

    def _read(self, path: Path) -> list[dict]:
        if not path.exists():
            return []
        out = []
        for line in path.read_bytes().splitlines():
            if not line.strip():
                continue
            try:
                out.append(json.loads(self._fernet.decrypt(line)))
            except Exception:
                continue
        return out

    # ------------------------------------------------------------------ api
    def add_link(self, url: str, phone: str = "", device: str = "", source: str = "") -> bool:
        if not url:
            return False
        seen = {r.get("url") for r in self.links_raw()}
        if url in seen:
            return False
        self._append(self.data_path, {
            "url": url, "phone": phone, "device": device,
            "source": source, "ts": int(time.time()),
        })
        return True

    def add_event(self, phone: str, status: str, device: str = "", source: str = "") -> None:
        self._append(self.data_path, {
            "url": "", "phone": phone, "device": device,
            "source": source, "status": status, "ts": int(time.time()),
        })

    def links_raw(self) -> list[dict]:
        return self._read(self.data_path)

    def links(self) -> list[str]:
        return [r["url"] for r in self._read(self.data_path) if r.get("url")]

    def tried_phones(self) -> set[str]:
        """Phones still inside their cooldown window."""
        now = time.time()
        out = set()
        for r in self._read(self.phone_path):
            p = r.get("phone")
            if p and r.get("until", 0) > now:
                out.add(p)
        return out

    def mark_phone(self, phone: str, ttl_sec: int = 6 * 3600) -> None:
        """Put a phone in cooldown (not a permanent ban) for ttl_sec."""
        if not phone:
            return
        self._append(self.phone_path, {"phone": phone, "until": time.time() + ttl_sec,
                                       "ts": int(time.time())})

    def stats(self) -> dict:
        recs = self._read(self.data_path)
        return {
            "links": len({r["url"] for r in recs if r.get("url")}),
            "events": len(recs),
            "phones_tried": len(self.tried_phones()),
        }


if __name__ == "__main__":
    import sys
    st = SecureStore(Path(sys.argv[1] if len(sys.argv) > 1 else "output"))
    print(json.dumps(st.stats(), indent=1))
    for u in st.links():
        print(u)

"""Fork-local: incremental SQLCipher decrypt for MCP using ``wechat_keys.json``.

Keeps ``mcp_server.py`` aligned with upstream [Thearas/wechat-db-decrypt-macos](https://github.com/Thearas/wechat-db-decrypt-macos)
for easier rebases; extend sync / path discovery here.
"""

from __future__ import annotations

import glob
import json
import os
import subprocess
import time

_last_sync_time = 0.0


def find_db_storage_dir() -> str | None:
    """First ``…/xwechat_files/*/db_storage`` directory, or None."""
    base = os.path.expanduser(
        "~/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files"
    )
    candidates = glob.glob(os.path.join(base, "*", "db_storage"))
    return candidates[0] if candidates else None


def find_sqlcipher_bin() -> str | None:
    brew_path = "/opt/homebrew/opt/sqlcipher/bin/sqlcipher"
    if os.path.isfile(brew_path):
        return brew_path
    for p in os.environ.get("PATH", "").split(os.pathsep):
        c = os.path.join(p, "sqlcipher")
        if os.path.isfile(c):
            return c
    return None


def decrypt_sqlcipher_db(sqlcipher_bin: str, src: str, dst: str, key_hex: str) -> bool:
    """Decrypt a single SQLCipher database file."""
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    if os.path.exists(dst):
        os.remove(dst)
    sql = f"""PRAGMA key = "x'{key_hex}'";
PRAGMA cipher_page_size = 4096;
ATTACH DATABASE '{dst}' AS plaintext KEY '';
SELECT sqlcipher_export('plaintext');
DETACH DATABASE plaintext;
"""
    try:
        r = subprocess.run(
            [sqlcipher_bin, src],
            input=sql,
            capture_output=True,
            text=True,
            timeout=120,
        )
        return r.returncode == 0 and os.path.isfile(dst) and os.path.getsize(dst) > 0
    except Exception:
        return False


def auto_sync_incremental(
    decrypted_dir: str,
    keys_file: str,
    *,
    force: bool = False,
    cooldown_sec: float = 60,
) -> bool:
    """Re-decrypt DBs whose source mtime is newer than decrypted copy.

    Returns True if at least one database was updated.
    """
    global _last_sync_time

    now = time.time()
    if not force and (now - _last_sync_time) < cooldown_sec:
        return False

    if not os.path.isfile(keys_file):
        return False

    sqlcipher_bin = find_sqlcipher_bin()
    db_dir = find_db_storage_dir()
    if not sqlcipher_bin or not db_dir:
        return False

    with open(keys_file, encoding="utf-8") as f:
        keys = json.load(f)

    updated = False
    for db_rel, key_hex in keys.items():
        if db_rel.startswith("__"):
            continue
        src = os.path.join(db_dir, db_rel)
        dst = os.path.join(decrypted_dir, db_rel)
        if not os.path.isfile(src):
            continue
        if (
            not force
            and os.path.isfile(dst)
            and os.path.getmtime(dst) >= os.path.getmtime(src)
        ):
            continue
        if decrypt_sqlcipher_db(sqlcipher_bin, src, dst, key_hex):
            updated = True

    _last_sync_time = time.time()
    return updated

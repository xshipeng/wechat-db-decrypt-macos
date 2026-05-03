#!/usr/bin/env python3
"""
Decrypt WeChat SQLCipher databases to plaintext SQLite files.

Requirements:
    brew install sqlcipher

Usage:
    python3 decrypt_db.py                  # decrypt all databases
    python3 decrypt_db.py -o ./decrypted   # specify output directory
    python3 decrypt_db.py -j 48          # explicit workers (default oversubscribes CPUs)
"""

import argparse
import glob
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

DB_DIR = os.path.expanduser(
    "~/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files"
)
PAGE_SZ = 4096
SALT_SZ = 16


def find_db_dir():
    pattern = os.path.join(DB_DIR, "*", "db_storage")
    candidates = glob.glob(pattern)
    if len(candidates) == 1:
        return candidates[0]
    if len(candidates) > 1:
        return candidates[0]
    if os.path.isdir(DB_DIR) and os.path.basename(DB_DIR) == "db_storage":
        return DB_DIR
    return None


def find_sqlcipher():
    brew_path = "/opt/homebrew/opt/sqlcipher/bin/sqlcipher"
    if os.path.isfile(brew_path):
        return brew_path
    for p in os.environ.get("PATH", "").split(":"):
        candidate = os.path.join(p, "sqlcipher")
        if os.path.isfile(candidate):
            return candidate
    return None


def decrypt_database(sqlcipher_bin, src_path, dst_path, key_hex):
    """Decrypt a SQLCipher database to a plaintext SQLite file."""
    os.makedirs(os.path.dirname(dst_path), exist_ok=True)

    # Remove existing decrypted file if present
    if os.path.exists(dst_path):
        os.remove(dst_path)

    sql_commands = f"""PRAGMA key = "x'{key_hex}'";
PRAGMA cipher_page_size = 4096;
ATTACH DATABASE '{dst_path}' AS plaintext KEY '';
SELECT sqlcipher_export('plaintext');
DETACH DATABASE plaintext;
"""

    try:
        result = subprocess.run(
            [sqlcipher_bin, src_path],
            input=sql_commands,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0 or "Error" in result.stderr:
            return False, result.stderr.strip()

        # Verify the decrypted file
        if not os.path.isfile(dst_path) or os.path.getsize(dst_path) == 0:
            return False, "output file is empty"

        return True, "OK"
    except subprocess.TimeoutExpired:
        return False, "timeout"
    except Exception as e:
        return False, str(e)


def _decrypt_job(sqlcipher_bin, db_rel_path, src_path, dst_path, key_hex):
    """Run in worker thread; returns (db_rel_path, dst_path, success, detail)."""
    ok, detail = decrypt_database(sqlcipher_bin, src_path, dst_path, key_hex)
    return db_rel_path, dst_path, ok, detail


def main():
    parser = argparse.ArgumentParser(description="Decrypt WeChat databases")
    parser.add_argument(
        "--keys",
        default="wechat_keys.json",
        help="Path to wechat_keys.json (default: wechat_keys.json)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="decrypted",
        help="Output directory for decrypted databases (default: decrypted)",
    )
    parser.add_argument(
        "-j",
        "--jobs",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Parallel decrypt workers (each runs sqlcipher). "
            "Default oversubscribes CPU (≈8× cores, capped) so disk/subprocess latency can overlap; "
            "use -j 1 for sequential."
        ),
    )
    args = parser.parse_args()

    if args.jobs is not None and args.jobs < 1:
        print("[-] --jobs must be >= 1", file=sys.stderr)
        sys.exit(1)

    if not os.path.isfile(args.keys):
        print(f"[-] Key file not found: {args.keys}")
        sys.exit(1)

    with open(args.keys, "r") as f:
        data = json.load(f)

    sqlcipher_bin = find_sqlcipher()
    if not sqlcipher_bin:
        print("[-] sqlcipher not found. Install it with: brew install sqlcipher")
        sys.exit(1)
    print(f"[*] Using sqlcipher: {sqlcipher_bin}")

    db_dir = find_db_dir()
    if not db_dir:
        print(f"[-] Could not find db_storage directory under {DB_DIR}")
        sys.exit(1)
    print(f"[*] DB storage: {db_dir}")

    entries = {k: v for k, v in data.items() if not k.startswith("__")}

    tasks = []
    skipped = []
    for db_rel_path, key_hex in sorted(entries.items()):
        src = os.path.join(db_dir, db_rel_path)
        dst = os.path.join(args.output, db_rel_path)
        if not os.path.isfile(src):
            skipped.append(db_rel_path)
            continue
        tasks.append((db_rel_path, src, dst, key_hex))

    cpus = os.cpu_count() or 4
    if args.jobs is not None:
        jobs = args.jobs
    else:
        # Oversubscribe: each worker is mostly waiting on sqlcipher / IO; keep many in flight.
        overshoot = max(24, cpus * 8)
        jobs = max(1, min(len(tasks), overshoot, 256))

    print(
        f"[*] Decrypting {len(entries)} databases to {args.output}/ "
        f"(workers={jobs}, CPUs={cpus}, pending={len(tasks)})\n"
    )

    for db_rel_path in skipped:
        print(f"  ⏭️  {db_rel_path}: source file not found, skipping")

    passed = 0
    failed = 0
    results = []

    if jobs <= 1:
        for db_rel_path, src, dst, key_hex in tasks:
            db_rel_path, dst, success, detail = _decrypt_job(
                sqlcipher_bin, db_rel_path, src, dst, key_hex
            )
            results.append((db_rel_path, dst, success, detail))
    else:
        with ThreadPoolExecutor(max_workers=jobs) as pool:
            future_to_rel = {
                pool.submit(
                    _decrypt_job, sqlcipher_bin, rel, s, d, k
                ): rel
                for rel, s, d, k in tasks
            }
            for fut in as_completed(future_to_rel):
                results.append(fut.result())

    order = {rel: i for i, (rel, _, _, _) in enumerate(tasks)}
    results.sort(key=lambda x: order.get(x[0], 0))

    for db_rel_path, dst, success, detail in results:
        if success:
            dst_size = os.path.getsize(dst)
            print(f"  ✅ {db_rel_path} -> {dst} ({dst_size / 1024:.0f} KB)")
            passed += 1
        else:
            print(f"  ❌ {db_rel_path}: {detail}")
            failed += 1

    print(f"\n[*] Done: {passed} decrypted, {failed} failed")
    if passed > 0:
        print(f"[*] Decrypted files saved to: {os.path.abspath(args.output)}/")
        print(f"[*] You can now run: python3 export_messages.py")


if __name__ == "__main__":
    main()

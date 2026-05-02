#!/usr/bin/env python3
"""
Export WeChat chat messages from decrypted databases.

Usage:
    python3 decrypt_db.py                          # first, decrypt databases
    python3 export_messages.py                     # list all conversations
    python3 export_messages.py -c wxid_xxx         # export a specific chat
    python3 export_messages.py -c 12345@chatroom   # export a group chat
    python3 export_messages.py --all               # export all chats
    python3 export_messages.py -c wxid_xxx -n 50   # last 50 messages
    python3 export_messages.py -s "keyword"        # search keyword
"""

import sqlite3
import os
import re
import sys
import html
import hashlib
import argparse
import glob
from datetime import datetime

try:
    import zstandard
except ImportError:
    zstandard = None

# Zstd frame magic (little-endian 0xFD2FB528); first byte is ASCII '('
ZSTD_FRAME_MAGIC = b"\x28\x2f\xb5\xfd"

# WCDB: column WCDB_CT_message_content == 4 means message_content is zstd (wechat-decrypt, etc.)


def _normalize_wcdb_ct(ct):
    if ct is None:
        return None
    try:
        return int(float(ct))
    except (TypeError, ValueError):
        return None


def _zstd_decompress_buffer(b: bytes, force: bool):
    """Decompress zstd. If force (WCDB ct==4), also try decompression of full buffer after offset scan."""
    if zstandard is None or not b:
        return None
    dctx = zstandard.ZstdDecompressor()
    if len(b) >= 4 and b[:4] == ZSTD_FRAME_MAGIC:
        try:
            return dctx.decompress(b)
        except Exception:
            pass
    for i in range(1, min(128, max(0, len(b) - 3))):
        if b[i : i + 4] == ZSTD_FRAME_MAGIC:
            try:
                return dctx.decompress(b[i:])
            except Exception:
                continue
    if force:
        try:
            return dctx.decompress(b)
        except Exception:
            return None
    return None


def _content_to_bytes_for_zstd(content):
    if isinstance(content, (bytes, bytearray)):
        return bytes(content)
    if isinstance(content, str):
        try:
            return content.encode("latin-1")
        except UnicodeEncodeError:
            return None
    return None


def decode_message_content(content, wcdb_ct=None):
    """Return UTF-8 text. WCDB often marks zstd blobs with WCDB_CT_message_content=4; see also zstd magic."""
    if content is None:
        return ""
    ct = _normalize_wcdb_ct(wcdb_ct)
    b = _content_to_bytes_for_zstd(content)
    if b and zstandard is not None:
        if ct == 4:
            dec = _zstd_decompress_buffer(b, force=True)
            if dec is not None:
                return dec.decode("utf-8", errors="replace")
        dec = _zstd_decompress_buffer(b, force=False)
        if dec is not None:
            return dec.decode("utf-8", errors="replace")
    if zstandard is None and b and len(b) >= 4 and b[:4] == ZSTD_FRAME_MAGIC:
        return f"(zstd BLOB; pip install zstandard) len={len(b)}"
    if isinstance(content, (bytes, bytearray)):
        return bytes(content).decode("utf-8", errors="replace")
    return str(content)


def try_format_quote_reply(s: str):
    """If content is 引用/回复 (appmsg type 57) with <refermsg>, return one-line text or None.

    - New reply: first <appmsg><title>…
    - Referenced: <refermsg><displayname>, <content>, <svrid> (for correlation in DB)
    """
    s = (s or "").strip()
    if not s or "refermsg" not in s.lower():
        return None
    m = re.search(r"<refermsg>([\s\S]*?)</refermsg>", s, re.IGNORECASE)
    if not m:
        return None
    ref_block = m.group(1)

    def g(tag):
        p = re.compile(
            rf"<{tag}>(?:<!\[CDATA\[([\s\S]*?)\]\]>|([\s\S]*?))</{tag}>",
            re.IGNORECASE,
        )
        x = p.search(ref_block)
        if not x:
            return ""
        return (x.group(1) or x.group(2) or "").strip()

    who = (g("displayname") or g("displayName") or g("fromusr") or "?").strip()
    ref_content = g("content")
    reftype = (g("type") or "").strip()
    svrid = (g("svrid") or "").strip()

    t_m = re.search(
        r"<title>(?:<!\[CDATA\[([\s\S]*?)\]\]>|([^<]*))</title>",
        s,
        re.IGNORECASE,
    )
    new_reply = (t_m.group(1) or t_m.group(2) or "").strip() if t_m else ""
    if not ref_content and not new_reply and not who:
        return None

    who = html.unescape(who)
    new_reply = html.unescape(new_reply)
    ref_preview = html.unescape(ref_content or "(empty)").replace("\n", " ")
    if len(ref_preview) > 400:
        ref_preview = ref_preview[:400] + "…"

    bits = [f"「{who}」"]
    if reftype and reftype != "1":
        bits.append(f"[quoted_type={reftype}]")
    bits.append(ref_preview)
    if new_reply:
        bits.append(f"→ 回复: {new_reply}")
    if svrid:
        bits.append(f"(ref_svrid={svrid})")
    return " ".join(bits)


def summarize_image_message_xml(s: str) -> str:
    """WeChat type-3 content is <msg><img …/> XML pointing at CDN/encrypted data, not inline pixels."""
    if not s or "<img" not in s.lower():
        return ""
    m_md5 = re.search(r'\bmd5="([^"]+)"', s, re.IGNORECASE)
    if not m_md5:
        m_md5 = re.search(r"<md5>([^<]+)</md5>", s, re.IGNORECASE)
    m_len = re.search(
        r'\b(?:length|totallen|cdnthumblength)="(\d+)"', s, re.IGNORECASE
    )
    parts = []
    if m_md5:
        parts.append(f"file_md5={m_md5.group(1)[:32]}")
    if m_len:
        parts.append(f"len={m_len.group(1)}")
    return " ".join(parts)


DECRYPTED_DIR = "decrypted"
MSG_TYPE_MAP = {
    1: "text",
    3: "image",
    34: "voice",
    42: "card",
    43: "video",
    47: "emoji",
    48: "location",
    49: "link/file",
    10000: "system",
    10002: "revoke",
}


# ── Contact name resolution ──────────────────────────────────────────────────


def load_contacts(decrypted_dir):
    """Load contact display names from contact.db.
    Returns dict: username -> display_name (remark > nick_name > username)
    """
    contact_db = os.path.join(decrypted_dir, "contact", "contact.db")
    contacts = {}

    if not os.path.isfile(contact_db):
        return contacts

    conn = sqlite3.connect(contact_db)
    try:
        for username, remark, nick_name in conn.execute(
            "SELECT username, remark, nick_name FROM contact"
        ):
            # Priority: remark (备注名) > nick_name (昵称) > username
            name = remark or nick_name or username
            if name:
                contacts[username] = name

        # Also load from stranger table for non-contacts
        for username, remark, nick_name in conn.execute(
            "SELECT username, remark, nick_name FROM stranger"
        ):
            if username not in contacts:
                name = remark or nick_name or username
                if name:
                    contacts[username] = name
    finally:
        conn.close()

    return contacts


def resolve_username(chat_name, contacts):
    """Resolve chat_name (display name, remark, or wxid) to username."""
    # Direct match
    if chat_name in contacts or chat_name.startswith("wxid_") or "@chatroom" in chat_name:
        return chat_name

    # Exact match on display name
    chat_lower = chat_name.lower()
    for uname, display in contacts.items():
        if chat_lower == display.lower():
            return uname

    # Fuzzy match (contains)
    for uname, display in contacts.items():
        if chat_lower in display.lower():
            return uname

    return None


# ── Multi-database support ───────────────────────────────────────────────────


def get_all_msg_dbs(decrypted_dir):
    """Find all message_N.db files (N = 0, 1, 2, ...)."""
    import re
    msg_dir = os.path.join(decrypted_dir, "message")
    if not os.path.isdir(msg_dir):
        return []
    dbs = []
    for f in sorted(os.listdir(msg_dir)):
        if re.match(r"^message_\d+\.db$", f):
            dbs.append(os.path.join(msg_dir, f))
    return dbs


def get_session_db_path(decrypted_dir):
    return os.path.join(decrypted_dir, "session", "session.db")


def username_to_table(username):
    """Convert username to Msg_<md5hash> table name."""
    h = hashlib.md5(username.encode()).hexdigest()
    return f"Msg_{h}"


def find_msg_db_paths_for_username(msg_dbs, username):
    """All message_*.db files that contain Msg_<hash> for this chat (history may be split)."""
    table = username_to_table(username)
    paths = []
    for db_path in msg_dbs:
        conn = sqlite3.connect(db_path)
        try:
            exists = conn.execute(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?",
                (table,),
            ).fetchone()[0]
            if exists:
                paths.append(db_path)
        finally:
            conn.close()
    return paths


def find_msg_db_for_username(msg_dbs, username):
    """First DB containing this chat (prefer find_msg_db_paths_for_username for full history)."""
    paths = find_msg_db_paths_for_username(msg_dbs, username)
    return paths[0] if paths else None


def collect_all_usernames(msg_dbs):
    """Collect all usernames from all message DBs, with their DB path."""
    username_to_db = {}
    for db_path in msg_dbs:
        conn = sqlite3.connect(db_path)
        try:
            rows = conn.execute(
                "SELECT user_name FROM Name2Id WHERE user_name != ''"
            ).fetchall()
            for (username,) in rows:
                # If username appears in multiple DBs, use the first one
                if username not in username_to_db:
                    username_to_db[username] = db_path
        finally:
            conn.close()
    return username_to_db


# ── Message formatting ───────────────────────────────────────────────────────


def msg_table_column_names(conn, table):
    try:
        return {row[1] for row in conn.execute(f"PRAGMA table_info([{table}])").fetchall()}
    except sqlite3.Error:
        return set()


def load_name2id_by_rowid(conn):
    """Map Name2Id.rowid -> wxid; used to resolve real_sender_id in group chats."""
    mapping = {}
    try:
        for rowid, user_name in conn.execute(
            "SELECT rowid, user_name FROM Name2Id WHERE user_name != ''"
        ):
            mapping[int(rowid)] = user_name
    except sqlite3.Error:
        pass
    return mapping


def peer_rowid_for_username(conn, peer_username):
    """Name2Id.rowid for this chat partner; matches Msg.real_sender_id for their messages."""
    if not peer_username:
        return None
    try:
        row = conn.execute(
            "SELECT rowid FROM Name2Id WHERE user_name = ? LIMIT 1",
            (peer_username,),
        ).fetchone()
        return int(row[0]) if row else None
    except sqlite3.Error:
        return None


def detect_my_sender_id(conn):
    """Find real_sender_id that represents this account (present across sampled chats).

    Heuristic: sample several Msg_* tables; the sender id common to all samples is 'me'.
    """
    try:
        tables = [
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg_%'"
            ).fetchall()
        ]
    except sqlite3.Error:
        return None
    if not tables:
        return None

    sender_sets = []
    for table in tables[:5]:
        try:
            rows = conn.execute(
                f"SELECT DISTINCT real_sender_id FROM [{table}] "
                f"WHERE local_type NOT IN (10000, 10002) LIMIT 20"
            ).fetchall()
            ids = set()
            for (rsid,) in rows:
                if rsid is None:
                    continue
                try:
                    ids.add(int(rsid))
                except (TypeError, ValueError):
                    continue
            if ids:
                sender_sets.append(ids)
        except sqlite3.Error:
            continue

    if not sender_sets:
        return None
    common = sender_sets[0]
    for s in sender_sets[1:]:
        common &= s
    common.discard(0)
    if len(common) == 1:
        return common.pop()
    if common:
        return min(common)
    return None


_sender_ctx_cache = {}

def sender_format_context(db_path):
    """(my_sender_id, name2id_by_rowid) for a message DB; cached per path."""
    if db_path not in _sender_ctx_cache:
        conn = sqlite3.connect(db_path)
        try:
            _sender_ctx_cache[db_path] = (
                detect_my_sender_id(conn),
                load_name2id_by_rowid(conn),
            )
        finally:
            conn.close()
    return _sender_ctx_cache[db_path]


def _normalize_sender_id(sender_id):
    if sender_id is None:
        return None
    try:
        return int(sender_id)
    except (TypeError, ValueError):
        return None


def _wechat_local_type_parts(local_type):
    """WeChat can store a 64-bit packed value: message kind in the low 32 bits,
    sub-type (e.g. app message class) in the high 32 bits. MSG_TYPE_MAP keys use the base only."""
    if local_type is None:
        return None, 0
    try:
        t = int(local_type)
    except (TypeError, ValueError):
        return local_type, 0
    if t < 0:
        t = t & ((1 << 64) - 1)
    base = t & 0xFFFFFFFF
    sub = (t >> 32) & 0xFFFFFFFF
    if base & 0x80000000:
        base = base - 0x100000000
    return base, sub


def format_message(
    row,
    is_group,
    contacts,
    peer_username=None,
    my_sender_id=None,
    name2id_by_rowid=None,
    peer_sender_rowid=None,
):
    """Format a single message row for display.

    Private chats: real_sender_id equals Name2Id.rowid for the peer -> 对方；否则 -> 我。
    Fallback: detect_my_sender_id() or name2id wxid match.
    Group chats: prefer wxid:\\n prefix in content; else resolve real_sender_id via Name2Id.
    """
    if len(row) == 7:
        local_id, local_type, create_time, sender_id, content, wcdb_ct, source = row
    else:
        local_id, local_type, create_time, sender_id, content, source = row
        wcdb_ct = None

    ts = datetime.fromtimestamp(create_time).strftime("%Y-%m-%d %H:%M:%S") if create_time else "?"
    base_type, type_sub = _wechat_local_type_parts(local_type)
    type_name = MSG_TYPE_MAP.get(base_type, f"type:{base_type}")
    if type_sub:
        type_name = f"{type_name} (sub:{type_sub})"

    sid = _normalize_sender_id(sender_id)
    sender = ""
    body = decode_message_content(content, wcdb_ct=wcdb_ct)

    if is_group and body and ":\n" in body:
        parts = body.split(":\n", 1)
        raw_sender = parts[0]
        body = parts[1]
        sender = contacts.get(raw_sender, raw_sender)
    elif is_group and sid is not None and name2id_by_rowid:
        if sid in name2id_by_rowid:
            wxid = name2id_by_rowid[sid]
            sender = contacts.get(wxid, wxid)
        elif my_sender_id is not None and sid == my_sender_id:
            sender = "我"
    elif not is_group and peer_username:
        peer_display = contacts.get(peer_username, peer_username)
        if peer_sender_rowid is not None and sid is not None:
            if sid == peer_sender_rowid:
                sender = peer_display
            else:
                sender = "我"
        elif my_sender_id is not None and sid is not None:
            if sid == my_sender_id:
                sender = "我"
            else:
                sender = peer_display
        elif sid is not None and name2id_by_rowid:
            wxid = name2id_by_rowid.get(sid)
            if wxid == peer_username:
                sender = peer_display
            elif wxid:
                sender = "我"

    if base_type != 1:
        quoted = try_format_quote_reply(body)
        if quoted is not None:
            body = f"[引用回复] {quoted}" if body else "[引用回复]"
        elif base_type == 3:
            sm = summarize_image_message_xml(body)
            if sm:
                body = f"[image] {sm}"
            else:
                body = f"[image] (no md5/len in XML) {body[:200]}"
        else:
            n = 800 if base_type == 49 else 100
            body = f"[{type_name}] {body[:n]}" if body else f"[{type_name}]"

    if sender:
        return f"[{ts}] {sender}: {body}"
    return f"[{ts}] {body}"


# ── Core operations ──────────────────────────────────────────────────────────


def list_conversations(msg_dbs, session_db_path, contacts):
    """List all conversations with display names."""
    sessions = {}
    if os.path.isfile(session_db_path):
        conn = sqlite3.connect(session_db_path)
        try:
            rows = conn.execute(
                "SELECT username, type, summary, last_sender_display_name, "
                "last_timestamp FROM SessionTable ORDER BY sort_timestamp DESC"
            ).fetchall()
            for username, stype, summary, sender, ts in rows:
                sessions[username] = {
                    "type": "group" if "@chatroom" in username else "private",
                    "summary": (summary or "")[:60],
                    "sender": sender or "",
                    "time": datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M") if ts else "",
                }
        finally:
            conn.close()

    # Collect all usernames across all message DBs
    username_to_db = collect_all_usernames(msg_dbs)

    # Build all message tables set per DB
    all_tables = {}
    for db_path in msg_dbs:
        conn = sqlite3.connect(db_path)
        try:
            tables = {
                r[0]
                for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg_%'"
                ).fetchall()
            }
            all_tables[db_path] = tables
        finally:
            conn.close()

    results = []
    for username, db_path in username_to_db.items():
        table = username_to_table(username)
        msg_paths = find_msg_db_paths_for_username(msg_dbs, username)
        has_msgs = any(table in all_tables.get(p, set()) for p in msg_paths)
        info = sessions.get(username, {})
        display_name = contacts.get(username, "")
        db_label = ", ".join(os.path.basename(p) for p in msg_paths) or os.path.basename(db_path)
        results.append({
            "username": username,
            "display_name": display_name,
            "db": db_label,
            "has_msgs": has_msgs,
            **info,
        })

    results.sort(key=lambda x: x.get("time", ""), reverse=True)
    return results


def export_chat(msg_dbs, username, contacts, limit=None):
    """Export messages for a specific conversation from all message DBs."""
    table = username_to_table(username)
    is_group = "@chatroom" in username

    db_paths = find_msg_db_paths_for_username(msg_dbs, username)
    if not db_paths:
        return None, f"No message table found for {username}"

    ctx_by_db = {}
    tagged_rows = []
    total = 0

    for db_path in db_paths:
        conn = sqlite3.connect(db_path)
        try:
            total += conn.execute(f"SELECT count(*) FROM [{table}]").fetchone()[0]
            my_sender_id = detect_my_sender_id(conn)
            name2id_by_rowid = load_name2id_by_rowid(conn)
            peer_sender_rowid = None if is_group else peer_rowid_for_username(conn, username)
            _sender_ctx_cache[db_path] = (my_sender_id, name2id_by_rowid)
            ctx_by_db[db_path] = (my_sender_id, name2id_by_rowid, peer_sender_rowid)

            cols = msg_table_column_names(conn, table)
            has_wcdb = "WCDB_CT_message_content" in cols
            if has_wcdb:
                q = (
                    f"SELECT local_id, local_type, create_time, real_sender_id, "
                    f"message_content, WCDB_CT_message_content, source FROM [{table}] "
                    f"ORDER BY create_time ASC"
                )
            else:
                q = (
                    f"SELECT local_id, local_type, create_time, real_sender_id, "
                    f"message_content, source FROM [{table}] ORDER BY create_time ASC"
                )
            for r in conn.execute(q).fetchall():
                if not has_wcdb:
                    r = (*r[:5], None, r[5])
                tagged_rows.append((db_path, r))
        finally:
            conn.close()

    tagged_rows.sort(key=lambda x: (x[1][2], x[1][0]))

    if limit:
        tagged_rows.sort(key=lambda x: x[1][2], reverse=True)
        tagged_rows = tagged_rows[:limit]
        tagged_rows.sort(key=lambda x: (x[1][2], x[1][0]))

    lines = []
    for db_path, r in tagged_rows:
        my_sender_id, name2id_by_rowid, peer_sender_rowid = ctx_by_db[db_path]
        lines.append(
            format_message(
                r,
                is_group,
                contacts,
                peer_username=username,
                my_sender_id=my_sender_id,
                name2id_by_rowid=name2id_by_rowid,
                peer_sender_rowid=peer_sender_rowid,
            )
        )

    display_name = contacts.get(username, username)
    db_label = ", ".join(os.path.basename(p) for p in db_paths)
    return lines, f"{display_name} | total: {total}, showing: {len(lines)} | db: {db_label}"


def safe_filename(display_name, username):
    """Generate a safe filename from display name, fallback to username."""
    name = display_name or username
    # Remove characters not safe for filenames
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '', name)
    name = name.strip('. ')
    if not name:
        name = username.replace('@', '_at_')
    # Truncate to reasonable length
    if len(name) > 80:
        name = name[:80]
    return name


def export_to_file(msg_dbs, username, output_dir, contacts, limit=None):
    """Export messages to a text file named by display name."""
    lines, info = export_chat(msg_dbs, username, contacts, limit)
    if lines is None:
        return False, info

    os.makedirs(output_dir, exist_ok=True)

    display_name = contacts.get(username, "")
    fname = safe_filename(display_name, username)
    output_path = os.path.join(output_dir, f"{fname}.txt")

    # Avoid collision
    if os.path.exists(output_path):
        output_path = os.path.join(output_dir, f"{fname}_{username.replace('@', '_at_')}.txt")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(f"# Chat: {display_name or username} ({username})\n")
        f.write(f"# {info}\n")
        f.write(f"# Exported: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write("\n".join(lines))
        f.write("\n")

    return True, f"{os.path.basename(output_path)} | {info}"


def main():
    parser = argparse.ArgumentParser(description="Export WeChat chat messages")
    parser.add_argument(
        "-d", "--dir", default=DECRYPTED_DIR,
        help=f"Decrypted database directory (default: {DECRYPTED_DIR})",
    )
    parser.add_argument("-c", "--chat", help="Username or chatroom ID to export")
    parser.add_argument("--all", action="store_true", help="Export all conversations")
    parser.add_argument(
        "-n", "--limit", type=int, default=None, help="Number of recent messages",
    )
    parser.add_argument(
        "-o", "--output", default="exported", help="Output directory (default: exported)",
    )
    parser.add_argument(
        "-s", "--search", help="Search keyword across all conversations",
    )
    args = parser.parse_args()

    # Load databases
    msg_dbs = get_all_msg_dbs(args.dir)
    if not msg_dbs:
        print(f"[-] No message databases found in {args.dir}/message/")
        print(f"    Run 'python3 decrypt_db.py' first.")
        sys.exit(1)

    print(f"[*] Loaded {len(msg_dbs)} message databases: {', '.join(os.path.basename(d) for d in msg_dbs)}")

    session_db = get_session_db_path(args.dir)
    contacts = load_contacts(args.dir)
    print(f"[*] Loaded {len(contacts)} contacts")

    if args.search:
        # Search across all conversations
        print(f"[*] Searching for '{args.search}'...\n")
        username_to_db = collect_all_usernames(msg_dbs)
        found = 0
        for username in username_to_db:
            table = username_to_table(username)
            is_group = "@chatroom" in username
            tagged = []
            for db_path in find_msg_db_paths_for_username(msg_dbs, username):
                conn = sqlite3.connect(db_path)
                try:
                    has_wcdb = "WCDB_CT_message_content" in msg_table_column_names(
                        conn, table
                    )
                    if has_wcdb:
                        sql = (
                            f"SELECT local_id, local_type, create_time, real_sender_id, "
                            f"message_content, WCDB_CT_message_content, source FROM [{table}] "
                            f"WHERE message_content LIKE ? ORDER BY create_time DESC LIMIT 10"
                        )
                    else:
                        sql = (
                            f"SELECT local_id, local_type, create_time, real_sender_id, "
                            f"message_content, source FROM [{table}] "
                            f"WHERE message_content LIKE ? ORDER BY create_time DESC LIMIT 10"
                        )
                    rows = conn.execute(sql, (f"%{args.search}%",)).fetchall()
                    for r in rows:
                        if not has_wcdb:
                            r = (*r[:5], None, r[5])
                        tagged.append((db_path, r))
                finally:
                    conn.close()
            if not tagged:
                continue
            tagged.sort(key=lambda x: x[1][2], reverse=True)
            tagged = tagged[:10]

            display = contacts.get(username, username)
            print(f"── {display} ({username}) ──")
            peer_rid_cache = {}

            def peer_rid_for(db_path):
                if is_group:
                    return None
                if db_path not in peer_rid_cache:
                    c = sqlite3.connect(db_path)
                    try:
                        peer_rid_cache[db_path] = peer_rowid_for_username(c, username)
                    finally:
                        c.close()
                return peer_rid_cache[db_path]

            for db_path, r in tagged:
                my_sid, n2i = sender_format_context(db_path)
                print(
                    f"  {format_message(r, is_group, contacts, peer_username=username, my_sender_id=my_sid, name2id_by_rowid=n2i, peer_sender_rowid=peer_rid_for(db_path))}"
                )
            print()
            found += len(tagged)
        print(f"[*] Found {found} messages matching '{args.search}'")

    elif args.chat:
        # Export specific chat (with fuzzy matching)
        username = resolve_username(args.chat, contacts)
        if not username:
            print(f"[-] Could not find chat: {args.chat}")
            print(f"    Try: python3 export_messages.py -s '{args.chat}'")
            sys.exit(1)

        if username != args.chat:
            display = contacts.get(username, username)
            print(f"[*] Matched '{args.chat}' -> {display} ({username})")

        lines, info = export_chat(msg_dbs, username, contacts, args.limit)
        if lines is None:
            print(f"[-] {info}")
            sys.exit(1)

        print(f"[*] {info}\n")
        for line in lines:
            print(line)

        success, result_info = export_to_file(msg_dbs, username, args.output, contacts, args.limit)
        print(f"\n[*] Saved: {result_info}")

    elif args.all:
        # Export all conversations
        convos = list_conversations(msg_dbs, session_db, contacts)
        os.makedirs(args.output, exist_ok=True)
        exported = 0
        for c in convos:
            if not c["has_msgs"]:
                continue
            success, info = export_to_file(
                msg_dbs, c["username"], args.output, contacts, args.limit,
            )
            if success:
                print(f"  ✅ {info}")
                exported += 1
        print(f"\n[*] Exported {exported} conversations to {args.output}/")

    else:
        # List conversations
        convos = list_conversations(msg_dbs, session_db, contacts)
        active = [c for c in convos if c.get("time") or c["has_msgs"]]
        print(f"[*] Found {len(active)} active conversations (from {len(convos)} total)\n")
        print(f"{'Display Name':<20} {'Username':<35} {'DB':<15} {'Time':<18} {'Last Message'}")
        print("-" * 120)
        for c in active:
            if not c.get("time"):
                continue
            marker = "💬" if c.get("type") == "private" else "👥"
            display = c.get("display_name", "")[:18] or ""
            summary = c.get("summary", "")[:40]
            time_str = c.get("time", "")
            db_name = c.get("db", "")
            print(f"{marker} {display:<18} {c['username']:<35} {db_name:<15} {time_str:<18} {summary}")

        print(f"\n[*] To export a chat: python3 export_messages.py -c <username>")
        print(f"[*] To export all:    python3 export_messages.py --all")
        print(f"[*] To search:        python3 export_messages.py -s <keyword>")


if __name__ == "__main__":
    main()

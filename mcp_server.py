#!/usr/bin/env python3
"""
WeChat MCP Server — let AI query your WeChat messages directly.

Requirements:
    pip3 install fastmcp

Setup with Claude Code:
    claude mcp add wechat -- python3 /path/to/mcp_server.py

Tools provided:
    - get_recent_sessions(limit)   — recent chat sessions
    - get_chat_history(chat_name)  — chat history (fuzzy name match)
    - search_messages(keyword)     — search across all chats
    - get_contacts(query)          — search contacts
"""

import sqlite3
import os
import re
import sys
import hashlib
import json
import time
from datetime import datetime

from fastmcp import FastMCP

# ── Configuration ────────────────────────────────────────────────────────────

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from export_messages import (  # noqa: E402
    decode_message_content,
    msg_table_column_names,
    try_format_quote_reply,
)

DECRYPTED_DIR = os.path.join(SCRIPT_DIR, "decrypted")
KEYS_FILE = os.path.join(SCRIPT_DIR, "wechat_keys.json")
SYNC_COOLDOWN = 60  # seconds between auto-syncs

_last_sync_time = 0

MSG_TYPE_MAP = {
    1: "文本", 3: "图片", 34: "语音", 42: "名片",
    43: "视频", 47: "表情", 48: "位置", 49: "链接/文件",
    50: "通话", 10000: "系统", 10002: "撤回",
}


# ── Auto-sync ────────────────────────────────────────────────────────────────


def _find_db_dir():
    """Find WeChat's encrypted db_storage directory."""
    import glob as _glob
    base = os.path.expanduser(
        "~/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files"
    )
    candidates = _glob.glob(os.path.join(base, "*", "db_storage"))
    return candidates[0] if candidates else None


def _find_sqlcipher():
    brew_path = "/opt/homebrew/opt/sqlcipher/bin/sqlcipher"
    if os.path.isfile(brew_path):
        return brew_path
    for p in os.environ.get("PATH", "").split(":"):
        c = os.path.join(p, "sqlcipher")
        if os.path.isfile(c):
            return c
    return None


def _decrypt_one(sqlcipher_bin, src, dst, key_hex):
    """Decrypt a single SQLCipher database."""
    import subprocess
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
            [sqlcipher_bin, src], input=sql,
            capture_output=True, text=True, timeout=120,
        )
        return r.returncode == 0 and os.path.isfile(dst) and os.path.getsize(dst) > 0
    except Exception:
        return False


def _auto_sync(force=False):
    """Re-decrypt only databases whose source file has changed. Clears contact cache if any DB was updated."""
    global _last_sync_time, _contacts, _contacts_full

    now = time.time()
    if not force and (now - _last_sync_time) < SYNC_COOLDOWN:
        return

    if not os.path.isfile(KEYS_FILE):
        return

    sqlcipher_bin = _find_sqlcipher()
    db_dir = _find_db_dir()
    if not sqlcipher_bin or not db_dir:
        return

    with open(KEYS_FILE) as f:
        keys = json.load(f)

    updated = False
    for db_rel, key_hex in keys.items():
        if db_rel.startswith("__"):
            continue
        src = os.path.join(db_dir, db_rel)
        dst = os.path.join(DECRYPTED_DIR, db_rel)
        if not os.path.isfile(src):
            continue
        # Skip if decrypted file is newer than source
        if not force and os.path.isfile(dst) and os.path.getmtime(dst) >= os.path.getmtime(src):
            continue
        if _decrypt_one(sqlcipher_bin, src, dst, key_hex):
            updated = True

    if updated:
        _contacts = None
        _contacts_full = None
    _last_sync_time = time.time()


# ── Database helpers ─────────────────────────────────────────────────────────


def _get_msg_dbs():
    """Find all decrypted message_N.db files."""
    msg_dir = os.path.join(DECRYPTED_DIR, "message")
    if not os.path.isdir(msg_dir):
        return []
    dbs = []
    for f in sorted(os.listdir(msg_dir)):
        if re.match(r"^message_\d+\.db$", f):
            dbs.append(os.path.join(msg_dir, f))
    return dbs


def _get_session_db():
    return os.path.join(DECRYPTED_DIR, "session", "session.db")


def _get_contact_db():
    return os.path.join(DECRYPTED_DIR, "contact", "contact.db")


def _username_to_table(username):
    h = hashlib.md5(username.encode()).hexdigest()
    return f"Msg_{h}"


# ── Contact cache ────────────────────────────────────────────────────────────

_contacts = None  # {username: display_name}
_contacts_full = None  # [{username, nick_name, remark}]


def _load_contacts():
    global _contacts, _contacts_full
    if _contacts is not None:
        return

    _contacts = {}
    _contacts_full = []
    db = _get_contact_db()
    if not os.path.isfile(db):
        return

    conn = sqlite3.connect(db)
    try:
        for username, remark, nick_name in conn.execute(
            "SELECT username, remark, nick_name FROM contact"
        ):
            display = remark or nick_name or username
            _contacts[username] = display
            _contacts_full.append({
                "username": username,
                "nick_name": nick_name or "",
                "remark": remark or "",
            })
        # Also load strangers
        for username, remark, nick_name in conn.execute(
            "SELECT username, remark, nick_name FROM stranger"
        ):
            if username not in _contacts:
                display = remark or nick_name or username
                _contacts[username] = display
                _contacts_full.append({
                    "username": username,
                    "nick_name": nick_name or "",
                    "remark": remark or "",
                })
    finally:
        conn.close()


def _get_contacts():
    _load_contacts()
    return _contacts


def _resolve_username(chat_name):
    """Resolve chat_name (display name, remark, or wxid) to username."""
    names = _get_contacts()

    # Direct match
    if chat_name in names or chat_name.startswith("wxid_") or "@chatroom" in chat_name:
        return chat_name

    # Exact match on display name
    chat_lower = chat_name.lower()
    for uname, display in names.items():
        if chat_lower == display.lower():
            return uname

    # Fuzzy match (contains)
    for uname, display in names.items():
        if chat_lower in display.lower():
            return uname

    return None


def _wechat_local_type_parts(local_type):
    """64-bit packed local_type: low 32 = base MsgType, high 32 = sub-type (see export_messages)."""
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


def _find_msg_table(username):
    """Find which DB contains messages for this username. Returns (db_path, table_name)."""
    table = _username_to_table(username)
    for db_path in _get_msg_dbs():
        conn = sqlite3.connect(db_path)
        try:
            exists = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                (table,),
            ).fetchone()
            if exists:
                return db_path, table
        finally:
            conn.close()
    return None, None


def _find_all_msg_tables(username):
    """Find ALL DBs that contain messages for this username. Returns list of (db_path, table_name)."""
    table = _username_to_table(username)
    results = []
    for db_path in _get_msg_dbs():
        conn = sqlite3.connect(db_path)
        try:
            exists = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                (table,),
            ).fetchone()
            if exists:
                results.append((db_path, table))
        finally:
            conn.close()
    return results


def _parse_message(content, local_type, is_group, names, wcdb_ct=None):
    """Parse message content, return formatted string."""
    if content is None:
        return ""
    text = decode_message_content(content, wcdb_ct=wcdb_ct)

    sender = ""
    if is_group and ":\n" in text:
        sender, text = text.split(":\n", 1)
        sender = names.get(sender, sender)

    base_type, type_sub = _wechat_local_type_parts(local_type)
    type_label = MSG_TYPE_MAP.get(base_type, f"type={base_type}")
    if type_sub:
        type_label = f"{type_label} (sub:{type_sub})"
    if base_type != 1:
        quoted = try_format_quote_reply(text)
        if quoted is not None:
            text = f"[引用回复] {quoted}" if text else "[引用回复]"
        else:
            n = 800 if base_type == 49 else 200
            text = f"[{type_label}] {text[:n]}" if text else f"[{type_label}]"

    if len(text) > 500:
        text = text[:500] + "..."

    if sender:
        return f"{sender}: {text}"
    return text


# ── MCP Server ───────────────────────────────────────────────────────────────

mcp = FastMCP("wechat", instructions="查询微信消息、联系人等数据。数据库会自动同步最新聊天记录（每60秒）。")


@mcp.tool()
def sync() -> str:
    """手动同步微信数据库，获取最新聊天记录。
    通常不需要手动调用，查询时会自动同步（每60秒）。
    """
    _auto_sync(force=True)
    return "同步完成，数据库已更新为最新状态。"


@mcp.tool()
def get_recent_sessions(limit: int = 20) -> str:
    """获取微信最近会话列表，包含最新消息摘要、未读数、时间等。
    用于了解最近有哪些人/群在聊天。

    Args:
        limit: 返回的会话数量，默认20
    """
    _auto_sync()
    db = _get_session_db()
    if not os.path.isfile(db):
        return "错误: session.db 未找到，请先运行 python3 decrypt_db.py"

    names = _get_contacts()
    conn = sqlite3.connect(db)
    try:
        rows = conn.execute("""
            SELECT username, unread_count, summary, last_timestamp,
                   last_msg_type, last_sender_display_name
            FROM SessionTable
            WHERE last_timestamp > 0
            ORDER BY last_timestamp DESC
            LIMIT ?
        """, (limit,)).fetchall()
    finally:
        conn.close()

    results = []
    for username, unread, summary, ts, msg_type, sender_name in rows:
        display = names.get(username, username)
        is_group = "@chatroom" in username
        time_str = datetime.fromtimestamp(ts).strftime("%m-%d %H:%M")

        if isinstance(summary, str) and ":\n" in summary:
            summary = summary.split(":\n", 1)[1]
        summary = (summary or "(no content)")[:80]

        type_label = MSG_TYPE_MAP.get(msg_type, "")

        entry = f"[{time_str}] {display}"
        if is_group:
            entry += " [群]"
        if unread and unread > 0:
            entry += f" ({unread}条未读)"
        entry += f"\n  {type_label}: "
        if is_group and sender_name:
            entry += f"{sender_name}: "
        entry += str(summary)
        results.append(entry)

    return f"最近 {len(results)} 个会话:\n\n" + "\n\n".join(results)


@mcp.tool()
def get_chat_history(chat_name: str, limit: int = 50, start_date: str = "", end_date: str = "") -> str:
    """获取指定聊天的消息记录。支持模糊匹配联系人名/备注名，支持按日期范围筛选。

    Args:
        chat_name: 聊天对象的名字、备注名或wxid，自动模糊匹配
        limit: 返回的消息数量，默认50
        start_date: 起始日期（含），格式 YYYY-MM-DD 或 YYYY-MM-DD HH:MM，留空不限
        end_date: 结束日期（含），格式 YYYY-MM-DD 或 YYYY-MM-DD HH:MM，留空不限
    """
    _auto_sync()
    username = _resolve_username(chat_name)
    if not username:
        return f"找不到聊天对象: {chat_name}\n提示: 用 get_contacts(query='{chat_name}') 搜索联系人"

    names = _get_contacts()
    display_name = names.get(username, username)
    is_group = "@chatroom" in username

    db_tables = _find_all_msg_tables(username)
    if not db_tables:
        return f"找不到 {display_name} 的消息记录"

    # Build time filter
    conditions = []
    time_params = []
    if start_date:
        try:
            for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d"):
                try:
                    ts = int(datetime.strptime(start_date, fmt).timestamp())
                    break
                except ValueError:
                    continue
            else:
                return f"日期格式错误: {start_date}，请用 YYYY-MM-DD 或 YYYY-MM-DD HH:MM"
            conditions.append("create_time >= ?")
            time_params.append(ts)
        except Exception:
            return f"日期格式错误: {start_date}，请用 YYYY-MM-DD 或 YYYY-MM-DD HH:MM"
    if end_date:
        try:
            for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d"):
                try:
                    dt = datetime.strptime(end_date, fmt)
                    break
                except ValueError:
                    continue
            else:
                return f"日期格式错误: {end_date}，请用 YYYY-MM-DD 或 YYYY-MM-DD HH:MM"
            # If only date given, include the entire day
            if len(end_date) <= 10:
                dt = dt.replace(hour=23, minute=59, second=59)
            ts = int(dt.timestamp())
            conditions.append("create_time <= ?")
            time_params.append(ts)
        except Exception:
            return f"日期格式错误: {end_date}，请用 YYYY-MM-DD 或 YYYY-MM-DD HH:MM"

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    # Query all matching databases and merge results
    rows = []
    for db_path, table_name in db_tables:
        params = time_params + [limit]
        conn = sqlite3.connect(db_path)
        try:
            has_wcdb = "WCDB_CT_message_content" in msg_table_column_names(conn, table_name)
            if has_wcdb:
                db_rows = conn.execute(f"""
                    SELECT local_type, create_time, message_content, WCDB_CT_message_content
                    FROM [{table_name}]
                    {where}
                    ORDER BY create_time DESC
                    LIMIT ?
                """, params).fetchall()
            else:
                db_rows = conn.execute(f"""
                    SELECT local_type, create_time, message_content
                    FROM [{table_name}]
                    {where}
                    ORDER BY create_time DESC
                    LIMIT ?
                """, params).fetchall()
            rows.extend(db_rows)
        finally:
            conn.close()

    # Sort by time descending and take top N
    rows.sort(key=lambda x: x[1], reverse=True)
    rows = rows[:limit]

    if not rows:
        msg = f"{display_name} 无消息记录"
        if start_date or end_date:
            msg += f"（{start_date or '...'} ~ {end_date or '...'}）"
        return msg

    lines = []
    for row in reversed(rows):
        if len(row) == 4:
            local_type, create_time, content, wcdb_ct = row
        else:
            local_type, create_time, content = row
            wcdb_ct = None
        time_str = datetime.fromtimestamp(create_time).strftime("%m-%d %H:%M")
        text = _parse_message(content, local_type, is_group, names, wcdb_ct=wcdb_ct)
        lines.append(f"[{time_str}] {text}")

    header = f"{display_name} 的 {len(lines)} 条消息"
    if start_date or end_date:
        header += f"（{start_date or '...'} ~ {end_date or '...'}）"
    if is_group:
        header += " [群聊]"
    return header + ":\n\n" + "\n".join(lines)


@mcp.tool()
def search_messages(keyword: str, limit: int = 20) -> str:
    """在所有聊天记录中搜索包含关键词的消息。

    Args:
        keyword: 搜索关键词
        limit: 返回的结果数量，默认20
    """
    _auto_sync()
    if not keyword:
        return "请提供搜索关键词"

    names = _get_contacts()
    results = []

    for db_path in _get_msg_dbs():
        if len(results) >= limit:
            break

        conn = sqlite3.connect(db_path)
        try:
            tables = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg_%'"
            ).fetchall()

            # Build reverse hash -> username mapping
            name2id = {}
            try:
                for (uname,) in conn.execute("SELECT user_name FROM Name2Id"):
                    h = hashlib.md5(uname.encode()).hexdigest()
                    name2id[f"Msg_{h}"] = uname
            except Exception:
                pass

            for (tname,) in tables:
                if len(results) >= limit:
                    break
                username = name2id.get(tname, "")
                is_group = "@chatroom" in username
                display = names.get(username, username) if username else tname

                try:
                    has_wcdb = "WCDB_CT_message_content" in msg_table_column_names(conn, tname)
                    if has_wcdb:
                        rows = conn.execute(f"""
                            SELECT local_type, create_time, message_content, WCDB_CT_message_content
                            FROM [{tname}]
                            WHERE message_content LIKE ?
                            ORDER BY create_time DESC
                            LIMIT ?
                        """, (f"%{keyword}%", limit - len(results))).fetchall()
                    else:
                        rows = conn.execute(f"""
                            SELECT local_type, create_time, message_content
                            FROM [{tname}]
                            WHERE message_content LIKE ?
                            ORDER BY create_time DESC
                            LIMIT ?
                        """, (f"%{keyword}%", limit - len(results))).fetchall()
                except Exception:
                    continue

                for row in rows:
                    if has_wcdb:
                        local_type, ts, content, wcdb_ct = row
                    else:
                        local_type, ts, content = row
                        wcdb_ct = None
                    text = _parse_message(content, local_type, is_group, names, wcdb_ct=wcdb_ct)
                    time_str = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")
                    entry = f"[{time_str}] [{display}] {text}"
                    if len(entry) > 300:
                        entry = entry[:300] + "..."
                    results.append((ts, entry))
        finally:
            conn.close()

    results.sort(key=lambda x: x[0], reverse=True)
    entries = [r[1] for r in results[:limit]]

    if not entries:
        return f'未找到包含 "{keyword}" 的消息'

    return f'搜索 "{keyword}" 找到 {len(entries)} 条结果:\n\n' + "\n\n".join(entries)


@mcp.tool()
def get_contacts(query: str = "", limit: int = 50) -> str:
    """搜索或列出微信联系人。

    Args:
        query: 搜索关键词（匹配昵称、备注名、wxid），留空列出所有
        limit: 返回数量，默认50
    """
    _auto_sync()
    _load_contacts()
    contacts = _contacts_full or []

    if not contacts:
        return "错误: 无法加载联系人数据，请先运行 decrypt_db.py"

    if query:
        q = query.lower()
        filtered = [
            c for c in contacts
            if q in c["nick_name"].lower()
            or q in c["remark"].lower()
            or q in c["username"].lower()
        ]
    else:
        filtered = contacts

    filtered = filtered[:limit]

    if not filtered:
        return f'未找到匹配 "{query}" 的联系人'

    lines = []
    for c in filtered:
        line = c["username"]
        if c["remark"]:
            line += f"  备注: {c['remark']}"
        if c["nick_name"]:
            line += f"  昵称: {c['nick_name']}"
        lines.append(line)

    header = f"找到 {len(filtered)} 个联系人"
    if query:
        header += f" (搜索: {query})"
    return header + ":\n\n" + "\n".join(lines)


if __name__ == "__main__":
    mcp.run()

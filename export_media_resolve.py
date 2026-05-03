"""Fork-local: locate WeChat cached images/emojis + DB-backed hints (hardlink, message_resource).

Keeps ``export_messages.py`` closer to upstream [Thearas/wechat-db-decrypt-macos](https://github.com/Thearas/wechat-db-decrypt-macos)
for easier rebases; extend disk-resolution logic here.
"""

from __future__ import annotations

import functools
import glob
import hashlib
import os
import re
import sqlite3
from datetime import datetime

WECHAT_XWECHAT_FILES_PARENT = os.path.expanduser(
    "~/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files"
)

_PACKED_RESOURCE_MD5_MARKER = b"\x12\x22\x0a\x20"


def _hex_md5_32(value):
    """Return lowercase 32-char hex md5 prefix from attribute string, or None."""
    if not value:
        return None
    v = value.strip().lower()
    if len(v) >= 32 and re.match(r"^[0-9a-f]{32}", v):
        return v[:32]
    return None


def extract_image_md5_from_xml(s: str):
    """32-char lowercase hex MD5 from type-3 <img …> XML, or None."""
    if not s:
        return None
    m_md5 = re.search(r'\bmd5="([^"]+)"', s, re.IGNORECASE)
    if not m_md5:
        m_md5 = re.search(r"<md5>([^<]+)</md5>", s, re.IGNORECASE)
    if not m_md5:
        return None
    return _hex_md5_32(m_md5.group(1))


def parse_image_xml_byte_length(s: str):
    """Pick best integer byte length from <img …> attributes (thumb vs original hints)."""
    if not s:
        return None
    best = None
    for attr in ("cdnthumblength", "length", "totallen"):
        m = re.search(rf'\b{attr}="(\d+)"', s, re.IGNORECASE)
        if m:
            v = int(m.group(1))
            if v > 0:
                best = v
                break
    return best


def summarize_image_message_xml(s: str) -> str:
    """WeChat type-3 content is <msg><img …/> XML pointing at CDN/encrypted data, not inline pixels."""
    if not s or "<img" not in s.lower():
        return ""
    m_len = re.search(
        r'\b(?:length|totallen|cdnthumblength)="(\d+)"', s, re.IGNORECASE
    )
    parts = []
    md5_hex = extract_image_md5_from_xml(s)
    if md5_hex:
        parts.append(f"file_md5={md5_hex}")
    bl = parse_image_xml_byte_length(s)
    if bl is not None:
        parts.append(f"len={bl}")
    elif m_len:
        parts.append(f"len={m_len.group(1)}")
    return " ".join(parts)


def _ym_variants_from_ts(create_time):
    """Try message month ±1 for timezone / indexing quirks."""

    def shift_month(year, month, delta):
        month += delta
        while month > 12:
            month -= 12
            year += 1
        while month < 1:
            month += 12
            year -= 1
        return year, month

    if not create_time:
        return []
    dtv = datetime.fromtimestamp(create_time)
    seen = []
    for delta in (0, -1, 1):
        y, m = shift_month(dtv.year, dtv.month, delta)
        ym = f"{y:04d}-{m:02d}"
        if ym not in seen:
            seen.append(ym)
    return seen


def _rank_img_paths_by_length_hint(paths, byte_len):
    """Prefer thumb variants when XML length is small; full _h/_M when large."""
    thumb = byte_len < 40000

    def tier(p):
        b = os.path.basename(p).lower()
        if thumb:
            if "_t_m.dat" in b or b.endswith("_t.dat"):
                return 0
            if "_t_" in b:
                return 1
            if "_m.dat" in b and "_t" not in b:
                return 2
            return 3
        if "_h.dat" in b or b.endswith("_h.dat"):
            return 0
        if "_m.dat" in b and "_t" not in b:
            return 1
        if b.endswith(".dat") and "_t" not in b:
            return 2
        return 3

    uniq = []
    hit = set()
    for p in paths:
        if p not in hit:
            hit.add(p)
            uniq.append(p)
    uniq.sort(key=lambda p: (tier(p), len(os.path.basename(p))))
    return uniq[0] if uniq else None


def _emoji_attrs_from_body(s: str):
    """Parse attribute map from first <emoji …/> tag."""
    if not s or "<emoji" not in s.lower():
        return {}
    m = re.search(r"<emoji\s+([\s\S]*?)/\s*>", s, re.IGNORECASE)
    if not m:
        m = re.search(r"<emoji\s+([\s\S]*?)>", s, re.IGNORECASE)
    if not m:
        return {}
    blob = m.group(1)
    return {k.lower(): v for k, v in re.findall(r'(\w+)="([^"]*)"', blob)}


def summarize_emoji_message_xml(s: str) -> str:
    """Human-readable sticker line from type-47 <emoji …/> (no truncation)."""
    d = _emoji_attrs_from_body(s)
    if not d:
        return ""
    parts = []
    if d.get("type"):
        parts.append(f"type={d['type']}")
    for label in ("md5", "androidmd5", "externmd5"):
        hx = _hex_md5_32(d.get(label, ""))
        if hx:
            parts.append(f"{label}={hx}")
    if d.get("productid"):
        parts.append(f"productid={d['productid']}")
    if d.get("len"):
        parts.append(f"len={d['len']}")
    return " ".join(parts)


def extract_sticker_md5_candidates_from_xml(s: str):
    """Distinct 32-char hex ids from ``<emoji …>``; disk often matches ``externmd5``."""
    d = _emoji_attrs_from_body(s)
    if not d:
        return []
    order = ("externmd5", "md5", "androidmd5")
    seen = set()
    out = []
    for key in order:
        hx = _hex_md5_32(d.get(key, ""))
        if hx and hx not in seen:
            seen.add(hx)
            out.append(hx)
    return out


def extract_sticker_md5_from_xml(s: str):
    """Pick primary md5 key from emoji XML for cache lookup (legacy order)."""
    for hx in extract_sticker_md5_candidates_from_xml(s):
        return hx
    return None


def parse_emoji_xml_byte_length(s: str):
    """Integer byte length from emoji attributes (for exact-size cache hit)."""
    d = _emoji_attrs_from_body(s)
    if not d:
        return None
    for key in ("len", "length", "totallen"):
        v = (d.get(key) or "").strip()
        if v.isdigit():
            n = int(v)
            if n > 0:
                return n
    return None


def discover_wechat_account_roots(explicit_roots=None):
    """Each root is one folder under xwechat_files (contains msg/, db_storage/, …)."""
    if explicit_roots:
        out = []
        for p in explicit_roots:
            if not p:
                continue
            ap = os.path.abspath(os.path.expanduser(p))
            if os.path.isdir(ap):
                out.append(ap)
        return out
    base = WECHAT_XWECHAT_FILES_PARENT
    if not os.path.isdir(base):
        return []
    roots = []
    for name in sorted(os.listdir(base)):
        path = os.path.join(base, name)
        if os.path.isdir(path) and os.path.isdir(os.path.join(path, "msg")):
            roots.append(path)
    return roots


def find_local_chat_image_path(chat_username, image_md5, account_roots):
    """Locate cached file under ``msg/attach/<md5(chat)>/<YYYY-MM>/{Img,Emoji,...}/``.
    Prefer *_h.dat over *_t.dat."""
    if not chat_username or not image_md5 or not account_roots:
        return None
    chat_hash = hashlib.md5(chat_username.encode("utf-8")).hexdigest()
    im = image_md5.lower()[:32]
    subdirs = ("Img", "Emoji", "emoji", "emotion")
    candidates = []
    for root in account_roots:
        attach = os.path.join(root, "msg", "attach", chat_hash)
        if not os.path.isdir(attach):
            continue
        try:
            for ym in os.listdir(attach):
                for sub in subdirs:
                    sub_dir = os.path.join(attach, ym, sub)
                    if not os.path.isdir(sub_dir):
                        continue
                    try:
                        for fn in os.listdir(sub_dir):
                            if fn.lower().startswith(im):
                                candidates.append(os.path.join(sub_dir, fn))
                    except OSError:
                        continue
        except OSError:
            continue
    if not candidates:
        return None

    def rank(p):
        b = os.path.basename(p).lower()
        pref = 0 if "_h." in b or b.endswith("_h.dat") else 1
        return (pref, b)

    candidates.sort(key=rank)
    return candidates[0]


_media_resolve_cache = {}
_length_resolve_cache = {}
_hardlink_image_resolve_cache = {}
_hardlink_file_resolve_cache = {}
# Built lazily: abspath(account root) -> {32-hex md5 prefix -> [paths under msg/attach]}
_attach_md5_prefix_index: dict[str, dict[str, list[str]]] = {}

_RE_FILE_LEADING_MD5 = re.compile(r"^[0-9a-f]{32}", re.I)


def clear_media_resolve_cache():
    _media_resolve_cache.clear()
    _length_resolve_cache.clear()
    _hardlink_image_resolve_cache.clear()
    _hardlink_file_resolve_cache.clear()
    _attach_md5_prefix_index.clear()
    _lookup_storage_md5_inner.cache_clear()


def _ensure_attach_md5_index(root_abs: str) -> dict[str, list[str]]:
    """Single walk of ``msg/attach`` per account root; cheap global md5 lookups afterward."""
    root_abs = os.path.abspath(root_abs)
    hit = _attach_md5_prefix_index.get(root_abs)
    if hit is not None:
        return hit
    idx: dict[str, list[str]] = {}
    attach = os.path.join(root_abs, "msg", "attach")
    if os.path.isdir(attach):
        try:
            for dirpath, _, filenames in os.walk(attach):
                for fn in filenames:
                    m = _RE_FILE_LEADING_MD5.match(fn)
                    if not m:
                        continue
                    pref = m.group(0).lower()
                    idx.setdefault(pref, []).append(os.path.join(dirpath, fn))
        except OSError:
            pass
    _attach_md5_prefix_index[root_abs] = idx
    return idx


def find_local_chat_image_by_exact_length(
    chat_username,
    byte_len,
    account_roots,
    create_time,
    *,
    attach_subdirs=("Img",),
):
    """Match encrypted cache by exact file size under ``msg/attach/<md5(chat)>/<YYYY-MM>/``."""
    if not chat_username or byte_len is None or byte_len <= 0 or not account_roots:
        return None
    chat_hash = hashlib.md5(chat_username.encode("utf-8")).hexdigest()
    sub_tuple = tuple(attach_subdirs)
    cache_key = (
        tuple(account_roots),
        chat_hash,
        int(byte_len),
        int(create_time or 0),
        sub_tuple,
    )
    if cache_key in _length_resolve_cache:
        return _length_resolve_cache[cache_key]

    matches = []
    for ym in _ym_variants_from_ts(create_time):
        for root in account_roots:
            base = os.path.join(root, "msg", "attach", chat_hash, ym)
            if not os.path.isdir(base):
                continue
            for sub in sub_tuple:
                sub_dir = os.path.join(base, sub)
                if not os.path.isdir(sub_dir):
                    continue
                try:
                    with os.scandir(sub_dir) as it:
                        for ent in it:
                            if not ent.is_file():
                                continue
                            try:
                                if ent.stat().st_size == byte_len:
                                    matches.append(ent.path)
                            except OSError:
                                continue
                except OSError:
                    continue

    best = _rank_img_paths_by_length_hint(matches, byte_len)
    _length_resolve_cache[cache_key] = best
    return best


def _scan_tree_for_md5_prefix(base_dir, md5_prefix, max_depth):
    """Depth-first scan for files whose basename starts with md5_prefix (lower)."""
    if not base_dir or not os.path.isdir(base_dir):
        return []
    md5_prefix = md5_prefix.lower()[:32]
    if len(md5_prefix) < 32:
        return []
    out = []

    def walk(dirpath, depth):
        if depth > max_depth:
            return
        try:
            with os.scandir(dirpath) as it:
                for ent in it:
                    try:
                        if ent.is_file():
                            if ent.name.lower().startswith(md5_prefix):
                                out.append(ent.path)
                        elif ent.is_dir():
                            walk(ent.path, depth + 1)
                    except OSError:
                        continue
        except OSError:
            pass

    walk(base_dir, 0)
    return out


def resolve_monthly_cache_emoticon_path(root_abs: str, md5_32_lower: str) -> str | None:
    """Stickers sometimes appear under ``cache/<YYYY-MM>/Emoticon/<aa>/<fullmd5>``."""
    if not md5_32_lower or len(md5_32_lower) < 32:
        return None
    md5_32_lower = md5_32_lower[:32].lower()
    pref2 = md5_32_lower[:2]
    base = os.path.join(os.path.abspath(root_abs), "cache")
    if not os.path.isdir(base):
        return None
    hits = glob.glob(os.path.join(base, "*", "Emoticon", pref2, md5_32_lower))
    return hits[0] if hits else None


def resolve_business_emoticon_cache_path(root_abs: str, md5_32_lower: str) -> str | None:
    """WeChat stores many downloaded stickers under ``business/emoticon/``, not ``msg/attach``."""
    if not md5_32_lower or len(md5_32_lower) < 32:
        return None
    md5_32_lower = md5_32_lower[:32].lower()
    pref2 = md5_32_lower[:2]
    base = os.path.join(os.path.abspath(root_abs), "business", "emoticon")
    persist = os.path.join(base, "Persist", pref2, md5_32_lower)
    if os.path.isfile(persist):
        return persist
    thumb = os.path.join(base, "Thumb", pref2, f"{md5_32_lower}.thumb")
    if os.path.isfile(thumb):
        return thumb
    return None


def _rank_cached_media_paths(paths):
    """Prefer plaintext images, then full _h.dat, then other .dat, thumbs last."""

    def rank_key(p):
        b = os.path.basename(p).lower()
        ext = os.path.splitext(b)[1]
        tier = 4
        if ext in (".png", ".jpg", ".jpeg", ".gif", ".webp"):
            tier = 0
        elif "_h.dat" in b or b.endswith("_h.dat"):
            tier = 1
        elif b.endswith(".dat"):
            tier = 2
        elif "_t.dat" in b or b.endswith("_t.dat"):
            tier = 3
        return (tier, len(b), b)

    uniq = []
    seen = set()
    for p in paths:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    uniq.sort(key=rank_key)
    return uniq[0] if uniq else None


def resolve_wechat_cached_media(account_roots, md5_hex, chat_username=None):
    """Resolve md5 to a local path: emoticon stores, chat attach trees, then global attach index."""
    im32 = _hex_md5_32(md5_hex) if md5_hex else None
    if not im32 or not account_roots:
        return None

    roots_key = tuple(account_roots)
    cache_key = (roots_key, im32, chat_username or "")
    if cache_key in _media_resolve_cache:
        return _media_resolve_cache[cache_key]

    if chat_username:
        hit = find_local_chat_image_path(chat_username, im32, account_roots)
        if hit:
            _media_resolve_cache[cache_key] = hit
            return hit

    for root in account_roots:
        bp = resolve_business_emoticon_cache_path(root, im32)
        if bp:
            _media_resolve_cache[cache_key] = bp
            return bp
        cp = resolve_monthly_cache_emoticon_path(root, im32)
        if cp:
            _media_resolve_cache[cache_key] = cp
            return cp

    hits = []
    for root in account_roots:
        if chat_username:
            ch = hashlib.md5(chat_username.encode("utf-8")).hexdigest()
            scoped = os.path.join(root, "msg", "attach", ch)
            if os.path.isdir(scoped):
                hits.extend(_scan_tree_for_md5_prefix(scoped, im32, max_depth=14))
        else:
            attach = os.path.join(root, "msg", "attach")
            if os.path.isdir(attach):
                for p in _ensure_attach_md5_index(root).get(im32, ()):
                    hits.append(p)
        for sub in ("Emoji", "emotion", "Emotion"):
            ed = os.path.join(root, sub)
            if os.path.isdir(ed):
                hits.extend(_scan_tree_for_md5_prefix(ed, im32, max_depth=14))

    best = _rank_cached_media_paths(hits)
    _media_resolve_cache[cache_key] = best
    return best


def extract_storage_md5_hex_from_packed_info(blob: bytes | None) -> str | None:
    """Storage-file md5 inside ``MessageResourceDetail.packed_info`` blob."""
    if not blob or not isinstance(blob, (bytes, bytearray)):
        return None
    b = bytes(blob)
    idx = b.find(_PACKED_RESOURCE_MD5_MARKER)
    if idx >= 0 and idx + len(_PACKED_RESOURCE_MD5_MARKER) + 32 <= len(b):
        raw = b[idx + len(_PACKED_RESOURCE_MD5_MARKER) : idx + len(_PACKED_RESOURCE_MD5_MARKER) + 32]
        try:
            s = raw.decode("ascii")
            if len(s) == 32:
                int(s, 16)
                return s.lower()
        except (UnicodeDecodeError, ValueError):
            pass
    ms = re.findall(rb"[0-9a-f]{32}", b, flags=re.I)
    if len(ms) == 1:
        try:
            s = ms[0].decode("ascii")
            int(s, 16)
            return s.lower()
        except ValueError:
            pass
    return None


def message_resource_db_path(decrypted_root: str) -> str | None:
    p = os.path.join(os.path.abspath(decrypted_root), "message", "message_resource.db")
    return p if os.path.isfile(p) else None


@functools.lru_cache(maxsize=8192)
def _lookup_storage_md5_inner(
    resource_db_abs: str,
    chat_username: str,
    message_local_id: int,
    message_create_time: int,
    server_id: int | None,
) -> str | None:
    try:
        conn = sqlite3.connect(f"file:{resource_db_abs}?mode=ro", uri=True)
    except sqlite3.Error:
        return None
    try:
        row = conn.execute(
            "SELECT rowid FROM ChatName2Id WHERE user_name=? LIMIT 1",
            (chat_username,),
        ).fetchone()
        if not row:
            return None
        chat_id = int(row[0])

        def _prefer_server(rows_list):
            rl = rows_list
            if server_id is not None:
                matched = [r for r in rl if r[1] == server_id]
                if matched:
                    return matched
            return rl

        def _packed_md5_for_rows(rows_list):
            for mid, _ in _prefer_server(rows_list):
                for (blob,) in conn.execute(
                    """
                    SELECT packed_info FROM MessageResourceDetail
                    WHERE message_id=? AND packed_info IS NOT NULL
                    """,
                    (int(mid),),
                ):
                    hx = extract_storage_md5_hex_from_packed_info(blob)
                    if hx:
                        return hx
            return None

        strict_rows = conn.execute(
            """
            SELECT message_id, message_svr_id FROM MessageResourceInfo
            WHERE chat_id=? AND message_local_id=? AND message_create_time=?
            """,
            (chat_id, int(message_local_id), int(message_create_time)),
        ).fetchall()
        hx = _packed_md5_for_rows(strict_rows)
        if hx:
            return hx

        loose_rows = conn.execute(
            """
            SELECT message_id, message_svr_id FROM MessageResourceInfo
            WHERE chat_id=? AND message_local_id=?
            ORDER BY ABS(message_create_time - ?) ASC, message_id ASC
            LIMIT 24
            """,
            (chat_id, int(message_local_id), int(message_create_time)),
        ).fetchall()
        strict_mids = {int(r[0]) for r in strict_rows}
        loose_rows = [r for r in loose_rows if int(r[0]) not in strict_mids]
        return _packed_md5_for_rows(loose_rows)
    finally:
        conn.close()


def lookup_storage_md5_via_message_resource(
    decrypted_root: str | None,
    chat_username: str | None,
    message_local_id: int | None,
    message_create_time: int | None,
    server_id: int | None,
) -> str | None:
    """Storage md5 from ``message_resource.db`` for this row (best-effort join)."""
    if (
        not decrypted_root
        or not chat_username
        or message_local_id is None
        or message_create_time is None
    ):
        return None
    db = message_resource_db_path(decrypted_root)
    if not db:
        return None
    return _lookup_storage_md5_inner(
        os.path.abspath(db),
        chat_username,
        int(message_local_id),
        int(message_create_time),
        server_id,
    )


def _dir2_folder_month(conn, d1, d2):
    rh = conn.execute(
        "SELECT username FROM dir2id WHERE rowid=? LIMIT 1", (int(d1),)
    ).fetchone()
    ym_row = conn.execute(
        "SELECT username FROM dir2id WHERE rowid=? LIMIT 1", (int(d2),)
    ).fetchone()
    if not rh or not ym_row:
        return None
    return rh[0], ym_row[0]


def resolve_image_via_hardlink_db(md5_hex, hardlink_db_path, account_roots):
    """``image_hardlink_info_v4`` → ``attach/<folder>/<month>/Img/<file>``."""
    im32 = _hex_md5_32(md5_hex) if md5_hex else None
    if not im32 or not hardlink_db_path or not account_roots:
        return None
    db_abs = os.path.abspath(hardlink_db_path)
    key = ("img", db_abs, im32)
    if key in _hardlink_image_resolve_cache:
        return _hardlink_image_resolve_cache[key]

    conn = sqlite3.connect(db_abs)
    try:
        row = conn.execute(
            "SELECT file_name, dir1, dir2 FROM image_hardlink_info_v4 WHERE lower(md5)=? LIMIT 1",
            (im32,),
        ).fetchone()
        if not row:
            _hardlink_image_resolve_cache[key] = None
            return None
        fn, d1, d2 = row
        pair = _dir2_folder_month(conn, d1, d2)
        if not pair:
            _hardlink_image_resolve_cache[key] = None
            return None
        folder_hash, month = pair
        for root in account_roots:
            path = os.path.normpath(
                os.path.join(root, "msg", "attach", folder_hash, month, "Img", fn)
            )
            if os.path.isfile(path):
                _hardlink_image_resolve_cache[key] = path
                return path
        _hardlink_image_resolve_cache[key] = None
        return None
    finally:
        conn.close()


def resolve_file_via_hardlink_db(md5_hex, hardlink_db_path, account_roots):
    """``file_hardlink_info_v4`` → attach path (often **no** ``Img/`` subdir; stickers vary)."""
    im32 = _hex_md5_32(md5_hex) if md5_hex else None
    if not im32 or not hardlink_db_path or not account_roots:
        return None
    db_abs = os.path.abspath(hardlink_db_path)
    key = ("file", db_abs, im32)
    if key in _hardlink_file_resolve_cache:
        return _hardlink_file_resolve_cache[key]

    conn = sqlite3.connect(db_abs)
    try:
        row = conn.execute(
            "SELECT file_name, dir1, dir2 FROM file_hardlink_info_v4 WHERE lower(md5)=? LIMIT 1",
            (im32,),
        ).fetchone()
        if not row:
            _hardlink_file_resolve_cache[key] = None
            return None
        fn, d1, d2 = row
        pair = _dir2_folder_month(conn, d1, d2)
        if not pair:
            _hardlink_file_resolve_cache[key] = None
            return None
        folder_hash, month = pair
        bases = [
            ["msg", "attach", folder_hash, month, fn],
            ["msg", "attach", folder_hash, month, "Img", fn],
            ["msg", "attach", folder_hash, month, "Emoji", fn],
            ["msg", "attach", folder_hash, month, "emoji", fn],
        ]
        for root in account_roots:
            for parts in bases:
                path = os.path.normpath(os.path.join(root, *parts))
                if os.path.isfile(path):
                    _hardlink_file_resolve_cache[key] = path
                    return path
        _hardlink_file_resolve_cache[key] = None
        return None
    finally:
        conn.close()


def resolve_any_hardlink_db(md5_hex, hardlink_db_path, account_roots):
    """Try image index then file index (covers stickers / PDF / misc cache names)."""
    p = resolve_image_via_hardlink_db(md5_hex, hardlink_db_path, account_roots)
    if p:
        return p
    return resolve_file_via_hardlink_db(md5_hex, hardlink_db_path, account_roots)

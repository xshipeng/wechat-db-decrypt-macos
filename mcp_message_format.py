"""Fork-local: MCP-facing message text (Chinese type labels, truncation).

Shared ``local_type`` unpacking lives in ``export_messages.wechat_local_type_parts``.
"""

from __future__ import annotations

from export_messages import (
    decode_message_content,
    try_format_quote_reply,
    wechat_local_type_parts,
)

MSG_TYPE_MAP = {
    1: "文本",
    3: "图片",
    34: "语音",
    42: "名片",
    43: "视频",
    47: "表情",
    48: "位置",
    49: "链接/文件",
    50: "通话",
    10000: "系统",
    10002: "撤回",
}


def format_mcp_message(content, local_type, is_group, names, wcdb_ct=None):
    """Parse message content for MCP tools; return formatted string."""
    if content is None:
        return ""
    text = decode_message_content(content, wcdb_ct=wcdb_ct)

    sender = ""
    if is_group and ":\n" in text:
        sender, text = text.split(":\n", 1)
        sender = names.get(sender, sender)

    base_type, type_sub = wechat_local_type_parts(local_type)
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

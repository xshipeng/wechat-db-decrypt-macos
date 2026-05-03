"""Fork-local: Markdown ``![](…)`` links + decode WeChat ``.dat`` cache for preview.

Formats (see also `L1en2407/wechat-decrypt`_):

- **Legacy**: whole file single-byte XOR (detect key via image magic).
- **V1** header ``\\x07\\x08V1\\x08\\x07``: AES-128-ECB + optional middle/raw + XOR tail (fixed AES key).
- **V2** header ``\\x07\\x08V2\\x08\\x07``: same layout as V1 but **per-session AES key** must be supplied
  (typically extracted from WeChat process memory while logged in).

.. _L1en2407/wechat-decrypt: https://github.com/L1en2407/wechat-decrypt

Requires ``cryptography`` **or** a working ``openssl`` CLI on PATH for V1/V2 AES sections.
"""

from __future__ import annotations

import hashlib
import os
import struct
import subprocess
from urllib.parse import quote

V2_MAGIC_FULL = b"\x07\x08V2\x08\x07"
V1_MAGIC_FULL = b"\x07\x08V1\x08\x07"

# Fixed V1 AES key from community reverse-engineering (same as L1en2407/wechat-decrypt).
V1_FIXED_AES_KEY = b"cfcd208495d565ef"


def load_wechat_dat_aes_key_v2(cli_hex: str | None = None) -> bytes | None:
    """16-byte AES key for V2 `.dat` blobs: 32 hex chars from CLI, env, or file."""
    raw = (cli_hex or "").strip()
    if not raw:
        raw = os.environ.get("WECHAT_DAT_AES_KEY", "").strip()
    if not raw:
        path = os.environ.get("WECHAT_DAT_AES_KEY_FILE", "").strip()
        if path and os.path.isfile(path):
            try:
                with open(path, encoding="utf-8") as f:
                    raw = f.read().strip()
            except OSError:
                raw = ""
    if len(raw) == 32:
        try:
            k = bytes.fromhex(raw)
            if len(k) == 16:
                return k
        except ValueError:
            pass
    return None


def markdown_image_link(abs_media_path, relative_to_dir):
    """Markdown image with path relative to export directory (URL-encoded)."""
    rel = os.path.relpath(abs_media_path, os.path.abspath(relative_to_dir))
    rel_posix = rel.replace(os.sep, "/")
    return f"![image]({quote(rel_posix, safe='/')})"


def _pkcs7_unpad(p: bytes, block_size: int = 16) -> bytes:
    if not p or len(p) % block_size != 0:
        raise ValueError("bad PKCS7 length")
    n = p[-1]
    if n < 1 or n > block_size:
        raise ValueError("bad PKCS7 byte")
    if p[-n:] != bytes([n]) * n:
        raise ValueError("bad PKCS7 block")
    return p[:-n]


def _aes_ecb_decrypt_blocks(key16: bytes, ciphertext: bytes) -> bytes | None:
    if len(key16) != 16 or len(ciphertext) % 16 != 0:
        return None
    try:
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        cipher = Cipher(
            algorithms.AES(key16), modes.ECB(), backend=default_backend()
        )
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
    except ImportError:
        pass
    try:
        proc = subprocess.run(
            [
                "openssl",
                "enc",
                "-aes-128-ecb",
                "-d",
                "-nopad",
                "-K",
                key16.hex(),
            ],
            input=ciphertext,
            capture_output=True,
            timeout=120,
            check=False,
        )
        if proc.returncode != 0:
            return None
        return proc.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def _aligned_aes_cipher_length(aes_size: int) -> int:
    aes_size &= 0xFFFFFFFF
    aligned = aes_size
    aligned -= ~(~aligned % 16)
    return aligned & 0xFFFFFFFF


def _plain_raster_magic_suffix(head: bytes) -> str | None:
    """If ``head`` begins like JPEG/PNG/GIF/WebP, return output suffix; else None."""
    if len(head) < 3:
        return None
    if head[:3] == b"\xff\xd8\xff":
        return ".jpg"
    if len(head) >= 4 and head[:4] == b"\x89PNG":
        return ".png"
    if len(head) >= 6 and head[:6] in (b"GIF87a", b"GIF89a"):
        return ".gif"
    if (
        len(head) >= 12
        and head[:4] == b"RIFF"
        and head[8:12] == b"WEBP"
    ):
        return ".webp"
    return None


def _suffix_from_decrypted_head(head: bytes) -> str:
    if len(head) < 3:
        return ".bin"
    if head[:3] == b"\xff\xd8\xff":
        return ".jpg"
    if len(head) >= 4 and head[:4] == b"\x89PNG":
        return ".png"
    if len(head) >= 6 and head[:6] in (b"GIF87a", b"GIF89a"):
        return ".gif"
    if (
        len(head) >= 12
        and head[:4] == b"RIFF"
        and head[8:12] == b"WEBP"
    ):
        return ".webp"
    if head[:4] == b"wxgf":
        return ".wxgf"
    return ".bin"


def _decode_wechat_v1_v2_dat(
    data: bytes,
    *,
    aes_key_16: bytes,
    xor_tail_byte: int = 0x88,
) -> bytes | None:
    if len(data) < 15:
        return None
    sig = data[:6]
    if sig not in (V1_MAGIC_FULL, V2_MAGIC_FULL):
        return None

    aes_size, xor_size = struct.unpack_from("<II", data, 6)
    aligned_aes = _aligned_aes_cipher_length(aes_size)
    offset = 15
    if offset + aligned_aes > len(data):
        return None

    aes_blob = data[offset : offset + aligned_aes]
    plain_aes = _aes_ecb_decrypt_blocks(aes_key_16, aes_blob)
    if plain_aes is None:
        return None
    try:
        dec_aes = _pkcs7_unpad(plain_aes, 16)
    except ValueError:
        return None

    offset += aligned_aes
    raw_end = len(data) - xor_size
    raw_part = data[offset:raw_end] if offset < raw_end else b""
    xor_part = data[raw_end:]
    dec_xor = bytes(b ^ xor_tail_byte for b in xor_part)
    return dec_aes + raw_part + dec_xor


def _decode_legacy_xor_dat(data: bytes) -> tuple[bytes, str] | tuple[None, None]:
    """Whole-file single-byte XOR (classic WeChat cache)."""
    if not data or len(data) < 8:
        return None, None

    magics = (
        (bytes([0xFF, 0xD8, 0xFF]), ".jpg"),
        (
            bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
            ".png",
        ),
        (b"GIF89a", ".gif"),
        (b"GIF87a", ".gif"),
        (bytes([0x52, 0x49, 0x46, 0x46]), ".webp"),
    )
    for magic, ext in magics:
        if len(data) < len(magic):
            continue
        key = data[0] ^ magic[0]
        ok = True
        for i in range(1, len(magic)):
            if (data[i] ^ key) != magic[i]:
                ok = False
                break
        if ok:
            return bytes(b ^ key for b in data), ext
    return None, None


def decode_wechat_dat_image(
    data: bytes,
    aes_key_v2_16: bytes | None = None,
    *,
    xor_tail_byte: int = 0x88,
) -> tuple[bytes | None, str | None]:
    """Decode `.dat` payload → ``(pixels, suffix)`` or ``(None, None)``.

    V1 uses a fixed built-in key. V2 requires ``aes_key_v2_16`` (16 raw bytes).
    """
    if not data:
        return None, None

    if len(data) >= 6:
        sig = data[:6]
        if sig == V1_MAGIC_FULL:
            dec = _decode_wechat_v1_v2_dat(
                data, aes_key_16=V1_FIXED_AES_KEY, xor_tail_byte=xor_tail_byte
            )
            if dec:
                return dec, _suffix_from_decrypted_head(dec[:32])
            return None, None
        if sig == V2_MAGIC_FULL:
            if not aes_key_v2_16 or len(aes_key_v2_16) != 16:
                return None, None
            dec = _decode_wechat_v1_v2_dat(
                data, aes_key_16=aes_key_v2_16, xor_tail_byte=xor_tail_byte
            )
            if dec:
                return dec, _suffix_from_decrypted_head(dec[:32])
            return None, None

    dec, suf = _decode_legacy_xor_dat(data)
    return dec, suf


def decode_wechat_xor_image_dat(data: bytes):
    """Compatibility alias: same as ``decode_wechat_dat_image`` without V2 key."""
    return decode_wechat_dat_image(data, aes_key_v2_16=None)


def _failure_hint(raw: bytes, *, aes_key_v2_supplied: bool) -> str:
    if len(raw) >= 6 and raw[:6] == V2_MAGIC_FULL:
        if not aes_key_v2_supplied:
            return (
                "*(微信 V2 `.dat`：需 16 字节 AES key → `--dat-aes-key HEX32` 或环境变量 "
                "`WECHAT_DAT_AES_KEY` / `WECHAT_DAT_AES_KEY_FILE`；密钥需从已登录微信进程内存提取，"
                "可参考 [L1en2407/wechat-decrypt](https://github.com/L1en2407/wechat-decrypt))*"
            )
        return (
            "*(V2 `.dat` AES 解密失败：密钥不匹配或格式已变更；仍可使用 `--raw-dat-links` 指向原始 `.dat`)*"
        )
    if len(raw) >= 6 and raw[:6] == V1_MAGIC_FULL:
        return (
            "*(V1 `.dat` AES 解密失败：请 `pip install cryptography` 或确保系统 PATH 上有 `openssl`)*"
        )
    return (
        "*(`.dat` 无法用内置规则解码：既非 V1/V2，也非常见 XOR 缩略图)*"
    )


def markdown_inline_image_link(
    abs_media_path,
    relative_to_dir,
    *,
    decode_xor_dat=True,
    aes_key_v2_16: bytes | None = None,
    xor_tail_byte: int = 0x88,
):
    """Emit ``![](…)`` for Markdown preview.

    Writes decoded JPEG/PNG (etc.) under ``_wechat_media/`` beside the export when possible.
    WeChat sticker caches under ``…/Emoticon/…`` are often encrypted blobs (not raster files):
    those get a short italic note instead of a broken ``![](…)``.
    """
    abs_media_path = os.path.abspath(abs_media_path)
    rel_base = os.path.abspath(relative_to_dir)
    low = abs_media_path.lower()
    norm = low.replace("\\", "/")

    def _write_wechat_media(dec: bytes, suffix: str, sig: tuple) -> str | None:
        media_dir = os.path.join(rel_base, "_wechat_media")
        os.makedirs(media_dir, exist_ok=True)
        h = hashlib.sha256(f"{sig[0]}\0{sig[1]}\0{sig[2]}".encode()).hexdigest()[:28]
        out_abs = os.path.join(media_dir, f"{h}{suffix}")
        try:
            if not os.path.isfile(out_abs) or os.path.getsize(out_abs) != len(dec):
                with open(out_abs, "wb") as wf:
                    wf.write(dec)
        except OSError:
            return None
        return markdown_image_link(out_abs, rel_base)

    if decode_xor_dat and low.endswith(".dat"):
        try:
            with open(abs_media_path, "rb") as f:
                raw = f.read()
            st = os.stat(abs_media_path)
            stamp = getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9))
            sig = (abs_media_path, stamp, st.st_size)
        except OSError:
            return markdown_image_link(abs_media_path, rel_base)

        dec, suffix = decode_wechat_dat_image(
            raw, aes_key_v2_16=aes_key_v2_16, xor_tail_byte=xor_tail_byte
        )
        if not dec:
            link = markdown_image_link(abs_media_path, rel_base)
            hint = _failure_hint(raw, aes_key_v2_supplied=aes_key_v2_16 is not None)
            return f"{link} {hint}"

        out = _write_wechat_media(dec, suffix or ".bin", sig)
        return out or markdown_image_link(abs_media_path, rel_base)

    # Extensionless / .thumb caches under sticker dirs are usually encrypted, not PNG/JPEG.
    if decode_xor_dat and (
        "/emoticon/" in norm or "/business/emoticon/" in norm
    ):
        try:
            with open(abs_media_path, "rb") as f:
                raw = f.read()
            st = os.stat(abs_media_path)
            stamp = getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9))
            sig = (abs_media_path, stamp, st.st_size)
        except OSError:
            return markdown_image_link(abs_media_path, rel_base)

        plain_suf = _plain_raster_magic_suffix(raw[:32])
        if plain_suf:
            out = _write_wechat_media(raw, plain_suf, sig)
            if out:
                return out

        dec, suffix = decode_wechat_dat_image(
            raw, aes_key_v2_16=aes_key_v2_16, xor_tail_byte=xor_tail_byte
        )
        if dec:
            out = _write_wechat_media(dec, suffix or ".bin", sig)
            if out:
                return out

        bn = os.path.basename(abs_media_path)
        return (
            f"*「表情包」`{bn}`（{len(raw)} B）：微信本地缓存多为加密二进制，"
            "不是 JPG/PNG，`![](…)` 无法正常预览。*"
        )

    return markdown_image_link(abs_media_path, rel_base)

"""Safe payload handling.

"Safe" here means:
  * Only a SHORT preview is ever shown (default 64 bytes) - payloads are never
    stored or accumulated in memory.
  * Bytes are never executed, evaluated or blindly decoded: control characters
    are replaced with '.', so terminal escape sequences in a packet cannot
    mess with your terminal.
  * Obvious secrets (Authorization / Cookie headers, password=... fields) are
    replaced with [REDACTED] before display. This is best-effort, NOT a
    guarantee - treat any capture as sensitive.
"""

from __future__ import annotations

import re
from typing import Tuple

# Whole-line HTTP headers that usually carry credentials or session identifiers.
_SENSITIVE_HEADER = re.compile(
    r"(?im)^(authorization|proxy-authorization|cookie|set-cookie)[ \t]*:[^\r\n]*"
)
# key=value pairs in URLs / form bodies that usually carry secrets.
_SENSITIVE_FIELD = re.compile(
    r"(?i)\b(password|passwd|pwd|pass|token|access_token|secret|api_key|apikey|sessionid)=[^&\s\"']*"
)

# If at least this fraction of the previewed bytes is printable, treat it as text.
_TEXT_THRESHOLD = 0.85


def redact_sensitive(text: str) -> str:
    """Hide credentials that commonly appear in clear-text HTTP traffic."""
    text = _SENSITIVE_HEADER.sub(lambda m: m.group(1) + ": [REDACTED]", text)
    text = _SENSITIVE_FIELD.sub(lambda m: m.group(1) + "=[REDACTED]", text)
    return text


def _is_printable(byte: int) -> bool:
    return 32 <= byte <= 126 or byte in (9, 10, 13)


def is_mostly_text(data: bytes) -> bool:
    """Heuristic: is this chunk of bytes readable text (vs binary/encrypted)?"""
    if not data:
        return False
    printable = sum(1 for b in data if _is_printable(b))
    return printable / len(data) >= _TEXT_THRESHOLD


def printable_preview(data: bytes, max_bytes: int = 64) -> str:
    """Turn the first `max_bytes` of `data` into a single safe line of text.

    * CR / LF / TAB are shown as the visible escapes \\r \\n \\t
    * every other non-printable byte becomes '.'
    * sensitive values are redacted
    * a "(+N more bytes)" suffix shows how much was cut off
    """
    chunk = data[:max_bytes]
    # latin-1 maps every byte 0-255 to a character, so this can never fail.
    text = redact_sensitive(chunk.decode("latin-1"))

    parts = []
    for ch in text:
        code = ord(ch)
        if ch == "\r":
            parts.append("\\r")
        elif ch == "\n":
            parts.append("\\n")
        elif ch == "\t":
            parts.append("\\t")
        elif 32 <= code <= 126:
            parts.append(ch)
        else:
            parts.append(".")
    preview = "".join(parts)

    hidden = len(data) - len(chunk)
    if hidden > 0:
        preview += f" ...(+{hidden} more bytes)"
    return preview


def hex_preview(data: bytes, max_bytes: int = 16) -> str:
    """Compact hex string of the first bytes, e.g. '16 03 01 02 00 ...'."""
    chunk = data[:max_bytes]
    text = " ".join(f"{b:02x}" for b in chunk)
    return text + (" ..." if len(data) > max_bytes else "")


def hexdump(data: bytes, width: int = 16) -> str:
    """Classic hexdump: offset | hex bytes | ASCII column."""
    lines = []
    for offset in range(0, len(data), width):
        row = data[offset:offset + width]
        hex_part = " ".join(f"{b:02x}" for b in row).ljust(width * 3 - 1)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in row)
        lines.append(f"{offset:04x}  {hex_part}  |{ascii_part}|")
    return "\n".join(lines)


def describe_payload(data: bytes, max_bytes: int = 64) -> Tuple[str, str]:
    """Return (kind, text) used by the compact display.

    kind is 'text' or 'binary'. Text is shown as a safe string; binary data is
    shown as a short hex string because ASCII would just be noise.
    """
    if is_mostly_text(data[:max_bytes]):
        return "text", printable_preview(data, max_bytes)
    return "binary", hex_preview(data, min(max_bytes, 16))

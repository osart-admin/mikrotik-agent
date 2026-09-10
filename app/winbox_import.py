"""Parse Winbox 3 ``Addresses.cdb`` (the address book) into candidate devices.

The file is a sequence of MikroTik "M2" binary messages, one per saved address. Field ids are
not documented; the UI shows what was found per field id and lets the user map/confirm columns.
If the structured parse finds nothing, a printable-strings fallback is used.
"""
from __future__ import annotations

import re
import struct
from typing import Any

MAGIC = b"M2"
_HOST_RE = re.compile(r"^(\[?[0-9a-fA-F:.\-]+\]?|[\w.-]+)(:\d{1,5})?$")
_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")


def _parse_message(buf: bytes, pos: int, end: int) -> tuple[dict[int, Any], int]:
    fields: dict[int, Any] = {}
    while pos + 4 <= end:
        fid = buf[pos] | (buf[pos + 1] << 8) | (buf[pos + 2] << 16)
        t = buf[pos + 3]
        pos += 4
        kind, short, is_array = t & 0x78, t & 0x01, t & 0x80
        if is_array:
            if pos + 2 > end:
                break
            count = struct.unpack_from("<H", buf, pos)[0]
            pos += 2
            items = []
            for _ in range(count):
                if kind == 0x00:
                    items.append(bool(buf[pos])); pos += 1
                elif kind == 0x08:
                    items.append(struct.unpack_from("<I", buf, pos)[0]); pos += 4
                elif kind == 0x10:
                    items.append(struct.unpack_from("<Q", buf, pos)[0]); pos += 8
                elif kind == 0x18:
                    items.append(buf[pos:pos + 16].hex()); pos += 16
                elif kind in (0x20, 0x28, 0x30):
                    ln = struct.unpack_from("<H", buf, pos)[0]; pos += 2
                    raw = buf[pos:pos + ln]; pos += ln
                    items.append(raw.decode("utf-8", "replace") if kind == 0x20 else raw.hex())
                else:
                    raise ValueError("unknown array kind")
            fields[fid] = items
            continue
        if kind == 0x00:
            fields[fid] = bool(short)
        elif kind == 0x08:
            if short:
                fields[fid] = buf[pos]; pos += 1
            else:
                fields[fid] = struct.unpack_from("<I", buf, pos)[0]; pos += 4
        elif kind == 0x10:
            fields[fid] = struct.unpack_from("<Q", buf, pos)[0]; pos += 8
        elif kind == 0x18:
            fields[fid] = buf[pos:pos + 16].hex(); pos += 16
        elif kind in (0x20, 0x28, 0x30):
            if short:
                ln = buf[pos]; pos += 1
            else:
                ln = struct.unpack_from("<H", buf, pos)[0]; pos += 2
            raw = buf[pos:pos + ln]; pos += ln
            if kind == 0x20:
                fields[fid] = raw.decode("utf-8", "replace")
            elif kind == 0x28:
                sub, _ = _parse_message(raw, 2 if raw.startswith(MAGIC) else 0, len(raw))
                fields[fid] = sub
            else:
                fields[fid] = raw.hex()
        else:
            raise ValueError(f"unknown field type 0x{t:02x}")
        if pos > end:
            raise ValueError("overrun")
    return fields, pos


def parse_cdb(data: bytes) -> list[dict[int, Any]]:
    records: list[dict[int, Any]] = []
    pos = 0
    while True:
        i = data.find(MAGIC, pos)
        if i < 0:
            break
        # Prefer the record length prefix (4 bytes LE before the magic) when it is plausible.
        end = len(data)
        if i >= 4:
            ln = struct.unpack_from("<I", data, i - 4)[0]
            if 2 < ln <= len(data) - (i - 4):
                end = i - 4 + ln + 4 if data[i - 4 + 4: i - 4 + 6] == MAGIC and i - 4 + ln <= len(data) else i + ln
                end = min(end, len(data))
        try:
            fields, consumed = _parse_message(data, i + 2, end)
        except (ValueError, IndexError, struct.error):
            fields, consumed = {}, i + 2
        if any(isinstance(v, str) and v for v in fields.values()):
            records.append(fields)
        pos = max(consumed, i + 2)
    return records


def fallback_strings(data: bytes) -> list[dict[int, Any]]:
    """Group printable strings between M2 magics - crude, but gives the user something to map."""
    out = []
    for chunk in data.split(MAGIC)[1:]:
        strings = [s.decode("utf-8", "replace") for s in re.findall(rb"[\x20-\x7e]{2,}", chunk)]
        if strings:
            out.append({i + 1: s for i, s in enumerate(strings)})
    return out


def guess_mapping(records: list[dict[int, Any]]) -> dict[str, int | None]:
    """Guess which field id holds host/login/password/note by looking at the values."""
    ids = sorted({k for r in records for k, v in r.items() if isinstance(v, str)})
    score_host = {i: sum(1 for r in records if isinstance(r.get(i), str) and (_HOST_RE.match(r[i]) or _MAC_RE.match(r[i])) and any(ch.isdigit() for ch in r[i])) for i in ids}
    host = max(score_host, key=score_host.get) if ids and max(score_host.values()) > 0 else (ids[0] if ids else None)
    rest = [i for i in ids if i != host]
    login = next((i for i in rest if sum(1 for r in records if str(r.get(i, "")).lower() in ("admin", "root", "agent")) > 0), rest[0] if rest else None)
    rest = [i for i in rest if i != login]
    password = rest[0] if rest else None
    rest = rest[1:]
    note = rest[0] if rest else None
    return {"host": host, "login": login, "password": password, "note": note}


def to_devices(records: list[dict[int, Any]], mapping: dict[str, int | None]) -> list[dict[str, str]]:
    out = []
    for r in records:
        host = str(r.get(mapping.get("host") or -1, "") or "").strip()
        if not host:
            continue
        port = 22
        if host.count(":") == 1 and host.rsplit(":", 1)[1].isdigit():
            host, port_s = host.rsplit(":", 1)
            port = 22  # the address-book port is the Winbox port, not SSH
        out.append({
            "host": host, "port": str(port),
            "login": str(r.get(mapping.get("login") or -1, "") or ""),
            "password": str(r.get(mapping.get("password") or -1, "") or ""),
            "note": str(r.get(mapping.get("note") or -1, "") or ""),
            "is_mac": bool(_MAC_RE.match(host)),
        })
    return out

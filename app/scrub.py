"""Strip secrets from text before it leaves for the LLM.

``/export hide-sensitive`` and a read-only user without the ``sensitive`` policy already keep
most secrets out of the stored exports; this is the last line of defence for anything that
slips through (script sources, live command output, older RouterOS).
"""
from __future__ import annotations

import re

SENSITIVE_KEYS = (
    "password", "passwd", "secret", "private-key", "preshared-key", "pre-shared-key",
    "wpa-pre-shared-key", "wpa2-pre-shared-key", "passphrase", "shared-secret", "auth-password",
    "encryption-password", "ca-passphrase", "auth-key", "priv-key", "encryption-key", "api-key",
    "token", "psk", "radius-secret", "client-secret", "connection-password", "peer-secret",
)
_KEY_RE = re.compile(
    r"(?<![\w.-])(?P<key>\.?(?:[\w-]+\.)*(?:" + "|".join(re.escape(k) for k in SENSITIVE_KEYS) + r"))="
    r"(?P<val>\"(?:[^\"\\]|\\.)*\"|\S+)",
    re.IGNORECASE,
)
# snmp community names are the credential; `/snmp community add name=public`
_SNMP_RE = re.compile(r"^(/snmp/? community add .*?\bname=)(\"(?:[^\"\\]|\\.)*\"|\S+)", re.IGNORECASE)
_PLACEHOLDER = '"<hidden>"'


def scrub(text: str) -> tuple[str, dict[str, int]]:
    """Return (scrubbed text, {key: occurrences})."""
    counts: dict[str, int] = {}

    def repl(m: re.Match) -> str:
        key = m.group("key")
        counts[key] = counts.get(key, 0) + 1
        return f"{key}={_PLACEHOLDER}"

    out_lines = []
    for line in text.splitlines(keepends=True):
        line = _KEY_RE.sub(repl, line)
        m = _SNMP_RE.match(line)
        if m:
            counts["snmp-community"] = counts.get("snmp-community", 0) + 1
            line = m.group(1) + _PLACEHOLDER + line[m.end():]
        out_lines.append(line)
    return "".join(out_lines), counts

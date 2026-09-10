"""Fernet-based encryption for secrets kept in the DB (API key, SSH keys, device passwords).

Key resolution: MASTER_KEY env var, else /data/master.key (created on first run).
Losing the key makes every stored secret unrecoverable - same trade-off as edupage-agent.
"""
from __future__ import annotations

import os

from cryptography.fernet import Fernet, InvalidToken

from .config import MASTER_KEY_PATH

_fernet: Fernet | None = None


def _load_key() -> bytes:
    env = os.getenv("MASTER_KEY", "").strip()
    if env:
        return env.encode()
    if MASTER_KEY_PATH.exists():
        return MASTER_KEY_PATH.read_bytes().strip()
    MASTER_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    key = Fernet.generate_key()
    MASTER_KEY_PATH.write_bytes(key)
    os.chmod(MASTER_KEY_PATH, 0o600)
    return key


def fernet() -> Fernet:
    global _fernet
    if _fernet is None:
        _fernet = Fernet(_load_key())
    return _fernet


def encrypt(value: str) -> str:
    return fernet().encrypt(value.encode()).decode()


def decrypt(token: str) -> str:
    try:
        return fernet().decrypt(token.encode()).decode()
    except InvalidToken as exc:
        raise ValueError("cannot decrypt: master key changed or data corrupt") from exc

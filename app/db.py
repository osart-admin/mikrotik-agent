"""SQLite persistence: users, settings, secrets, devices, collection runs, chats, audit.

Small app, small tables - plain sqlite3 with short-lived connections is enough.
"""
from __future__ import annotations

import json
import re
import secrets as pysecrets
import sqlite3
from datetime import datetime, timezone
from typing import Any

from . import vault
from .config import DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'admin',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS secrets (
    key TEXT PRIMARY KEY,
    value_enc TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY,
    slug TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 22,
    username TEXT NOT NULL DEFAULT 'agent',
    auth TEXT NOT NULL DEFAULT 'key',          -- 'key' | 'password'
    password_enc TEXT,
    site TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL DEFAULT '',
    tags TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    -- discovered facts
    identity TEXT, ros_version TEXT, board TEXT, model TEXT, serial TEXT, arch TEXT,
    -- volatile state (never goes to git)
    status TEXT NOT NULL DEFAULT 'new',        -- new | ok | unreachable | auth_failed | error
    status_message TEXT NOT NULL DEFAULT '',
    last_seen TEXT, last_collected TEXT, last_changed TEXT,
    uptime TEXT, cpu_load TEXT, export_lines INTEGER
);
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    trigger TEXT NOT NULL DEFAULT 'manual',
    ok_count INTEGER NOT NULL DEFAULT 0,
    fail_count INTEGER NOT NULL DEFAULT 0,
    changed_count INTEGER NOT NULL DEFAULT 0,
    commit_sha TEXT
);
CREATE TABLE IF NOT EXISTS run_devices (
    run_id INTEGER NOT NULL,
    device_id INTEGER NOT NULL,
    status TEXT NOT NULL,
    message TEXT NOT NULL DEFAULT '',
    changed INTEGER NOT NULL DEFAULT 0,
    duration_ms INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (run_id, device_id)
);
CREATE TABLE IF NOT EXISTS chats (
    id INTEGER PRIMARY KEY,
    title TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY,
    chat_id INTEGER NOT NULL,
    role TEXT NOT NULL,                        -- user | assistant | tool | system
    content TEXT NOT NULL DEFAULT '',
    extra TEXT NOT NULL DEFAULT '{}',          -- json: tool_calls / tool_call_id / usage / scrubbed
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_messages_chat ON messages(chat_id, id);
CREATE TABLE IF NOT EXISTS models (
    model_id TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    input REAL NOT NULL DEFAULT 0,
    cached_input REAL NOT NULL DEFAULT 0,
    cache_write REAL NOT NULL DEFAULT 0,
    output REAL NOT NULL DEFAULT 0,
    long_input REAL NOT NULL DEFAULT 0,
    long_cached_input REAL NOT NULL DEFAULT 0,
    long_cache_write REAL NOT NULL DEFAULT 0,
    long_output REAL NOT NULL DEFAULT 0,
    long_threshold INTEGER NOT NULL DEFAULT 272000,
    sort_order INTEGER NOT NULL DEFAULT 100,
    enabled INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS usage (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    day TEXT NOT NULL,
    month TEXT NOT NULL,
    chat_id INTEGER,
    provider TEXT NOT NULL DEFAULT '',
    model TEXT NOT NULL DEFAULT '',
    tier TEXT NOT NULL DEFAULT 'short',
    uncached_input INTEGER NOT NULL DEFAULT 0,
    cached_input INTEGER NOT NULL DEFAULT 0,
    cache_write INTEGER NOT NULL DEFAULT 0,
    output INTEGER NOT NULL DEFAULT 0,
    reasoning INTEGER NOT NULL DEFAULT 0,
    cost_usd REAL NOT NULL DEFAULT 0,
    latency_ms INTEGER NOT NULL DEFAULT 0,
    kind TEXT NOT NULL DEFAULT 'chat'
);
CREATE INDEX IF NOT EXISTS idx_usage_month ON usage(month);
CREATE INDEX IF NOT EXISTS idx_usage_day ON usage(day);
CREATE INDEX IF NOT EXISTS idx_usage_chat ON usage(chat_id, id);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    username TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL,
    details TEXT NOT NULL DEFAULT ''
);
"""


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    with connect() as conn:
        conn.executescript(SCHEMA)
    if get_setting("session_secret") is None:
        set_setting("session_secret", pysecrets.token_urlsafe(48))
    seed_models()


def seed_models() -> None:
    """Insert catalogue entries that are missing. Never overwrites prices edited in the UI."""
    from .pricing import CATALOG

    with connect() as conn:
        for m in CATALOG:
            d = m.as_dict()
            cols = ", ".join(d)
            marks = ", ".join("?" for _ in d)
            conn.execute(f"INSERT OR IGNORE INTO models({cols}) VALUES({marks})", tuple(d.values()))


# ---------------------------------------------------------------- settings / secrets

def get_setting(key: str, default: str | None = None) -> str | None:
    with connect() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(key: str, value: str) -> None:
    with connect() as conn:
        conn.execute(
            "INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )


def get_secret(key: str) -> str | None:
    with connect() as conn:
        row = conn.execute("SELECT value_enc FROM secrets WHERE key=?", (key,)).fetchone()
    return vault.decrypt(row["value_enc"]) if row else None


def set_secret(key: str, value: str) -> None:
    with connect() as conn:
        conn.execute(
            "INSERT INTO secrets(key,value_enc,updated_at) VALUES(?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET value_enc=excluded.value_enc, updated_at=excluded.updated_at",
            (key, vault.encrypt(value), now_iso()),
        )


def delete_secret(key: str) -> None:
    with connect() as conn:
        conn.execute("DELETE FROM secrets WHERE key=?", (key,))


def has_secret(key: str) -> bool:
    with connect() as conn:
        return conn.execute("SELECT 1 FROM secrets WHERE key=?", (key,)).fetchone() is not None


# ---------------------------------------------------------------- users

def user_count() -> int:
    with connect() as conn:
        return conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]


def get_user(username: str) -> sqlite3.Row | None:
    with connect() as conn:
        return conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()


def list_users() -> list[sqlite3.Row]:
    with connect() as conn:
        return conn.execute("SELECT id, username, role, created_at FROM users ORDER BY id").fetchall()


def create_user(username: str, password_hash: str, role: str = "admin") -> None:
    with connect() as conn:
        conn.execute(
            "INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
            (username, password_hash, role, now_iso()),
        )


def update_user_password(user_id: int, password_hash: str) -> None:
    with connect() as conn:
        conn.execute("UPDATE users SET password_hash=? WHERE id=?", (password_hash, user_id))


def delete_user(user_id: int) -> None:
    with connect() as conn:
        conn.execute("DELETE FROM users WHERE id=?", (user_id,))


# ---------------------------------------------------------------- devices

def slugify(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return s or "device"


def unique_slug(base: str, exclude_id: int | None = None) -> str:
    slug, n = base, 2
    with connect() as conn:
        while True:
            row = conn.execute("SELECT id FROM devices WHERE slug=?", (slug,)).fetchone()
            if row is None or (exclude_id is not None and row["id"] == exclude_id):
                return slug
            slug = f"{base}-{n}"
            n += 1


def list_devices(enabled_only: bool = False) -> list[sqlite3.Row]:
    q = "SELECT * FROM devices"
    if enabled_only:
        q += " WHERE enabled=1"
    q += " ORDER BY site, name"
    with connect() as conn:
        return conn.execute(q).fetchall()


def get_device(device_id: int) -> sqlite3.Row | None:
    with connect() as conn:
        return conn.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()


def get_device_by_slug(slug: str) -> sqlite3.Row | None:
    with connect() as conn:
        return conn.execute("SELECT * FROM devices WHERE slug=?", (slug,)).fetchone()


def find_device(ref: str) -> sqlite3.Row | None:
    """Resolve a device by slug, name, identity or host - used by agent tools."""
    ref = ref.strip()
    with connect() as conn:
        for col in ("slug", "name", "identity", "host"):
            row = conn.execute(f"SELECT * FROM devices WHERE lower({col})=lower(?)", (ref,)).fetchone()
            if row:
                return row
        row = conn.execute("SELECT * FROM devices WHERE slug=?", (slugify(ref),)).fetchone()
    return row


def create_device(fields: dict[str, Any]) -> int:
    fields = dict(fields)
    fields.setdefault("created_at", now_iso())
    if "password" in fields:
        pw = fields.pop("password")
        fields["password_enc"] = vault.encrypt(pw) if pw else None
    cols = ", ".join(fields)
    marks = ", ".join("?" for _ in fields)
    with connect() as conn:
        cur = conn.execute(f"INSERT INTO devices({cols}) VALUES({marks})", tuple(fields.values()))
        return cur.lastrowid


def update_device(device_id: int, fields: dict[str, Any]) -> None:
    fields = dict(fields)
    if "password" in fields:
        pw = fields.pop("password")
        if pw:
            fields["password_enc"] = vault.encrypt(pw)
    if not fields:
        return
    sets = ", ".join(f"{k}=?" for k in fields)
    with connect() as conn:
        conn.execute(f"UPDATE devices SET {sets} WHERE id=?", (*fields.values(), device_id))


def delete_device(device_id: int) -> None:
    with connect() as conn:
        conn.execute("DELETE FROM devices WHERE id=?", (device_id,))
        conn.execute("DELETE FROM run_devices WHERE device_id=?", (device_id,))


def device_password(row: sqlite3.Row) -> str | None:
    return vault.decrypt(row["password_enc"]) if row["password_enc"] else None


# ---------------------------------------------------------------- runs

def start_run(trigger: str) -> int:
    with connect() as conn:
        cur = conn.execute("INSERT INTO runs(started_at, trigger) VALUES(?,?)", (now_iso(), trigger))
        return cur.lastrowid


def finish_run(run_id: int, ok: int, fail: int, changed: int, commit_sha: str | None) -> None:
    with connect() as conn:
        conn.execute(
            "UPDATE runs SET finished_at=?, ok_count=?, fail_count=?, changed_count=?, commit_sha=? WHERE id=?",
            (now_iso(), ok, fail, changed, commit_sha, run_id),
        )


def record_run_device(run_id: int, device_id: int, status: str, message: str, changed: bool, duration_ms: int) -> None:
    with connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO run_devices(run_id,device_id,status,message,changed,duration_ms) VALUES(?,?,?,?,?,?)",
            (run_id, device_id, status, message[:2000], int(changed), duration_ms),
        )


def list_runs(limit: int = 30) -> list[sqlite3.Row]:
    with connect() as conn:
        return conn.execute("SELECT * FROM runs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()


def run_details(run_id: int) -> list[sqlite3.Row]:
    with connect() as conn:
        return conn.execute(
            "SELECT rd.*, d.name, d.slug FROM run_devices rd JOIN devices d ON d.id=rd.device_id "
            "WHERE rd.run_id=? ORDER BY d.site, d.name",
            (run_id,),
        ).fetchall()


# ---------------------------------------------------------------- chats

def create_chat(title: str) -> int:
    ts = now_iso()
    with connect() as conn:
        cur = conn.execute("INSERT INTO chats(title,created_at,updated_at) VALUES(?,?,?)", (title, ts, ts))
        return cur.lastrowid


def list_chats(limit: int = 50) -> list[sqlite3.Row]:
    with connect() as conn:
        return conn.execute("SELECT * FROM chats ORDER BY updated_at DESC LIMIT ?", (limit,)).fetchall()


def get_chat(chat_id: int) -> sqlite3.Row | None:
    with connect() as conn:
        return conn.execute("SELECT * FROM chats WHERE id=?", (chat_id,)).fetchone()


def rename_chat(chat_id: int, title: str) -> None:
    with connect() as conn:
        conn.execute("UPDATE chats SET title=? WHERE id=?", (title, chat_id))


def delete_chat(chat_id: int) -> None:
    with connect() as conn:
        conn.execute("DELETE FROM messages WHERE chat_id=?", (chat_id,))
        conn.execute("DELETE FROM chats WHERE id=?", (chat_id,))


def add_message(chat_id: int, role: str, content: str, extra: dict[str, Any] | None = None) -> int:
    ts = now_iso()
    with connect() as conn:
        cur = conn.execute(
            "INSERT INTO messages(chat_id,role,content,extra,created_at) VALUES(?,?,?,?,?)",
            (chat_id, role, content, json.dumps(extra or {}, ensure_ascii=False), ts),
        )
        conn.execute("UPDATE chats SET updated_at=? WHERE id=?", (ts, chat_id))
        return cur.lastrowid


def list_messages(chat_id: int) -> list[dict[str, Any]]:
    with connect() as conn:
        rows = conn.execute("SELECT * FROM messages WHERE chat_id=? ORDER BY id", (chat_id,)).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["extra"] = json.loads(d["extra"] or "{}")
        out.append(d)
    return out


# ---------------------------------------------------------------- audit

def audit(username: str, action: str, details: str = "") -> None:
    with connect() as conn:
        conn.execute("INSERT INTO audit(ts,username,action,details) VALUES(?,?,?,?)", (now_iso(), username, action, details[:4000]))


def list_audit(limit: int = 200) -> list[sqlite3.Row]:
    with connect() as conn:
        return conn.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,)).fetchall()


# ---------------------------------------------------------------- models & prices

def list_models(provider: str | None = None, enabled_only: bool = True) -> list[sqlite3.Row]:
    q, args = "SELECT * FROM models", []
    where = []
    if provider:
        where.append("provider=?")
        args.append(provider)
    if enabled_only:
        where.append("enabled=1")
    if where:
        q += " WHERE " + " AND ".join(where)
    q += " ORDER BY sort_order, model_id"
    with connect() as conn:
        return conn.execute(q, args).fetchall()


def get_model(model_id: str) -> dict[str, Any] | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM models WHERE model_id=?", (model_id,)).fetchone()
    return dict(row) if row else None


def upsert_model(fields: dict[str, Any]) -> None:
    fields = dict(fields)
    cols = ", ".join(fields)
    marks = ", ".join("?" for _ in fields)
    updates = ", ".join(f"{k}=excluded.{k}" for k in fields if k != "model_id")
    with connect() as conn:
        conn.execute(
            f"INSERT INTO models({cols}) VALUES({marks}) ON CONFLICT(model_id) DO UPDATE SET {updates}",
            tuple(fields.values()),
        )


def delete_model(model_id: str) -> None:
    with connect() as conn:
        conn.execute("DELETE FROM models WHERE model_id=?", (model_id,))


# ---------------------------------------------------------------- usage & cost

def record_usage(chat_id: int | None, provider: str, model: str, tier: str, usage: Any,
                 cost_usd: float, latency_ms: int, kind: str = "chat") -> None:
    ts = now_iso()
    with connect() as conn:
        conn.execute(
            "INSERT INTO usage(ts,day,month,chat_id,provider,model,tier,uncached_input,cached_input,"
            "cache_write,output,reasoning,cost_usd,latency_ms,kind) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (ts, ts[:10], ts[:7], chat_id, provider, model, tier, usage.uncached_input,
             usage.cached_input, usage.cache_write, usage.output, usage.reasoning,
             cost_usd, latency_ms, kind),
        )


_SUMS = ("COUNT(*) AS calls, COALESCE(SUM(cost_usd),0) AS cost, "
         "COALESCE(SUM(uncached_input),0) AS uncached_input, COALESCE(SUM(cached_input),0) AS cached_input, "
         "COALESCE(SUM(cache_write),0) AS cache_write, COALESCE(SUM(output),0) AS output, "
         "COALESCE(SUM(reasoning),0) AS reasoning")


def usage_totals(where: str = "", args: tuple = ()) -> dict[str, Any]:
    q = f"SELECT {_SUMS} FROM usage"
    if where:
        q += " WHERE " + where
    with connect() as conn:
        return dict(conn.execute(q, args).fetchone())


def month_cost(month: str | None = None) -> float:
    month = month or now_iso()[:7]
    with connect() as conn:
        return conn.execute("SELECT COALESCE(SUM(cost_usd),0) FROM usage WHERE month=?", (month,)).fetchone()[0]


def usage_by(group: str, limit: int = 60) -> list[dict[str, Any]]:
    if group not in ("day", "month", "model", "provider", "chat_id"):
        raise ValueError("bad grouping")
    with connect() as conn:
        rows = conn.execute(
            f"SELECT {group} AS key, {_SUMS} FROM usage GROUP BY {group} ORDER BY "
            f"{'key DESC' if group in ('day', 'month') else 'cost DESC'} LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def chat_cost(chat_id: int) -> dict[str, Any]:
    return usage_totals("chat_id=?", (chat_id,))


def recent_usage(limit: int = 100) -> list[dict[str, Any]]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT u.*, c.title AS chat_title FROM usage u LEFT JOIN chats c ON c.id=u.chat_id "
            "ORDER BY u.id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]

"""Environment-driven settings. Everything else lives in the DB (see db.py)."""
from __future__ import annotations

import os
from pathlib import Path

DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))
CONFIGS_DIR = DATA_DIR / "configs"          # git repo with one folder per device
DB_PATH = DATA_DIR / "app.db"
MASTER_KEY_PATH = DATA_DIR / "master.key"
KNOWN_HOSTS_PATH = DATA_DIR / "known_hosts"
APP_TIMEZONE = os.getenv("APP_TIMEZONE", "Europe/Berlin")

# Collector limits
SSH_CONNECT_TIMEOUT = int(os.getenv("SSH_CONNECT_TIMEOUT", "15"))
SSH_COMMAND_TIMEOUT = int(os.getenv("SSH_COMMAND_TIMEOUT", "90"))
COLLECT_CONCURRENCY = int(os.getenv("COLLECT_CONCURRENCY", "3"))

# Agent limits (keep tool output bounded so 10+ devices can't blow the context)
TOOL_MAX_CHARS = 40_000
SEARCH_MAX_TOTAL = 150
SEARCH_MAX_PER_DEVICE = 30
AGENT_MAX_ITERATIONS = 10

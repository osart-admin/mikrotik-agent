"""Point the app at a throwaway data dir before importing it, then create the schema."""
from __future__ import annotations

import os
import tempfile

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp(prefix="mtagent-test-"))

from app import db, store  # noqa: E402

db.init_db()
store.ensure_repo()

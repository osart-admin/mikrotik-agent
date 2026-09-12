"""Point the app at a throwaway data dir before importing it, then create the schema."""
from __future__ import annotations

import os
import tempfile

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp(prefix="mtagent-test-"))

from app import db, store  # noqa: E402

db.init_db()
store.ensure_repo()


import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def logged_in_changes():
    """A logged-in client plus a fresh pending plan on a throwaway device."""
    from app import db
    from app.main import app

    with TestClient(app) as client:
        if db.user_count() == 0:
            client.post("/setup", data={"username": "tester", "password": "testpass123",
                                        "password2": "testpass123"})
        else:
            client.post("/login", data={"username": "tester", "password": "testpass123", "next": "/"})
        dev_id = db.create_device({"slug": "planfix", "name": "PlanFix", "host": "192.0.2.90",
                                   "port": 22, "username": "agent", "auth": "key"})
        plan_id = db.create_plan({"device_id": dev_id, "created_by": "agent", "title": "t",
                                  "rationale": "r", "commands": "/ip dns set servers=1.1.1.1",
                                  "risk": "normal", "status": "pending"})
        yield client, plan_id
        db.delete_device(dev_id)

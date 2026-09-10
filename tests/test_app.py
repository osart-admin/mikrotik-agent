"""End-to-end HTTP tests against the real ASGI app (no router needed).

Covers the middleware ordering trap: the auth guard reads request.session, so SessionMiddleware
must sit OUTSIDE it. Registered in the wrong order every protected page 500s.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app import db
from app.main import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def logged_in(client):
    if db.user_count() == 0:
        r = client.post("/setup", data={"username": "tester", "password": "testpass123", "password2": "testpass123"})
        assert r.status_code == 200
    else:
        client.post("/login", data={"username": "tester", "password": "testpass123", "next": "/"})
    return client


def test_health_is_public(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_protected_page_redirects_not_500(client):
    r = client.get("/settings", follow_redirects=False)
    assert r.status_code == 303, f"expected a redirect, got {r.status_code}"
    assert r.headers["location"] in ("/setup", "/login?next=/settings")


def test_api_returns_401_not_500_when_anonymous(client):
    r = client.post("/api/collect", follow_redirects=False)
    assert r.status_code in (401, 303)


@pytest.mark.parametrize("path", ["/", "/chat", "/search", "/runs", "/settings", "/import"])
def test_pages_render(logged_in, path):
    r = logged_in.get(path)
    assert r.status_code == 200, f"{path} -> {r.status_code}"
    assert "MikroTik AI" in r.text


def test_device_lifecycle_and_pages(logged_in):
    r = logged_in.post("/devices/new", data={"name": "Test Router", "host": "192.0.2.10", "port": "22",
                                             "username": "agent", "auth_mode": "key", "site": "lab", "role": "edge"})
    assert r.status_code == 200
    dev = db.get_device_by_slug("test-router")
    assert dev is not None and dev["host"] == "192.0.2.10"

    assert logged_in.get(f"/devices/{dev['id']}").status_code == 200
    assert logged_in.get(f"/devices/{dev['id']}/edit").status_code == 200
    assert "Test Router" in logged_in.get("/").text

    # No config collected yet -> export 404s rather than exploding.
    assert logged_in.get(f"/devices/{dev['id']}/export").status_code == 404

    logged_in.post(f"/devices/{dev['id']}/delete")
    assert db.get_device_by_slug("test-router") is None


def test_unreachable_device_test_returns_json_error(logged_in):
    logged_in.post("/devices/new", data={"name": "Ghost", "host": "192.0.2.99", "port": "22",
                                         "username": "agent", "auth_mode": "key"})
    dev = db.get_device_by_slug("ghost")
    body = logged_in.post(f"/api/devices/{dev['id']}/test").json()
    assert body["ok"] is False and body["kind"] in ("unreachable", "timeout", "error")
    logged_in.post(f"/devices/{dev['id']}/delete")


def test_chat_without_api_key_reports_config_error(logged_in):
    cid = logged_in.post("/api/chat/new").json()["id"]
    with logged_in.stream("POST", f"/api/chat/{cid}/send", json={"message": "hi"}) as r:
        body = "".join(chunk for chunk in r.iter_text())
    assert "no API key stored" in body
    logged_in.post(f"/api/chat/{cid}/delete")


def test_search_page_without_devices(logged_in):
    r = logged_in.get("/search", params={"q": "wireguard"})
    assert r.status_code == 200 and "No matches" in r.text

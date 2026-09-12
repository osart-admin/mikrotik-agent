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


def test_ui_password_is_rejected_as_api_key(logged_in):
    """Browser autofill used to drop the UI login password into the API key field."""
    r = logged_in.post("/settings/llm", data={"provider": "openai", "model": "admin",
                                              "base_url": "", "api_key": "testpass123"})
    assert r.status_code == 200
    assert "совпадает с вашим паролем" in r.text
    assert not db.has_secret("openai_api_key")


def test_real_api_key_is_stored(logged_in):
    logged_in.post("/settings/llm", data={"provider": "openai", "model": "gpt-4.1",
                                          "base_url": "", "api_key": "sk-test-not-a-real-key"})
    assert db.has_secret("openai_api_key")
    assert db.get_setting("openai_model") == "gpt-4.1"
    logged_in.post("/settings/llm/delete-key", data={"provider": "openai"})
    assert not db.has_secret("openai_api_key")


def test_settings_form_does_not_expose_a_password_field(logged_in):
    """A type=password input is exactly what makes Chrome treat this as a login form."""
    html = logged_in.get("/settings").text
    form = html.split('action="/settings/llm"')[1].split("</form>")[0]
    assert 'name="api_key"' in form
    assert 'type="password" name="api_key"' not in form
    assert 'autocomplete="off"' in form


def test_model_dropdown_defaults_to_mid_tier_not_the_priciest(logged_in):
    """An unset model must not fall through to whichever row sorts first (gpt-6-astra)."""
    from app import pricing
    db.set_setting("openai_model", "")          # earlier tests leave a model selected
    html = logged_in.get("/settings").text
    form = html.split('action="/settings/llm"')[1].split("</form>")[0]
    default = pricing.DEFAULT_MODEL["openai"]
    assert f'value="{default}" selected' in form.replace("  ", " ")
    assert 'value="gpt-6-astra" selected' not in form


def test_model_dropdown_lists_the_catalog(logged_in):
    form = logged_in.get("/settings").text.split('action="/settings/llm"')[1].split("</form>")[0]
    for mid in ("gpt-6-astra", "gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna"):
        assert f'value="{mid}"' in form
    assert 'value="__custom__"' in form


def test_custom_model_id_is_accepted(logged_in):
    logged_in.post("/settings/llm", data={"provider": "openai", "model": "__custom__",
                                          "model_custom": "gpt-7-unreleased", "base_url": "",
                                          "api_key": "", "reasoning_effort": "high"})
    assert db.get_setting("openai_model") == "gpt-7-unreleased"
    assert db.get_setting("openai_reasoning_effort") == "high"
    logged_in.post("/settings/llm", data={"provider": "openai", "model": "gpt-5.6-terra",
                                          "base_url": "", "api_key": "", "reasoning_effort": ""})


def test_bogus_reasoning_effort_is_dropped(logged_in):
    logged_in.post("/settings/llm", data={"provider": "openai", "model": "gpt-5.6-terra",
                                          "base_url": "", "api_key": "", "reasoning_effort": "turbo"})
    assert db.get_setting("openai_reasoning_effort") == ""


def test_budget_blocks_the_chat_when_exceeded(logged_in):
    from app import pricing
    db.set_setting("monthly_budget_usd", "0.01")
    db.record_usage(None, "openai", "gpt-5.6-terra", "short", pricing.Usage(output=1_000_000), 12.0, 100)
    cid = logged_in.post("/api/chat/new").json()["id"]
    with logged_in.stream("POST", f"/api/chat/{cid}/send", json={"message": "hi"}) as r:
        body = "".join(r.iter_text())
    assert "лимит" in body
    db.set_setting("monthly_budget_usd", "0")
    logged_in.post(f"/api/chat/{cid}/delete")


def test_costs_page_renders(logged_in):
    r = logged_in.get("/costs")
    assert r.status_code == 200 and "Расходы на модель" in r.text


def test_model_prices_are_editable(logged_in):
    logged_in.post("/settings/models", data={
        "model_id": ["gpt-5.6-luna"], "provider": ["openai"], "label": ["Luna"],
        "input": ["0.25"], "cached_input": ["0.02"], "cache_write": ["0.25"], "output": ["1.20"],
        "long_input": ["0.50"], "long_cached_input": ["0.04"], "long_cache_write": ["0.50"],
        "long_output": ["1.80"], "long_threshold": ["272000"], "enabled": ["0"],
    })
    assert db.get_model("gpt-5.6-luna")["input"] == 0.25
    logged_in.post("/settings/models/reset")
    assert db.get_model("gpt-5.6-luna")["input"] == 0.20


def test_onboarding_form_has_no_password_field(logged_in):
    """Chrome autofilled the UI login into the router-admin fields; a masked text input avoids it."""
    logged_in.post("/devices/new", data={"name": "Autofill Probe", "host": "192.0.2.55",
                                         "port": "22", "username": "admin", "auth_mode": "password"})
    dev = db.get_device_by_slug("autofill-probe")
    html = logged_in.get(f"/devices/{dev['id']}").text
    form = html.split("onboard(event)")[1].split("</form>")[0]
    assert 'name="admin_password"' in form
    assert 'type="password" name="admin_password"' not in form
    assert 'class="secret" name="admin_password"' in form
    logged_in.post(f"/devices/{dev['id']}/delete")


def test_manual_script_matches_the_automated_path(logged_in):
    from app import collector, onboard as ob

    pub = collector.public_keys()["ed25519"]
    script = ob.manual_script("agent", pub, "ed25519", "192.0.2.10/32")
    assert f"/user group add name={ob.GROUP} policy={ob.GROUP_POLICY}" in script
    assert "write" not in ob.GROUP_POLICY and "sensitive" not in ob.GROUP_POLICY
    assert "address=192.0.2.10/32" in script
    assert pub in script
    assert "/user ssh-keys import user=agent" in script
    assert script.count("\n") == 4


def test_device_page_offers_the_manual_script(logged_in):
    logged_in.post("/devices/new", data={"name": "Manual Probe", "host": "192.0.2.56",
                                         "port": "22", "username": "agent", "auth_mode": "key"})
    dev = db.get_device_by_slug("manual-probe")
    html = logged_in.get(f"/devices/{dev['id']}").text
    assert "/user ssh-keys import user=agent" in html
    assert "mikrotik-agent-ro" in html
    logged_in.post(f"/devices/{dev['id']}/delete")


def test_use_agent_key_refuses_when_the_key_is_not_installed(logged_in):
    """The switch must verify the login first, or a failed manual install leaves a broken device."""
    logged_in.post("/devices/new", data={"name": "Switch Probe", "host": "192.0.2.57",
                                         "port": "22", "username": "admin", "auth_mode": "password",
                                         "password": "irrelevant"})
    dev = db.get_device_by_slug("switch-probe")
    body = logged_in.post(f"/api/devices/{dev['id']}/use-agent-key", data={"agent_user": "agent"}).json()
    assert body["ok"] is False
    after = db.get_device(dev["id"])
    assert after["username"] == "admin" and after["auth"] == "password"
    logged_in.post(f"/devices/{dev['id']}/delete")


def test_device_page_offers_the_switch_after_manual_install(logged_in):
    logged_in.post("/devices/new", data={"name": "Switch UI", "host": "192.0.2.58",
                                         "port": "22", "username": "admin", "auth_mode": "password"})
    dev = db.get_device_by_slug("switch-ui")
    html = logged_in.get(f"/devices/{dev['id']}").text
    assert "use-agent-key" in html and "Ключ установлен вручную" in html
    logged_in.post(f"/devices/{dev['id']}/delete")


def test_device_list_shows_auth_mode_and_delete(logged_in):
    logged_in.post("/devices/new", data={"name": "KeyDev", "host": "192.0.2.60", "port": "22",
                                         "username": "agent", "auth_mode": "key"})
    logged_in.post("/devices/new", data={"name": "PwDev", "host": "192.0.2.61", "port": "22",
                                         "username": "osart", "auth_mode": "password", "password": "x"})
    html = logged_in.get("/").text
    assert "🔑 ключ" in html and "пароль" in html
    assert "data-del=" in html
    for slug in ("keydev", "pwdev"):
        logged_in.post(f"/devices/{db.get_device_by_slug(slug)['id']}/delete")


def test_duplicate_hosts_are_flagged(logged_in):
    for n in ("Dup A", "Dup B"):
        logged_in.post("/devices/new", data={"name": n, "host": "192.0.2.62", "port": "22",
                                             "username": "agent", "auth_mode": "key"})
    assert "дубликат адреса" in logged_in.get("/").text
    for slug in ("dup-a", "dup-b"):
        logged_in.post(f"/devices/{db.get_device_by_slug(slug)['id']}/delete")
    assert "дубликат адреса" not in logged_in.get("/").text


def test_delete_removes_stored_config_too(logged_in):
    from app import store
    logged_in.post("/devices/new", data={"name": "Doomed", "host": "192.0.2.63", "port": "22",
                                         "username": "agent", "auth_mode": "key"})
    dev = db.get_device_by_slug("doomed")
    store.write_device("doomed", "/ip address add address=10.0.0.1/24\n", "{}")
    assert store.read_export("doomed") is not None
    logged_in.post(f"/devices/{dev['id']}/delete")
    assert db.get_device(dev["id"]) is None
    assert store.read_export("doomed") is None


def test_delete_button_markup_survives_a_quote_in_the_name(logged_in):
    """A name in an onclick="" attribute broke the markup, because tojson leaves \" unescaped."""
    from html.parser import HTMLParser

    logged_in.post("/devices/new", data={"name": 'He said "hi" <b>', "host": "192.0.2.64",
                                         "port": "22", "username": "agent", "auth_mode": "key"})
    dev = db.get_device_by_slug("he-said-hi-b")
    html = logged_in.get("/").text

    seen = []

    class P(HTMLParser):
        def handle_starttag(self, tag, attrs):
            d = dict(attrs)
            if "data-del" in d:
                seen.append(d)

    P().feed(html)
    assert seen, "delete button not found or its markup did not parse"
    assert seen[-1]["data-name"] == 'He said "hi" <b>'
    assert seen[-1]["data-del"] == str(dev["id"])
    logged_in.post(f"/devices/{dev['id']}/delete")


def test_identity_is_used_as_the_display_name(logged_in):
    logged_in.post("/devices/new", data={"name": "10.0.3.254", "host": "10.0.3.254", "port": "22",
                                         "username": "agent", "auth_mode": "key"})
    dev = db.get_device_by_slug("10-0-3-254")
    db.update_device(dev["id"], {"identity": "HSH-D"})
    html = logged_in.get("/").text
    assert "HSH-D" in html
    logged_in.post(f"/devices/{dev['id']}/delete")


def test_agent_group_grants_only_what_the_collector_uses():
    """The read path must stay incapable of writing, reading secrets, or generating traffic."""
    import re
    from pathlib import Path

    from app import onboard as ob

    granted = set(ob.GROUP_POLICY.split(","))
    assert granted == {"ssh", "read"}
    for forbidden in ("write", "policy", "sensitive", "test", "ftp", "reboot", "sniff"):
        assert forbidden not in granted

    # Every command the collector sends must be a read: a print or an export.
    src = Path(ob.__file__).with_name("collector.py").read_text()
    commands = re.findall(r'r\.run\("([^"]+)"\)', src)
    assert commands, "no router commands found - did collector.py change shape?"
    for cmd in commands:
        assert cmd.startswith("/export") or cmd.endswith("print"), f"{cmd!r} is not a read command"


def test_no_tool_can_change_a_router():
    """The model may *propose* a change; it must never be able to apply one.

    The model's entire surface is tools.REGISTRY - it cannot call HTTP routes. Applying is a UI
    action performed by a person (see apply.py), so this pins that no tool reaches that path.
    """
    import inspect

    from app import live, tools

    assert set(tools.REGISTRY) == {
        "list_devices", "fleet_summary", "list_sections", "get_sections", "search_config",
        "get_device_facts", "get_full_export", "config_history", "config_diff", "get_live_state",
        "propose_change",
    }

    for name, fn in tools.REGISTRY.items():
        src = inspect.getsource(fn)
        # Only the live-state tool opens a session, and only via the constant whitelist.
        if name == "get_live_state":
            assert "live.fetch" in src
        else:
            assert "RouterSSH" not in src and "live.fetch" not in src, f"{name} touches a router"
        # Nothing may reach the apply engine.
        for forbidden in ("apply_plan", "confirm_plan", "rollback_now", "from .apply", "apply."):
            assert forbidden not in src, f"{name} reaches the apply path via {forbidden!r}"

    assert all(q.command.startswith("/") and "{" not in q.command for q in live.QUERIES.values())


def test_propose_change_only_writes_a_queue_row():
    """It must validate and enqueue - never execute."""
    import inspect

    from app import tools

    src = inspect.getsource(tools.propose_change)
    assert "changes.validate" in src and "db.create_plan" in src
    assert "RouterSSH" not in src and "r.run(" not in src


def test_admin_credentials_never_reach_storage():
    """The onboarding password lives in the request only - not the DB, audit rows or settings."""
    import re
    from pathlib import Path

    app_dir = Path(__file__).resolve().parents[1] / "app"
    onboard_src = (app_dir / "onboard.py").read_text()
    main_src = (app_dir / "main.py").read_text()

    # It may only be passed to Credentials(...) - never to db.*, a logger, or an audit row.
    for line in onboard_src.splitlines() + main_src.splitlines():
        if "admin_password" not in line or line.strip().startswith("#"):
            continue
        assert not re.search(r"db\.\w+\(.*admin_password", line), line
        assert not re.search(r"log\.\w+\(.*admin_password", line), line
        assert not re.search(r"audit\(.*admin_password", line), line

    assert "password_enc" not in onboard_src.split("async def onboard")[1].split("return log")[0] \
        or 'db.update_device(dev["id"], {"username": agent_user, "auth": "key", "password_enc": None' in onboard_src


def test_runs_page_is_labelled_as_a_history(logged_in):
    html = logged_in.get("/runs").text
    assert "История сбора" in html
    assert ">Сборы<" not in html          # the old ambiguous nav label
    assert "один проход по всем включённым устройствам" in html


def test_trigger_values_are_shown_in_russian(logged_in):
    db.start_run("manual")
    db.start_run("schedule")
    for path in ("/runs", "/"):
        html = logged_in.get(path).text
        assert "вручную" in html and "по расписанию" in html
        assert ">manual<" not in html and ">schedule<" not in html

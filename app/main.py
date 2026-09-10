"""FastAPI app: inventory, collection, config browsing, chat, settings."""
from __future__ import annotations

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Form, HTTPException, Request, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from . import agent, auth, collector, db, live, llm, onboard, pricing, rsc, scheduler, scrub, store, tools, winbox_import
from .config import APP_TIMEZONE, DATA_DIR
from .ssh import SSHError, forget_host, known_host_entry

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("main")

BASE_DIR = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


@asynccontextmanager
async def lifespan(app: FastAPI):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    db.init_db()
    store.ensure_repo()
    collector.ensure_keys()
    scheduler.start()
    log.info("mikrotik-agent ready (tz=%s, data=%s)", APP_TIMEZONE, DATA_DIR)
    yield
    scheduler.stop()


app = FastAPI(title="MikroTik AI Agent", lifespan=lifespan)

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


@app.middleware("http")
async def guard(request: Request, call_next):
    path = request.url.path
    public = path in ("/login", "/setup", "/health") or path.startswith("/static")
    if not public:
        if db.user_count() == 0:
            return RedirectResponse("/setup", status_code=303)
        if auth.current_user(request) is None:
            if path.startswith("/api/"):
                return JSONResponse({"error": "not authenticated"}, status_code=401)
            return auth.login_redirect(request)
    return await call_next(request)


# Starlette wraps middleware in reverse registration order, so SessionMiddleware is added AFTER
# the guard above to end up OUTSIDE it - the guard reads request.session and needs it present.
# The DB is initialised here (not in lifespan) because the session secret lives in it.
db.init_db()
app.add_middleware(
    SessionMiddleware,
    secret_key=db.get_setting("session_secret", "dev"),
    session_cookie="mtagent",
    max_age=14 * 24 * 3600,
    same_site="lax",
    https_only=False,
)


def render(request: Request, name: str, **ctx: Any) -> HTMLResponse:
    ctx.setdefault("user", auth.current_user(request))
    ctx.setdefault("collecting", collector.is_running())
    return templates.TemplateResponse(request, name, ctx)


# ---------------------------------------------------------------- auth

@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/setup", response_class=HTMLResponse)
async def setup_form(request: Request):
    if db.user_count() > 0:
        return RedirectResponse("/login", status_code=303)
    return render(request, "setup.html")


@app.post("/setup")
async def setup_submit(request: Request, username: str = Form(...), password: str = Form(...), password2: str = Form(...)):
    if db.user_count() > 0:
        return RedirectResponse("/login", status_code=303)
    if len(password) < 8 or password != password2:
        return render(request, "setup.html", error="Пароли не совпадают или короче 8 символов")
    db.create_user(username.strip(), auth.hash_password(password), "admin")
    db.audit(username, "setup", "initial admin created")
    request.session["user"] = username.strip()
    return RedirectResponse("/", status_code=303)


@app.get("/login", response_class=HTMLResponse)
async def login_form(request: Request, next: str = "/"):
    if db.user_count() == 0:
        return RedirectResponse("/setup", status_code=303)
    return render(request, "login.html", next=next)


@app.post("/login")
async def login_submit(request: Request, username: str = Form(...), password: str = Form(...), next: str = Form("/")):
    row = db.get_user(username.strip())
    if row is None or not auth.verify_password(password, row["password_hash"]):
        await asyncio.sleep(1)
        db.audit(username, "login_failed")
        return render(request, "login.html", error="Неверный логин или пароль", next=next)
    request.session["user"] = row["username"]
    db.audit(row["username"], "login")
    return RedirectResponse(next if next.startswith("/") else "/", status_code=303)


@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


# ---------------------------------------------------------------- devices

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    devices = [dict(d) for d in db.list_devices()]
    for d in devices:
        raw = store.read_facts(d["slug"])
        d["facts"] = json.loads(raw) if raw else None
    runs = [dict(r) for r in db.list_runs(5)]
    dupes: dict[str, int] = {}
    for d in devices:
        dupes[d["host"]] = dupes.get(d["host"], 0) + 1
    return render(request, "devices.html", devices=devices, runs=runs, next_run=scheduler.next_run(),
                  dupes=dupes, sites=sorted({d["site"] for d in devices if d["site"]}))


@app.get("/devices/new", response_class=HTMLResponse)
async def device_new(request: Request):
    return render(request, "device_form.html", device=None)


@app.post("/devices/new")
async def device_create(request: Request, name: str = Form(...), host: str = Form(...), port: int = Form(22),
                        username: str = Form("agent"), auth_mode: str = Form("key"), password: str = Form(""),
                        site: str = Form(""), role: str = Form(""), tags: str = Form(""), notes: str = Form("")):
    user = auth.require_user(request)
    slug = db.unique_slug(db.slugify(name))
    dev_id = db.create_device({"slug": slug, "name": name.strip(), "host": host.strip(), "port": port,
                               "username": username.strip() or "agent", "auth": auth_mode, "password": password,
                               "site": site.strip(), "role": role.strip(), "tags": tags.strip(), "notes": notes.strip()})
    db.audit(user["username"], "device_create", f"{slug} {host}")
    return RedirectResponse(f"/devices/{dev_id}", status_code=303)


@app.get("/devices/{device_id}", response_class=HTMLResponse)
async def device_detail(request: Request, device_id: int):
    dev = db.get_device(device_id)
    if dev is None:
        raise HTTPException(404, "device not found")
    raw = store.read_facts(dev["slug"])
    export = store.read_export(dev["slug"])
    return render(request, "device.html", device=dict(dev), facts=json.loads(raw) if raw else None,
                  export=export, sections=rsc.section_index(export) if export else {},
                  history=store.history(dev["slug"], 15),
                  hostkey=bool(known_host_entry(dev["host"], dev["port"])),
                  pubkeys=collector.public_keys(),
                  live_queries=[(k, q.label) for k, q in live.QUERIES.items()],
                  manual_ros7=onboard.manual_script("agent", collector.public_keys()["ed25519"], "ed25519"),
                  manual_ros6=onboard.manual_script("agent", collector.public_keys()["rsa"], "rsa"))


@app.get("/devices/{device_id}/edit", response_class=HTMLResponse)
async def device_edit(request: Request, device_id: int):
    dev = db.get_device(device_id)
    if dev is None:
        raise HTTPException(404, "device not found")
    return render(request, "device_form.html", device=dict(dev))


@app.post("/devices/{device_id}/edit")
async def device_update(request: Request, device_id: int, name: str = Form(...), host: str = Form(...), port: int = Form(22),
                        username: str = Form("agent"), auth_mode: str = Form("key"), password: str = Form(""),
                        site: str = Form(""), role: str = Form(""), tags: str = Form(""), notes: str = Form(""),
                        enabled: str = Form("")):
    user = auth.require_user(request)
    dev = db.get_device(device_id)
    if dev is None:
        raise HTTPException(404, "device not found")
    slug = db.unique_slug(db.slugify(name), exclude_id=device_id)
    if slug != dev["slug"]:
        store.rename_device(dev["slug"], slug)
    fields = {"slug": slug, "name": name.strip(), "host": host.strip(), "port": port,
              "username": username.strip() or "agent", "auth": auth_mode, "site": site.strip(),
              "role": role.strip(), "tags": tags.strip(), "notes": notes.strip(), "enabled": 1 if enabled else 0}
    if password:
        fields["password"] = password
    db.update_device(device_id, fields)
    db.audit(user["username"], "device_update", slug)
    return RedirectResponse(f"/devices/{device_id}", status_code=303)


@app.post("/devices/{device_id}/delete")
async def device_delete(request: Request, device_id: int):
    user = auth.require_user(request)
    dev = db.get_device(device_id)
    if dev is None:
        raise HTTPException(404, "device not found")
    store.remove_device(dev["slug"])
    store.commit(f"remove device {dev['slug']}")
    db.delete_device(device_id)
    db.audit(user["username"], "device_delete", dev["slug"])
    return RedirectResponse("/", status_code=303)


@app.post("/api/devices/{device_id}/test")
async def device_test(request: Request, device_id: int):
    dev = db.get_device(device_id)
    if dev is None:
        raise HTTPException(404, "device not found")
    try:
        info = await collector.probe(dev)
    except SSHError as exc:
        db.update_device(device_id, {"status": exc.kind, "status_message": exc.message})
        return JSONResponse({"ok": False, "kind": exc.kind, "message": exc.message}, status_code=200)
    db.update_device(device_id, {"status": "ok", "status_message": "", "identity": info["identity"],
                                 "ros_version": info["version"], "board": info["board"], "arch": info["arch"],
                                 "last_seen": db.now_iso()})
    return {"ok": True, **info}


@app.post("/api/devices/{device_id}/forget-hostkey")
async def device_forget_hostkey(request: Request, device_id: int):
    user = auth.require_user(request)
    dev = db.get_device(device_id)
    if dev is None:
        raise HTTPException(404, "device not found")
    forget_host(dev["host"], dev["port"])
    db.audit(user["username"], "forget_hostkey", dev["slug"])
    return {"ok": True}


@app.post("/api/devices/{device_id}/use-agent-key")
async def device_use_agent_key(request: Request, device_id: int, agent_user: str = Form("agent")):
    """Switch a device to key auth after the key was installed by hand.

    Verifies the login before saving, so a half-finished manual install cannot leave the device
    pointing at credentials that do not work.
    """
    user = auth.require_user(request)
    dev = db.get_device(device_id)
    if dev is None:
        raise HTTPException(404, "device not found")
    agent_user = agent_user.strip() or "agent"
    probe = dict(dev)
    probe.update({"username": agent_user, "auth": "key", "password_enc": None})
    try:
        info = await collector.probe(probe)
    except SSHError as exc:
        return JSONResponse({"ok": False, "kind": exc.kind, "message": exc.message}, status_code=200)
    db.update_device(device_id, {"username": agent_user, "auth": "key", "password_enc": None,
                                 "status": "ok", "status_message": "", "identity": info["identity"],
                                 "ros_version": info["version"], "board": info["board"],
                                 "arch": info["arch"], "last_seen": db.now_iso()})
    db.audit(user["username"], "use_agent_key", f"{dev['slug']} -> {agent_user}")
    return {"ok": True, **info}


@app.post("/api/devices/{device_id}/onboard")
async def device_onboard(request: Request, device_id: int, admin_user: str = Form(...), admin_password: str = Form(...),
                         agent_user: str = Form("agent"), allowed_address: str = Form("")):
    user = auth.require_user(request)
    dev = db.get_device(device_id)
    if dev is None:
        raise HTTPException(404, "device not found")
    try:
        steps = await onboard.onboard(dev, admin_user, admin_password, agent_user.strip() or "agent", allowed_address.strip())
    except SSHError as exc:
        db.audit(user["username"], "onboard_failed", f"{dev['slug']}: {exc.message}")
        return JSONResponse({"ok": False, "message": exc.message}, status_code=200)
    db.audit(user["username"], "onboard", f"{dev['slug']} -> {agent_user}")
    return {"ok": True, "steps": steps}


# ---------------------------------------------------------------- collection

@app.get("/api/devices/{device_id}/live")
async def device_live(request: Request, device_id: int, query: str, match: str = "", limit: int = 50):
    dev = db.get_device(device_id)
    if dev is None:
        raise HTTPException(404, "device not found")
    try:
        raw = await live.fetch(dev, query)
        body, shown, total = live.filter_lines(raw, match or None, limit, live.QUERIES[query].tail)
    except live.LiveError as exc:
        return JSONResponse({"ok": False, "message": str(exc)}, status_code=200)
    return {"ok": True, "command": live.QUERIES[query].command, "label": live.QUERIES[query].label,
            "shown": shown, "total": total, "text": body}


@app.post("/api/collect")
async def collect_now(request: Request, device_id: int | None = None):
    user = auth.require_user(request)
    result = await collector.collect_all("manual", [device_id] if device_id else None)
    db.audit(user["username"], "collect", json.dumps(result, ensure_ascii=False)[:500])
    return result


@app.get("/runs", response_class=HTMLResponse)
async def runs_page(request: Request):
    runs = [dict(r) for r in db.list_runs(40)]
    detail = {r["id"]: [dict(x) for x in db.run_details(r["id"])] for r in runs[:10]}
    return render(request, "runs.html", runs=runs, detail=detail, next_run=scheduler.next_run())


# ---------------------------------------------------------------- config browsing

@app.get("/devices/{device_id}/export", response_class=PlainTextResponse)
async def device_export(request: Request, device_id: int, scrubbed: int = 0):
    dev = db.get_device(device_id)
    if dev is None:
        raise HTTPException(404, "device not found")
    text = store.read_export(dev["slug"])
    if text is None:
        raise HTTPException(404, "no config collected yet")
    return scrub.scrub(text)[0] if scrubbed else text


@app.get("/devices/{device_id}/diff", response_class=PlainTextResponse)
async def device_diff(request: Request, device_id: int, commit: str = ""):
    dev = db.get_device(device_id)
    if dev is None:
        raise HTTPException(404, "device not found")
    hist = store.history(dev["slug"], 1)
    sha = commit or (hist[0]["sha"] if hist else "")
    if not sha:
        return "No commits yet."
    return store.diff_prev(dev["slug"], sha) or "(no changes to this device in that commit)"


@app.get("/search", response_class=HTMLResponse)
async def search_page(request: Request, q: str = "", context: int = 0):
    result = tools.search_config(pattern=q, context=min(max(context, 0), 3)) if q else ""
    return render(request, "search.html", q=q, context=context, result=result)


# ---------------------------------------------------------------- chat

@app.get("/chat", response_class=HTMLResponse)
async def chat_index(request: Request):
    chats = [dict(c) for c in db.list_chats()]
    if not chats:
        cid = db.create_chat("Новый чат")
        return RedirectResponse(f"/chat/{cid}", status_code=303)
    return RedirectResponse(f"/chat/{chats[0]['id']}", status_code=303)


@app.get("/chat/{chat_id}", response_class=HTMLResponse)
async def chat_page(request: Request, chat_id: int):
    chat = db.get_chat(chat_id)
    if chat is None:
        raise HTTPException(404, "chat not found")
    provider = db.get_setting("llm_provider", "openai")
    return render(request, "chat.html", chat=dict(chat), chats=[dict(c) for c in db.list_chats()],
                  messages=db.list_messages(chat_id), provider=provider,
                  model=db.get_setting(f"{provider}_model", "") or "",
                  has_key=db.has_secret(f"{provider}_api_key"),
                  device_count=len(db.list_devices()),
                  chat_totals=db.chat_cost(chat_id), budget=agent.budget_status(),
                  fmt_usd=pricing.fmt_usd)


@app.post("/api/chat/new")
async def chat_new(request: Request):
    return {"id": db.create_chat("Новый чат")}


@app.post("/api/chat/{chat_id}/delete")
async def chat_delete(request: Request, chat_id: int):
    db.delete_chat(chat_id)
    return {"ok": True}


@app.post("/api/chat/{chat_id}/send")
async def chat_send(request: Request, chat_id: int):
    user = auth.require_user(request)
    body = await request.json()
    text = (body.get("message") or "").strip()
    if not text:
        raise HTTPException(400, "empty message")
    chat = db.get_chat(chat_id)
    if chat is None:
        raise HTTPException(404, "chat not found")
    if chat["title"] == "Новый чат":
        db.rename_chat(chat_id, text[:60])
    db.audit(user["username"], "chat", f"#{chat_id}: {text[:200]}")

    async def stream():
        try:
            async for event in agent.run_turn(chat_id, text):
                yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
        except Exception as exc:  # noqa: BLE001
            log.exception("chat turn failed")
            yield f"data: {json.dumps({'type': 'error', 'message': str(exc)}, ensure_ascii=False)}\n\n"
        yield "data: {\"type\": \"done\"}\n\n"

    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ---------------------------------------------------------------- settings

@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request, imported: int = 0, error: str = "", provider: str = ""):
    # ?provider= previews another provider's settings without switching the active one.
    provider = provider if provider in llm.PROVIDERS else (db.get_setting("llm_provider", "openai") or "openai")
    # Falling back to the first catalogue row would silently select the most expensive model,
    # so an unset provider gets an explicit mid-range default instead.
    chosen = {p: (db.get_setting(f"{p}_model", "") or pricing.DEFAULT_MODEL.get(p, "")) for p in llm.PROVIDERS}
    return render(request, "settings.html", provider=provider,
                  models=chosen,
                  keys={p: db.has_secret(f"{p}_api_key") for p in llm.PROVIDERS},
                  base_urls={p: db.get_setting(f"{p}_base_url", "") or "" for p in llm.PROVIDERS},
                  efforts={p: db.get_setting(f"{p}_reasoning_effort", "") or "" for p in llm.PROVIDERS},
                  catalog={p: [dict(m) for m in db.list_models(llm.family(p))] for p in llm.PROVIDERS},
                  provider_labels=llm.PROVIDER_LABELS,
                  reasoning_ok=llm.PROVIDERS[provider].supports_reasoning_with_tools,
                  all_models=[dict(m) for m in db.list_models(enabled_only=False)],
                  reasoning_efforts=pricing.REASONING_EFFORTS,
                  budget=agent.budget_status(), fmt_usd=pricing.fmt_usd,
                  interval=db.get_setting("collect_interval_minutes", "0"),
                  next_run=scheduler.next_run(), pubkeys=collector.public_keys(),
                  users=[dict(u) for u in db.list_users()], audit=[dict(a) for a in db.list_audit(50)],
                  imported=imported, error=error)


@app.post("/settings/llm")
async def settings_llm(request: Request, provider: str = Form("openai"), model: str = Form(""),
                       model_custom: str = Form(""), base_url: str = Form(""), api_key: str = Form(""),
                       reasoning_effort: str = Form("")):
    user = auth.require_user(request)
    if provider not in llm.PROVIDERS:
        raise HTTPException(400, "unknown provider")
    api_key, base_url = api_key.strip(), base_url.strip()
    # "__custom__" in the dropdown reveals a free-text box, so new models can be used before
    # they are added to the catalogue.
    model = (model_custom.strip() if model == "__custom__" else model.strip())
    if reasoning_effort not in pricing.REASONING_EFFORTS:
        reasoning_effort = ""

    # Browsers used to autofill this form as if it were a login (see settings.html). Catch the
    # accident server-side too: storing the operator's own UI password as an API key would leak
    # it to the LLM provider on the next request.
    row = db.get_user(user["username"])
    if api_key and row is not None and auth.verify_password(api_key, row["password_hash"]):
        return await settings_page(request, error="Введённый API-ключ совпадает с вашим паролем от этого интерфейса — похоже, поле заполнил браузер. Ключ не сохранён.")

    db.set_setting("llm_provider", provider)
    db.set_setting(f"{provider}_model", model)
    db.set_setting(f"{provider}_base_url", base_url)
    db.set_setting(f"{provider}_reasoning_effort", reasoning_effort)
    if api_key:
        db.set_secret(f"{provider}_api_key", api_key)
        db.audit(user["username"], "api_key_set", provider)
    db.audit(user["username"], "llm_settings", f"{provider} {model}")
    return RedirectResponse("/settings", status_code=303)


@app.post("/settings/llm/delete-key")
async def settings_delete_key(request: Request, provider: str = Form(...)):
    user = auth.require_user(request)
    db.delete_secret(f"{provider}_api_key")
    db.audit(user["username"], "api_key_deleted", provider)
    return RedirectResponse("/settings", status_code=303)


@app.post("/api/settings/llm/test")
async def settings_llm_test(request: Request):
    try:
        provider = agent.provider_from_settings()
        reply = await provider.chat("Reply with the single word: ok", [{"role": "user", "content": "ping"}], [])
    except llm.LLMError as exc:
        return {"ok": False, "message": str(exc)}
    return {"ok": True, "model": reply.model, "reply": reply.content.strip()[:100],
            "tokens": reply.input_tokens + reply.output_tokens}


@app.post("/settings/schedule")
async def settings_schedule(request: Request, interval: int = Form(0)):
    user = auth.require_user(request)
    db.set_setting("collect_interval_minutes", str(max(0, interval)))
    scheduler.apply_settings()
    db.audit(user["username"], "schedule", f"{interval} min")
    return RedirectResponse("/settings", status_code=303)


@app.post("/settings/users")
async def settings_add_user(request: Request, username: str = Form(...), password: str = Form(...), role: str = Form("admin")):
    user = auth.require_user(request)
    if len(password) < 8:
        raise HTTPException(400, "password too short")
    db.create_user(username.strip(), auth.hash_password(password), role)
    db.audit(user["username"], "user_create", username)
    return RedirectResponse("/settings", status_code=303)


@app.post("/settings/users/{user_id}/delete")
async def settings_delete_user(request: Request, user_id: int):
    user = auth.require_user(request)
    if user["id"] == user_id:
        raise HTTPException(400, "cannot delete yourself")
    db.delete_user(user_id)
    db.audit(user["username"], "user_delete", str(user_id))
    return RedirectResponse("/settings", status_code=303)


# ---------------------------------------------------------------- winbox import

@app.get("/import", response_class=HTMLResponse)
async def import_page(request: Request):
    return render(request, "import.html", parsed=None)


@app.post("/import", response_class=HTMLResponse)
async def import_upload(request: Request, file: UploadFile = File(...)):
    data = await file.read()
    records = winbox_import.parse_cdb(data)
    fallback = False
    if not records:
        records = winbox_import.fallback_strings(data)
        fallback = True
    mapping = winbox_import.guess_mapping(records)
    rows = winbox_import.to_devices(records, mapping)
    field_ids = sorted({k for r in records for k, v in r.items() if isinstance(v, str)})
    samples = {i: [str(r.get(i, ""))[:40] for r in records[:4] if r.get(i)] for i in field_ids}
    request.session["import_records"] = json.dumps(records)[:900_000]
    return render(request, "import.html", parsed=True, rows=rows, mapping=mapping, fallback=fallback,
                  field_ids=field_ids, samples=samples, count=len(records))


@app.post("/import/confirm")
async def import_confirm(request: Request):
    user = auth.require_user(request)
    form = await request.form()
    raw = request.session.get("import_records")
    if not raw:
        return RedirectResponse("/import", status_code=303)
    records = json.loads(raw)
    mapping = {k: (int(form[k]) if form.get(k) else None) for k in ("host", "login", "password", "note")}
    rows = winbox_import.to_devices([{int(k): v for k, v in r.items()} for r in records], mapping)
    selected = set(form.getlist("select"))
    site = str(form.get("site", "")).strip()
    created = 0
    for i, row in enumerate(rows):
        if str(i) not in selected or row["is_mac"]:
            continue
        name = row["note"] or row["host"]
        slug = db.unique_slug(db.slugify(name))
        db.create_device({"slug": slug, "name": name, "host": row["host"], "port": 22,
                          "username": row["login"] or "admin", "auth": "password" if row["password"] else "key",
                          "password": row["password"], "site": site, "notes": "imported from Winbox address book"})
        created += 1
    request.session.pop("import_records", None)
    db.audit(user["username"], "winbox_import", f"{created} devices")
    return RedirectResponse(f"/settings?imported={created}", status_code=303)


@app.post("/settings/budget")
async def settings_budget(request: Request, monthly_budget_usd: float = Form(0)):
    user = auth.require_user(request)
    db.set_setting("monthly_budget_usd", str(max(0.0, monthly_budget_usd)))
    db.audit(user["username"], "budget", f"${monthly_budget_usd}/mo")
    return RedirectResponse("/settings", status_code=303)


@app.post("/settings/models")
async def settings_models(request: Request):
    """Save the price table. Prices change without notice, so they are editable, not baked in."""
    user = auth.require_user(request)
    form = await request.form()
    ids = form.getlist("model_id")
    numeric = ("input", "cached_input", "cache_write", "output",
               "long_input", "long_cached_input", "long_cache_write", "long_output")
    saved = 0
    for i, mid in enumerate(ids):
        mid = str(mid).strip()
        if not mid:
            continue
        fields: dict[str, Any] = {"model_id": mid,
                                  "provider": llm.family(str(form.getlist("provider")[i]).strip() or "openai"),
                                  "label": str(form.getlist("label")[i]).strip()}
        for key in numeric:
            try:
                fields[key] = float(str(form.getlist(key)[i]) or 0)
            except (ValueError, IndexError):
                fields[key] = 0.0
        try:
            fields["long_threshold"] = int(str(form.getlist("long_threshold")[i]) or pricing.LONG_CONTEXT_THRESHOLD)
        except (ValueError, IndexError):
            fields["long_threshold"] = pricing.LONG_CONTEXT_THRESHOLD
        fields["enabled"] = 1 if str(i) in set(form.getlist("enabled")) else 0
        db.upsert_model(fields)
        saved += 1
    db.audit(user["username"], "model_prices", f"{saved} models")
    return RedirectResponse("/settings", status_code=303)


@app.post("/settings/models/reset")
async def settings_models_reset(request: Request):
    user = auth.require_user(request)
    for m in pricing.CATALOG:
        db.upsert_model(m.as_dict() | {"enabled": 1})
    db.audit(user["username"], "model_prices_reset")
    return RedirectResponse("/settings", status_code=303)


@app.get("/costs", response_class=HTMLResponse)
async def costs_page(request: Request):
    today = db.now_iso()[:10]
    month = db.now_iso()[:7]
    return render(request, "costs.html",
                  total=db.usage_totals(),
                  today=db.usage_totals("day=?", (today,)),
                  this_month=db.usage_totals("month=?", (month,)),
                  by_day=db.usage_by("day", 30),
                  by_model=db.usage_by("model"),
                  by_chat=db.usage_by("chat_id", 15),
                  chats={c["id"]: c["title"] for c in db.list_chats(200)},
                  recent=db.recent_usage(60),
                  budget=agent.budget_status(),
                  fmt_usd=pricing.fmt_usd)

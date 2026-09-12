# CLAUDE.md

Guidance for Claude Code (claude.ai/code) working in this repository.

## Orientation

- `README.md` - what the service does and how to run it.
- `docs/DECISIONS.md` - **why** the architecture is what it is, and the phase plan. Read this
  before changing a load-bearing decision (SSH-only transport, git storage, tools instead of RAG,
  the `ssh,read` router group, Responses API).
- `docs/ROUTEROS-NOTES.md` - RouterOS behaviour verified against live hardware.
- `DEPLOY.md` - putting it on a server.

## What this is

A self-hosted FastAPI service that SSHes into a fleet of MikroTik routers, stores each device's
`/export` in a git repo, and lets an LLM answer questions about how the fleet is configured
("как настроен файрвол на office-ccr?"). Read-only today; the write path (change proposals,
approval, rollback) is designed for but not implemented. UI strings are Russian; code is English.

## Running & developing

The app is **baked into the image** (only `./data` is bind-mounted), so any code change needs a
rebuild:

```bash
docker compose up -d --build    # UI at http://localhost:8090 (container port 8080)
docker logs mikrotik-agent      # primary diagnostic
docker compose down
```

Tests run **inside the image** - the local interpreter is Python 3.9 and the code needs 3.10+
union syntax plus asyncssh:

```bash
docker run --rm -v "$PWD/tests:/app/tests" mikrotik-agent-mikrotik-agent python -m pytest tests -q
```

`tests/conftest.py` points `DATA_DIR` at a temp dir before importing the app, so tests never touch
real data. `tests/test_app.py` drives the real ASGI app with `TestClient`; no router needed.

To verify against a real router without creating an account in the user's live instance, run a
throwaway container with a tmpfs data dir:

```bash
docker run -d --name mtagent-uitest -p 8091:8080 --tmpfs /data:rw,size=64m mikrotik-agent-mikrotik-agent
```

## Architecture

Request/data flow (all in `app/`):

- **`main.py`** - FastAPI routes. **Middleware order matters**: Starlette wraps in reverse
  registration order, so `SessionMiddleware` is added *after* the `@app.middleware("http")` guard
  to end up outside it - the guard reads `request.session`. Registered the other way round, every
  protected page 500s with "SessionMiddleware must be installed". `db.init_db()` runs at import
  time (not in lifespan) because the session secret lives in the DB.
- **`ssh.py`** - asyncssh wrapper. Logs in as `<user>+ct` (RouterOS suffix that disables colours
  and terminal autodetect, so output is parseable). Explicit algorithm lists widen support back to
  RouterOS 6; **asyncssh's `get_*_algs()` return `bytes`**, so the wish-list intersection decodes
  first - a str/bytes mismatch silently empties the lists and drops back to modern-only defaults.
  `get_server_host_key()` accepts only `kex_algs`/`server_host_key_algs`, not the cipher/mac lists.
  Host keys are pinned TOFU into `/data/known_hosts`; a mismatch is an error, never auto-accepted.
- **`rsc.py`** - parser for `/export terse`. Every line is a full-path command
  (`/ip firewall filter add ...`), which is what section lookup and search rely on.
  `strip_header()` drops the `#` banner (timestamp, software id) so unchanged configs produce no
  git commit.
- **`facts.py`** - deterministic facts from a parsed export (interfaces, VLANs, subnets, tunnels,
  routing protocols, firewall counts). `summary()` renders the compact per-device block that makes
  up the fleet map in the system prompt.
- **`scrub.py`** - removes secrets before anything reaches the LLM. Last line of defence; the
  first two are `/export hide-sensitive` and a router-side group without the `sensitive` policy.
- **`store.py`** - git repo at `/data/configs/<slug>/export.rsc` + `facts.json`, one commit per
  collection run, committed once at the end (git's index is not concurrency-safe).
- **`collector.py`** - the run: bounded concurrency, per-device failures isolated, volatile values
  (uptime, cpu) to SQLite only so they never churn git.
- **`onboard.py`** - the one write operation: creates group `mikrotik-agent-ro`
  (`ssh,read` - deliberately no `write`, no `sensitive`, and no `test`, which would
  grant bandwidth-test and flood-ping) and imports the agent's public key.
  Admin credentials come from the request and are never stored. ed25519 for ROS 7, RSA for ROS 6.
- **`live.py`** - live router state (routes, ARP, leases, log, counters, Wi-Fi clients, tunnel
  handshakes). **The command is never built from model input**: the caller passes a key and the
  command is a literal constant from `QUERIES`, and filtering happens in Python over the returned
  lines rather than in a `where` clause - so there is no command-injection surface. Every entry is
  a `print` covered by `read`, so this needs no extra router rights; active probes (ping,
  traceroute, bandwidth-test) would need the `test` policy and are deliberately out of scope.
  Results are cached for 15s so a chain of tool calls cannot hammer a device.
- **`tools.py`** / **`agent.py`** - the LLM tool layer and loop. `tools.call` is async because
  `get_live_state` opens an SSH session; `ASYNC_TOOLS` lists which handlers must be awaited, and a
  test asserts that set matches which handlers are actually coroutines. Tools are size-capped; the system
  prompt carries the fleet map so the model navigates instead of grepping blindly.
- **`llm/`** - provider adapters behind one interface. **`openai` is the Responses API
  (`/v1/responses`), and that is not a preference**: `/v1/chat/completions` refuses function tools
  together with reasoning, and these models reason by default - so on that endpoint
  `reasoning_effort="none"` must be sent explicitly whenever tools are present (the `openai-chat`
  adapter does this; it exists for OpenAI-compatible proxies). Tool schemas are flat on Responses
  (`{"type":"function","name":...}`) and nested on Chat Completions. Responses runs with
  `store: false` so router configs are not retained provider-side, which means reasoning state
  must be echoed back by us: `include: ["reasoning.encrypted_content"]` and the opaque output
  items ride through chat history as `Reply.raw_items` -> message `extra["raw"]`. Both adapters
  expose `build_payload()` so the wire format is testable without a network. API keys are entered
  in the UI and stored Fernet-encrypted; there is no key env var by design. Each adapter
  normalises usage into `pricing.Usage`: **OpenAI's `prompt_tokens` already includes cached
  tokens** (so uncached = prompt - cached - written) while Anthropic reports cache reads/writes
  as separate fields. Getting this wrong bills cached input twice, at both rates.
- **`pricing.py`** - model catalogue and cost arithmetic. Prices are per 1M tokens and seeded into
  the `models` table so they can be corrected from the UI without a rebuild; `db.list_models()`
  is the runtime source of truth. Above `long_threshold` input tokens (272k, verified against the
  OpenAI pricing page 2026-09-10) the long tier applies to the **whole** request, not the excess -
  uniformly 2x input / 1.5x output. Reasoning tokens are a subset of output, billed at the output
  rate, so `reasoning_effort` directly moves the bill.
- Every API call writes a `usage` row; one chat turn is several calls because of the tool loop.
  `/costs` aggregates by day/model/chat, and `agent.budget_status()` gates a turn before the
  provider is even constructed.

## Notable constraints

- Losing `/data/master.key` makes every stored secret unrecoverable.
- RouterOS 6 `/export` shows secrets **unless** `hide-sensitive` is passed (v7 is the reverse), and
  only accepts RSA user keys.
- The read path must stay incapable of writing - keep the onboarded group free of `write`.
- Config text (especially comments) is attacker-controllable input to the LLM; the system prompt
  says so, and the future write path must rely on deterministic validation plus human approval.

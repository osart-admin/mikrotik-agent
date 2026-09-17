# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

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
("как настроен файрвол на office-ccr?"). Read-only toward routers: the model can queue a change
plan (`propose_change` -> `/changes`), which is validated and then carried out by a human in
Winbox; automatic applying exists in code but is switched off (see `apply.py` below). UI strings are Russian; code is English.

## Running & developing

The app is **baked into the image** (only `./data` is bind-mounted), so any code change needs a
rebuild:

```bash
./deploy.sh                     # UI at http://localhost:8090 (container port 8080)
docker logs mikrotik-agent      # primary diagnostic
docker compose down
```

`deploy.sh` is `docker compose up -d --build` plus the `APP_VERSION` (`git describe --always
--dirty`) and `APP_BUILT` build args, shown in the header and `/health` so it is clear which build
a server runs. `.git` is in `.dockerignore`, so a bare `docker compose up --build` reports `unknown`.

Tests run **inside the image** - the local interpreter is Python 3.9 and the code needs 3.10+
union syntax plus asyncssh:

```bash
docker run --rm -v "$PWD/tests:/app/tests" mikrotik-agent-mikrotik-agent python -m pytest tests -q
```

That runs the tests against the `app/` **baked into the last build**. To test uncommitted edits
without rebuilding, mount `app/` as well; single files and single tests work as usual:

```bash
docker run --rm -v "$PWD/tests:/app/tests" -v "$PWD/app:/app/app" mikrotik-agent-mikrotik-agent \
  python -m pytest -q tests/test_audit.py::test_a_negated_empty_list_widens_the_rule_instead
```

There is no linter or formatter configured.

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
  time (not in lifespan) because the session secret lives in the DB. A chat turn runs as a task
  in `_turns`, detached from its SSE response: Starlette cancels a streaming response when the
  client disconnects, and a turn cancelled with it (`CancelledError` slips past `except Exception`)
  leaves paid tool rounds with no answer. One turn per chat at a time (409 otherwise).
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
- **`audit.py`** - deterministic findings over a stored export, no SSH round-trip: rules matching
  on an address-list with no enabled members, terminal rules that shadow every rule below them in
  the same chain, and disabled entries that are stale past `STALE_DAYS` or whose comment marks them
  as temporary. Every finding carries the export
  line number and raw command so it can be checked in Winbox without trusting the model; staleness
  dates come from `store.blame_dates()` (git blame on `export.rsc`, not a stored timestamp) so an
  uncommitted line (all-zero sha, which git dates *now*) is dropped and reads as "unknown", not
  "new". The empty-list check only looks at rule tables, resolves IPv4 and IPv6 lists separately,
  and skips any list that is filled at runtime (`address-list=` on add-*-to-address-list rules,
  `/ppp profile`, DHCP `address-lists=`), the built-in interface lists and lists with `include=`,
  because none of those members appear in `/export`. A false positive here costs more than a
  miss: the page exists to be trusted without the model. Surfaced both as the `/audit` page and
  the `get_audit` tool.
- **Timestamps** are stored as UTC ISO strings. Templates render them with the `localtime` filter
  (`main.py`), which emits `<time datetime=...>`; a script in `base.html` rewrites it into the
  browser's zone. Don't slice timestamp strings in templates - that shows UTC.
- **`netcheck.py`** - "Проверить связь" when SSH fails: ping, TCP connect and SSH banner, to tell a
  dead host from a closed port or a firewall drop. It **never attempts a login**, so repeated
  checks cannot trip RouterOS's failed-login protection against the agent's own address.
- **`vault.py`** - Fernet encryption for every secret in SQLite (API keys, SSH keys, device
  passwords). The key is the `MASTER_KEY` env var if set, else `/data/master.key`, created on
  first run.
- **`winbox_import.py`** - bulk device import from a Winbox 3 `Addresses.cdb`. The binary field ids
  are undocumented, so the parser guesses a column mapping and the UI has the user confirm it; the
  parsed records are held encrypted on disk between the upload and confirm steps.
- **`changes.py`** - deterministic validator for proposed change plans. Blocks the destructive
  set outright (resets, reboots, firmware, user management, scripts, schedulers, files, `/import`,
  scripting expressions, `;` chaining), allows a menu whitelist, flags lockout risks. **Rejects,
  never sanitises** - a plan is not quietly edited into something permissible. A value that only
  exists after another plan runs (the WireGuard public key the other device generates) is queued
  as a `<placeholder>`; the operator fills it on the plan page, the value must be one plain token,
  the filled plan is validated again, and "done"/apply are refused while any placeholder remains.
- **`apply.py`** - **dormant**: automatic applying is off (`apply_enabled` setting, default 0).
  On RouterOS 7.22 a `/system scheduler` entry carries its creator's policy set and editing one
  requires holding all of those policies, so a minimal write account cannot even toggle
  `disabled`; and `/system backup save` is refused for `ssh,read,write`, `+ftp` and `+policy`.
  The rollback net therefore cannot be built without handing the write account near-full rights,
  which defeats the separation. Plans are executed by a human in Winbox (safe mode gives the same
  protection for free). The code is kept for the untested case of a scheduler created with an
  explicitly narrow `policy=`. Its design, if revived: Commit/confirm: backup under a fixed name -> enable the pre-installed
  rollback scheduler for N minutes -> run the commands -> the operator confirms the device is
  alive, which disables the scheduler. The scheduler is **pre-installed by admin during write
  onboarding** because creating one that carries commands needs the `policy` right, which also
  grants user management; the write account only ever toggles `disabled`/`interval`. That is why
  the scheduler, `/system backup load` and `/file` are on the validator's forbidden list.
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

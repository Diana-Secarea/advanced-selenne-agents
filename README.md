# Selenne Agents

Monitoring and security for AI agents and chatbots — the second product of
[selenne.app](https://selenne.app), next to the Wazuh-based SIEM.

Same accounts as Selenne, own runtime: this service runs in its own Docker
stack and reads users, sessions, API keys and entitlements from Selenne over
HTTP. Selenne code is copied in where useful, never imported.

```
customer agent ──OTel SDK / OTLP──┐
customer agent ──native JSON──────┼──► ingest.selenne.app ──► Postgres (spans, host_events)
selenne-sensor ──host events──────┘         │                        │
                                            └── key check ──► Selenne /internal/keys/verify
browser ── selenne.app/agents/ ──► console ─┴── session check ─► Selenne /api/auth/me
```

## Status

| Part | State |
|---|---|
| Ingestion (`selenne_agents/ingest`, `selenne_agents/store`) | **built** |
| Keys + `/internal/keys/verify` in Selenne, keys card on the profile page | **built** (Selenne repo) |
| Console skeleton at `selenne.app/agents/` (`selenne_agents/console`) | **built** — sessions = traces for now |
| Landing option, "Launch console ▾" and the SIEM ⇄ AI Agents switcher | **built** (Selenne repo) |
| Alerts: detection rules v0 at ingest + `/agents/alerts` page (the SIEM Live Alerts layout) | **built** |
| Session aggregation, scoring, reconciliation, agent RAG, reactor | not yet |
| Sensor (sidecar) | not yet — the `/v1/host-events` endpoint already accepts its format |
| Stripe add-on | not yet — `AGENTS_OPEN_BETA=1` in Selenne entitles everyone meanwhile |

## Console — `selenne.app/agents/`

Same origin as the SIEM, so the browser brings Selenne's session cookie. The
console forwards it to Selenne's `/api/auth/me` (cached 30 s) and shows only
that user's sessions. Signed out → `/login.html?next=/agents/`. It uses
Selenne's own `/assets/style.css` and `/assets/product-switch.js`, so both
consoles share one look and one SIEM ⇄ AI Agents menu.

## Alerts — `selenne.app/agents/alerts`

Rules run on every ingested batch (`selenne_agents/alerting/rules.py`) and
write to this stack's `agent_alerts` table — never to Selenne's alert
pipeline. Each alert has a rule id, level 0–15, score 0–100 and label
(CRITICAL ≥ 90, HIGH ≥ 75, POSSIBLE ≥ 50, NORMAL), tagged with OWASP Top 10
for LLM Applications and MITRE ATLAS ids. Evidence is an excerpt with secrets
masked.

| Rule | Fires on | Level / score |
|---|---|---|
| AG-101 | credential/secrets paths (`~/.ssh`, `/etc/shadow`, `.aws/credentials`, `.env`…) | 12 / 85 |
| AG-102 | secrets in agent data (AWS, private keys, GitHub/Slack/API tokens, JWTs) | 11 / 80 |
| AG-103 | prompt-injection phrasing in prompts or tool output | 10 / 72 |
| AG-104 | dangerous shell (`curl … \| sh`, reverse shells, `rm -rf /`…) | 13 / 92 |
| AG-105 | paste/exfiltration services or raw public IPs in URLs | 11 / 78 |
| AG-106 | a code/shell execution tool was used | 7 / 55 |
| AG-107 | a step ended in error | 3 / 25 |
| AG-201…204 | sensor: secrets file opened, dangerous exec, shell/network binary, public connect | 4–13 |

"🛡 Benign" on a card zero-scores that rule for the user (never hides it),
like the SIEM's benign rules. Rules are the stand-in until per-agent scoring
and reconciliation (build steps 5–6).

## Same look as the SIEM

The console ships its own copy of Selenne's UI in `frontend/assets/selenne/`,
so it renders identically whether reached through nginx or directly on :4319
(it never loads anything from Selenne's `/assets/`). The copy is generated:

```bash
scripts/sync-selenne-ui.sh ~/wazuh    # path to the advanced-ai-siem checkout
```

It copies `style.css` and `product-switch.js`, and builds `ui.js` from only
the presentation sections of Selenne's `app.js` (particles, reveals, counters,
card glow, tilt, transitions, nav shrink, cinematic layer). SIEM behaviour —
list managers, collector downloads, the SIEM auth redirect — is excluded, and
the script fails if any of it leaks in. Re-run it whenever Selenne's UI changes.

## Logs — kept apart from Selenne's alerting

OTel/Agents activity never reaches the files Selenne's Wazuh collector reads
(`selenne-audit.json`, `flask_access.log`), so it cannot raise SIEM alerts:

| Where | What |
|---|---|
| `ingest.json`, `console.json` in this stack's `logs` volume (`/var/log/selenne-agents/`) | one JSON line per ingested batch, errors, console activity |
| Selenne `logs/selenne-agents.json` (`AGENTS_LOG`) | key created/revoked, internal verify calls, and the containers' HTTP calls into Selenne — instead of `flask_access.log` |

Records are namespaced `selenne_agents.*`, never `selenne.*`, so even a
collector pointed at them by mistake matches none of `selenne_rules.xml`.

```bash
docker compose exec ingest tail -f /var/log/selenne-agents/ingest.json
```

## Ingestion API — `https://ingest.selenne.app`

Every request carries the project's ingestion key:
`Authorization: Bearer sk_sel_…`

| Endpoint | Format |
|---|---|
| `POST /v1/traces` | OTLP/HTTP — `application/x-protobuf` or `application/json`, optional `Content-Encoding: gzip` |
| gRPC `opentelemetry.proto.collector.trace.v1.TraceService/Export` on :443 | OTLP/gRPC, gzip supported |
| `POST /v1/events` | Native JSON spans, for teams without OpenTelemetry |
| `POST /v1/host-events` | Sensor events, `application/x-ndjson`, optional gzip |
| `GET /health` | Liveness, no auth |

### Already on OpenTelemetry

No code change — point the exporter at Selenne:

```bash
export OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=https://ingest.selenne.app/v1/traces
export OTEL_EXPORTER_OTLP_TRACES_HEADERS="Authorization=Bearer sk_sel_…"
export OTEL_SERVICE_NAME=support-bot
```

For gRPC use `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=https://ingest.selenne.app`
and `OTEL_EXPORTER_OTLP_TRACES_PROTOCOL=grpc`.

### Native JSON

```bash
curl https://ingest.selenne.app/v1/events \
  -H "Authorization: Bearer sk_sel_…" -H "Content-Type: application/json" \
  -d '{"resource": {"service.name": "support-bot"},
       "spans": [{"trace_id": "5b8efff798038103d269b633813fc60c",
                  "span_id": "eee19b7ec3c1b174",
                  "name": "tool.read_file", "kind": "internal",
                  "start_time": "2026-09-29T10:00:00.120Z",
                  "end_time":   "2026-09-29T10:00:00.480Z",
                  "status": "ok",
                  "attributes": {"gen_ai.tool.name": "read_file", "path": "report.pdf"}}]}'
# -> {"accepted": 1, "rejected": 0}
```

Times are ISO-8601 (`start_time`) or integer nanoseconds (`start_time_unix_nano`).
`parent_span_id`, `end_time`, `status`, `status_message`, `attributes` and
`events` (`[{"name", "time", "attributes"}]`) are optional.

### Host events (sensor)

One JSON object per line; `kind`, `host`, `pid` and `ts`/`ts_unix_nano` are
required, everything else is kept verbatim in `detail`. An `event_id` makes
retries idempotent.

```json
{"kind": "open", "host": "worker-1", "pid": 4242, "ppid": 1, "ts": "2026-09-29T10:00:00.2Z", "path": "/home/app/.ssh/id_rsa", "event_id": "w1-981"}
{"kind": "connect", "host": "worker-1", "pid": 4242, "ts": "2026-09-29T10:00:00.3Z", "daddr": "203.0.113.9", "dport": 443}
```

### Responses

| Status | Meaning | Client retries? |
|---|---|---|
| 200 | Stored. OTLP reports dropped spans as `partialSuccess`; native/host return `{"accepted", "rejected", "error"}` | — |
| 400 / 413 / 415 | Malformed body / over 5 MB (20 MB decompressed) / wrong content type or encoding | no |
| 401 | Missing, unknown or revoked key | no |
| 402 | Selenne Agents add-on not active on the account | no |
| 429 | Per-key rate limit, see `Retry-After` | yes |
| 503 | Key verification or storage temporarily unavailable, see `Retry-After` | yes |

gRPC maps these to `INVALID_ARGUMENT`, `UNAUTHENTICATED`, `PERMISSION_DENIED`,
`RESOURCE_EXHAUSTED` and `UNAVAILABLE`. Retried batches never duplicate spans
(unique per tenant + trace + span).

## Key verification (contract with Selenne)

Selenne owns keys and entitlements. For each unknown key, ingest asks:

```
POST {SELENNE_VERIFY_URL}                 # e.g. http://host.docker.internal:5000/internal/keys/verify
X-Selenne-Internal: {SELENNE_INTERNAL_SECRET}
{"key": "sk_sel_…"}

200 {"valid": true, "username": "diana", "project": "support-bot", "entitled": true, "key_id": "k_12"}
200 {"valid": false}
```

Answers are cached 60 s (unknown keys 10 s), so revoking a key in Selenne takes
effect within a minute. If Selenne is unreachable the request gets a retryable
503 — ingest never accepts on a guess. Tenancy (`username`, `project`) always
comes from this answer, never from the payload.

## Running

```bash
cp .env.example .env        # set passwords, SELENNE_VERIFY_URL, SELENNE_INTERNAL_SECRET
docker compose up -d --build
curl -s 127.0.0.1:4318/health
```

Listeners are published on loopback only (`127.0.0.1:4317` gRPC,
`127.0.0.1:4318` HTTP); `infra/nginx/ingest.selenne.app.conf` puts TLS and a
per-IP limit in front. Read the Cloudflare note at the top of that file before
enabling gRPC.

For a local demo without Selenne, set
`SELENNE_AGENTS_DEV_KEYS=sk_sel_devkey_0123456789abcdef=diana:demo` and leave
`SELENNE_VERIFY_URL` empty.

## Tests

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/pytest -q
# Postgres store tests (drops and recreates tables — use a throwaway DB):
SELENNE_AGENTS_TEST_DSN=postgresql://postgres:t@127.0.0.1:55432/sa .venv/bin/pytest -q tests/test_postgres.py
```

The end-to-end tests send spans through the stock OpenTelemetry SDK exporters
(HTTP and gRPC), so they prove compatibility with what customers already run.

## Layout

```
selenne_agents/
  config.py           settings from the environment
  ingest/
    keys.py           bearer parsing, Selenne verifier, dev keys, TTL cache
    ratelimit.py      per-key token bucket
    gate.py           key -> principal -> entitlement -> rate limit (shared by HTTP + gRPC)
    normalize.py      OTLP / native / host events -> one row shape
    otlp.py           protobuf <-> OTLP-JSON dict, OTLP responses
    http_app.py       Flask: /v1/traces, /v1/events, /v1/host-events
    grpc_server.py    OTLP/gRPC TraceService
    __main__.py       runs both listeners
  console/
    app.py            /agents/ page + /agents/api/* (sessions, one session)
    selenne_session.py  cookie -> Selenne /api/auth/me, cached
  logging_setup.py    stderr + own JSON files (never Selenne's collector files)
frontend/             the console UI, served at /agents/ (FRONTEND_DIR)
  index.html          sessions
  alerts.html         alerts (the SIEM Live Alerts layout)
  assets/             console.js, alerts.js, console.css
    selenne/          Selenne's style.css, product-switch.js and ui.js —
                      GENERATED by scripts/sync-selenne-ui.sh, do not edit
scripts/
  sync-selenne-ui.sh  re-copy Selenne's look & feel after changing its UI
  store/
    schema.sql        spans, host_events
    postgres.py       pooled writes, retry-safe inserts
infra/nginx/          ingest.selenne.app server block (selenne.app's /agents/
                      and /internal/ blocks are in Selenne's nginx.conf.sample)
```

Owned by Diana Secarea.

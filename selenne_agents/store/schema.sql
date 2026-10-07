-- Selenne Agents raw store. Applied at ingest startup; every statement is
-- idempotent. Tenancy is (username, project), taken from the verified key —
-- never from the payload.

CREATE TABLE IF NOT EXISTS spans (
    id              bigserial PRIMARY KEY,
    username        text        NOT NULL,
    project         text        NOT NULL,
    key_id          text,
    source          text        NOT NULL,          -- otlp-http | otlp-grpc | native
    trace_id        char(32)    NOT NULL,
    span_id         char(16)    NOT NULL,
    parent_span_id  char(16),
    name            text        NOT NULL,
    kind            text        NOT NULL,
    start_ns        bigint      NOT NULL,
    end_ns          bigint,
    status_code     text        NOT NULL,
    status_message  text,
    service_name    text,
    scope_name      text,
    scope_version   text,
    resource        jsonb       NOT NULL DEFAULT '{}'::jsonb,
    attributes      jsonb       NOT NULL DEFAULT '{}'::jsonb,
    events          jsonb       NOT NULL DEFAULT '[]'::jsonb,
    links           jsonb       NOT NULL DEFAULT '[]'::jsonb,
    received_at     timestamptz NOT NULL DEFAULT now(),
    -- exporters retry whole batches; a replayed span is dropped, not duplicated
    UNIQUE (username, project, trace_id, span_id)
);
CREATE INDEX IF NOT EXISTS spans_tenant_time ON spans (username, project, start_ns DESC);
CREATE INDEX IF NOT EXISTS spans_trace       ON spans (trace_id);

CREATE TABLE IF NOT EXISTS host_events (
    id              bigserial PRIMARY KEY,
    username        text        NOT NULL,
    project         text        NOT NULL,
    key_id          text,
    event_id        text,                           -- sensor-assigned, for retry dedup
    host            text        NOT NULL,
    pid             integer     NOT NULL,
    ppid            integer,
    cgroup          text,
    container_id    text,
    kind            text        NOT NULL,           -- exec | open | connect | dns | ...
    ts_ns           bigint      NOT NULL,
    detail          jsonb       NOT NULL,
    received_at     timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS host_events_dedup
    ON host_events (username, project, host, event_id) WHERE event_id IS NOT NULL;
-- reconciliation joins host events to spans by host + process + time window
CREATE INDEX IF NOT EXISTS host_events_join ON host_events (username, project, host, ts_ns);

-- Selenne Agents alerts (rules v0 today; scoring/reconciliation later).
-- Lives here, in this stack's database — never in Selenne's alert pipeline.
CREATE TABLE IF NOT EXISTS agent_alerts (
    id              bigserial PRIMARY KEY,
    username        text        NOT NULL,
    project         text        NOT NULL,
    rule_id         text        NOT NULL,
    level           smallint    NOT NULL,
    score           smallint    NOT NULL,
    title           text        NOT NULL,
    tags            jsonb       NOT NULL DEFAULT '[]'::jsonb,
    evidence        jsonb       NOT NULL DEFAULT '{}'::jsonb,
    source_ref      text        NOT NULL,           -- span:<trace>:<span> | host:<host>:<event>
    trace_id        char(32),
    span_id         char(16),
    service_name    text,
    host            text,
    ts_ns           bigint      NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    -- one alert per rule per span/event, so exporter retries never duplicate
    UNIQUE (username, project, rule_id, source_ref)
);
CREATE INDEX IF NOT EXISTS agent_alerts_tenant_time ON agent_alerts (username, ts_ns DESC);

-- "🛡 Benign" exceptions, per user and rule — same idea as Selenne's benign
-- rules: matching alerts are zero-scored and labelled BENIGN, never hidden.
CREATE TABLE IF NOT EXISTS agent_benign_rules (
    username    text        NOT NULL,
    rule_id     text        NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (username, rule_id)
);

-- --- aggregation (selenne_agents.aggregate) ----------------------------------
-- Derived tables: everything below can be dropped and rebuilt from spans and
-- host_events by resetting aggregator_state.
--
-- Indexes the aggregator needs on the big raw tables (spans, host_events,
-- agent_alerts) are NOT here: a plain CREATE INDEX blocks ingest writes for
-- the whole build. They are ONLINE_INDEXES in postgres.py, built CONCURRENTLY
-- by the aggregator at startup.

-- How far the aggregator has read each raw table. last_id alone is not enough:
-- bigserial ids commit out of order, so each tick also re-reads rows at or
-- below last_id received shortly before the previous tick (scanned_at), which
-- catches a batch that was still in flight when the aggregator passed its id.
CREATE TABLE IF NOT EXISTS aggregator_state (
    name        text PRIMARY KEY,               -- spans | host_events | agent_alerts | reconcile
    last_id     bigint      NOT NULL DEFAULT 0,
    scanned_at  timestamptz,                    -- database time of the last tick
    updated_at  timestamptz NOT NULL DEFAULT now()
);
INSERT INTO aggregator_state (name) VALUES ('spans'), ('host_events'), ('agent_alerts'), ('reconcile')
    ON CONFLICT DO NOTHING;

-- Which session each trace belongs to. A trace carrying gen_ai.conversation.id
-- (or session.id) joins that conversation; otherwise it is its own session.
CREATE TABLE IF NOT EXISTS session_traces (
    username        text     NOT NULL,
    project         text     NOT NULL,
    trace_id        char(32) NOT NULL,
    session_id      char(32) NOT NULL,          -- trace_id, or md5('c:' || project || ':' || conversation)
    conversation_id text,
    PRIMARY KEY (username, project, trace_id)
);
CREATE INDEX IF NOT EXISTS session_traces_session ON session_traces (username, project, session_id);

-- One row per session, rebuilt whole whenever any of its spans arrives.
-- Open vs idle is decided when reading (last_ns), so nothing has to close them.
CREATE TABLE IF NOT EXISTS agent_sessions (
    username        text     NOT NULL,
    project         text     NOT NULL,
    session_id      char(32) NOT NULL,
    kind            text     NOT NULL,          -- trace | conversation
    conversation_id text,
    service_name    text,
    root_name       text,
    first_ns        bigint   NOT NULL,
    last_ns         bigint   NOT NULL,
    traces          integer  NOT NULL,
    spans           integer  NOT NULL,
    errors          integer  NOT NULL,
    tool_calls      integer  NOT NULL,
    llm_calls       integer  NOT NULL,
    input_tokens    bigint   NOT NULL DEFAULT 0,
    output_tokens   bigint   NOT NULL DEFAULT 0,
    alert_scores    jsonb    NOT NULL DEFAULT '{}'::jsonb,  -- {rule_id: highest score}; benign applied on read
    hosts           text[]   NOT NULL DEFAULT '{}',
    updated_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (username, project, session_id)
);
CREATE INDEX IF NOT EXISTS agent_sessions_recent ON agent_sessions (username, last_ns DESC);

-- The processes agents run in, seen from span resources (process.pid +
-- host.name) and from the sensor. Reconciliation joins host events to spans
-- through this table.
CREATE TABLE IF NOT EXISTS agent_processes (
    username        text     NOT NULL,
    project         text     NOT NULL,
    host            text     NOT NULL,
    pid             integer  NOT NULL,
    proc_start_ns   bigint   NOT NULL DEFAULT 0,    -- 0 = unknown; the sensor will set it (pid reuse)
    container_id    text,
    ppid            integer,
    service_name    text,
    executable      text,
    from_spans      boolean  NOT NULL DEFAULT false,
    from_sensor     boolean  NOT NULL DEFAULT false,
    first_ns        bigint   NOT NULL,
    last_ns         bigint   NOT NULL,
    PRIMARY KEY (username, project, host, pid, proc_start_ns)
);

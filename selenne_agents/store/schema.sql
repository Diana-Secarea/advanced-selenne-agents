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

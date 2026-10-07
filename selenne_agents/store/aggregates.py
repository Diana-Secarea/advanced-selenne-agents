"""SQL for one aggregator tick (PostgresStore.aggregate_tick).

A tick runs in one transaction:
  1. pick this tick's raw rows (spans, host events, alerts) into temp tables:
     the next page by id, plus rows at or below the watermark received around
     the previous tick (an ingest batch that was still uncommitted when the
     watermark passed it);
  2. map the traces they touch to sessions (session_traces) — an alert that
     arrives late, e.g. from reconciliation, touches its trace like a span;
  3. rebuild every touched session from ALL its spans — so re-running a tick,
     or seeing a row twice, gives the same result;
  4. upsert the processes seen in span resources and in host events;
  5. move the watermarks.
Temp tables are ON COMMIT DROP, so a pooled connection carries nothing over.

The catch-up scan only works if no ingest transaction stays open longer than
the overlap, which ingest's transaction_timeout enforces. The periodic check
(PostgresStore.verify_recent) runs steps 2–4 over a whole recent window, by
time instead of id, and counts the sessions it had to repair — a safety net
for anything that slips past the watermark anyway, and a measure of whether
anything ever does.
"""


def _num(expr):
    """Non-negative integer attribute as bigint, NULL if it is anything else —
    a bad customer value must never make the cast fail the whole tick."""
    return f"(CASE WHEN ({expr}) ~ '^[0-9]{{1,15}}$' THEN ({expr})::bigint END)"


# Conversation key of one span; the earliest span with one decides the trace.
_CONVERSATION = """left(coalesce(nullif(s.attributes->>'gen_ai.conversation.id', ''),
                         nullif(s.attributes->>'session.id', ''),
                         nullif(s.resource->>'session.id', '')), 1024)"""

PAGE_SQL = """
SELECT coalesce(max(id), %(last_id)s), count(*)
FROM (SELECT id FROM {table} WHERE id > %(last_id)s ORDER BY id LIMIT %(batch)s) page
"""

# Tick: the next page by id, plus the catch-up scan (id <= last_id AND
# received > scanned_at - overlap); with no previous tick (scanned_at NULL)
# the catch-up matches nothing.
_TICK_WHERE = """(id > %(last_id)s AND id <= %(upto)s)
   OR (id <= %(last_id)s AND {received} > %(scanned_at)s::timestamptz - make_interval(secs => %(overlap)s))"""
# Periodic check: everything received in the window, whatever its id.
_WINDOW_WHERE = "{received} > now() - make_interval(secs => %(window)s)"

# Host-event alerts (no trace) reach sessions through reconciliation, later.
_PICKS = (
    ("spans", "agg_spans", "received_at", "true",
     "username, project, trace_id, service_name, resource, start_ns, end_ns"),
    ("host_events", "agg_events", "received_at", "true",
     "username, project, host, pid, ppid, container_id, kind, ts_ns, detail"),
    ("agent_alerts", "agg_alerts", "created_at", "trace_id IS NOT NULL",
     "DISTINCT username, project, trace_id"),
)


def _pick_sql(where):
    return {table: f"""
CREATE TEMP TABLE {temp} ON COMMIT DROP AS
SELECT {cols} FROM {table} WHERE {cond} AND ({where.format(received=received)})"""
            for table, temp, received, cond, cols in _PICKS}


PICK_TICK_SQL = _pick_sql(_TICK_WHERE)      # {table: sql}, params last_id/upto/scanned_at/overlap
PICK_WINDOW_SQL = _pick_sql(_WINDOW_WHERE)  # {table: sql}, param window

RESOLVE_SQL = f"""
CREATE TEMP TABLE agg_traces ON COMMIT DROP AS
SELECT t.username, t.project, t.trace_id, c.conversation_id,
       CASE WHEN c.conversation_id IS NULL THEN t.trace_id
            ELSE md5('c:' || t.project || ':' || c.conversation_id) END::char(32) AS session_id,
       old.session_id AS old_session_id
FROM (SELECT username, project, trace_id FROM agg_spans
      UNION
      SELECT username, project, trace_id FROM agg_alerts) t
LEFT JOIN LATERAL (
    SELECT {_CONVERSATION} AS conversation_id
    FROM spans s
    WHERE s.username = t.username AND s.project = t.project AND s.trace_id = t.trace_id
      AND {_CONVERSATION} IS NOT NULL
    ORDER BY s.start_ns, s.span_id
    LIMIT 1
) c ON true
LEFT JOIN session_traces old
       ON old.username = t.username AND old.project = t.project AND old.trace_id = t.trace_id
"""

MAP_TRACES_SQL = """
INSERT INTO session_traces (username, project, trace_id, session_id, conversation_id)
SELECT username, project, trace_id, session_id, conversation_id FROM agg_traces
ON CONFLICT (username, project, trace_id) DO UPDATE
   SET session_id = EXCLUDED.session_id, conversation_id = EXCLUDED.conversation_id
"""

# A trace that moved into a conversation leaves its old session behind; that
# one is rebuilt too, and simply disappears if no trace points at it any more.
AFFECTED_SQL = """
CREATE TEMP TABLE agg_affected ON COMMIT DROP AS
SELECT username, project, session_id FROM agg_traces
UNION
SELECT username, project, old_session_id FROM agg_traces WHERE old_session_id IS NOT NULL
"""

# The check keeps the rows it is about to rebuild, to count what changed.
SNAPSHOT_SQL = """
CREATE TEMP TABLE agg_before ON COMMIT DROP AS
SELECT a.* FROM agent_sessions a JOIN agg_affected f
  ON a.username = f.username AND a.project = f.project AND a.session_id = f.session_id
"""

_CONTENT = """username, project, session_id, kind, conversation_id, service_name, root_name,
       first_ns, last_ns, traces, spans, errors, tool_calls, llm_calls, input_tokens,
       output_tokens, alert_scores, hosts"""

# Sessions whose rebuilt row differs from the stored one (or exists on one
# side only) — each is a session the tick had missed.
REPAIRED_SQL = f"""
WITH after AS (
    SELECT a.* FROM agent_sessions a JOIN agg_affected f
      ON a.username = f.username AND a.project = f.project AND a.session_id = f.session_id
)
SELECT count(DISTINCT (username, project, session_id)) FROM (
    (SELECT {_CONTENT} FROM after EXCEPT SELECT {_CONTENT} FROM agg_before)
    UNION ALL
    (SELECT {_CONTENT} FROM agg_before EXCEPT SELECT {_CONTENT} FROM after)
) diff
"""

DELETE_SESSIONS_SQL = """
DELETE FROM agent_sessions a USING agg_affected f
WHERE a.username = f.username AND a.project = f.project AND a.session_id = f.session_id
"""

_LLM_OPS = "('chat', 'text_completion', 'generate_content')"

REBUILD_SESSIONS_SQL = f"""
WITH sp AS (
    SELECT st.username, st.project, st.session_id, st.conversation_id,
           s.trace_id, s.name, s.parent_span_id, s.start_ns, s.end_ns, s.status_code,
           s.service_name, s.attributes, s.resource
    FROM agg_affected f
    JOIN session_traces st ON st.username = f.username AND st.project = f.project
                          AND st.session_id = f.session_id
    JOIN spans s ON s.username = st.username AND s.project = st.project
                AND s.trace_id = st.trace_id
), alerts AS (
    -- highest score per rule; benign rules are applied when reading, so
    -- toggling one takes effect at once, without a rebuild
    SELECT username, project, session_id, jsonb_object_agg(rule_id, score) AS scores
    FROM (SELECT f.username, f.project, f.session_id, a.rule_id, max(a.score) AS score
          FROM agg_affected f
          JOIN session_traces st ON st.username = f.username AND st.project = f.project
                                AND st.session_id = f.session_id
          JOIN agent_alerts a ON a.username = st.username AND a.project = st.project
                             AND a.trace_id = st.trace_id
          GROUP BY 1, 2, 3, 4) per_rule
    GROUP BY 1, 2, 3
)
INSERT INTO agent_sessions (username, project, session_id, kind, conversation_id, service_name,
                            root_name, first_ns, last_ns, traces, spans, errors, tool_calls,
                            llm_calls, input_tokens, output_tokens, alert_scores, hosts)
SELECT sp.username, sp.project, sp.session_id,
       CASE WHEN max(sp.conversation_id) IS NULL THEN 'trace' ELSE 'conversation' END,
       max(sp.conversation_id),
       (array_agg(sp.service_name ORDER BY sp.start_ns) FILTER (WHERE sp.service_name IS NOT NULL))[1],
       (array_agg(sp.name ORDER BY (sp.parent_span_id IS NULL) DESC, sp.start_ns))[1],
       min(sp.start_ns),
       max(greatest(sp.start_ns, coalesce(sp.end_ns, sp.start_ns))),
       count(DISTINCT sp.trace_id),
       count(*),
       count(*) FILTER (WHERE sp.status_code = 'error'),
       count(*) FILTER (WHERE sp.attributes ? 'gen_ai.tool.name'
                           OR sp.attributes->>'gen_ai.operation.name' = 'execute_tool'),
       count(*) FILTER (WHERE sp.attributes->>'gen_ai.operation.name' IN {_LLM_OPS}),
       coalesce(sum(coalesce({_num("sp.attributes->>'gen_ai.usage.input_tokens'")},
                             {_num("sp.attributes->>'gen_ai.usage.prompt_tokens'")})), 0),
       coalesce(sum(coalesce({_num("sp.attributes->>'gen_ai.usage.output_tokens'")},
                             {_num("sp.attributes->>'gen_ai.usage.completion_tokens'")})), 0),
       coalesce(al.scores, '{{}}'),
       coalesce(array_agg(DISTINCT left(sp.resource->>'host.name', 1024))
                FILTER (WHERE sp.resource->>'host.name' IS NOT NULL), '{{}}')
FROM sp
LEFT JOIN alerts al ON al.username = sp.username AND al.project = sp.project
                   AND al.session_id = sp.session_id
GROUP BY sp.username, sp.project, sp.session_id, al.scores
"""

# Spans without host.name and process.pid in their resource say nothing about
# a process; most SDKs need their process/host resource detectors turned on.
SPAN_PROCESSES_SQL = f"""
INSERT INTO agent_processes AS p (username, project, host, pid, container_id, service_name,
                                  executable, from_spans, first_ns, last_ns)
SELECT username, project, left(resource->>'host.name', 1024),
       {_num("resource->>'process.pid'")}::integer,
       max(resource->>'container.id'), max(service_name),
       max(resource->>'process.executable.name'), true,
       min(start_ns), max(greatest(start_ns, coalesce(end_ns, start_ns)))
FROM agg_spans
WHERE resource->>'host.name' IS NOT NULL AND resource->>'process.pid' ~ '^[0-9]{{1,9}}$'
GROUP BY 1, 2, 3, 4
ON CONFLICT (username, project, host, pid, proc_start_ns) DO UPDATE SET
    container_id = coalesce(EXCLUDED.container_id, p.container_id),
    service_name = coalesce(EXCLUDED.service_name, p.service_name),
    executable   = coalesce(EXCLUDED.executable, p.executable),
    from_spans   = true,
    first_ns     = least(p.first_ns, EXCLUDED.first_ns),
    last_ns      = greatest(p.last_ns, EXCLUDED.last_ns)
"""


def _latest(expr, cond=None):
    where = f"({expr}) IS NOT NULL" + (f" AND {cond}" if cond else "")
    return f"(array_agg({expr} ORDER BY ts_ns DESC) FILTER (WHERE {where}))[1]"


_EXEC_PATH = "coalesce(detail->>'path', detail->>'filename')"

EVENT_PROCESSES_SQL = f"""
INSERT INTO agent_processes AS p (username, project, host, pid, container_id, ppid,
                                  service_name, executable, from_sensor, first_ns, last_ns)
SELECT username, project, host, pid,
       {_latest("container_id")}, {_latest("ppid")},
       {_latest("detail->>'service_name'")}, {_latest(_EXEC_PATH, "kind = 'exec'")},
       true, min(ts_ns), max(ts_ns)
FROM agg_events
GROUP BY 1, 2, 3, 4
ON CONFLICT (username, project, host, pid, proc_start_ns) DO UPDATE SET
    container_id = coalesce(EXCLUDED.container_id, p.container_id),
    ppid         = coalesce(EXCLUDED.ppid, p.ppid),
    service_name = coalesce(EXCLUDED.service_name, p.service_name),
    executable   = coalesce(EXCLUDED.executable, p.executable),
    from_sensor  = true,
    first_ns     = least(p.first_ns, EXCLUDED.first_ns),
    last_ns      = greatest(p.last_ns, EXCLUDED.last_ns)
"""

MARK_SQL = """
INSERT INTO aggregator_state (name, last_id, scanned_at, updated_at)
VALUES (%(name)s, %(last_id)s, now(), now())
ON CONFLICT (name) DO UPDATE
   SET last_id = EXCLUDED.last_id, scanned_at = EXCLUDED.scanned_at, updated_at = now()
"""

# --- reads for the console ---------------------------------------------------

SESSIONS_READ_SQL = """
SELECT a.project, a.session_id, a.kind, a.conversation_id, a.service_name, a.root_name,
       a.first_ns, a.last_ns, a.traces, a.spans, a.errors, a.tool_calls, a.llm_calls,
       a.input_tokens, a.output_tokens, a.alert_scores, a.hosts,
       -- benign rules count as 0 (never hidden); NULL = no alerts at all
       (SELECT max(CASE WHEN b.rule_id IS NULL THEN e.value::smallint ELSE 0 END)
        FROM jsonb_each_text(a.alert_scores) e
        LEFT JOIN agent_benign_rules b ON b.username = a.username AND b.rule_id = e.key
       ) AS max_alert_score
FROM agent_sessions a
WHERE a.username = %(username)s AND a.last_ns >= %(since_ns)s
  AND (%(project)s::text IS NULL OR a.project = %(project)s)
ORDER BY a.last_ns DESC
LIMIT %(limit)s
"""

# The id may be a session id or the id of any trace in a session (an alert's
# deep link carries a trace id): either way, the whole session comes back.
SESSION_SPANS_SQL = """
WITH sess AS (
    SELECT DISTINCT project, session_id FROM session_traces
    WHERE username = %(username)s
      AND (session_id = %(session_id)s OR trace_id = %(session_id)s)
)
SELECT st.session_id, s.trace_id, s.span_id, s.parent_span_id, s.name, s.kind, s.start_ns, s.end_ns,
       s.status_code, s.status_message, s.service_name, s.scope_name, s.project, s.source,
       s.attributes, s.events, s.resource
FROM sess
JOIN session_traces st ON st.username = %(username)s AND st.project = sess.project
                      AND st.session_id = sess.session_id
JOIN spans s ON s.username = st.username AND s.project = st.project AND s.trace_id = st.trace_id
ORDER BY s.start_ns
LIMIT %(limit)s
"""

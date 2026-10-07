"""SQL for Deviations and Incidents — the same alerts, read two ways.

A deviation is any rule hit in agent_alerts: a policy the agent's own spans
broke (AG-1xx), one the host broke (AG-2xx), or host activity the agent never
reported (AG-3xx, reconciliation). Each is placed in its session: span alerts
through their trace, host alerts by agent (service name) and time.

An incident is a deviation with consequences (score >= 50, not benign, not
itself an input finding) together with its probable cause: the most recent
untrusted input in the same session before it — a prompt-injection finding
(AG-103) first, else what came from outside the agent: a tool's output, a
retrieved document, a fetched page.
"""

_SESSION_OF = """
LEFT JOIN session_traces st
       ON a.trace_id IS NOT NULL AND st.username = a.username AND st.project = a.project
      AND st.trace_id = a.trace_id
LEFT JOIN LATERAL (
    SELECT s.session_id FROM agent_sessions s
    WHERE a.trace_id IS NULL AND a.service_name IS NOT NULL
      AND s.username = a.username AND s.service_name = a.service_name
      AND a.ts_ns BETWEEN s.first_ns - 5000000000 AND s.last_ns + 60000000000
    ORDER BY abs(a.ts_ns - s.last_ns)
    LIMIT 1
) hs ON true
"""

DEVIATIONS_SQL = f"""
SELECT a.id, a.username, a.project, a.rule_id, a.level, a.score, a.title, a.tags, a.evidence,
       a.source_ref, a.trace_id, a.span_id, a.service_name, a.host, a.ts_ns,
       (b.rule_id IS NOT NULL) AS benign,
       coalesce(st.session_id, hs.session_id) AS session_id
FROM agent_alerts a
LEFT JOIN agent_benign_rules b ON b.username = a.username AND b.rule_id = a.rule_id
{_SESSION_OF}
WHERE a.username = %(username)s AND a.ts_ns >= %(since_ns)s
  AND (%(prefix)s::text IS NULL OR a.rule_id LIKE %(prefix)s)
ORDER BY a.ts_ns DESC, a.id DESC
LIMIT %(limit)s
"""

# spans that carry input from outside the agent
_UNTRUSTED = """(
       s.attributes ? 'gen_ai.tool.name'
    OR s.attributes->>'gen_ai.operation.name' IN ('execute_tool', 'retrieve', 'retrieval', 'embeddings')
    OR s.name ILIKE '%%retriev%%'
    OR s.attributes ? 'url.full' OR s.attributes ? 'http.url')"""

INCIDENTS_SQL = f"""
WITH dev AS (
    SELECT a.id, a.username, a.project, a.rule_id, a.level, a.score, a.title, a.evidence,
           a.source_ref, a.trace_id, a.span_id, a.service_name, a.host, a.ts_ns,
           coalesce(st.session_id, hs.session_id) AS session_id
    FROM agent_alerts a
    LEFT JOIN agent_benign_rules b ON b.username = a.username AND b.rule_id = a.rule_id
    {_SESSION_OF}
    WHERE a.username = %(username)s AND a.ts_ns >= %(since_ns)s
      AND b.rule_id IS NULL AND a.score >= %(min_score)s
      -- an input finding is a cause, not a consequence; a failed step is neither
      AND a.rule_id NOT IN ('AG-103', 'AG-107')
)
SELECT dev.*, ss.root_name, ss.kind AS session_kind,
       c.cause_kind, c.trace_id AS cause_trace_id, c.span_id AS cause_span_id,
       c.name AS cause_name, c.start_ns AS cause_ns, c.tool AS cause_tool,
       c.excerpt AS cause_excerpt, c.url AS cause_url, c.preview AS cause_preview
FROM dev
LEFT JOIN agent_sessions ss ON ss.username = dev.username AND ss.session_id = dev.session_id
JOIN LATERAL (
    SELECT s.trace_id, s.span_id, s.name, s.start_ns, s.attributes->>'gen_ai.tool.name' AS tool,
           ia.evidence->>'excerpt' AS excerpt,
           coalesce(s.attributes->>'url.full', s.attributes->>'http.url') AS url,
           left(coalesce(s.attributes->>'gen_ai.tool.output', s.attributes->>'gen_ai.tool.call.result',
                         s.attributes->>'output', s.attributes->>'result'), 400) AS preview,
           CASE WHEN ia.id IS NOT NULL THEN 'prompt_injection'
                WHEN s.attributes->>'gen_ai.operation.name' IN ('retrieve', 'retrieval', 'embeddings')
                  OR s.name ILIKE '%%retriev%%' THEN 'retrieved_content'
                WHEN s.attributes ? 'url.full' OR s.attributes ? 'http.url' THEN 'web_content'
                ELSE 'tool_output' END AS cause_kind
    FROM session_traces t
    JOIN spans s ON s.username = t.username AND s.project = t.project AND s.trace_id = t.trace_id
    LEFT JOIN agent_alerts ia ON ia.username = s.username AND ia.rule_id = 'AG-103'
         AND ia.source_ref = 'span:' || s.trace_id || ':' || s.span_id
    WHERE t.username = dev.username AND t.session_id = dev.session_id
      AND s.start_ns <= dev.ts_ns
      AND 'span:' || s.trace_id || ':' || s.span_id <> dev.source_ref
      AND (ia.id IS NOT NULL OR {_UNTRUSTED})
    ORDER BY (ia.id IS NOT NULL) DESC, s.start_ns DESC
    LIMIT 1
) c ON true
WHERE dev.session_id IS NOT NULL
ORDER BY dev.ts_ns DESC
LIMIT %(limit)s
"""

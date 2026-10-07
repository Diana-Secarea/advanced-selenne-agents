"""SQL for reconciliation: host activity an agent never reported.

The sensor sees what an agent's processes did; spans say what the agent says
it did. A host event from an agent that reports spans at all, at a moment no
span of that agent covers, is unexplained — a deviation (AG-301/302/303).

  * a program started (exec) needs a tool-call span around it: an agent
    running a program while it is "thinking" or idle did not mean to;
  * a connection or a file access needs any span around it;
  * the agent's own main process (agent_root) is never unexplained;
  * an agent with no spans near the event is not instrumented: nothing to
    compare against, so nothing is flagged (the Activity page still shows it).

Matched by username + service name (the sensor's OTEL_SERVICE_NAME, the
spans' service.name), not host or project: span host.name is often a
container id, and the sensor may report under its own project key.

Host events are taken once they have settled — received `settle` seconds
ago, so the spans describing the same moment have arrived — in id order
under the 'reconcile' watermark. Ingest's transaction timeout (30 s) is far
below the settle time, so no row below the watermark can still commit.
"""

PAGE_SQL = """
SELECT coalesce(max(id), %(last_id)s), count(*)
FROM (SELECT id FROM host_events
      WHERE id > %(last_id)s AND received_at < now() - make_interval(secs => %(settle)s)
      ORDER BY id LIMIT %(batch)s) page
"""

_SPAN_NEAR = """
    FROM spans s
    WHERE s.username = h.username AND s.service_name = h.detail->>'service_name'
"""

UNEXPLAINED_SQL = f"""
SELECT h.username, h.project, h.host, h.event_id, h.pid, h.kind, h.ts_ns, h.detail
FROM host_events h
WHERE h.id > %(last_id)s AND h.id <= %(upto)s
  AND h.event_id IS NOT NULL
  AND h.detail->>'service_name' IS NOT NULL
  AND (h.kind IN ('connect', 'open')
       OR (h.kind = 'exec' AND NOT coalesce((h.detail->>'agent_root')::boolean, false)))
  -- instrumented: the agent sent spans within the hour around it
  AND EXISTS (SELECT 1 {_SPAN_NEAR}
                AND s.start_ns BETWEEN h.ts_ns - 3600000000000 AND h.ts_ns + 3600000000000)
  -- and none of them covers this moment
  AND NOT EXISTS (
      SELECT 1 {_SPAN_NEAR}
        AND s.start_ns BETWEEN h.ts_ns - 3600000000000 AND h.ts_ns + %(slack_ns)s
        AND coalesce(s.end_ns, s.start_ns) >= h.ts_ns - %(slack_ns)s
        AND (h.kind <> 'exec' OR s.attributes ? 'gen_ai.tool.name'
             OR s.attributes->>'gen_ai.operation.name' = 'execute_tool'))
ORDER BY h.id
"""

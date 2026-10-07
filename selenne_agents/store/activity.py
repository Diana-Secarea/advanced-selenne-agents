"""SQL for the console's Activity page: what the sensor saw agents do on
their hosts (host_events), newest first, with the alerts each event raised.

An alert on a host event points back at it through source_ref
('host:<host>:<event_id>', alerting._host_ref), so the join needs no extra
column; the sensor always sends an event_id.
"""

# Filters are all optional (NULL = any). Heartbeats are the sensor talking
# about itself, shown separately (SENSORS_SQL).
_FILTERS = """
      h.username = %(username)s AND h.ts_ns >= %(since_ns)s AND h.ts_ns < %(before_ns)s
  AND h.kind <> 'sensor.heartbeat'
  AND (%(project)s::text IS NULL OR h.project = %(project)s)
  AND (%(kind)s::text    IS NULL OR h.kind = %(kind)s)
  AND (%(agent)s::text   IS NULL OR h.detail->>'service_name' = %(agent)s)
  AND (%(host)s::text    IS NULL OR h.host = %(host)s)
  AND (%(scope)s::text   IS NULL OR h.detail->>'scope' = %(scope)s)
"""

_ALERTS_OF = """
    SELECT a.id, a.rule_id, a.score, a.title, (b.rule_id IS NOT NULL) AS benign
    FROM agent_alerts a
    LEFT JOIN agent_benign_rules b ON b.username = a.username AND b.rule_id = a.rule_id
    WHERE a.username = h.username AND h.event_id IS NOT NULL
      AND a.source_ref = 'host:' || h.host || ':' || h.event_id
"""

ACTIVITY_SQL = f"""
SELECT h.id, h.project, h.host, h.pid, h.ppid, h.container_id, h.kind, h.ts_ns, h.detail,
       coalesce((SELECT jsonb_agg(to_jsonb(x) ORDER BY x.score DESC) FROM ({_ALERTS_OF}) x),
                '[]'::jsonb) AS alerts
FROM host_events h
WHERE {_FILTERS}
  AND (NOT %(alerts_only)s OR EXISTS ({_ALERTS_OF}))
ORDER BY h.ts_ns DESC, h.id DESC
LIMIT %(limit)s
"""

# What the filter menus offer, with counts, over the same window.
FACETS_SQL = """
SELECT 'agent' AS facet, coalesce(detail->>'service_name', '') AS value, count(*) AS n
FROM host_events h WHERE {where} GROUP BY 2
UNION ALL
SELECT 'host', host, count(*) FROM host_events h WHERE {where} GROUP BY 2
UNION ALL
SELECT 'kind', kind, count(*) FROM host_events h WHERE {where} GROUP BY 2
UNION ALL
SELECT 'scope', detail->>'scope', count(*) FROM host_events h
WHERE {where} AND kind = 'connect' GROUP BY 2
UNION ALL
SELECT 'alerts', 'events', count(*) FROM host_events h
WHERE {where} AND EXISTS ({alerts})
""".format(alerts=_ALERTS_OF, where="""h.username = %(username)s AND h.ts_ns >= %(since_ns)s
  AND h.kind <> 'sensor.heartbeat'
  AND (%(project)s::text IS NULL OR h.project = %(project)s)""")

# The latest heartbeat of each sensor (one per host): is it alive, what does
# it watch, is it dropping or spooling.
SENSORS_SQL = """
SELECT DISTINCT ON (host) host, project, ts_ns, detail
FROM host_events
WHERE username = %(username)s AND kind = 'sensor.heartbeat' AND ts_ns >= %(since_ns)s
ORDER BY host, ts_ns DESC
"""

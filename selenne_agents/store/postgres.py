"""Postgres writes for the ingest path."""

import contextlib
import logging
import os
import threading

import psycopg2
import psycopg2.pool
from psycopg2.extras import Json, RealDictCursor, execute_values

log = logging.getLogger("store")

SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "schema.sql")

_SPAN_COLS = ("username", "project", "key_id", "source", "trace_id", "span_id",
              "parent_span_id", "name", "kind", "start_ns", "end_ns", "status_code",
              "status_message", "service_name", "scope_name", "scope_version",
              "resource", "attributes", "events", "links")
_SPAN_SQL = (f"INSERT INTO spans ({', '.join(_SPAN_COLS)}) VALUES %s "
             "ON CONFLICT (username, project, trace_id, span_id) DO NOTHING RETURNING 1")

_HOST_COLS = ("username", "project", "key_id", "event_id", "host", "pid", "ppid",
              "cgroup", "container_id", "kind", "ts_ns", "detail")
_HOST_SQL = (f"INSERT INTO host_events ({', '.join(_HOST_COLS)}) VALUES %s "
             "ON CONFLICT (username, project, host, event_id) WHERE event_id IS NOT NULL "
             "DO NOTHING RETURNING 1")


# Until the session aggregator exists (build step 3), a "session" is one trace.
# A span counts as a tool call when it follows the OTel GenAI conventions.
_SESSIONS_SQL = """
WITH active AS (
    -- sessions with any activity in the window; their stats below cover ALL
    -- their spans, so a run that started before the window edge is not cut
    SELECT DISTINCT trace_id, project FROM spans
    WHERE username = %(username)s
      AND start_ns >= %(since_ns)s
      AND (%(project)s::text IS NULL OR project = %(project)s)
)
SELECT s.trace_id, s.project,
       min(s.start_ns)                                   AS start_ns,
       max(coalesce(s.end_ns, s.start_ns))               AS end_ns,
       count(*)                                          AS spans,
       count(*) FILTER (WHERE s.status_code = 'error')   AS errors,
       count(*) FILTER (WHERE s.attributes ? 'gen_ai.tool.name'
                           OR s.attributes->>'gen_ai.operation.name' = 'execute_tool') AS tool_calls,
       (array_agg(s.name ORDER BY (s.parent_span_id IS NULL) DESC, s.start_ns))[1]     AS root_name,
       (array_agg(s.service_name ORDER BY s.start_ns) FILTER (WHERE s.service_name IS NOT NULL))[1]
                                                         AS service_name
FROM spans s JOIN active a ON a.trace_id = s.trace_id AND a.project = s.project
WHERE s.username = %(username)s
GROUP BY s.trace_id, s.project
ORDER BY max(s.start_ns) DESC
LIMIT %(limit)s
"""

_TRACE_SQL = """
SELECT span_id, parent_span_id, name, kind, start_ns, end_ns, status_code, status_message,
       service_name, scope_name, project, source, attributes, events, resource
FROM spans
WHERE username = %(username)s AND trace_id = %(trace_id)s
ORDER BY start_ns
LIMIT %(limit)s
"""


_ALERT_COLS = ("username", "project", "rule_id", "level", "score", "title", "tags", "evidence",
               "source_ref", "trace_id", "span_id", "service_name", "host", "ts_ns")
_ALERT_SQL = (f"INSERT INTO agent_alerts ({', '.join(_ALERT_COLS)}) VALUES %s "
              "ON CONFLICT (username, project, rule_id, source_ref) DO NOTHING RETURNING 1")

_ALERTS_READ_SQL = """
SELECT a.id, a.project, a.rule_id, a.level, a.score, a.title, a.tags, a.evidence,
       a.trace_id, a.span_id, a.service_name, a.host, a.ts_ns,
       (b.rule_id IS NOT NULL) AS benign
FROM agent_alerts a
LEFT JOIN agent_benign_rules b ON b.username = a.username AND b.rule_id = a.rule_id
WHERE a.username = %(username)s AND a.ts_ns >= %(since_ns)s
ORDER BY a.ts_ns DESC
LIMIT %(limit)s
"""


class StoreUnavailable(Exception):
    """The database could not take the write — retryable for the client."""


class PostgresStore:
    def __init__(self, dsn, minconn=1, maxconn=16):
        self.dsn = dsn
        self.minconn = minconn
        self.maxconn = maxconn
        self._pool = None
        self._pool_lock = threading.Lock()

    def _get_pool(self):
        # Created lazily so the process can start (and answer /health) while
        # the database is still coming up.
        with self._pool_lock:
            if self._pool is None:
                self._pool = psycopg2.pool.ThreadedConnectionPool(
                    self.minconn, self.maxconn, self.dsn, connect_timeout=5)
            return self._pool

    @contextlib.contextmanager
    def _conn(self):
        try:
            pool = self._get_pool()
            conn = pool.getconn()
        except (psycopg2.OperationalError, psycopg2.pool.PoolError) as e:
            raise StoreUnavailable(str(e).strip()) from e
        broken = False
        try:
            with conn:              # commit on success, rollback on error
                yield conn
        except (psycopg2.OperationalError, psycopg2.InterfaceError) as e:
            broken = True
            raise StoreUnavailable(str(e).strip()) from e
        finally:
            pool.putconn(conn, close=broken or conn.closed != 0)

    def init_schema(self):
        with open(SCHEMA_PATH) as f:
            ddl = f.read()
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute(ddl)

    def ping(self):
        try:
            with self._conn() as conn, conn.cursor() as cur:
                cur.execute("SELECT 1")
            return True
        except StoreUnavailable:
            return False

    def insert_spans(self, principal, rows, source):
        """Returns how many spans were new (replays are skipped)."""
        if not rows:
            return 0
        values = [(principal.username, principal.project, principal.key_id, source,
                   r["trace_id"], r["span_id"], r["parent_span_id"], r["name"], r["kind"],
                   r["start_ns"], r["end_ns"], r["status_code"], r["status_message"],
                   r["service_name"], r["scope_name"], r["scope_version"],
                   Json(r["resource"]), Json(r["attributes"]), Json(r["events"]),
                   Json(r["links"]))
                  for r in rows]
        with self._conn() as conn, conn.cursor() as cur:
            return len(execute_values(cur, _SPAN_SQL, values, fetch=True))

    def insert_host_events(self, principal, rows):
        if not rows:
            return 0
        values = [(principal.username, principal.project, principal.key_id, r["event_id"],
                   r["host"], r["pid"], r["ppid"], r["cgroup"], r["container_id"],
                   r["kind"], r["ts_ns"], Json(r["detail"]))
                  for r in rows]
        with self._conn() as conn, conn.cursor() as cur:
            return len(execute_values(cur, _HOST_SQL, values, fetch=True))

    # --- reads for the console (always scoped to one username) --------------

    def list_sessions(self, username, since_ns, project=None, limit=100):
        with self._conn() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(_SESSIONS_SQL, {"username": username, "since_ns": since_ns,
                                        "project": project, "limit": limit})
            return [dict(r) for r in cur.fetchall()]

    def list_projects(self, username):
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT DISTINCT project FROM spans WHERE username = %s ORDER BY 1",
                        (username,))
            return [r[0] for r in cur.fetchall()]

    def get_trace(self, username, trace_id, limit=5000):
        with self._conn() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(_TRACE_SQL, {"username": username, "trace_id": trace_id, "limit": limit})
            return [dict(r) for r in cur.fetchall()]

    # --- alerts --------------------------------------------------------------

    def insert_alerts(self, principal, found):
        values = [(principal.username, principal.project, f["alert"].rule_id, f["alert"].level,
                   f["alert"].score, f["alert"].title, Json(f["alert"].tags),
                   Json(f["alert"].evidence), f["source_ref"], f["trace_id"], f["span_id"],
                   f["service_name"], f["host"], f["ts_ns"])
                  for f in found]
        with self._conn() as conn, conn.cursor() as cur:
            return len(execute_values(cur, _ALERT_SQL, values, fetch=True))

    def list_alerts(self, username, since_ns, limit=500):
        with self._conn() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(_ALERTS_READ_SQL, {"username": username, "since_ns": since_ns,
                                           "limit": limit})
            return [dict(r) for r in cur.fetchall()]

    def list_benign_rules(self, username):
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT rule_id FROM agent_benign_rules WHERE username = %s ORDER BY 1",
                        (username,))
            return [r[0] for r in cur.fetchall()]

    def set_benign_rule(self, username, rule_id, benign):
        with self._conn() as conn, conn.cursor() as cur:
            if benign:
                cur.execute("INSERT INTO agent_benign_rules (username, rule_id) VALUES (%s, %s) "
                            "ON CONFLICT DO NOTHING", (username, rule_id))
            else:
                cur.execute("DELETE FROM agent_benign_rules WHERE username = %s AND rule_id = %s",
                            (username, rule_id))

    def close(self):
        with self._pool_lock:
            if self._pool is not None:
                self._pool.closeall()
                self._pool = None

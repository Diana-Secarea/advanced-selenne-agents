"""Reconciliation: host activity an instrumented agent never reported becomes
AG-301/302/303. Runs only with SELENNE_AGENTS_TEST_DSN (drops tables)."""

import json

import pytest

from selenne_agents.alerting import for_unexplained
from selenne_agents.ingest import normalize
from test_aggregate_store import T0, T1, _put, _span, _sql, pg  # noqa: F401
from test_postgres import DSN, ME

pytestmark = pytest.mark.skipif(not DSN, reason="SELENNE_AGENTS_TEST_DSN not set")

S = 10**9


def host(store, *events):
    rows = normalize.host_events("\n".join(json.dumps(e) for e in events).encode()).rows
    store.insert_host_events(ME, rows)


def he(n, kind, at, service="support-bot", **detail):
    return dict({"kind": kind, "host": "worker-1", "pid": 100 + n, "ts_unix_nano": T0 + at,
                 "event_id": f"e{n}", "service_name": service}, **detail)


@pytest.fixture
def scene(pg):  # noqa: F811
    # what the agent says: a 10 s run, a shell tool call at 2–3 s, an LLM call at 4–5 s
    _put(pg,
         _span(T1, 1, name="agent.run", end_dt=10 * S),
         _span(T1, 2, {"gen_ai.tool.name": "run_shell"}, parent=1, dt=2 * S, end_dt=3 * S),
         _span(T1, 3, {"gen_ai.operation.name": "chat"}, parent=1, dt=4 * S, end_dt=5 * S),
         resource={"service.name": "support-bot"})
    # what the machine shows
    host(pg,
         he(1, "exec", 0, agent_root=True, exe="/usr/bin/python3", argv=["python3", "bot.py"]),
         he(2, "exec", int(2.5 * S), exe="/usr/bin/curl", argv=["curl", "https://api.example"]),  # in the tool call
         he(3, "exec", int(4.5 * S), exe="/bin/sh", argv=["sh", "-c", "id"]),                      # during the LLM call
         he(4, "connect", int(4.6 * S), daddr="1.2.3.4", dport=443, scope="public"),               # inside a step
         he(5, "connect", 20 * S, daddr="127.0.0.1", dport=6379, scope="local", dest_service="redis"),
         he(6, "open", 25 * S, path="/srv/customers.csv"),
         he(7, "open", 25 * S, service="cve-agent", path="/etc/hosts"),                            # not instrumented
         he(8, "exit", 30 * S, status=0))
    return pg


def rules_by_event(store):
    return dict(_sql(store, "SELECT split_part(source_ref, ':', 3), rule_id FROM agent_alerts "
                            "WHERE rule_id LIKE 'AG-30%%'"))


def test_unexplained_activity_is_flagged(scene):
    stats = scene.reconcile_tick(for_unexplained, settle_s=0)
    assert (stats.checked, stats.unexplained, stats.alerts) == (8, 3, 3)
    assert rules_by_event(scene) == {"e3": "AG-301", "e5": "AG-302", "e6": "AG-303"}
    [(service, evidence)] = _sql(scene, "SELECT service_name, evidence->>'excerpt' FROM agent_alerts "
                                        "WHERE rule_id = 'AG-302'")
    assert service == "support-bot" and evidence == "redis (127.0.0.1:6379) · local"


def test_watermark_and_idempotence(scene):
    scene.reconcile_tick(for_unexplained, settle_s=0)
    again = scene.reconcile_tick(for_unexplained, settle_s=0)
    assert (again.checked, again.alerts) == (0, 0)                  # nothing new
    _sql(scene, "UPDATE aggregator_state SET last_id = 0 WHERE name = 'reconcile'")
    redo = scene.reconcile_tick(for_unexplained, settle_s=0)
    assert (redo.unexplained, redo.alerts) == (3, 0)                 # rebuilt, nothing duplicated


def test_waits_for_events_to_settle(scene):
    early = scene.reconcile_tick(for_unexplained, settle_s=3600)
    assert early.checked == 0 and rules_by_event(scene) == {}


def test_late_span_explains_before_settling(scene):
    # the span for the 20 s connection arrives (late), before reconciliation runs
    _put(scene, _span(T1, 4, {"gen_ai.tool.name": "cache_lookup"}, parent=1, dt=19 * S, end_dt=21 * S),
         resource={"service.name": "support-bot"})
    scene.reconcile_tick(for_unexplained, settle_s=0)
    assert "e5" not in rules_by_event(scene)


def test_skips_while_the_aggregator_runs(scene):
    from selenne_agents.store import PostgresStore
    from selenne_agents.store.postgres import _AGG_LOCK
    other = PostgresStore(DSN)
    try:
        with other._conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT pg_advisory_lock(%s)", (_AGG_LOCK,))
            assert scene.reconcile_tick(for_unexplained, settle_s=0) is None
            cur.execute("SELECT pg_advisory_unlock(%s)", (_AGG_LOCK,))
    finally:
        other.close()

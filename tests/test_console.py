import pytest
import requests

from selenne_agents.config import Settings
from selenne_agents.console.app import create_console_app
from selenne_agents.console.selenne_session import SelenneSessions, SessionUnavailable
from selenne_agents.store import StoreUnavailable

TRACE = "5b8efff798038103d269b633813fc60c"
TRACE2 = "6c9f0008a9149214e37ac744924ad71d"
CONV = "0123456789abcdef0123456789abcdef"     # a conversation session: TRACE + TRACE2
NOW = 1790676000.0                       # 2026-09-29T10:00:00Z
NS = int(NOW * 1e9)


class FakeSessions:
    def __init__(self):
        self.users = {"tok-diana": {"username": "diana", "role": "analyst", "agents": True},
                      "tok-carol": {"username": "carol", "role": "analyst", "agents": False}}
        self.down = False

    def user_for(self, token):
        if self.down:
            raise SessionUnavailable("down")
        return self.users.get(token)


class FakeStore:
    def __init__(self):
        self.calls = []
        self.down = False

    def _check(self):
        if self.down:
            raise StoreUnavailable("down")

    def list_projects(self, username):
        self._check()
        return {"diana": ["support-bot"]}.get(username, [])

    lag = 2.5

    def aggregator_lag(self):
        self._check()
        return self.lag

    def list_agent_projects(self, username):
        self._check()
        return {"diana": ["support-bot"]}.get(username, [])

    def list_agent_sessions(self, username, since_ns, project=None, limit=100):
        self._check()
        self.calls.append(("agent_sessions", username, since_ns, project, limit))
        if username != "diana":
            return []
        return [{"session_id": CONV, "kind": "conversation", "conversation_id": "chat-7",
                 "project": "support-bot", "service_name": "bot", "root_name": "agent.run",
                 "first_ns": NS + 123_456_789, "last_ns": NS + 1_623_456_789, "traces": 2,
                 "spans": 3, "errors": 1, "tool_calls": 1, "llm_calls": 2, "input_tokens": 120,
                 "output_tokens": 30, "alert_scores": {"AG-101": 85}, "max_alert_score": 85,
                 "hosts": ["w1"]}]

    def get_session_spans(self, username, session_id, limit=5000):
        self._check()
        self.calls.append(("session", username, session_id))
        if username != "diana" or session_id not in (CONV, TRACE, TRACE2):
            return []
        return [dict(s, session_id=CONV) for s in self._spans(TRACE) + self._spans(TRACE2)]

    @staticmethod
    def _spans(trace_id):
        return [{"trace_id": trace_id, "span_id": "eee19b7ec3c1b174", "parent_span_id": None,
                 "name": "agent.run", "kind": "internal", "start_ns": NS,
                 "end_ns": NS + 1_500_000_000, "status_code": "ok", "status_message": None,
                 "service_name": "bot", "scope_name": "s", "project": "support-bot",
                 "source": "otlp-http", "attributes": {"a": 1}, "resource": {"service.name": "bot"},
                 "events": [{"name": "e", "time_ns": NS + 1_000_000, "attributes": {}}]}]

    def list_sessions(self, username, since_ns, project=None, limit=100):
        self._check()
        self.calls.append(("sessions", username, since_ns, project, limit))
        if username != "diana":
            return []
        return [{"trace_id": TRACE, "project": "support-bot", "start_ns": NS + 123_456_789,
                 "end_ns": NS + 1_623_456_789, "spans": 3, "errors": 1, "tool_calls": 1,
                 "root_name": "agent.run", "service_name": "bot"}]

    def get_trace(self, username, trace_id, limit=5000):
        self._check()
        self.calls.append(("trace", username, trace_id))
        if username != "diana" or trace_id != TRACE:
            return []
        return self._spans(TRACE)


    def list_alerts(self, username, since_ns, limit=500):
        self._check()
        self.calls.append(("alerts", username, since_ns, limit))
        if username != "diana":
            return []
        return [{"id": 7, "project": "support-bot", "rule_id": "AG-101", "level": 12, "score": 85,
                 "title": "Agent touched a credential or secrets file", "tags": ["owasp:LLM02"],
                 "evidence": {"field": "attributes.path", "match": "~/.ssh/id_rsa", "excerpt": "cat ~/.ssh/id_rsa"},
                 "trace_id": TRACE, "span_id": "eee19b7ec3c1b174", "service_name": "bot", "host": None,
                 "ts_ns": NS, "benign": "AG-101" in self.benign}]

    benign = set()

    def list_benign_rules(self, username):
        return sorted(self.benign)

    def set_benign_rule(self, username, rule_id, on):
        self.calls.append(("benign", username, rule_id, on))
        (self.benign.add if on else self.benign.discard)(rule_id)


def _env(**settings):
    sessions, store = FakeSessions(), FakeStore()
    store.benign = set()
    app = create_console_app(Settings(**settings), sessions, store, clock=lambda: NOW)
    return app.test_client(), sessions, store


@pytest.fixture
def env():
    return _env()


@pytest.fixture
def raw_env():
    return _env(sessions_source="raw")


def as_user(client, token):
    client.set_cookie("session_token", token, domain="localhost")
    return client


def test_page_requires_selenne_login(env):
    c, _, _ = env
    r = c.get("/agents/")
    assert r.status_code == 302 and r.headers["Location"] == "/login.html?next=/agents/"
    assert c.get("/agents").status_code == 301
    as_user(c, "tok-diana")
    r = c.get("/agents/")
    assert r.status_code == 200 and b"AI Agents" in r.data
    assert r.headers["X-Frame-Options"] == "DENY"


def test_page_when_selenne_down(env):
    c, sessions, _ = env
    sessions.down = True
    assert as_user(c, "tok-diana").get("/agents/").status_code == 503


def test_api_auth_and_entitlement(env):
    c, _, store = env
    r = c.get("/agents/api/sessions")
    assert r.status_code == 401 and r.get_json()["login"].startswith("/login.html")
    as_user(c, "tok-carol")
    assert c.get("/agents/api/sessions").status_code == 402
    assert c.get("/agents/api/me").get_json()["user"]["agents"] is False
    assert store.calls == []                     # nothing queried for them


def test_sessions_scoped_to_user_and_in_ms(env):
    c, _, store = env
    r = as_user(c, "tok-diana").get("/agents/api/sessions?hours=24&limit=50&project=support-bot")
    assert r.status_code == 200 and r.headers["Cache-Control"] == "no-store"
    [s] = r.get_json()["sessions"]
    assert s["start_ms"] == pytest.approx((NS + 123_456_789) / 1e6)
    assert s["duration_ms"] == pytest.approx(1500.0)
    _, username, since_ns, project, limit = store.calls[-1]
    assert (username, project, limit) == ("diana", "support-bot", 50)
    assert since_ns == int((NOW - 24 * 3600) * 1e9)


def test_sessions_param_validation(env):
    c, _, _ = env
    as_user(c, "tok-diana")
    assert c.get("/agents/api/sessions?project=../x").status_code == 400
    assert c.get("/agents/api/sessions?hours=abc").status_code == 400
    c.get("/agents/api/sessions?hours=99999&limit=99999")
    # clamped rather than refused


def test_sessions_come_from_the_aggregator(env):
    c, _, store = env
    [s] = as_user(c, "tok-diana").get("/agents/api/sessions").get_json()["sessions"]
    assert (s["session_id"], s["kind"], s["conversation_id"], s["traces"]) == (CONV, "conversation", "chat-7", 2)
    assert (s["llm_calls"], s["input_tokens"], s["output_tokens"]) == (2, 120, 30)
    assert (s["max_alert_score"], s["max_alert_label"], s["hosts"]) == (85, "HIGH", ["w1"])
    assert [k for k, *_ in store.calls] == ["agent_sessions"]
    assert c.get("/agents/api/projects").get_json()["projects"] == ["support-bot"]


def test_session_detail(env):
    c, _, store = env
    as_user(c, "tok-diana")
    r = c.get(f"/agents/api/sessions/{CONV.upper()}")
    assert r.status_code == 200
    d = r.get_json()
    assert d["session_id"] == CONV and d["traces"] == sorted([TRACE, TRACE2])
    span = d["spans"][0]
    assert span["trace_id"] == TRACE
    assert span["start_ms"] == pytest.approx(NS / 1e6) and span["events"][0]["time_ms"] == pytest.approx((NS + 1_000_000) / 1e6)
    assert c.get("/agents/api/sessions/not-a-trace").status_code == 400
    assert c.get("/agents/api/sessions/" + "a" * 32).status_code == 404


def test_trace_id_opens_its_whole_session(env):
    # an alert's deep link carries a trace id
    c, _, _ = env
    d = as_user(c, "tok-diana").get(f"/agents/api/sessions/{TRACE2}").get_json()
    assert d["session_id"] == CONV and len(d["spans"]) == 2


def test_detail_falls_back_to_the_raw_trace(env, monkeypatch):
    # a trace the aggregator hasn't reached yet still opens
    c, _, store = env
    monkeypatch.setattr(store, "get_session_spans", lambda *a, **k: [])
    d = as_user(c, "tok-diana").get(f"/agents/api/sessions/{TRACE}").get_json()
    assert d["session_id"] == TRACE and d["traces"] == [TRACE] and len(d["spans"]) == 1


def test_raw_source_is_the_old_query_in_the_new_shape(raw_env, env):
    c, _, store = raw_env
    as_user(c, "tok-diana")
    r = c.get("/agents/api/sessions").get_json()
    [s] = r["sessions"]
    assert r["source"] == "raw" and [k for k, *_ in store.calls] == ["sessions"]
    assert (s["session_id"], s["kind"], s["traces"], s["llm_calls"]) == (TRACE, "trace", 1, None)
    agg = as_user(env[0], "tok-diana").get("/agents/api/sessions").get_json()["sessions"][0]
    assert s.keys() == agg.keys()                # the page renders either
    d = c.get(f"/agents/api/sessions/{TRACE}").get_json()
    assert d["session_id"] == TRACE and len(d["spans"]) == 1
    assert "session" not in [k for k, *_ in store.calls]       # never touches the aggregate


def test_bad_sessions_source_refused():
    with pytest.raises(ValueError, match="CONSOLE_SESSIONS_SOURCE"):
        Settings(sessions_source="spans")


def test_health_reports_aggregator_lag_but_never_fails(env):
    c, _, store = env
    assert c.get("/agents/health").get_json() == {
        "status": "ok", "sessions_source": "aggregate", "aggregator_lag_s": 2.5}
    store.down = True
    r = c.get("/agents/health")
    assert r.status_code == 200 and r.get_json()["aggregator_lag_s"] is None


def test_other_users_trace_is_404(env):
    c, sessions, _ = env
    sessions.users["tok-bob"] = {"username": "bob", "role": "analyst", "agents": True}
    assert as_user(c, "tok-bob").get(f"/agents/api/sessions/{TRACE}").status_code == 404


def test_store_down_is_503(env):
    c, _, store = env
    store.down = True
    assert as_user(c, "tok-diana").get("/agents/api/sessions").status_code == 503


def test_static_assets_public(env):
    c, _, _ = env
    assert c.get("/agents/assets/console.js").status_code == 200
    assert c.get("/agents/assets/alerts.js").status_code == 200
    assert c.get("/agents/assets/../index.html").status_code == 404   # pages are auth-gated
    assert c.get("/agents/assets/../../README.md").status_code == 404


# --- SelenneSessions against a fake /api/auth/me ---------------------------------

class Resp:
    def __init__(self, status, body):
        self.status_code, self._body = status, body

    def json(self):
        if isinstance(self._body, Exception):
            raise self._body
        return self._body


class FakeHTTP:
    def __init__(self, *responses):
        self.responses, self.calls = list(responses), []

    def get(self, url, cookies, headers, timeout):
        self.calls.append((cookies, headers))
        r = self.responses.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


def test_selenne_sessions_forwards_cookie_and_caches():
    t = [0.0]
    http = FakeHTTP(Resp(200, {"auth_enabled": True, "user": {"username": "diana", "role": "admin",
                                                              "agents": True, "email_verified": True}}),
                    Resp(401, {"user": None}))
    s = SelenneSessions("http://selenne/api/auth/me", session=http, ttl=30, clock=lambda: t[0],
                        internal_secret="shh")
    assert s.user_for("tok")["username"] == "diana"
    assert s.user_for("tok")["role"] == "admin"
    assert http.calls == [({"session_token": "tok"}, {"X-Selenne-Internal": "shh"})]
    t[0] += 31                                   # logged out on Selenne meanwhile
    assert s.user_for("tok") is None
    assert s.user_for(None) is None and s.user_for("x" * 200) is None


@pytest.mark.parametrize("resp", [requests.ConnectionError("x"), Resp(500, {}), Resp(200, ValueError())])
def test_selenne_sessions_unavailable(resp):
    s = SelenneSessions("http://selenne/api/auth/me", session=FakeHTTP(resp))
    with pytest.raises(SessionUnavailable):
        s.user_for("tok")


def test_alerts_page_and_api(env):
    c, _, store = env
    assert c.get("/agents/alerts").headers["Location"] == "/login.html?next=/agents/alerts"
    as_user(c, "tok-diana")
    assert c.get("/agents/alerts").status_code == 200
    [a] = c.get("/agents/api/alerts?hours=24").get_json()["alerts"]
    assert a["anomaly_label"] == "HIGH" and a["anomaly_score"] == 85 and a["level"] == 12
    assert a["timestamp_ms"] == pytest.approx(NS / 1e6) and a["full_log"] == "cat ~/.ssh/id_rsa"
    assert a["agent_name"] == "bot" and a["trace_id"] == TRACE
    assert store.calls[-1][:2] == ("alerts", "diana")


def test_benign_rules_zero_score(env):
    c, _, store = env
    as_user(c, "tok-diana")
    r = c.post("/agents/api/benign-rules", json={"rule_id": "AG-101"})
    assert r.status_code == 200 and r.get_json()["benign"] == ["AG-101"]
    [a] = c.get("/agents/api/alerts").get_json()["alerts"]
    assert a["anomaly_label"] == "BENIGN" and a["anomaly_score"] == 0
    assert c.delete("/agents/api/benign-rules/AG-101").get_json()["benign"] == []
    assert c.post("/agents/api/benign-rules", json={"rule_id": "DROP TABLE"}).status_code == 400
    assert c.post("/agents/api/benign-rules", json={"rule_id": "AG-101"},
                  headers={"Origin": "https://evil.example"}).status_code == 403
    rules = c.get("/agents/api/rules").get_json()
    assert "AG-104" in rules["rules"]


def test_alerts_need_entitlement(env):
    c, _, store = env
    as_user(c, "tok-carol")
    assert c.get("/agents/api/alerts").status_code == 402
    assert c.post("/agents/api/benign-rules", json={"rule_id": "AG-101"}).status_code == 402
    assert not [x for x in store.calls if x[0] in ("alerts", "benign")]


@pytest.mark.parametrize("page", ["/agents/", "/agents/alerts"])
def test_every_page_asset_is_served_by_the_console(env, page):
    """The page must render with Selenne's look even when the console is
    reached directly (no nginx, no Selenne /assets/ on the same origin) —
    that dependency is what made the pages come out unstyled/white."""
    import re
    c, _, _ = env
    html = as_user(c, "tok-diana").get(page).data.decode()
    refs = re.findall(r'(?:href|src)="(/[^"]+\.(?:css|js))"', html)
    assert refs and all(r.startswith("/agents/assets/") for r in refs), refs
    for ref in refs:
        assert c.get(ref).status_code == 200, ref
    assert '<canvas id="particles">' in html          # Selenne's animated background

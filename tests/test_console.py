import pytest
import requests

from selenne_agents.config import Settings
from selenne_agents.console.app import create_console_app
from selenne_agents.console.selenne_session import SelenneSessions, SessionUnavailable
from selenne_agents.store import StoreUnavailable

TRACE = "5b8efff798038103d269b633813fc60c"
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
        return [{"span_id": "eee19b7ec3c1b174", "parent_span_id": None, "name": "agent.run",
                 "kind": "internal", "start_ns": NS, "end_ns": NS + 1_500_000_000,
                 "status_code": "ok", "status_message": None, "service_name": "bot",
                 "scope_name": "s", "project": "support-bot", "source": "otlp-http",
                 "attributes": {"a": 1}, "resource": {"service.name": "bot"},
                 "events": [{"name": "e", "time_ns": NS + 1_000_000, "attributes": {}}]}]


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

    def list_batches(self, username, limit=200):
        self.calls.append(("batches", username, limit))
        return [{"id": 1, "project": "support-bot", "key_id": "k_1", "source": "otlp-http", "accepted": 3,
                 "new": 3, "rejected": 0, "error": None, "received_ms": NOW * 1000}] if username == "diana" else []

    def recent_events(self, username, limit=200):
        self.calls.append(("events", username, limit))
        if username != "diana":
            return []
        return [{"type": "span", "project": "support-bot", "source": "otlp-http", "title": "tool.read_file",
                 "origin": "bot", "status": "ok", "trace_id": TRACE, "ts_ns": NS, "received_ms": NOW * 1000,
                 "detail": {"gen_ai.tool.name": "read_file"}},
                {"type": "host", "project": "support-bot", "source": "sensor", "title": "open", "origin": "w1",
                 "status": None, "trace_id": None, "ts_ns": NS, "received_ms": NOW * 1000,
                 "detail": {"path": "/root/.ssh/id_rsa"}}]

    def list_benign_rules(self, username):
        return sorted(self.benign)

    def set_benign_rule(self, username, rule_id, on):
        self.calls.append(("benign", username, rule_id, on))
        (self.benign.add if on else self.benign.discard)(rule_id)


@pytest.fixture
def env():
    sessions, store = FakeSessions(), FakeStore()
    store.benign = set()
    app = create_console_app(Settings(), sessions, store, clock=lambda: NOW)
    return app.test_client(), sessions, store


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


def test_session_detail(env):
    c, _, store = env
    as_user(c, "tok-diana")
    r = c.get(f"/agents/api/sessions/{TRACE.upper()}")
    assert r.status_code == 200
    [span] = r.get_json()["spans"]
    assert span["start_ms"] == pytest.approx(NS / 1e6) and span["events"][0]["time_ms"] == pytest.approx((NS + 1_000_000) / 1e6)
    assert c.get("/agents/api/sessions/not-a-trace").status_code == 400
    assert c.get("/agents/api/sessions/" + "a" * 32).status_code == 404


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


PAGES = ["/agents/", "/agents/alerts", "/agents/keys", "/agents/logs"]


@pytest.mark.parametrize("page", PAGES)
def test_every_page_asset_is_served_by_the_console(env, page):
    """Pages reference their CSS/JS relatively, and every one is served by the
    console itself — no dependency on Selenne's /assets/ (which is what made
    the pages come out unstyled/white when opened on their own)."""
    import re
    from urllib.parse import urljoin
    c, _, _ = env
    html = as_user(c, "tok-diana").get(page).data.decode()
    refs = [r for r in re.findall(r'(?:href|src)="([^"]+\.(?:css|js))"', html) if not r.startswith("http")]
    assert refs and not any(r.startswith("/") for r in refs), refs
    for ref in refs:
        url = urljoin("http://localhost" + page, ref)[len("http://localhost"):]
        assert c.get(url).status_code == 200, (page, ref, url)
    assert '<canvas id="particles">' in html                 # Selenne's animated background
    assert 'data-selenne-link="/landing.html"' in html          # ◈SELENNE → landing page


@pytest.mark.parametrize("page", PAGES)
def test_frontend_opens_as_plain_files(page):
    """Opened straight from disk (file://) every relative CSS/JS path must
    exist in frontend/, so the page is styled and falls back to preview."""
    import os, re
    from selenne_agents.console.app import FRONTEND_DIR
    name = {"/agents/": "index.html"}.get(page, page.rsplit("/", 1)[1] + ".html")
    html = open(os.path.join(FRONTEND_DIR, name), encoding="utf-8").read()
    for ref in re.findall(r'(?:href|src)="([^"]+\.(?:css|js))"', html):
        if not ref.startswith("http"):
            assert os.path.isfile(os.path.join(FRONTEND_DIR, ref)), (name, ref)
    for nav in ("index.html", "alerts.html", "logs.html", "keys.html"):
        assert f'href="{nav}"' in html


def test_page_aliases(env):
    c, _, _ = env
    as_user(c, "tok-diana")
    for url in ("/agents/index.html", "/agents/alerts.html", "/agents/keys", "/agents/keys.html",
                "/agents/logs", "/agents/logs.html"):
        assert c.get(url).status_code == 200, url


class FakeSelenne:
    def __init__(self):
        self.calls = []
        self.down = False

    def call(self, method, path, token, json_body=None):
        from selenne_agents.console.selenne_session import SelenneUnavailable
        if self.down:
            raise SelenneUnavailable("down")
        self.calls.append((method, path, token, json_body))
        if path == "/api/keys" and method == "POST":
            return 201, {"key": "sk_sel_fake", "record": {"id": "k_1", "project": json_body["project"]}}
        return 200, {"keys": [], "status": "ok"}


def _console(selenne=None, public="", sessions=None, store=None):
    from dataclasses import replace
    s = replace(Settings(), selenne_public_url=public)
    return create_console_app(s, sessions or FakeSessions(), store or FakeStore(),
                              clock=lambda: NOW, selenne=selenne).test_client()


def test_keys_are_relayed_to_selenne_with_the_session():
    sel = FakeSelenne()
    c = as_user(_console(sel), "tok-diana")
    assert c.get("/agents/api/keys").status_code == 200
    r = c.post("/agents/api/keys", json={"project": "bot"})
    assert r.status_code == 201 and r.get_json()["key"] == "sk_sel_fake"
    assert c.delete("/agents/api/keys/k_1a2b").status_code == 200
    assert [x[:3] for x in sel.calls] == [("GET", "/api/keys", "tok-diana"), ("POST", "/api/keys", "tok-diana"),
                                           ("DELETE", "/api/keys/k_1a2b", "tok-diana")]
    assert c.delete("/agents/api/keys/..%2Fauth").status_code in (400, 404)
    assert c.post("/agents/api/keys", json={"project": "x"}, headers={"Origin": "https://evil.example"}).status_code == 403
    sel.down = True
    assert c.get("/agents/api/keys").status_code == 503


def test_keys_need_sign_in_and_entitlement():
    sel = FakeSelenne()
    c = _console(sel)
    assert c.get("/agents/api/keys").status_code == 401
    assert as_user(c, "tok-carol").get("/agents/api/keys").status_code == 402
    assert sel.calls == []


def test_logout_relays_and_clears_cookie():
    sel = FakeSelenne()
    c = as_user(_console(sel, public="https://selenne.app"), "tok-diana")
    r = c.post("/agents/api/logout")
    assert r.get_json()["next"] == "https://selenne.app/landing.html"
    assert ("POST", "/api/auth/logout", "tok-diana") == sel.calls[0][:3]
    assert "session_token=;" in r.headers["Set-Cookie"]


def test_selenne_paths_redirect_to_selenne_when_standalone():
    c = _console(public="http://127.0.0.1:5000")
    assert c.get("/landing.html").headers["Location"] == "http://127.0.0.1:5000/landing.html"
    assert c.get("/login.html?next=/agents/").headers["Location"] == "http://127.0.0.1:5000/login.html?next=/agents/"
    r = c.get("/agents/")
    assert r.headers["Location"] == "http://127.0.0.1:5000/login.html?next=/agents/"
    assert _console().get("/landing.html").status_code == 404      # no public URL configured
    me = as_user(c, "tok-diana").get("/agents/api/me").get_json()
    assert me["selenne_url"] == "http://127.0.0.1:5000"


def test_dev_mode_signs_in_without_selenne():
    from selenne_agents.console.selenne_session import DevSessions
    c = _console(sessions=DevSessions("dev"))
    assert c.get("/agents/").status_code == 200
    assert c.get("/agents/api/me").get_json()["user"]["username"] == "dev"
    r = c.get("/agents/api/keys")
    assert r.status_code == 503 and r.get_json()["dev"] is True


def test_logs_api(env):
    c, _, store = env
    as_user(c, "tok-diana")
    d = c.get("/agents/api/logs?limit=5").get_json()
    assert d["batches"][0]["source"] == "otlp-http" and d["batches"][0]["accepted"] == 3
    ev = {e["type"]: e for e in d["events"]}
    assert ev["span"]["summary"] == "read_file" and ev["host"]["summary"] == "/root/.ssh/id_rsa"
    assert store.calls[-1] == ("events", "diana", 5)
    assert c.get("/agents/api/logs?limit=x").status_code == 400


def test_writes_accepted_behind_a_proxy_that_drops_the_port():
    """nginx sends "Host: $host" (no port) while the browser's Origin keeps
    it — the console's own pages must still be allowed to write."""
    sel = FakeSelenne()
    c = _console(sel)
    c.set_cookie("session_token", "tok-diana", domain="127.0.0.1")
    r = c.post("/agents/api/keys", json={"project": "bot"}, base_url="http://127.0.0.1",
               headers={"Origin": "http://127.0.0.1:8088"})
    assert r.status_code == 201
    assert c.post("/agents/api/benign-rules", json={"rule_id": "AG-101"}, base_url="http://127.0.0.1",
                  headers={"Origin": "http://127.0.0.1:8088"}).status_code == 200
    assert c.post("/agents/api/keys", json={"project": "bot"}, base_url="http://127.0.0.1",
                  headers={"Origin": "http://evil.example:8088"}).status_code == 403

"""Flask app for selenne.app/agents/ (nginx forwards /agents/ here).

    GET /agents/                          the console page (signed in only)
    GET /agents/assets/<file>             its JS/CSS (Selenne's style.css and the
                                          product switcher come from /assets/)

The pages and their assets live in the repo's top-level frontend/ directory
(FRONTEND_DIR overrides it), apart from the Python package.
    GET /agents/api/me                    who is signed in, per Selenne
    GET /agents/api/projects
    GET /agents/api/sessions?project=&hours=&limit=
    GET /agents/api/sessions/<id>         every span of one session (id: a
                                          session id, or any trace id in it)
    GET /agents/activity                  the activity page (what the sensor saw)
    GET /agents/api/activity?hours=&limit=&before_ms=&project=&kind=&agent=&host=&scope=&alerts=1
    GET /agents/api/activity/facets?hours=&project=   filter menus + sensor status
    GET /agents/deviations                the deviations page (/agents/alerts redirects here)
    GET /agents/api/deviations?hours=&limit=&category=   rule hits, Selenne-alert
                                          shaped, each with its session (/api/alerts: same)
    GET /agents/incidents                 the incidents page
    GET /agents/api/incidents?hours=      deviations grouped with their probable cause
    GET /agents/api/rules                 rule catalogue + this user's benign rules
    POST/DELETE /agents/api/benign-rules[/<rule_id>]
    GET /agents/health
"""

import logging
import os
import re
import time

from flask import Flask, jsonify, redirect, request, send_from_directory

import hashlib

from ..alerting.rules import RULES, _mask_all_secrets, label_for
from ..store import StoreUnavailable
from .selenne_session import COOKIE, SessionUnavailable

log = logging.getLogger("console")

FRONTEND_DIR = os.path.abspath(os.environ.get(
    "FRONTEND_DIR", os.path.join(os.path.dirname(__file__), "..", "..", "frontend")))
ASSETS_DIR = os.path.join(FRONTEND_DIR, "assets")
_TRACE_RE = re.compile(r"^[0-9a-f]{32}$")
_PROJECT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
LOGIN_URL = "/login.html?next=/agents/"


def _ms(ns):
    # Nanosecond epochs exceed 2**53, so they would lose precision as JSON
    # numbers in the browser. Milliseconds (with sub-ms fraction) do not.
    return None if ns is None else ns / 1e6


def _session_json(r):
    """An aggregated session (store.list_agent_sessions)."""
    score = r["max_alert_score"]
    return {"session_id": r["session_id"].strip(), "kind": r["kind"],
            "conversation_id": r["conversation_id"], "traces": r["traces"],
            "project": r["project"], "service_name": r["service_name"],
            "root_name": r["root_name"], "start_ms": _ms(r["first_ns"]),
            "duration_ms": (r["last_ns"] - r["first_ns"]) / 1e6,
            "spans": r["spans"], "errors": r["errors"], "tool_calls": r["tool_calls"],
            "llm_calls": r["llm_calls"], "input_tokens": r["input_tokens"],
            "output_tokens": r["output_tokens"], "max_alert_score": score,
            "max_alert_label": None if score is None else label_for(score),
            "hosts": r["hosts"] or []}


def _raw_session_json(r):
    """One trace grouped from raw spans (CONSOLE_SESSIONS_SOURCE=raw), in the
    same shape; what raw grouping doesn't count is None."""
    end = r["end_ns"] if r["end_ns"] is not None else r["start_ns"]
    return {"session_id": r["trace_id"].strip(), "kind": "trace", "conversation_id": None,
            "traces": 1, "project": r["project"], "service_name": r["service_name"],
            "root_name": r["root_name"], "start_ms": _ms(r["start_ns"]),
            "duration_ms": (end - r["start_ns"]) / 1e6,
            "spans": r["spans"], "errors": r["errors"], "tool_calls": r["tool_calls"],
            "llm_calls": None, "input_tokens": None, "output_tokens": None,
            "max_alert_score": None, "max_alert_label": None, "hosts": []}


def _span_json(r):
    return {"trace_id": r["trace_id"].strip(), "span_id": r["span_id"].strip(),
            "parent_span_id": r["parent_span_id"].strip() if r["parent_span_id"] else None,
            "name": r["name"], "kind": r["kind"], "status_code": r["status_code"],
            "status_message": r["status_message"], "service_name": r["service_name"],
            "scope_name": r["scope_name"], "project": r["project"], "source": r["source"],
            "start_ms": _ms(r["start_ns"]), "end_ms": _ms(r["end_ns"]),
            "attributes": r["attributes"], "events": [
                dict(e, time_ms=_ms(e.get("time_ns"))) for e in (r["events"] or [])],
            "resource": r["resource"]}


DEVIATION_CATEGORIES = ("reported", "host", "unexplained")


def _category(rule_id):
    """AG-1xx: the agent's own spans broke a policy; AG-2xx: the host did;
    AG-3xx: the host did something the agent never reported."""
    return {"AG-1": "reported", "AG-2": "host", "AG-3": "unexplained"}.get(rule_id[:4], "reported")


def _alert_json(r):
    """Same field names as Selenne's /api/alerts/scored, so the Agents alert
    page reads like the SIEM one. A benign rule zero-scores its alerts."""
    ev = r["evidence"] or {}
    ref = r.get("source_ref") or ""
    session = r.get("session_id")
    return {"category": _category(r["rule_id"]),
            "source": "host" if ref.startswith("host:") else "span",
            "event_id": ref.split(":", 2)[2] if ref.startswith("host:") else None,
            "session_id": session.strip() if session else None,
            "id": r["id"], "timestamp_ms": _ms(r["ts_ns"]), "rule_id": r["rule_id"],
            "rule_description": r["title"], "level": r["level"],
            "anomaly_score": 0 if r["benign"] else r["score"],
            "anomaly_label": "BENIGN" if r["benign"] else label_for(r["score"]),
            "agent_name": r["service_name"] or r["host"] or "—", "project": r["project"],
            "groups": r["tags"] or [], "full_log": ev.get("excerpt") or "",
            "evidence_field": ev.get("field"), "evidence_match": ev.get("match"),
            "trace_id": r["trace_id"].strip() if r["trace_id"] else None,
            "span_id": r["span_id"].strip() if r["span_id"] else None, "host": r["host"]}


ACTIVITY_KINDS = ("exec", "exit", "open", "connect", "listen")
SCOPES = ("local", "private", "public")
# what the sensor sends that the page shows as fields (the rest is in detail)
_ACTIVITY_FIELDS = ("service_name", "exe", "argv", "cwd", "path", "daddr", "dport", "saddr", "sport",
                    "protocol", "scope", "dest_service", "status", "signal", "duration_ms",
                    "agent_root", "exec_id")


def _activity_json(r):
    d = r["detail"] or {}
    out = {"id": r["id"], "ts_ms": _ms(r["ts_ns"]), "project": r["project"], "host": r["host"],
           "pid": r["pid"], "ppid": r["ppid"], "container_id": r["container_id"], "kind": r["kind"],
           "detail": d}
    for f in _ACTIVITY_FIELDS:
        out[f] = d.get(f)
    out["agent"] = out.pop("service_name")
    out["alerts"] = [{"id": a["id"], "rule_id": a["rule_id"], "title": a["title"],
                      "score": 0 if a["benign"] else a["score"],
                      "label": "BENIGN" if a["benign"] else label_for(a["score"])}
                     for a in r["alerts"] or []]
    return out


def _sensor_json(r, now_ms):
    d = r["detail"] or {}
    last = _ms(r["ts_ns"])
    return {"host": r["host"], "project": r["project"], "last_ms": last,
            "age_s": max(0, round((now_ms - last) / 1000)), "version": d.get("sensor_version"),
            "stats": d.get("stats") or {}}


CAUSES = {"prompt_injection": "Prompt injection", "tool_output": "Tool output",
          "retrieved_content": "Retrieved content", "web_content": "Web content"}


def _incidents(rows):
    """Group consequential deviations by session + probable cause: one
    injected page that made the agent run a command and read a key is one
    incident with two effects. Newest incident first."""
    groups = {}
    for r in rows:
        key = (r["session_id"].strip(), r["cause_trace_id"].strip(), r["cause_span_id"].strip())
        g = groups.get(key)
        if g is None:
            g = groups[key] = {
                "id": hashlib.sha256(":".join(key).encode()).hexdigest()[:16],
                "session_id": key[0], "session_root": r.get("root_name"),
                "session_kind": r.get("session_kind"), "agent": r["service_name"],
                "project": r["project"],
                "cause": {"kind": r["cause_kind"], "label": CAUSES.get(r["cause_kind"], r["cause_kind"]),
                          "trace_id": key[1], "span_id": key[2], "name": r["cause_name"],
                          "tool": r["cause_tool"], "url": r["cause_url"], "ts_ms": _ms(r["cause_ns"]),
                          "excerpt": _mask_all_secrets(r["cause_excerpt"]) if r["cause_excerpt"] else None,
                          "preview": _mask_all_secrets(r["cause_preview"]) if r["cause_preview"] else None},
                "effects": []}
        ev = r["evidence"] or {}
        g["effects"].append({"id": r["id"], "rule_id": r["rule_id"], "title": r["title"],
                             "score": r["score"], "label": label_for(r["score"]),
                             "category": _category(r["rule_id"]), "ts_ms": _ms(r["ts_ns"]),
                             "source": "host" if r["source_ref"].startswith("host:") else "span",
                             "host": r["host"], "excerpt": ev.get("excerpt"),
                             "trace_id": r["trace_id"].strip() if r["trace_id"] else None,
                             "span_id": r["span_id"].strip() if r["span_id"] else None})
    out = []
    for g in groups.values():
        g["effects"].sort(key=lambda e: e["ts_ms"])
        g["score"] = max(e["score"] for e in g["effects"])
        g["label"] = label_for(g["score"])
        g["first_ms"], g["last_ms"] = g["effects"][0]["ts_ms"], g["effects"][-1]["ts_ms"]
        out.append(g)
    return sorted(out, key=lambda g: -g["last_ms"])


def create_console_app(settings, sessions, store, clock=time.time):
    app = Flask(__name__, static_folder=None)
    aggregated = settings.sessions_source == "aggregate"
    if settings.trust_proxy:
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    def _user():
        return sessions.user_for(request.cookies.get(COOKIE))

    def _api_user():
        """(user, None) or (None, error response)."""
        try:
            user = _user()
        except SessionUnavailable as e:
            log.warning("session check unavailable: %s", e)
            return None, (jsonify({"error": "Sign-in service unavailable, retry shortly"}), 503)
        if not user:
            return None, (jsonify({"error": "Sign in required", "login": LOGIN_URL}), 401)
        if not user["agents"]:
            return None, (jsonify({"error": "Selenne Agents is not enabled on this account",
                                   "reason": "not_entitled"}), 402)
        return user, None

    @app.after_request
    def _headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        if request.path.startswith("/agents/api/"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.errorhandler(StoreUnavailable)
    def _store_down(e):
        log.error("store unavailable: %s", e)
        return jsonify({"error": "Storage temporarily unavailable"}), 503

    @app.get("/agents")
    def _slash():
        return redirect("/agents/", code=301)

    def _page(filename, login_url):
        try:
            user = _user()
        except SessionUnavailable:
            return ("Sign-in service unavailable — retry in a moment.", 503,
                    {"Content-Type": "text/plain; charset=utf-8", "Retry-After": "5"})
        if not user:
            return redirect(login_url)
        # Signed in but not entitled still gets the page: it explains the
        # add-on instead of bouncing the user somewhere confusing.
        resp = send_from_directory(FRONTEND_DIR, filename)
        resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.get("/agents/")
    def page():
        return _page("index.html", LOGIN_URL)

    @app.get("/agents/activity")
    def activity_page():
        return _page("activity.html", "/login.html?next=/agents/activity")

    def _window():
        """(since_ns, hours) from ?hours=, or raises ValueError."""
        hours = min(max(float(request.args.get("hours", 24)), 0.1), 24 * 90)
        return int((clock() - hours * 3600) * 1e9), hours

    def _short_arg(name, allowed=None):
        v = (request.args.get(name) or "").strip() or None
        if v is None:
            return None
        if (allowed and v not in allowed) or len(v) > 200:
            raise ValueError(f"bad {name}")
        return v

    @app.get("/agents/api/activity")
    def activity_list():
        user, err = _api_user()
        if err:
            return err
        try:
            since_ns, hours = _window()
            limit = min(max(int(request.args.get("limit", 200)), 1), 1000)
            before = request.args.get("before_ms")
            before_ns = int(float(before) * 1e6) if before else None
            filters = {"kind": _short_arg("kind", ACTIVITY_KINDS),
                       "scope": _short_arg("scope", SCOPES),
                       "agent": _short_arg("agent"), "host": _short_arg("host"),
                       "project": _short_arg("project")}
        except ValueError as e:
            return jsonify({"error": str(e) if str(e).startswith("bad ") else
                            "hours, limit and before_ms must be numbers"}), 400
        if filters["project"] and not _PROJECT_RE.match(filters["project"]):
            return jsonify({"error": "bad project"}), 400
        rows = store.list_activity(user["username"], since_ns, before_ns=before_ns, limit=limit,
                                   alerts_only=request.args.get("alerts") == "1", **filters)
        return jsonify({"events": [_activity_json(r) for r in rows], "hours": hours,
                        "limit": limit, "more": len(rows) == limit})

    @app.get("/agents/api/activity/facets")
    def activity_facets():
        user, err = _api_user()
        if err:
            return err
        try:
            since_ns, hours = _window()
            project = _short_arg("project")
        except ValueError:
            return jsonify({"error": "hours must be a number"}), 400
        if project and not _PROJECT_RE.match(project):
            return jsonify({"error": "bad project"}), 400
        now_ms = clock() * 1000
        sensors = store.list_sensors(user["username"], int((clock() - 24 * 3600) * 1e9))
        return jsonify({"facets": store.activity_facets(user["username"], since_ns, project=project),
                        "sensors": [_sensor_json(s, now_ms) for s in sensors], "hours": hours})

    @app.get("/agents/alerts")
    def alerts_page():
        # Alerts became Deviations; old links and bookmarks still land
        qs = request.query_string.decode()
        return redirect("/agents/deviations" + ("?" + qs if qs else ""), code=301)

    @app.get("/agents/deviations")
    def deviations_page():
        return _page("deviations.html", "/login.html?next=/agents/deviations")

    @app.get("/agents/incidents")
    def incidents_page():
        return _page("incidents.html", "/login.html?next=/agents/incidents")

    @app.get("/agents/api/incidents")
    def incidents_list():
        user, err = _api_user()
        if err:
            return err
        try:
            hours = min(max(float(request.args.get("hours", 168)), 0.1), 24 * 90)
        except ValueError:
            return jsonify({"error": "hours must be a number"}), 400
        since_ns = int((clock() - hours * 3600) * 1e9)
        rows = store.list_incident_rows(user["username"], since_ns)
        return jsonify({"incidents": _incidents(rows), "hours": hours})

    @app.get("/agents/assets/<path:name>")
    def asset(name):
        return send_from_directory(ASSETS_DIR, name)

    @app.get("/agents/health")
    def health():
        # Liveness first: the console is up even when the database or the
        # aggregator is not, so the lag is informational (None = unknown or
        # no round yet) and never fails the check.
        try:
            lag = store.aggregator_lag()
        except Exception as e:
            log.debug("aggregator lag unavailable: %s", e)
            lag = None
        return jsonify({"status": "ok", "sessions_source": settings.sessions_source,
                        "aggregator_lag_s": None if lag is None else round(lag, 1)})

    @app.get("/agents/api/me")
    def me():
        try:
            user = _user()
        except SessionUnavailable:
            return jsonify({"error": "Sign-in service unavailable, retry shortly"}), 503
        if not user:
            return jsonify({"user": None, "login": LOGIN_URL}), 401
        return jsonify({"user": user})

    @app.get("/agents/api/projects")
    def projects():
        user, err = _api_user()
        if err:
            return err
        list_projects = store.list_agent_projects if aggregated else store.list_projects
        return jsonify({"projects": list_projects(user["username"])})

    @app.get("/agents/api/sessions")
    def sessions_list():
        user, err = _api_user()
        if err:
            return err
        project = request.args.get("project") or None
        if project is not None and not _PROJECT_RE.match(project):
            return jsonify({"error": "bad project name"}), 400
        try:
            hours = min(max(float(request.args.get("hours", 168)), 0.1), 24 * 90)
            limit = min(max(int(request.args.get("limit", 100)), 1), 500)
        except ValueError:
            return jsonify({"error": "hours and limit must be numbers"}), 400
        since_ns = int((clock() - hours * 3600) * 1e9)
        if aggregated:
            rows = store.list_agent_sessions(user["username"], since_ns, project=project,
                                             limit=limit)
            out = [_session_json(r) for r in rows]
        else:
            rows = store.list_sessions(user["username"], since_ns, project=project, limit=limit)
            out = [_raw_session_json(r) for r in rows]
        return jsonify({"sessions": out, "source": settings.sessions_source,
                        "hours": hours, "limit": limit})

    @app.get("/agents/api/sessions/<session_id>")
    def session_detail(session_id):
        user, err = _api_user()
        if err:
            return err
        session_id = session_id.lower()
        if not _TRACE_RE.match(session_id):         # session ids are 32 hex too
            return jsonify({"error": "bad session id"}), 400
        spans = store.get_session_spans(user["username"], session_id) if aggregated else []
        if spans:
            session_id = spans[0]["session_id"].strip()     # a trace id resolves to its session
        else:
            # raw mode, or a trace the aggregator hasn't reached yet: one trace
            spans = store.get_trace(user["username"], session_id)
        if not spans:
            # Another user's session looks exactly like a missing one.
            return jsonify({"error": "No such session"}), 404
        traces = sorted({s["trace_id"].strip() for s in spans})
        return jsonify({"session_id": session_id, "traces": traces,
                        "spans": [_span_json(s) for s in spans]})

    @app.get("/agents/api/deviations")
    @app.get("/agents/api/alerts")
    def alerts_list():
        user, err = _api_user()
        if err:
            return err
        try:
            hours = min(max(float(request.args.get("hours", 168)), 0.1), 24 * 90)
            limit = min(max(int(request.args.get("limit", 500)), 1), 2000)
        except ValueError:
            return jsonify({"error": "hours and limit must be numbers"}), 400
        since_ns = int((clock() - hours * 3600) * 1e9)
        category = request.args.get("category") or None
        if category is not None and category not in DEVIATION_CATEGORIES:
            return jsonify({"error": "bad category"}), 400
        rows = store.list_deviations(user["username"], since_ns, category=category, limit=limit)
        items = [_alert_json(r) for r in rows]
        return jsonify({"alerts": items, "deviations": items, "hours": hours})

    @app.get("/agents/api/rules")
    def rules_catalogue():
        user, err = _api_user()
        if err:
            return err
        return jsonify({"rules": RULES, "benign": store.list_benign_rules(user["username"])})

    def _same_origin():
        # The Lax session cookie already keeps cross-site writes out; this is
        # the belt to that pair of braces for the two state-changing routes.
        origin = request.headers.get("Origin")
        return not origin or origin.rstrip("/") == request.host_url.rstrip("/")

    @app.post("/agents/api/benign-rules")
    def benign_add():
        if not _same_origin():
            return jsonify({"error": "cross-origin request refused"}), 403
        user, err = _api_user()
        if err:
            return err
        rule_id = str((request.get_json(silent=True) or {}).get("rule_id") or "")
        if rule_id not in RULES:
            return jsonify({"error": "unknown rule"}), 400
        store.set_benign_rule(user["username"], rule_id, True)
        return jsonify({"benign": store.list_benign_rules(user["username"])})

    @app.delete("/agents/api/benign-rules/<rule_id>")
    def benign_remove(rule_id):
        if not _same_origin():
            return jsonify({"error": "cross-origin request refused"}), 403
        user, err = _api_user()
        if err:
            return err
        if rule_id not in RULES:
            return jsonify({"error": "unknown rule"}), 400
        store.set_benign_rule(user["username"], rule_id, False)
        return jsonify({"benign": store.list_benign_rules(user["username"])})

    return app

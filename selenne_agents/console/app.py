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
    GET /agents/alerts                    the alerts page
    GET /agents/api/alerts?hours=&limit=  alerts, Selenne-alert shaped
    GET /agents/api/rules                 rule catalogue + this user's benign rules
    POST/DELETE /agents/api/benign-rules[/<rule_id>]
    GET /agents/health
"""

import logging
import os
import re
import time

from flask import Flask, jsonify, redirect, request, send_from_directory

from ..alerting.rules import RULES, label_for
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


def _alert_json(r):
    """Same field names as Selenne's /api/alerts/scored, so the Agents alert
    page reads like the SIEM one. A benign rule zero-scores its alerts."""
    ev = r["evidence"] or {}
    return {"id": r["id"], "timestamp_ms": _ms(r["ts_ns"]), "rule_id": r["rule_id"],
            "rule_description": r["title"], "level": r["level"],
            "anomaly_score": 0 if r["benign"] else r["score"],
            "anomaly_label": "BENIGN" if r["benign"] else label_for(r["score"]),
            "agent_name": r["service_name"] or r["host"] or "—", "project": r["project"],
            "groups": r["tags"] or [], "full_log": ev.get("excerpt") or "",
            "evidence_field": ev.get("field"), "evidence_match": ev.get("match"),
            "trace_id": r["trace_id"].strip() if r["trace_id"] else None,
            "span_id": r["span_id"].strip() if r["span_id"] else None, "host": r["host"]}


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

    @app.get("/agents/alerts")
    def alerts_page():
        return _page("alerts.html", "/login.html?next=/agents/alerts")

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
        rows = store.list_alerts(user["username"], since_ns, limit=limit)
        return jsonify({"alerts": [_alert_json(r) for r in rows], "hours": hours})

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

"""Flask app for selenne.app/agents/ (nginx forwards /agents/ here).

Pages (signed in only; each also answers at <name>.html so the frontend's
relative links work however it is opened):
    GET /agents/  /agents/alerts  /agents/keys  /agents/logs
    GET /agents/assets/<file>             JS/CSS, incl. the copied Selenne UI

The pages and their assets live in the repo's top-level frontend/ directory
(FRONTEND_DIR overrides it), apart from the Python package.

API:
    GET /agents/api/me                    who is signed in, per Selenne (+ selenne_url)
    GET /agents/api/projects
    GET /agents/api/sessions?project=&hours=&limit=
    GET /agents/api/sessions/<trace_id>   every span of one session
    GET /agents/alerts                    the alerts page
    GET /agents/api/alerts?hours=&limit=  alerts, Selenne-alert shaped
    GET /agents/api/rules                 rule catalogue + this user's benign rules
    POST/DELETE /agents/api/benign-rules[/<rule_id>]
    GET/POST /agents/api/keys, DELETE /agents/api/keys/<id>   forwarded to Selenne
    GET /agents/api/logs                  ingest history + raw span/sensor feed
    POST /agents/api/logout               signs out of Selenne (both consoles)
    GET /agents/health

Selenne pages (/landing.html, /login.html, /profile.html, /index.html) only
reach this app when it is opened on its own port; they redirect to
SELENNE_PUBLIC_URL so ◈SELENNE and the switcher still land in the right place.
"""

import logging
import os
import re
import time
from urllib.parse import urlparse

from flask import Flask, jsonify, redirect, request, send_from_directory

from ..alerting.rules import RULES, label_for
from ..store import StoreUnavailable
from .selenne_session import COOKIE, SelenneUnavailable, SessionUnavailable

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
    end = r["end_ns"] if r["end_ns"] is not None else r["start_ns"]
    return {"trace_id": r["trace_id"].strip(), "project": r["project"],
            "service_name": r["service_name"], "root_name": r["root_name"],
            "start_ms": _ms(r["start_ns"]), "duration_ms": (end - r["start_ns"]) / 1e6,
            "spans": r["spans"], "errors": r["errors"], "tool_calls": r["tool_calls"]}


def _span_json(r):
    return {"span_id": r["span_id"].strip(),
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


def _batch_json(r):
    return {"id": r["id"], "project": r["project"], "key_id": r["key_id"], "source": r["source"],
            "accepted": r["accepted"], "new": r["new"], "rejected": r["rejected"],
            "error": r["error"], "received_ms": float(r["received_ms"])}


def _event_json(r):
    d = r["detail"] or {}
    if r["type"] == "host":
        summary = d.get("path") or " ".join(map(str, d.get("argv") or [])) or \
            (f"{d.get('daddr')}:{d.get('dport', '?')}" if d.get("daddr") else "") or d.get("query") or ""
    else:
        summary = d.get("gen_ai.tool.name") or d.get("gen_ai.request.model") or ""
    return {"type": r["type"], "project": r["project"], "source": r["source"], "title": r["title"],
            "origin": r["origin"], "status": r["status"],
            "trace_id": r["trace_id"].strip() if r["trace_id"] else None,
            "ts_ms": _ms(r["ts_ns"]), "received_ms": float(r["received_ms"]),
            "summary": str(summary)[:300]}


def create_console_app(settings, sessions, store, clock=time.time, selenne=None):
    app = Flask(__name__, static_folder=None)
    public = settings.selenne_public_url      # "" = same origin (behind nginx)
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
            return None, (jsonify({"error": "Sign in required", "login": f"{public}{LOGIN_URL}"}), 401)
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

    for route, filename in (("/agents/", "index.html"), ("/agents/index.html", "index.html"),
                            ("/agents/alerts", "alerts.html"), ("/agents/alerts.html", "alerts.html"),
                            ("/agents/keys", "keys.html"), ("/agents/keys.html", "keys.html"),
                            ("/agents/logs", "logs.html"), ("/agents/logs.html", "logs.html")):
        def view(filename=filename, route=route):
            return _page(filename, f"{public}/login.html?next={route}")
        app.add_url_rule(route, f"page_{route}", view)

    # Only reached when the console is opened on its own port (behind nginx
    # these paths belong to Selenne): send the browser to Selenne itself.
    for selenne_path in ("/", "/landing.html", "/login.html", "/profile.html", "/index.html"):
        def to_selenne(p=selenne_path):
            if not public:
                return ("This path belongs to Selenne. Set SELENNE_PUBLIC_URL so the Agents "
                        "console can send you there.", 404, {"Content-Type": "text/plain; charset=utf-8"})
            qs = request.query_string.decode()
            return redirect(f"{public}{p}" + (f"?{qs}" if qs else ""))
        app.add_url_rule(selenne_path, f"selenne_{selenne_path}", to_selenne)

    @app.get("/agents/assets/<path:name>")
    def asset(name):
        return send_from_directory(ASSETS_DIR, name)

    @app.get("/agents/health")
    def health():
        return jsonify({"status": "ok"})

    @app.get("/agents/api/me")
    def me():
        try:
            user = _user()
        except SessionUnavailable:
            return jsonify({"error": "Sign-in service unavailable, retry shortly"}), 503
        if not user:
            return jsonify({"user": None, "login": f"{public}{LOGIN_URL}",
                            "selenne_url": public}), 401
        return jsonify({"user": user, "selenne_url": public})

    @app.get("/agents/api/projects")
    def projects():
        user, err = _api_user()
        if err:
            return err
        return jsonify({"projects": store.list_projects(user["username"])})

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
        rows = store.list_sessions(user["username"], since_ns, project=project, limit=limit)
        return jsonify({"sessions": [_session_json(r) for r in rows],
                        "hours": hours, "limit": limit})

    @app.get("/agents/api/sessions/<trace_id>")
    def session_detail(trace_id):
        user, err = _api_user()
        if err:
            return err
        trace_id = trace_id.lower()
        if not _TRACE_RE.match(trace_id):
            return jsonify({"error": "bad trace id"}), 400
        spans = store.get_trace(user["username"], trace_id)
        if not spans:
            # Another user's trace looks exactly like a missing one.
            return jsonify({"error": "No such session"}), 404
        return jsonify({"trace_id": trace_id, "spans": [_span_json(s) for s in spans]})

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
        # the belt to those braces for the state-changing routes. Host NAMES
        # are compared, not ports: nginx forwards "Host: $host", which drops
        # the port, so a full-origin match refused the console's own pages
        # whenever it sat behind a proxy on a non-default port.
        origin = request.headers.get("Origin")
        if not origin:
            return True
        if public and origin.rstrip("/") == public:
            return True
        return (urlparse(origin).hostname or "") == (urlparse("//" + request.host).hostname or "")

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

    # --- ingestion keys: Selenne owns them; the console only relays -------------

    def _selenne(method, path, json_body=None):
        user, err = _api_user()
        if err:
            return err
        if user.get("dev") or selenne is None:
            return jsonify({"error": "Keys are managed by Selenne, which this console is not "
                                     "connected to (dev mode). Ingest accepts the "
                                     "SELENNE_AGENTS_DEV_KEYS from .env meanwhile.",
                            "dev": True}), 503
        try:
            status, body = selenne.call(method, path, request.cookies.get(COOKIE), json_body)
        except SelenneUnavailable as e:
            log.warning("selenne unavailable: %s", e)
            return jsonify({"error": "Selenne is unreachable, retry shortly"}), 503
        return jsonify(body), status

    @app.get("/agents/api/keys")
    def keys_list():
        return _selenne("GET", "/api/keys")

    @app.post("/agents/api/keys")
    def keys_create():
        if not _same_origin():
            return jsonify({"error": "cross-origin request refused"}), 403
        project = (request.get_json(silent=True) or {}).get("project")
        return _selenne("POST", "/api/keys", {"project": project})

    @app.delete("/agents/api/keys/<key_id>")
    def keys_revoke(key_id):
        if not _same_origin():
            return jsonify({"error": "cross-origin request refused"}), 403
        if not re.match(r"^k_[0-9a-f]{1,32}$", key_id):
            return jsonify({"error": "bad key id"}), 400
        return _selenne("DELETE", f"/api/keys/{key_id}")

    @app.post("/agents/api/logout")
    def logout():
        if not _same_origin():
            return jsonify({"error": "cross-origin request refused"}), 403
        token = request.cookies.get(COOKIE)
        if token and selenne is not None:
            try:
                selenne.call("POST", "/api/auth/logout", token)
            except SelenneUnavailable as e:
                log.warning("logout relay failed: %s", e)
        resp = jsonify({"status": "ok", "next": f"{public}/landing.html"})
        resp.delete_cookie(COOKIE)
        return resp

    # --- logs ---------------------------------------------------------------------

    @app.get("/agents/api/logs")
    def logs():
        user, err = _api_user()
        if err:
            return err
        try:
            limit = min(max(int(request.args.get("limit", 200)), 1), 1000)
        except ValueError:
            return jsonify({"error": "limit must be a number"}), 400
        return jsonify({"batches": [_batch_json(b) for b in store.list_batches(user["username"], limit)],
                        "events": [_event_json(e) for e in store.recent_events(user["username"], limit)]})

    return app

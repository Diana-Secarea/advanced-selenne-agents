"""HTTP front door: OTLP/HTTP, the native JSON API and sidecar host events.

Status codes follow what OTLP exporters expect: 429/502/503/504 are retried
(honouring Retry-After), every other 4xx is dropped by the client — so only
"try again later" conditions may use the retryable codes.
"""

import json
import logging
import zlib

from flask import Flask, jsonify, request
from werkzeug.exceptions import RequestEntityTooLarge

from . import normalize, otlp
from .gate import NOT_ENTITLED, RATE_LIMITED, UNAUTHENTICATED, UNAVAILABLE, Denied
from .. import alerting
from ..store import StoreUnavailable

log = logging.getLogger("ingest.http")

_DENIED_STATUS = {UNAUTHENTICATED: 401, NOT_ENTITLED: 402, RATE_LIMITED: 429, UNAVAILABLE: 503}
_PROTOBUF = "application/x-protobuf"


def bounded_gunzip(raw, limit):
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        out = d.decompress(raw, limit + 1)
    except zlib.error as e:
        raise normalize.PayloadError("body is not valid gzip") from e
    if len(out) > limit or d.unconsumed_tail:
        raise normalize.PayloadError(f"decompressed body exceeds {limit} bytes", status=413)
    if not d.eof:
        raise normalize.PayloadError("gzip body is truncated")
    return out


def create_app(settings, gate, store):
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = settings.max_body_bytes
    if settings.trust_proxy:
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    def _body():
        raw = request.get_data(cache=False)
        encoding = (request.headers.get("Content-Encoding") or "").strip().lower()
        if encoding in ("", "identity"):
            return raw
        if encoding == "gzip":
            return bounded_gunzip(raw, settings.max_decompressed_bytes)
        raise normalize.PayloadError(f"unsupported Content-Encoding: {encoding[:32]}", status=415)

    def _json_body():
        raw = _body()   # outside the try: its PayloadError is a ValueError too
        try:
            return json.loads(raw)
        except (ValueError, UnicodeDecodeError) as e:
            raise normalize.PayloadError("body is not valid JSON") from e

    def _admit():
        # Before the body is read: unauthenticated callers never cost a parse.
        return gate.admit(request.headers.get("Authorization"))

    @app.errorhandler(Denied)
    def _denied(e):
        resp = jsonify({"error": e.message, "reason": e.reason})
        resp.status_code = _DENIED_STATUS[e.reason]
        if e.retry_after:
            resp.headers["Retry-After"] = str(e.retry_after)
        if e.reason == UNAUTHENTICATED:
            resp.headers["WWW-Authenticate"] = 'Bearer realm="selenne-ingest"'
        return resp

    @app.errorhandler(normalize.PayloadError)
    def _payload(e):
        return jsonify({"error": str(e)}), e.status

    @app.errorhandler(RequestEntityTooLarge)
    def _too_large(e):
        return jsonify({"error": f"body exceeds {settings.max_body_bytes} bytes"}), 413

    @app.errorhandler(StoreUnavailable)
    def _store_down(e):
        log.error("store unavailable: %s", e)
        resp = jsonify({"error": "storage temporarily unavailable"})
        resp.status_code = 503
        resp.headers["Retry-After"] = "5"
        return resp

    @app.post("/v1/traces")
    def otlp_traces():
        principal = _admit()
        ctype = request.mimetype
        if ctype == _PROTOBUF:
            doc = otlp.decode_request(_body())
        elif ctype == "application/json":
            doc = _json_body()
        else:
            raise normalize.PayloadError(
                f"Content-Type must be {_PROTOBUF} or application/json", status=415)
        batch = normalize.otlp_spans(doc)
        new = store.insert_spans(principal, batch.rows, "otlp-http")
        alerting.record(store, principal, alerting.for_spans(batch.rows))
        log_batch("otlp-http", principal, batch, new)
        record_batch(store, "otlp-http", principal, batch, new)
        if ctype == _PROTOBUF:
            return app.response_class(otlp.response(batch).SerializeToString(),
                                      mimetype=_PROTOBUF)
        return jsonify(otlp.response_json(batch))

    @app.post("/v1/events")
    def native_events():
        principal = _admit()
        if request.mimetype != "application/json":
            raise normalize.PayloadError("Content-Type must be application/json", status=415)
        batch = normalize.native_spans(_json_body())
        new = store.insert_spans(principal, batch.rows, "native")
        alerting.record(store, principal, alerting.for_spans(batch.rows))
        log_batch("native", principal, batch, new)
        record_batch(store, "native", principal, batch, new)
        return jsonify(_summary(batch))

    @app.post("/v1/host-events")
    def sensor_events():
        principal = _admit()
        if request.mimetype not in ("application/x-ndjson", "application/jsonl", "text/plain"):
            raise normalize.PayloadError("Content-Type must be application/x-ndjson", status=415)
        batch = normalize.host_events(_body())
        new = store.insert_host_events(principal, batch.rows)
        alerting.record(store, principal, alerting.for_host_events(batch.rows))
        log_batch("host-events", principal, batch, new)
        record_batch(store, "host-events", principal, batch, new)
        return jsonify(_summary(batch))

    @app.get("/health")
    def health():
        return jsonify({"status": "ok"})

    @app.get("/ready")
    def ready():
        ok = store.ping()
        return jsonify({"status": "ok" if ok else "degraded", "database": ok}), (200 if ok else 503)

    return app


def _summary(batch):
    out = {"accepted": len(batch.rows), "rejected": batch.rejected}
    if batch.error:
        out["error"] = batch.error
    return out


def record_batch(store, source, principal, batch, new):
    """Delivery history for the Logs page. Never fails the request."""
    try:
        store.record_batch(principal, source, len(batch.rows), new, batch.rejected, batch.error)
    except Exception:            # noqa: BLE001
        logging.getLogger("ingest.batch").exception("could not record batch history")


def log_batch(source, principal, batch, new):
    """One line per accepted request — to stderr and this stack's own
    ingest.json, never to anything Selenne's Wazuh collector reads."""
    logging.getLogger("ingest.batch").info(
        "%s %s/%s accepted=%d new=%d rejected=%d", source, principal.username,
        principal.project, len(batch.rows), new, batch.rejected,
        extra={"fields": {"event": "batch", "source": source,
                          "username": principal.username, "project": principal.project,
                          "key_id": principal.key_id, "accepted": len(batch.rows),
                          "new": new, "rejected": batch.rejected}})

"""One normalizer for every way data arrives.

OTLP/HTTP protobuf, OTLP/HTTP JSON and OTLP/gRPC all become an OTLP-JSON
shaped dict first (see otlp.py) and go through otlp_spans(). The native HTTP
format goes through native_spans(). Both produce the same span row, so
nothing downstream knows which door the data came through. Sidecar host
events go through host_events().

Bad top-level shape raises PayloadError (the whole request is refused, 400).
A bad individual span or event is dropped and counted in Batch.rejected, which
OTLP reports back to the client as partial success.
"""

import base64
import binascii
import datetime as _dt
import json
import math
from dataclasses import dataclass, field

MAX_NAME = 1024
MAX_TEXT = 65536   # per string value; long prompts are kept, runaway blobs are not

_SPAN_KINDS = {0: "unspecified", 1: "internal", 2: "server", 3: "client",
               4: "producer", 5: "consumer"}
_STATUS_CODES = {0: "unset", 1: "ok", 2: "error"}
_EPOCH = _dt.datetime(1970, 1, 1, tzinfo=_dt.timezone.utc)


class PayloadError(ValueError):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


@dataclass
class Batch:
    rows: list = field(default_factory=list)
    rejected: int = 0
    error: str = None   # first rejection reason, for the client

    def reject(self, reason):
        self.rejected += 1
        if self.error is None:
            self.error = reason


# --- value helpers -----------------------------------------------------------

def clean(v):
    """Make a value safe for Postgres jsonb/text: no NUL characters (text and
    jsonb both refuse them), no NaN/Infinity (jsonb refuses them), bounded
    string length."""
    if isinstance(v, str):
        v = v.replace("\x00", "�")
        return v if len(v) <= MAX_TEXT else v[:MAX_TEXT] + "…[truncated]"
    if isinstance(v, bool) or v is None or isinstance(v, int):
        return v
    if isinstance(v, float):
        return v if math.isfinite(v) else str(v)
    if isinstance(v, dict):
        return {clean(str(k)): clean(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [clean(x) for x in v]
    return clean(str(v))


def _text(v, cap=MAX_NAME):
    if v is None:
        return None
    s = clean(str(v))
    return s[:cap]


def _hex_id(v, length):
    """Lower-case hex id of exactly `length` chars, not all zeros, else None."""
    if not isinstance(v, str):
        return None
    s = v.strip().lower()
    if len(s) != length or s.strip("0") == "":
        return None
    try:
        int(s, 16)
    except ValueError:
        return None
    return s


def b64_to_hex(v):
    """protobuf's JSON mapping writes bytes as base64; OTLP ids are hex."""
    try:
        return base64.b64decode(v, validate=True).hex()
    except (binascii.Error, ValueError, TypeError):
        return v


def _enum(v, table, prefix):
    if v is None or v == "":
        return table[0]
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return table.get(v)
    s = str(v).strip().lower()
    if s.isdigit():
        return table.get(int(s))
    if s.startswith(prefix):
        s = s[len(prefix):]
    return s if s in table.values() else None


def _nanos(v):
    """uint64 nanoseconds, given as int or decimal string (OTLP JSON allows both)."""
    if v is None or isinstance(v, bool):
        return None
    try:
        n = int(v)
    except (TypeError, ValueError):
        return None
    return n if 0 < n < 2 ** 63 else None


def _iso_nanos(v):
    if not isinstance(v, str):
        return None
    try:
        t = _dt.datetime.fromisoformat(v.strip())
    except ValueError:
        return None
    if t.tzinfo is None:
        t = t.replace(tzinfo=_dt.timezone.utc)
    return _nanos((t - _EPOCH) // _dt.timedelta(microseconds=1) * 1000)


def _time(obj, nano_key, iso_key):
    n = _nanos(obj.get(nano_key))
    return n if n is not None else _iso_nanos(obj.get(iso_key))


# --- OTLP ---------------------------------------------------------------------

def _any(v):
    if not isinstance(v, dict):
        return None
    if "stringValue" in v:
        return v["stringValue"]
    if "boolValue" in v:
        return bool(v["boolValue"])
    if "intValue" in v:
        try:
            return int(v["intValue"])
        except (TypeError, ValueError):
            return None
    if "doubleValue" in v:
        try:
            return float(v["doubleValue"])
        except (TypeError, ValueError):
            return None
    if "arrayValue" in v:
        return [_any(x) for x in (v["arrayValue"] or {}).get("values") or []]
    if "kvlistValue" in v:
        return _kv((v["kvlistValue"] or {}).get("values"))
    if "bytesValue" in v:
        return v["bytesValue"]   # kept as the base64 text it arrived as
    return None


def _kv(items):
    out = {}
    for it in items or []:
        if isinstance(it, dict) and isinstance(it.get("key"), str):
            out[it["key"]] = _any(it.get("value"))
    return clean(out)


def _list_of_dicts(v, what):
    if v is None:
        return []
    if not isinstance(v, list):
        raise PayloadError(f"'{what}' must be a list")
    return [x for x in v if isinstance(x, dict)]


def otlp_spans(doc):
    if not isinstance(doc, dict):
        raise PayloadError("OTLP body must be an ExportTraceServiceRequest object")
    batch = Batch()
    for rs in _list_of_dicts(doc.get("resourceSpans"), "resourceSpans"):
        resource = _kv((rs.get("resource") or {}).get("attributes"))
        # instrumentationLibrarySpans: pre-1.0 name of scopeSpans, still sent by old SDKs
        scopes = rs.get("scopeSpans")
        if scopes is None:
            scopes = rs.get("instrumentationLibrarySpans")
        for ss in _list_of_dicts(scopes, "scopeSpans"):
            scope = ss.get("scope") or ss.get("instrumentationLibrary") or {}
            for sp in _list_of_dicts(ss.get("spans"), "spans"):
                row, reason = _otlp_span(sp, resource, scope)
                if row:
                    batch.rows.append(row)
                else:
                    batch.reject(reason)
    return batch


def _otlp_span(sp, resource, scope):
    trace_id = _hex_id(sp.get("traceId"), 32)
    span_id = _hex_id(sp.get("spanId"), 16)
    if not trace_id or not span_id:
        return None, "span with invalid traceId/spanId"
    start = _nanos(sp.get("startTimeUnixNano"))
    if start is None:
        return None, "span without startTimeUnixNano"
    kind = _enum(sp.get("kind"), _SPAN_KINDS, "span_kind_")
    status = sp.get("status") or {}
    events = [{"name": _text(e.get("name")),
               "time_ns": _nanos(e.get("timeUnixNano")),
               "attributes": _kv(e.get("attributes"))}
              for e in sp.get("events") or [] if isinstance(e, dict)]
    links = [{"trace_id": _hex_id(l.get("traceId"), 32),
              "span_id": _hex_id(l.get("spanId"), 16),
              "attributes": _kv(l.get("attributes"))}
             for l in sp.get("links") or [] if isinstance(l, dict)]
    return _row(trace_id, span_id, _hex_id(sp.get("parentSpanId") or "", 16),
                sp.get("name"), kind, start, _nanos(sp.get("endTimeUnixNano")),
                _enum(status.get("code"), _STATUS_CODES, "status_code_"),
                status.get("message"), resource, scope.get("name"), scope.get("version"),
                _kv(sp.get("attributes")), events, links), None


def _row(trace_id, span_id, parent, name, kind, start, end, status_code,
         status_message, resource, scope_name, scope_version, attributes, events, links):
    return {
        "trace_id": trace_id,
        "span_id": span_id,
        "parent_span_id": parent,
        "name": _text(name) or "(unnamed)",
        "kind": kind or "unspecified",
        "start_ns": start,
        "end_ns": end if end and end >= start else None,
        "status_code": status_code or "unset",
        "status_message": _text(status_message, MAX_TEXT) or None,
        "service_name": _text(resource.get("service.name")),
        "scope_name": _text(scope_name),
        "scope_version": _text(scope_version),
        "resource": resource,
        "attributes": attributes,
        "events": events,
        "links": links,
    }


# --- native HTTP format ------------------------------------------------------

def native_spans(doc):
    """Body of POST /v1/events:

    {"resource": {"service.name": "my-agent"},          # optional
     "spans": [{"trace_id": "<32 hex>", "span_id": "<16 hex>",
                "parent_span_id": "<16 hex>",            # optional
                "name": "tool.read_file", "kind": "internal",
                "start_time": "2026-09-29T10:00:00.123Z" | "start_time_unix_nano": 1759...,
                "end_time": ... | "end_time_unix_nano": ...,   # optional
                "status": "ok" | "error" | "unset", "status_message": "...",
                "attributes": {"any": "json"},
                "events": [{"name": "...", "time": "...", "attributes": {}}]}]}
    """
    if not isinstance(doc, dict):
        raise PayloadError("body must be a JSON object with a 'spans' list")
    resource = doc.get("resource")
    if resource is None:
        resource = {}
    elif not isinstance(resource, dict):
        raise PayloadError("'resource' must be an object")
    resource = clean(resource)
    spans = doc.get("spans")
    if not isinstance(spans, list):
        raise PayloadError("body must contain a 'spans' list")
    batch = Batch()
    for sp in spans:
        if not isinstance(sp, dict):
            batch.reject("span is not an object")
            continue
        trace_id = _hex_id(sp.get("trace_id"), 32)
        span_id = _hex_id(sp.get("span_id"), 16)
        if not trace_id or not span_id:
            batch.reject("span with invalid trace_id/span_id")
            continue
        start = _time(sp, "start_time_unix_nano", "start_time")
        if start is None:
            batch.reject("span without start_time/start_time_unix_nano")
            continue
        attributes = sp.get("attributes") or {}
        if not isinstance(attributes, dict):
            batch.reject("span 'attributes' must be an object")
            continue
        events = [{"name": _text(e.get("name")),
                   "time_ns": _time(e, "time_unix_nano", "time"),
                   "attributes": clean(e.get("attributes") if isinstance(e.get("attributes"), dict) else {})}
                  for e in sp.get("events") or [] if isinstance(e, dict)]
        batch.rows.append(_row(
            trace_id, span_id, _hex_id(sp.get("parent_span_id") or "", 16),
            sp.get("name"), _enum(sp.get("kind"), _SPAN_KINDS, "span_kind_"),
            start, _time(sp, "end_time_unix_nano", "end_time"),
            _enum(sp.get("status"), _STATUS_CODES, "status_code_"),
            sp.get("status_message"), resource, "native", None,
            clean(attributes), events, []))
    return batch


# --- sidecar host events -----------------------------------------------------

_PID_MAX = 2 ** 31 - 1


def _pid(v):
    if isinstance(v, bool):
        return None
    try:
        n = int(v)
    except (TypeError, ValueError):
        return None
    return n if 0 <= n <= _PID_MAX else None


def host_events(body):
    """NDJSON body of POST /v1/host-events, one event per line:

    {"kind": "exec"|"open"|"connect"|"dns"|..., "host": "worker-1",
     "pid": 4242, "ts": "2026-09-29T10:00:00.123456Z" | "ts_unix_nano": ...,
     "ppid": 1, "cgroup": "...", "container_id": "...", "event_id": "...",
     ...kind-specific fields (path, flags, argv, daddr, dport, query...)}
    The whole object is kept in `detail`.
    """
    if isinstance(body, bytes):
        try:
            body = body.decode("utf-8")
        except UnicodeDecodeError as e:
            raise PayloadError("host events must be UTF-8 NDJSON") from e
    batch = Batch()
    for line in body.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except ValueError:
            batch.reject("line is not valid JSON")
            continue
        if not isinstance(ev, dict):
            batch.reject("line is not a JSON object")
            continue
        kind, host, pid = ev.get("kind"), ev.get("host"), _pid(ev.get("pid"))
        ts = _time(ev, "ts_unix_nano", "ts")
        if not isinstance(kind, str) or not kind or not isinstance(host, str) or not host \
                or pid is None or ts is None:
            batch.reject("event needs kind, host, pid and ts/ts_unix_nano")
            continue
        batch.rows.append({
            "event_id": _text(ev.get("event_id")),
            "host": _text(host),
            "pid": pid,
            "ppid": _pid(ev.get("ppid")),
            "cgroup": _text(ev.get("cgroup"), MAX_TEXT),
            "container_id": _text(ev.get("container_id")),
            "kind": _text(kind, 64).lower(),
            "ts_ns": ts,
            "detail": clean(ev),
        })
    return batch

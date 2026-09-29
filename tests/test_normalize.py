import gzip
import json

import pytest

from selenne_agents.ingest import normalize, otlp
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest

TRACE = "5b8efff798038103d269b633813fc60c"
SPAN = "eee19b7ec3c1b174"
PARENT = "eee19b7ec3c1b173"


def otlp_json_doc(**span_overrides):
    span = {
        "traceId": TRACE, "spanId": SPAN, "parentSpanId": PARENT,
        "name": "tool.read_file", "kind": 3,
        "startTimeUnixNano": "1759140000000000000", "endTimeUnixNano": "1759140000500000000",
        "attributes": [
            {"key": "gen_ai.tool.name", "value": {"stringValue": "read_file"}},
            {"key": "file.size", "value": {"intValue": "42"}},
            {"key": "score", "value": {"doubleValue": "NaN"}},
            {"key": "tags", "value": {"arrayValue": {"values": [{"stringValue": "a"}, {"boolValue": True}]}}},
            {"key": "nested", "value": {"kvlistValue": {"values": [{"key": "k", "value": {"stringValue": "v\u0000x"}}]}}},
        ],
        "events": [{"timeUnixNano": "1759140000100000000", "name": "prompt",
                    "attributes": [{"key": "len", "value": {"intValue": 7}}]}],
        "status": {"code": 2, "message": "boom"},
    }
    span.update(span_overrides)
    return {"resourceSpans": [{
        "resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "cve-agent"}}]},
        "scopeSpans": [{"scope": {"name": "selenne.sdk", "version": "0.1"}, "spans": [span]}],
    }]}


def test_otlp_json_span_is_normalised():
    batch = normalize.otlp_spans(otlp_json_doc())
    assert batch.rejected == 0
    [row] = batch.rows
    assert row["trace_id"] == TRACE and row["span_id"] == SPAN and row["parent_span_id"] == PARENT
    assert row["kind"] == "client"
    assert row["status_code"] == "error" and row["status_message"] == "boom"
    assert row["start_ns"] == 1759140000000000000 and row["end_ns"] == 1759140000500000000
    assert row["service_name"] == "cve-agent"
    assert row["scope_name"] == "selenne.sdk"
    a = row["attributes"]
    assert a["gen_ai.tool.name"] == "read_file" and a["file.size"] == 42
    assert a["score"] == "nan"                   # jsonb cannot hold NaN
    assert a["tags"] == ["a", True]
    assert a["nested"] == {"k": "v�x"}      # nor NUL
    assert row["events"][0]["attributes"] == {"len": 7}


def test_protobuf_path_matches_json_path():
    doc = otlp_json_doc()
    req = ExportTraceServiceRequest()
    # Build the protobuf from the same content: ids become raw bytes.
    rs = req.resource_spans.add()
    kv = rs.resource.attributes.add(); kv.key = "service.name"; kv.value.string_value = "cve-agent"
    ss = rs.scope_spans.add(); ss.scope.name = "selenne.sdk"; ss.scope.version = "0.1"
    sp = ss.spans.add()
    sp.trace_id = bytes.fromhex(TRACE); sp.span_id = bytes.fromhex(SPAN)
    sp.parent_span_id = bytes.fromhex(PARENT)
    sp.name = "tool.read_file"; sp.kind = 3
    sp.start_time_unix_nano = 1759140000000000000; sp.end_time_unix_nano = 1759140000500000000
    sp.status.code = 2; sp.status.message = "boom"
    a = sp.attributes.add(); a.key = "gen_ai.tool.name"; a.value.string_value = "read_file"

    from_pb = normalize.otlp_spans(otlp.decode_request(req.SerializeToString())).rows[0]
    from_json = normalize.otlp_spans(otlp_json_doc(attributes=doc["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["attributes"][:1], events=[])).rows[0]
    assert from_pb == from_json


def test_bad_spans_are_rejected_not_fatal():
    doc = otlp_json_doc()
    spans = doc["resourceSpans"][0]["scopeSpans"][0]["spans"]
    spans.append(dict(spans[0], traceId="00000000000000000000000000000000"))
    spans.append(dict(spans[0], spanId="xyz"))
    spans.append({k: v for k, v in spans[0].items() if k != "startTimeUnixNano"})
    batch = normalize.otlp_spans(doc)
    assert len(batch.rows) == 1 and batch.rejected == 3
    assert "traceId" in batch.error


def test_enum_names_and_legacy_scope_key():
    doc = otlp_json_doc(kind="SPAN_KIND_SERVER", status={"code": "STATUS_CODE_OK"})
    rs = doc["resourceSpans"][0]
    rs["instrumentationLibrarySpans"] = rs.pop("scopeSpans")
    [row] = normalize.otlp_spans(doc).rows
    assert row["kind"] == "server" and row["status_code"] == "ok"


def test_otlp_top_level_shape():
    with pytest.raises(normalize.PayloadError):
        normalize.otlp_spans([])
    with pytest.raises(normalize.PayloadError):
        normalize.otlp_spans({"resourceSpans": "nope"})
    assert normalize.otlp_spans({}).rows == []


def test_native_span_with_iso_times():
    batch = normalize.native_spans({
        "resource": {"service.name": "support-bot"},
        "spans": [{"trace_id": TRACE, "span_id": SPAN, "name": "llm.call", "kind": "client",
                   "start_time": "2026-09-29T10:00:00.250Z", "end_time": "2026-09-29T10:00:01Z",
                   "status": "ok", "attributes": {"gen_ai.request.model": "claude-sonnet-5-5",
                                                  "usage": {"input_tokens": 12}},
                   "events": [{"name": "tool_result", "time": "2026-09-29T10:00:00.5Z"}]},
                  {"trace_id": TRACE, "span_id": "bad", "name": "x", "start_time": "2026-09-29T10:00:00Z"},
                  "not-an-object"]})
    assert batch.rejected == 2
    [row] = batch.rows
    assert row["start_ns"] == 1790676000250000000
    assert row["end_ns"] == 1790676001000000000
    assert row["kind"] == "client" and row["status_code"] == "ok"
    assert row["service_name"] == "support-bot"
    assert row["attributes"]["usage"] == {"input_tokens": 12}
    assert row["events"][0]["time_ns"] == 1790676000500000000


def test_native_shape_errors():
    for bad in ([], {"spans": {}}, {"resource": [], "spans": []}):
        with pytest.raises(normalize.PayloadError):
            normalize.native_spans(bad)


def test_host_events_ndjson():
    lines = [
        {"kind": "OPEN", "host": "worker-1", "pid": 4242, "ppid": 1, "ts_unix_nano": 1759140000000000000,
         "path": "/home/app/.ssh/id_rsa", "event_id": "e1"},
        {"kind": "connect", "host": "worker-1", "pid": "4242", "ts": "2026-09-29T10:00:00Z",
         "daddr": "203.0.113.9", "dport": 443},
        {"kind": "exec", "host": "worker-1", "ts": "2026-09-29T10:00:00Z"},   # no pid
    ]
    body = ("\n".join(json.dumps(l) for l in lines) + "\n{not json\n\n").encode()
    batch = normalize.host_events(body)
    assert len(batch.rows) == 2 and batch.rejected == 2
    first, second = batch.rows
    assert first["kind"] == "open" and first["event_id"] == "e1" and first["ppid"] == 1
    assert first["detail"]["path"] == "/home/app/.ssh/id_rsa"
    assert second["pid"] == 4242 and second["ts_ns"] == 1790676000000000000


def test_clean_truncates_huge_strings():
    s = normalize.clean("x" * (normalize.MAX_TEXT + 10))
    assert s.endswith("…[truncated]") and len(s) < normalize.MAX_TEXT + 20

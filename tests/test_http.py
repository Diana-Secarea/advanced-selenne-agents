import gzip
import json

from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
    ExportTraceServiceRequest,
    ExportTraceServiceResponse,
)

from conftest import AUTH
from test_normalize import SPAN, TRACE, otlp_json_doc

PB = "application/x-protobuf"


def _pb_request(n=1):
    req = ExportTraceServiceRequest()
    ss = req.resource_spans.add().scope_spans.add()
    for i in range(n):
        sp = ss.spans.add()
        sp.trace_id = bytes.fromhex(TRACE)
        sp.span_id = (i + 1).to_bytes(8, "big")
        sp.name = f"step-{i}"
        sp.start_time_unix_nano = 1759140000000000000 + i
    return req.SerializeToString()


def test_otlp_json(client, store):
    r = client.post("/v1/traces", json=otlp_json_doc(), headers=AUTH)
    assert r.status_code == 200 and r.get_json() == {}
    [span] = store.spans
    assert span["source"] == "otlp-http" and span["principal"].username == "diana"
    assert span["principal"].project == "cve-agent"


def test_otlp_protobuf_gzip(client, store):
    r = client.post("/v1/traces", data=gzip.compress(_pb_request(3)),
                    headers={**AUTH, "Content-Type": PB, "Content-Encoding": "gzip"})
    assert r.status_code == 200 and r.mimetype == PB
    resp = ExportTraceServiceResponse.FromString(r.data)
    assert resp.partial_success.rejected_spans == 0
    assert [s["name"] for s in store.spans] == ["step-0", "step-1", "step-2"]


def test_otlp_partial_success_reported(client, store):
    doc = otlp_json_doc()
    spans = doc["resourceSpans"][0]["scopeSpans"][0]["spans"]
    spans.append(dict(spans[0], spanId="nope"))
    r = client.post("/v1/traces", json=doc, headers=AUTH)
    assert r.status_code == 200
    assert r.get_json()["partialSuccess"]["rejectedSpans"] == "1"
    assert len(store.spans) == 1


def test_retry_is_idempotent(client, store):
    for _ in range(2):
        assert client.post("/v1/traces", json=otlp_json_doc(), headers=AUTH).status_code == 200
    assert len(store.spans) == 1


def test_auth_required_before_body(client, store):
    r = client.post("/v1/traces", data=b"garbage", headers={"Content-Type": PB})
    assert r.status_code == 401 and "Bearer" in r.headers["WWW-Authenticate"]
    r = client.post("/v1/traces", json={}, headers={"Authorization": "Bearer sk_sel_wrong_key_0123456789"})
    assert r.status_code == 401
    assert store.spans == []


def test_bad_payloads(client):
    assert client.post("/v1/traces", data=b"\xff\x00junk", headers={**AUTH, "Content-Type": PB}).status_code == 400
    assert client.post("/v1/traces", data=b"{", headers={**AUTH, "Content-Type": "application/json"}).status_code == 400
    assert client.post("/v1/traces", data=b"x", headers={**AUTH, "Content-Type": "text/xml"}).status_code == 415
    r = client.post("/v1/traces", data=b"{}", headers={**AUTH, "Content-Type": "application/json",
                                                        "Content-Encoding": "br"})
    assert r.status_code == 415
    r = client.post("/v1/traces", data=b"not gzip", headers={**AUTH, "Content-Type": "application/json",
                                                              "Content-Encoding": "gzip"})
    assert r.status_code == 400


def test_body_limits(client, settings):
    big = b"{" + b" " * settings.max_body_bytes + b"}"
    r = client.post("/v1/traces", data=big, headers={**AUTH, "Content-Type": "application/json"})
    assert r.status_code == 413
    bomb = gzip.compress(b" " * (settings.max_decompressed_bytes + 1))
    assert len(bomb) < settings.max_body_bytes
    r = client.post("/v1/traces", data=bomb, headers={**AUTH, "Content-Type": "application/json",
                                                       "Content-Encoding": "gzip"})
    assert r.status_code == 413


def test_store_outage_is_retryable(client, store):
    store.down = True
    r = client.post("/v1/traces", json=otlp_json_doc(), headers=AUTH)
    assert r.status_code == 503 and r.headers["Retry-After"] == "5"
    assert client.get("/ready").status_code == 503
    assert client.get("/health").status_code == 200


def test_native_events(client, store):
    body = {"resource": {"service.name": "bot"},
            "spans": [{"trace_id": TRACE, "span_id": SPAN, "name": "llm", "start_time": "2026-09-29T10:00:00Z"},
                      {"trace_id": "x"}]}
    r = client.post("/v1/events", json=body, headers=AUTH)
    assert r.status_code == 200
    assert r.get_json() == {"accepted": 1, "rejected": 1, "error": "span with invalid trace_id/span_id"}
    assert store.spans[0]["source"] == "native"
    assert client.post("/v1/events", json={"nope": 1}, headers=AUTH).status_code == 400


def test_host_events(client, store):
    lines = b"\n".join(json.dumps(e).encode() for e in [
        {"kind": "open", "host": "w1", "pid": 7, "ts": "2026-09-29T10:00:00Z", "path": "/etc/passwd"},
        {"kind": "exec", "host": "w1"},
    ])
    r = client.post("/v1/host-events", data=gzip.compress(lines),
                    headers={**AUTH, "Content-Type": "application/x-ndjson", "Content-Encoding": "gzip"})
    assert r.status_code == 200 and r.get_json()["accepted"] == 1 and r.get_json()["rejected"] == 1
    assert store.host_events[0]["detail"]["path"] == "/etc/passwd"


def test_not_entitled_and_rate_limit_status(settings, store):
    from selenne_agents.ingest.gate import Gate
    from selenne_agents.ingest.http_app import create_app
    from selenne_agents.ingest.keys import Principal
    from selenne_agents.ingest.ratelimit import RateLimiter

    class V:
        def __init__(self, p):
            self.p = p

        def verify(self, key):
            return self.p

    c = create_app(settings, Gate(V(Principal("d", "p", False)), RateLimiter(10, 10)), store).test_client()
    assert c.post("/v1/traces", json={}, headers=AUTH).status_code == 402

    c = create_app(settings, Gate(V(Principal("d", "p", True)), RateLimiter(0.5, 1)), store).test_client()
    assert c.post("/v1/traces", json={}, headers=AUTH).status_code == 200
    r = c.post("/v1/traces", json={}, headers=AUTH)
    assert r.status_code == 429 and int(r.headers["Retry-After"]) >= 1


def test_ingest_raises_alerts(client, store):
    body = {"spans": [{"trace_id": TRACE, "span_id": SPAN, "name": "tool.read_file",
                       "start_time": "2026-09-29T10:00:00Z",
                       "attributes": {"gen_ai.tool.name": "read_file", "path": "/root/.ssh/id_rsa"}}]}
    assert client.post("/v1/events", json=body, headers=AUTH).status_code == 200
    [a] = store.alerts
    assert a["alert"].rule_id == "AG-101" and a["principal"].username == "diana"
    lines = b'{"kind":"open","host":"w1","pid":7,"ts":"2026-09-29T10:00:00Z","path":"/etc/shadow"}'
    client.post("/v1/host-events", data=lines, headers={**AUTH, "Content-Type": "application/x-ndjson"})
    assert [x["alert"].rule_id for x in store.alerts] == ["AG-101", "AG-201"]


def test_alerting_failure_never_loses_data(client, store):
    store.alerts_broken = True
    body = {"spans": [{"trace_id": TRACE, "span_id": SPAN, "name": "x", "start_time": "2026-09-29T10:00:00Z",
                       "attributes": {"p": "/etc/shadow"}}]}
    r = client.post("/v1/events", json=body, headers=AUTH)
    assert r.status_code == 200 and len(store.spans) == 1

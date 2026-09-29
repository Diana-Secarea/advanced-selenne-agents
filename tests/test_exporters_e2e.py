"""Real OpenTelemetry SDK exporters against our listeners — the proof that a
customer's stock OTel setup works with nothing but an endpoint and a header."""

import grpc
import pytest
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter as GrpcExporter
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter as HttpExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor

from conftest import DEV_KEY
from selenne_agents.ingest.grpc_server import build_server

HEADER = {"authorization": f"Bearer {DEV_KEY}"}


def _emit(exporter):
    provider = TracerProvider(resource=Resource.create({"service.name": "cve-agent"}))
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = provider.get_tracer("selenne.test")
    with tracer.start_as_current_span("agent.run") as run:
        run.set_attribute("gen_ai.conversation.id", "conv-1")
        with tracer.start_as_current_span("tool.read_file") as tool:
            tool.set_attribute("gen_ai.tool.name", "read_file")
    provider.shutdown()


def _assert_stored(store, source):
    by_name = {s["name"]: s for s in store.spans}
    assert set(by_name) == {"agent.run", "tool.read_file"}
    run, tool = by_name["agent.run"], by_name["tool.read_file"]
    assert tool["parent_span_id"] == run["span_id"] and tool["trace_id"] == run["trace_id"]
    assert run["parent_span_id"] is None
    assert run["service_name"] == "cve-agent"
    assert run["attributes"]["gen_ai.conversation.id"] == "conv-1"
    assert all(s["source"] == source for s in store.spans)


def test_otel_http_exporter(live_http, store):
    _emit(HttpExporter(endpoint=f"{live_http}/v1/traces", headers=HEADER))
    _assert_stored(store, "otlp-http")


def test_otel_http_exporter_bad_key_is_refused(live_http, store):
    _emit(HttpExporter(endpoint=f"{live_http}/v1/traces",
                       headers={"authorization": "Bearer sk_sel_wrong_0123456789abcdef"}))
    assert store.spans == []


@pytest.fixture
def live_grpc(settings, gate, store):
    server, port = build_server(settings, gate, store, address="127.0.0.1:0")
    server.start()
    yield f"127.0.0.1:{port}"
    server.stop(0)


def test_otel_grpc_exporter_gzip(live_grpc, store):
    _emit(GrpcExporter(endpoint=live_grpc, insecure=True, headers=HEADER,
                       compression=grpc.Compression.Gzip))
    _assert_stored(store, "otlp-grpc")


def test_grpc_status_codes(live_grpc, store):
    from opentelemetry.proto.collector.trace.v1 import trace_service_pb2, trace_service_pb2_grpc
    stub = trace_service_pb2_grpc.TraceServiceStub(grpc.insecure_channel(live_grpc))
    req = trace_service_pb2.ExportTraceServiceRequest()
    sp = req.resource_spans.add().scope_spans.add().spans.add()
    sp.trace_id, sp.span_id, sp.name = b"\x01" * 16, b"\x02" * 8, "s"
    sp.start_time_unix_nano = 1759140000000000000
    with pytest.raises(grpc.RpcError) as e:
        stub.Export(req)
    assert e.value.code() == grpc.StatusCode.UNAUTHENTICATED
    assert stub.Export(req, metadata=tuple(HEADER.items())).partial_success.rejected_spans == 0
    store.down = True
    with pytest.raises(grpc.RpcError) as e:
        stub.Export(req, metadata=tuple(HEADER.items()))
    assert e.value.code() == grpc.StatusCode.UNAVAILABLE

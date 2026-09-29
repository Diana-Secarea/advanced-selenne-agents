"""OTLP/gRPC front door (TraceService/Export). Same gate, normalizer and
store as the HTTP side; only the transport differs."""

import logging
from concurrent import futures

import grpc
from opentelemetry.proto.collector.trace.v1 import trace_service_pb2_grpc

from . import normalize, otlp
from .http_app import log_batch, record_batch
from .gate import NOT_ENTITLED, RATE_LIMITED, UNAUTHENTICATED, UNAVAILABLE, Denied
from .. import alerting
from ..store import StoreUnavailable

log = logging.getLogger("ingest.grpc")

_DENIED_CODE = {
    UNAUTHENTICATED: grpc.StatusCode.UNAUTHENTICATED,
    NOT_ENTITLED: grpc.StatusCode.PERMISSION_DENIED,
    RATE_LIMITED: grpc.StatusCode.RESOURCE_EXHAUSTED,
    UNAVAILABLE: grpc.StatusCode.UNAVAILABLE,
}


class TraceService(trace_service_pb2_grpc.TraceServiceServicer):
    def __init__(self, gate, store):
        self.gate = gate
        self.store = store

    def Export(self, request, context):
        metadata = dict(context.invocation_metadata())
        try:
            principal = self.gate.admit(metadata.get("authorization"))
        except Denied as d:
            if d.retry_after:
                context.set_trailing_metadata((("retry-after", str(d.retry_after)),))
            context.abort(_DENIED_CODE[d.reason], d.message)
        try:
            batch = normalize.otlp_spans(otlp.request_to_dict(request))
        except normalize.PayloadError as e:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, str(e))
        try:
            new = self.store.insert_spans(principal, batch.rows, "otlp-grpc")
        except StoreUnavailable as e:
            log.error("store unavailable: %s", e)
            context.abort(grpc.StatusCode.UNAVAILABLE, "storage temporarily unavailable")
        alerting.record(self.store, principal, alerting.for_spans(batch.rows))
        log_batch("otlp-grpc", principal, batch, new)
        record_batch(self.store, "otlp-grpc", principal, batch, new)
        return otlp.response(batch)


def build_server(settings, gate, store, address=None):
    """Returns (server, bound_port). Pass address='127.0.0.1:0' for an
    ephemeral port in tests."""
    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=settings.grpc_workers),
        options=[("grpc.max_receive_message_length", settings.max_decompressed_bytes)])
    trace_service_pb2_grpc.add_TraceServiceServicer_to_server(TraceService(gate, store), server)
    port = server.add_insecure_port(address or f"{settings.bind}:{settings.grpc_port}")
    return server, port

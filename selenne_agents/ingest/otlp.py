"""OTLP protobuf <-> the OTLP-JSON shaped dict normalize.otlp_spans() reads."""

from google.protobuf.json_format import MessageToDict
from google.protobuf.message import DecodeError
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
    ExportTraceServiceRequest,
    ExportTraceServiceResponse,
)

from .normalize import PayloadError, b64_to_hex


def request_to_dict(req):
    """MessageToDict already produces OTLP/JSON's camelCase field names, but
    writes bytes as base64 where OTLP/JSON uses hex for trace/span ids."""
    doc = MessageToDict(req)
    for rs in doc.get("resourceSpans", []):
        for ss in rs.get("scopeSpans", []):
            for sp in ss.get("spans", []):
                for f in ("traceId", "spanId", "parentSpanId"):
                    if f in sp:
                        sp[f] = b64_to_hex(sp[f])
                for link in sp.get("links", []):
                    for f in ("traceId", "spanId"):
                        if f in link:
                            link[f] = b64_to_hex(link[f])
    return doc


def decode_request(body):
    req = ExportTraceServiceRequest()
    try:
        req.ParseFromString(body)
    except DecodeError as e:
        raise PayloadError("body is not a valid ExportTraceServiceRequest protobuf") from e
    return request_to_dict(req)


def response(batch):
    resp = ExportTraceServiceResponse()
    if batch.rejected:
        resp.partial_success.rejected_spans = batch.rejected
        resp.partial_success.error_message = batch.error or ""
    return resp


def response_json(batch):
    if not batch.rejected:
        return {}
    # int64 fields are strings in OTLP/JSON
    return {"partialSuccess": {"rejectedSpans": str(batch.rejected),
                               "errorMessage": batch.error or ""}}

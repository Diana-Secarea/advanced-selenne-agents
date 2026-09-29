"""ingest.selenne.app — receives agent traces and sensor host events.

    POST /v1/traces        OTLP/HTTP, protobuf or JSON
    gRPC TraceService      OTLP/gRPC
    POST /v1/events        native JSON spans (no OpenTelemetry needed)
    POST /v1/host-events   sidecar NDJSON
"""

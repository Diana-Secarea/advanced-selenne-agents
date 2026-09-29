"""python -m selenne_agents.ingest — runs the gRPC and HTTP listeners.

TLS is terminated by nginx in front (ingest.selenne.app); both listeners bind
to INGEST_BIND, which should stay 127.0.0.1 outside a container.
"""

import logging
import signal
import sys
import time

import waitress

from ..config import Settings
from ..logging_setup import setup_logging
from ..store import PostgresStore, StoreUnavailable
from .gate import Gate
from .grpc_server import build_server
from .http_app import create_app
from .keys import build_verifier
from .ratelimit import RateLimiter

log = logging.getLogger("ingest")


def _wait_for_schema(store, attempts=30, delay=2.0):
    for i in range(1, attempts + 1):
        try:
            store.init_schema()
            return
        except StoreUnavailable as e:
            log.warning("database not ready (%d/%d): %s", i, attempts, e)
            time.sleep(delay)
    raise SystemExit("database never became ready — check SELENNE_AGENTS_DATABASE_URL")


def main():
    setup_logging("ingest")
    settings = Settings.from_env()
    store = PostgresStore(settings.database_url)
    _wait_for_schema(store)
    gate = Gate(build_verifier(settings), RateLimiter(settings.rate_per_sec, settings.rate_burst))

    grpc_server, grpc_port = build_server(settings, gate, store)
    grpc_server.start()
    log.info("OTLP/gRPC listening on %s:%d", settings.bind, grpc_port)

    def _stop(signum, frame):
        grpc_server.stop(5)
        store.close()
        sys.exit(0)
    signal.signal(signal.SIGTERM, _stop)

    log.info("HTTP listening on %s:%d", settings.bind, settings.http_port)
    waitress.serve(create_app(settings, gate, store), host=settings.bind,
                   port=settings.http_port, threads=settings.http_threads,
                   max_request_body_size=settings.max_body_bytes, ident="selenne-ingest")


if __name__ == "__main__":
    main()

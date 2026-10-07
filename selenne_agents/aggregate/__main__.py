"""python -m selenne_agents.aggregate — runs the aggregator loop.

    python -m selenne_agents.aggregate          the loop (the compose service)
    python -m selenne_agents.aggregate check    exit 1 when the last tick is
                                                older than AGG_MAX_LAG (default
                                                120 s): the container healthcheck

Ingest owns the schema; this waits for it, like the console reads it.
"""

import logging
import os
import signal
import sys
import threading

from ..config import Settings
from ..logging_setup import setup_logging
from ..store import PostgresStore, StoreUnavailable
from .worker import Aggregator, build_online_indexes

log = logging.getLogger("aggregate")


def _wait_for_schema(store, stop, attempts=60, delay=2.0):
    for i in range(1, attempts + 1):
        try:
            if store.schema_ready():
                return
            log.info("waiting for ingest to apply the schema (%d/%d)", i, attempts)
        except StoreUnavailable as e:
            log.warning("database not ready (%d/%d): %s", i, attempts, e)
        if stop.wait(delay):
            sys.exit(0)
    raise SystemExit("schema never appeared — is the ingest service running?")


def check(settings):
    max_lag = float(os.environ.get("AGG_MAX_LAG", 120))
    store = PostgresStore(settings.require_database(), maxconn=1)
    try:
        lag = store.aggregator_lag()
    except StoreUnavailable as e:
        print(f"database unavailable: {e}")
        return 1
    finally:
        store.close()
    if lag is None or lag > max_lag:
        print("aggregator has not ticked yet" if lag is None
              else f"aggregator lag {round(lag)}s (max {max_lag:g}s)")
        return 1
    return 0


def main(argv=sys.argv[1:]):
    settings = Settings.from_env()
    if argv[:1] == ["check"]:
        sys.exit(check(settings))
    setup_logging("aggregate")
    # the loop, the index builder and the odd check: a small pool is plenty
    store = PostgresStore(settings.require_database(), maxconn=4)
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda signum, frame: stop.set())

    _wait_for_schema(store, stop)
    # daemon: a SIGTERM mid-build leaves an INVALID index, which the next
    # start drops and rebuilds
    threading.Thread(target=build_online_indexes, args=(store, stop),
                     name="online-indexes", daemon=True).start()
    try:
        Aggregator(store, settings).run(stop)   # returns once stop is set; a tick in flight finishes
    finally:
        store.close()
    log.info("aggregator stopped")


if __name__ == "__main__":
    main()

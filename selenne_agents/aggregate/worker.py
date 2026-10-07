"""The aggregator loop.

Each step runs one PostgresStore.aggregate_tick (one transaction, under an
advisory lock, so a second replica just skips), then one reconcile_tick —
host activity no span explains becomes AG-301/302/303 — and the periodic
check (verify_recent) when it is due. A full page means a backlog: the next step
runs at once instead of after AGG_INTERVAL. A database outage backs off
instead of crashing — every tick is idempotent, so nothing is lost by
waiting, and the next one picks up where the watermarks stopped.
"""

import logging
import time

from ..alerting import for_unexplained
from ..store import StoreUnavailable

log = logging.getLogger("aggregate")

MAX_BACKOFF = 60.0


class Aggregator:
    def __init__(self, store, settings, clock=time.monotonic):
        self.store = store
        self.settings = settings
        self.clock = clock
        # first check one interval after start: right after a restart the
        # ticks are still draining the backlog by id anyway
        self.next_verify = clock() + settings.agg_verify_interval
        self.failures = 0

    def step(self):
        """One pass. Returns how many seconds to wait before the next."""
        try:
            if self.clock() >= self.next_verify:
                self._verify()
            stats = self.store.aggregate_tick(batch=self.settings.agg_batch,
                                              overlap_s=self.settings.agg_overlap)
            recon = self.store.reconcile_tick(for_unexplained,
                                              settle_s=self.settings.agg_reconcile_settle)
        except StoreUnavailable as e:
            return self._failed("database unavailable: %s", e)
        except Exception:
            # a bug, not an outage: keep the process up (the log says why) and
            # retry slowly rather than restart-looping the container
            return self._failed("aggregator step failed", exc_info=True)
        self.failures = 0
        if recon is not None and recon.alerts:
            log.info("reconcile: %d host events checked, %d unexplained, %d new deviations",
                     recon.checked, recon.unexplained, recon.alerts,
                     extra={"fields": {"event": "reconcile", "checked": recon.checked,
                                       "unexplained": recon.unexplained, "alerts": recon.alerts}})
        if stats is None:
            log.debug("tick skipped: another aggregator holds the lock")
            return self.settings.agg_interval
        # rows re-read by the catch-up scan alone are routine: only new ones log
        if stats.new:
            log.info("tick: %d spans, %d host events, %d alerts -> %d sessions, %d processes "
                     "in %.2fs%s", stats.spans, stats.host_events, stats.alerts, stats.sessions,
                     stats.processes, stats.seconds, " (more)" if stats.more else "",
                     extra={"fields": {"event": "tick", "spans": stats.spans,
                                       "host_events": stats.host_events, "alerts": stats.alerts,
                                       "sessions": stats.sessions, "processes": stats.processes,
                                       "more": stats.more, "new": stats.new, "seconds": round(stats.seconds, 3)}})
        more = stats.more or (recon is not None and recon.more)
        return 0.0 if more else self.settings.agg_interval

    def run(self, stop):
        """Step until the threading.Event `stop` is set (SIGTERM)."""
        log.info("aggregator running: every %gs, batch %d, overlap %gs, check every %gs over %gs",
                 self.settings.agg_interval, self.settings.agg_batch, self.settings.agg_overlap,
                 self.settings.agg_verify_interval, self.settings.agg_verify_window)
        while not stop.is_set():
            stop.wait(self.step())

    def _verify(self):
        check = self.store.verify_recent(window_s=self.settings.agg_verify_window)
        if check is None:
            return                  # another aggregator's tick holds the lock: next step
        self.next_verify = self.clock() + self.settings.agg_verify_interval
        # verify_recent already warns when it repaired anything
        log.info("check: %d sessions rebuilt, %d repaired in %.2fs",
                 check.sessions, check.repaired, check.seconds,
                 extra={"fields": {"event": "check", "sessions": check.sessions,
                                   "repaired": check.repaired,
                                   "seconds": round(check.seconds, 3)}})

    def _failed(self, msg, *args, exc_info=False):
        self.failures += 1
        wait = min(self.settings.agg_interval * 2 ** (self.failures - 1), MAX_BACKOFF)
        log.warning(msg + " (retry in %gs)", *args, wait, exc_info=exc_info)
        return wait


def build_online_indexes(store, stop, retry=30.0):
    """Build store.ONLINE_INDEXES (CREATE INDEX CONCURRENTLY). Meant for a
    background thread next to the loop: on a big table this takes minutes,
    and ticks keep running meanwhile — only their catch-up reads are slower.
    Retries while the database is down or another process holds the build
    lock (it may die halfway, leaving an index for us to repair)."""
    while not stop.is_set():
        try:
            built = store.ensure_online_indexes()
        except StoreUnavailable as e:
            log.warning("online indexes: database unavailable (%s), retry in %gs", e, retry)
        except Exception:
            log.exception("online indexes: build failed; ticks run without them")
            return
        else:
            if built is not None:
                if built:
                    log.info("online indexes built: %s", ", ".join(built))
                return
            log.info("online indexes: another process is building them, retry in %gs", retry)
        stop.wait(retry)

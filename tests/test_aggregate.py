"""The aggregator loop (selenne_agents.aggregate). The SQL is covered by
test_aggregate_store.py; here a fake store drives the loop's decisions, and
one test runs the real loop against Postgres."""

import logging
import threading
import time

import pytest

from selenne_agents.aggregate import Aggregator, build_online_indexes
from selenne_agents.aggregate import __main__ as entry
from selenne_agents.config import Settings
from selenne_agents.store import StoreUnavailable, TickStats, VerifyStats

SETTINGS = Settings(agg_interval=5, agg_batch=100, agg_verify_interval=3600,
                    agg_verify_window=7200)


def _stats(spans=0, more=False, new=None):
    return TickStats(spans, 0, 0, 1 if spans else 0, 0, more, spans if new is None else new, 0.01)


class FakeStore:
    def __init__(self, ticks=(), checks=()):
        self.ticks = list(ticks)        # TickStats | None | Exception, one per tick
        self.checks = list(checks)
        self.tick_args = []
        self.verify_args = []

    @staticmethod
    def _next(queue, default):
        item = queue.pop(0) if queue else default
        if isinstance(item, Exception):
            raise item
        return item

    def aggregate_tick(self, batch, overlap_s):
        self.tick_args.append((batch, overlap_s))
        return self._next(self.ticks, _stats())

    def verify_recent(self, window_s):
        self.verify_args.append(window_s)
        return self._next(self.checks, VerifyStats(3, 0, 0.1))


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def test_waits_the_interval_and_passes_settings():
    store = FakeStore([_stats(spans=4)])
    assert Aggregator(store, SETTINGS).step() == 5
    assert store.tick_args == [(100, SETTINGS.agg_overlap)]


def test_full_page_ticks_again_at_once():
    agg = Aggregator(FakeStore([_stats(100, more=True), _stats(100, more=True), _stats(7)]),
                     SETTINGS)
    assert [agg.step() for _ in range(3)] == [0, 0, 5]


def test_skipped_tick_waits_normally():
    assert Aggregator(FakeStore([None]), SETTINGS).step() == 5


def test_outage_backs_off_and_recovers(caplog):
    down = StoreUnavailable("connection refused")
    agg = Aggregator(FakeStore([down] * 6 + [_stats()]), SETTINGS)
    assert [agg.step() for _ in range(7)] == [5, 10, 20, 40, 60, 60, 5]
    assert "connection refused" in caplog.text


def test_a_bug_is_logged_not_fatal(caplog):
    agg = Aggregator(FakeStore([RuntimeError("bad sql"), _stats()]), SETTINGS)
    assert agg.step() == 5
    assert "bad sql" in caplog.text            # with the traceback
    assert agg.step() == 5 and agg.failures == 0


def test_check_runs_once_per_interval():
    clock = Clock()
    store = FakeStore()
    agg = Aggregator(store, SETTINGS, clock=clock)
    agg.step()
    assert store.verify_args == []             # not at start
    clock.now += 3600
    agg.step()
    agg.step()
    assert store.verify_args == [7200]
    clock.now += 3599
    agg.step()
    assert len(store.verify_args) == 1
    clock.now += 1
    agg.step()
    assert len(store.verify_args) == 2
    assert len(store.tick_args) == 5           # a check never replaces the tick


def test_check_skipped_by_the_lock_is_retried_next_step():
    clock = Clock()
    store = FakeStore(checks=[None])
    agg = Aggregator(store, SETTINGS, clock=clock)
    clock.now += 3600
    agg.step()
    agg.step()
    assert len(store.verify_args) == 2
    agg.step()
    assert len(store.verify_args) == 2


def test_tick_logs_only_when_new_rows_arrived(caplog):
    caplog.set_level(logging.INFO, logger="aggregate")
    agg = Aggregator(FakeStore([_stats(), _stats(spans=2, new=0), _stats(spans=3)]), SETTINGS)
    agg.step()
    agg.step()                                  # catch-up re-reads only
    assert not [r for r in caplog.records if getattr(r, "fields", {}).get("event") == "tick"]
    agg.step()
    [rec] = [r for r in caplog.records if getattr(r, "fields", {}).get("event") == "tick"]
    assert rec.fields["spans"] == 3 and rec.fields["sessions"] == 1


def test_run_stops_on_the_event():
    stop = threading.Event()
    store = FakeStore()
    t = threading.Thread(target=Aggregator(store, Settings(agg_interval=0.01)).run, args=(stop,))
    t.start()
    time.sleep(0.1)
    stop.set()
    t.join(2)
    assert not t.is_alive() and len(store.tick_args) > 1


class IndexStore:
    def __init__(self, results):
        self.results = list(results)
        self.calls = 0

    def ensure_online_indexes(self):
        self.calls += 1
        r = self.results.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


def test_index_builder_retries_until_it_owns_the_build():
    store = IndexStore([StoreUnavailable("down"), None, ["spans_received"]])
    build_online_indexes(store, threading.Event(), retry=0)
    assert store.calls == 3


def test_index_builder_gives_up_on_a_bug_and_stops_on_the_event(caplog):
    store = IndexStore([RuntimeError("permission denied")])
    build_online_indexes(store, threading.Event(), retry=0)
    assert store.calls == 1 and "permission denied" in caplog.text
    stop = threading.Event()
    stop.set()
    build_online_indexes(IndexStore([]), stop)          # never calls the store


def test_check_command(monkeypatch, capsys):
    lags = iter([3.0, 500.0, None])

    class LagStore:
        def __init__(self, dsn, maxconn):
            pass

        def aggregator_lag(self):
            return next(lags)

        def close(self):
            pass

    monkeypatch.setattr(entry, "PostgresStore", LagStore)
    settings = Settings(database_url="postgresql://x")
    assert entry.check(settings) == 0
    assert entry.check(settings) == 1 and "500s" in capsys.readouterr().out
    assert entry.check(settings) == 1          # never ticked


# --- the real loop against Postgres ------------------------------------------

from test_aggregate_store import T1, T2, _put, _sessions, pg  # noqa: E402,F401
from test_postgres import DSN  # noqa: E402


@pytest.mark.skipif(not DSN, reason="SELENNE_AGENTS_TEST_DSN not set")
def test_loop_aggregates_what_ingest_writes(pg):  # noqa: F811
    stop = threading.Event()
    agg = Aggregator(pg, Settings(agg_interval=0.05, agg_batch=1))
    t = threading.Thread(target=agg.run, args=(stop,))
    t.start()
    try:
        _put(pg, *[{"trace_id": tid, "span_id": f"{n:016x}", "name": "s",
                    "start_time_unix_nano": 1759140000000000000 + n} for tid in (T1, T2)
                   for n in (1, 2)])
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            got = _sessions(pg)
            if got.get(T1, {}).get("spans") == 2 and got.get(T2, {}).get("spans") == 2:
                break
            time.sleep(0.05)
        else:
            pytest.fail(f"loop never caught up: {got}")
        assert 0 <= pg.aggregator_lag() < 60
    finally:
        stop.set()
        t.join(5)
    assert not t.is_alive()
    assert agg.failures == 0

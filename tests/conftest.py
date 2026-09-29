import threading

import pytest
from werkzeug.serving import make_server

from selenne_agents.config import Settings
from selenne_agents.ingest.gate import Gate
from selenne_agents.ingest.http_app import create_app
from selenne_agents.ingest.keys import CachingVerifier, StaticVerifier
from selenne_agents.ingest.ratelimit import RateLimiter
from selenne_agents.store import StoreUnavailable

DEV_KEY = "sk_sel_devkey_0123456789abcdef"
AUTH = {"Authorization": f"Bearer {DEV_KEY}"}


class FakeStore:
    def __init__(self):
        self.spans = []
        self.host_events = []
        self.alerts = []
        self.down = False
        self.alerts_broken = False

    def _check(self):
        if self.down:
            raise StoreUnavailable("fake outage")

    def insert_spans(self, principal, rows, source):
        self._check()
        seen = {(s["principal"], s["trace_id"], s["span_id"]) for s in self.spans}
        new = [dict(r, principal=principal, source=source) for r in rows
               if (principal, r["trace_id"], r["span_id"]) not in seen]
        self.spans.extend(new)
        return len(new)

    def insert_host_events(self, principal, rows):
        self._check()
        self.host_events.extend(dict(r, principal=principal) for r in rows)
        return len(rows)

    def insert_alerts(self, principal, found):
        if self.alerts_broken:
            raise RuntimeError("alerts table missing")
        self.alerts.extend(dict(f, principal=principal) for f in found)
        return len(found)

    def record_batch(self, principal, source, accepted, new, rejected, error=None):
        self.batches = getattr(self, "batches", []) + [(principal.username, source, accepted, new, rejected)]

    def ping(self):
        return not self.down


@pytest.fixture
def settings():
    return Settings(dev_keys={DEV_KEY: ("diana", "cve-agent")}, max_body_bytes=64 * 1024,
                    max_decompressed_bytes=256 * 1024, rate_per_sec=1000, rate_burst=1000)


@pytest.fixture
def store():
    return FakeStore()


@pytest.fixture
def gate(settings):
    verifier = CachingVerifier(StaticVerifier(settings.dev_keys))
    return Gate(verifier, RateLimiter(settings.rate_per_sec, settings.rate_burst))


@pytest.fixture
def client(settings, gate, store):
    return create_app(settings, gate, store).test_client()


@pytest.fixture
def live_http(settings, gate, store):
    """The real app on an ephemeral port, for real OTel exporters."""
    server = make_server("127.0.0.1", 0, create_app(settings, gate, store), threaded=True)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()

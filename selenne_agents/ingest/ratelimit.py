"""Per-key token bucket. In-process: one ingest process per box, so no shared
store is needed. nginx adds a coarse per-IP limit in front of this."""

import threading
import time


class RateLimiter:
    MAX_BUCKETS = 50_000

    def __init__(self, rate, burst, clock=time.monotonic):
        self.rate = float(rate)
        self.burst = float(burst)
        self.clock = clock
        self._buckets = {}   # key digest -> [tokens, last_refill]
        self._lock = threading.Lock()

    def take(self, bucket_id):
        """Spend one token. Returns 0 when allowed, otherwise the seconds
        until a token is available (for Retry-After)."""
        now = self.clock()
        with self._lock:
            b = self._buckets.get(bucket_id)
            if b is None:
                if len(self._buckets) >= self.MAX_BUCKETS:
                    self._prune(now)
                b = self._buckets[bucket_id] = [self.burst, now]
            b[0] = min(self.burst, b[0] + (now - b[1]) * self.rate)
            b[1] = now
            if b[0] >= 1.0:
                b[0] -= 1.0
                return 0.0
            return (1.0 - b[0]) / self.rate if self.rate > 0 else 60.0

    def _prune(self, now):
        # A bucket that would be full again carries no state worth keeping.
        full_after = self.burst / self.rate if self.rate > 0 else float("inf")
        self._buckets = {k: v for k, v in self._buckets.items() if now - v[1] < full_after}

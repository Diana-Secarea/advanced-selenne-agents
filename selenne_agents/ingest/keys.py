"""Ingestion API keys: parsing, verification against Selenne, and caching.

Selenne owns the keys (issued on its account page). This service never stores
them: every request's key is verified by POSTing it to Selenne's internal
endpoint, and the answer is cached for key_cache_ttl seconds, so a revoked
key stops working within that window.

Contract — POST {SELENNE_VERIFY_URL}
    headers  X-Selenne-Internal: <SELENNE_INTERNAL_SECRET>
    body     {"key": "sk_sel_…"}
    200      {"valid": true, "username": "...", "project": "...",
              "entitled": true, "key_id": "..."}   or   {"valid": false}
Anything else (timeout, 5xx, garbage) means "cannot tell", which the gate
turns into a retryable 503 — never into an accept.
"""

import hashlib
import hmac
import logging
import re
import threading
import time
from dataclasses import dataclass

import requests

log = logging.getLogger("ingest.keys")

KEY_PREFIX = "sk_sel_"
# Checked before any network call, so junk tokens never reach Selenne.
_KEY_RE = re.compile(r"^sk_sel_[A-Za-z0-9_\-]{16,128}$")


@dataclass(frozen=True)
class Principal:
    username: str
    project: str
    entitled: bool
    key_id: str = None


class VerifierUnavailable(Exception):
    """Selenne could not give an answer — retryable, not a rejection."""


def digest(key):
    return hashlib.sha256(key.encode()).hexdigest()


def redact(key):
    """Safe form for logs: the prefix plus a few characters."""
    return (key or "")[:12] + "…"


def parse_bearer(header):
    """'Bearer sk_sel_…' -> key, or None when absent or malformed."""
    if not header:
        return None
    scheme, _, token = header.strip().partition(" ")
    token = token.strip()
    if scheme.lower() != "bearer" or not _KEY_RE.match(token):
        return None
    return token


class RemoteVerifier:
    def __init__(self, url, secret, session=None, timeout=3.0):
        if not url or not secret:
            raise ValueError("RemoteVerifier needs SELENNE_VERIFY_URL and SELENNE_INTERNAL_SECRET")
        self.url = url
        self.secret = secret
        self.session = session or requests.Session()
        self.timeout = timeout

    def verify(self, key):
        try:
            r = self.session.post(self.url, json={"key": key},
                                  headers={"X-Selenne-Internal": self.secret},
                                  timeout=self.timeout)
        except requests.RequestException as e:
            raise VerifierUnavailable(f"verify request failed: {e.__class__.__name__}") from e
        if r.status_code != 200:
            raise VerifierUnavailable(f"verify returned HTTP {r.status_code}")
        try:
            body = r.json()
        except ValueError as e:
            raise VerifierUnavailable("verify returned non-JSON") from e
        if not isinstance(body, dict):
            raise VerifierUnavailable("verify returned malformed body")
        if not body.get("valid"):
            return None
        username = body.get("username")
        if not username:
            raise VerifierUnavailable("verify said valid but named no user")
        return Principal(username=str(username),
                         project=str(body.get("project") or "default"),
                         entitled=bool(body.get("entitled")),
                         key_id=str(body["key_id"]) if body.get("key_id") else None)


class StaticVerifier:
    """Fixed dev keys from SELENNE_AGENTS_DEV_KEYS. Always entitled."""

    def __init__(self, keys):
        self._keys = {digest(k): Principal(u, p, True, key_id="dev")
                      for k, (u, p) in keys.items()}

    def verify(self, key):
        d = digest(key)
        for known, principal in self._keys.items():
            if hmac.compare_digest(known, d):
                return principal
        return None


class ChainVerifier:
    """First verifier that recognises the key wins; later ones are only asked
    when earlier ones say 'unknown'."""

    def __init__(self, verifiers):
        self.verifiers = list(verifiers)

    def verify(self, key):
        for v in self.verifiers:
            principal = v.verify(key)
            if principal:
                return principal
        return None


class CachingVerifier:
    """Caches answers by key digest. Positive answers live key_cache_ttl,
    negative ones a shorter key_negative_ttl. Outages are not cached and are
    not papered over with stale entries: an expired entry is re-asked, and if
    Selenne is down the request fails retryably."""

    MAX_ENTRIES = 50_000

    def __init__(self, inner, ttl=60.0, negative_ttl=10.0, clock=time.monotonic):
        self.inner = inner
        self.ttl = ttl
        self.negative_ttl = negative_ttl
        self.clock = clock
        self._cache = {}
        self._lock = threading.Lock()

    def verify(self, key):
        d = digest(key)
        now = self.clock()
        with self._lock:
            hit = self._cache.get(d)
            if hit and hit[0] > now:
                return hit[1]
        principal = self.inner.verify(key)   # may raise VerifierUnavailable
        ttl = self.ttl if principal else self.negative_ttl
        with self._lock:
            if len(self._cache) >= self.MAX_ENTRIES:
                self._cache = {k: v for k, v in self._cache.items() if v[0] > now}
                if len(self._cache) >= self.MAX_ENTRIES:
                    self._cache.clear()
            self._cache[d] = (now + ttl, principal)
        return principal


def build_verifier(settings):
    chain = []
    if settings.dev_keys:
        log.warning("dev ingestion keys enabled (%d) — do not use in production",
                    len(settings.dev_keys))
        chain.append(StaticVerifier(settings.dev_keys))
    if settings.selenne_verify_url:
        chain.append(RemoteVerifier(settings.selenne_verify_url, settings.selenne_internal_secret))
    if not chain:
        raise ValueError("no key verifier configured: set SELENNE_VERIFY_URL "
                         "(+ SELENNE_INTERNAL_SECRET) or SELENNE_AGENTS_DEV_KEYS")
    return CachingVerifier(ChainVerifier(chain), settings.key_cache_ttl, settings.key_negative_ttl)

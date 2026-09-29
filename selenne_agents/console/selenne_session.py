"""Who is signed in? Asked of Selenne, never decided here.

The browser's `session_token` cookie (HttpOnly, host-only, set by Selenne's
login) reaches this container because the console is served on the same
origin. We forward just that cookie to Selenne's /api/auth/me and cache the
answer for a short TTL, so logging out on the SIEM side signs the user out of
this console within that window too.

Probes carry the shared internal secret so Selenne can recognise them as
Agents traffic and keep them out of its Wazuh-collected access log (a
signed-out visitor's probe is a 401, and a stream of those must not look like
an attack on the SIEM).
"""

import hashlib
import logging
import threading
import time

import requests

log = logging.getLogger("console.session")

COOKIE = "session_token"


class SessionUnavailable(Exception):
    """Selenne could not answer — show an error, never guess a user."""


class SelenneSessions:
    MAX_ENTRIES = 20_000

    def __init__(self, me_url, session=None, timeout=3.0, ttl=30.0,
                 negative_ttl=5.0, clock=time.monotonic, internal_secret=""):
        self.me_url = me_url
        self.headers = {"X-Selenne-Internal": internal_secret} if internal_secret else {}
        self.session = session or requests.Session()
        self.timeout = timeout
        self.ttl = ttl
        self.negative_ttl = negative_ttl
        self.clock = clock
        self._cache = {}
        self._lock = threading.Lock()

    def user_for(self, token):
        """{'username', 'role', 'agents', ...} or None when not signed in."""
        if not token or len(token) > 128:
            return None
        key = hashlib.sha256(token.encode()).hexdigest()
        now = self.clock()
        with self._lock:
            hit = self._cache.get(key)
            if hit and hit[0] > now:
                return hit[1]
        user = self._ask(token)
        with self._lock:
            if len(self._cache) >= self.MAX_ENTRIES:
                self._cache = {k: v for k, v in self._cache.items() if v[0] > now}
                if len(self._cache) >= self.MAX_ENTRIES:
                    self._cache.clear()
            self._cache[key] = (now + (self.ttl if user else self.negative_ttl), user)
        return user

    def _ask(self, token):
        try:
            r = self.session.get(self.me_url, cookies={COOKIE: token},
                                 headers=self.headers, timeout=self.timeout)
        except requests.RequestException as e:
            raise SessionUnavailable(f"auth probe failed: {e.__class__.__name__}") from e
        if r.status_code == 401:
            return None
        if r.status_code != 200:
            raise SessionUnavailable(f"auth probe returned HTTP {r.status_code}")
        try:
            body = r.json()
        except ValueError as e:
            raise SessionUnavailable("auth probe returned non-JSON") from e
        user = body.get("user") if isinstance(body, dict) else None
        if not isinstance(user, dict) or not user.get("username"):
            return None
        return {"username": str(user["username"]),
                "role": str(user.get("role") or "analyst"),
                "agents": bool(user.get("agents")),
                "email_verified": bool(user.get("email_verified"))}

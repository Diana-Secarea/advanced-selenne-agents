import pytest
import requests

from selenne_agents.config import parse_dev_keys
from selenne_agents.ingest import keys
from selenne_agents.ingest.gate import Denied, Gate
from selenne_agents.ingest.ratelimit import RateLimiter

KEY = "sk_sel_live_abcdefghijklmnop"


class FakeResponse:
    def __init__(self, status, body):
        self.status_code = status
        self._body = body

    def json(self):
        if isinstance(self._body, Exception):
            raise self._body
        return self._body


class FakeSession:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def post(self, url, json, headers, timeout):
        self.calls.append((url, json, headers))
        r = self.responses.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def remote(*responses):
    session = FakeSession(*responses)
    return keys.RemoteVerifier("http://selenne/internal/keys/verify", "s3cret", session=session), session


def test_parse_bearer():
    assert keys.parse_bearer(f"Bearer {KEY}") == KEY
    assert keys.parse_bearer(f"bearer   {KEY} ") == KEY
    for bad in (None, "", KEY, f"Basic {KEY}", "Bearer sk_sel_short", "Bearer abc_" + "x" * 20,
                "Bearer sk_sel_" + "x" * 20 + "!"):
        assert keys.parse_bearer(bad) is None


def test_remote_verifier_contract():
    v, session = remote(FakeResponse(200, {"valid": True, "username": "diana", "project": "p1",
                                           "entitled": True, "key_id": "k9"}))
    p = v.verify(KEY)
    assert p == keys.Principal("diana", "p1", True, "k9")
    url, body, headers = session.calls[0]
    assert body == {"key": KEY} and headers == {"X-Selenne-Internal": "s3cret"}


@pytest.mark.parametrize("response", [
    requests.ConnectionError("down"),
    FakeResponse(500, {}),
    FakeResponse(200, ValueError("not json")),
    FakeResponse(200, ["list"]),
    FakeResponse(200, {"valid": True}),          # valid but no user — refuse to guess
])
def test_remote_verifier_unavailable(response):
    v, _ = remote(response)
    with pytest.raises(keys.VerifierUnavailable):
        v.verify(KEY)


def test_remote_verifier_invalid_key():
    v, _ = remote(FakeResponse(200, {"valid": False}))
    assert v.verify(KEY) is None


def test_cache_expires_so_revocation_takes_effect():
    clock = Clock()
    v, session = remote(FakeResponse(200, {"valid": True, "username": "d", "entitled": True}),
                        FakeResponse(200, {"valid": False}))
    cached = keys.CachingVerifier(v, ttl=60, negative_ttl=10, clock=clock)
    assert cached.verify(KEY).username == "d"
    clock.t += 59
    assert cached.verify(KEY).username == "d"
    assert len(session.calls) == 1               # served from cache
    clock.t += 2
    assert cached.verify(KEY) is None            # revoked upstream, seen after TTL
    assert len(session.calls) == 2


def test_outage_is_not_cached_and_not_served_stale():
    clock = Clock()
    v, session = remote(FakeResponse(200, {"valid": True, "username": "d", "entitled": True}),
                        requests.Timeout("slow"),
                        FakeResponse(200, {"valid": True, "username": "d", "entitled": True}))
    cached = keys.CachingVerifier(v, ttl=60, clock=clock)
    cached.verify(KEY)
    clock.t += 61
    with pytest.raises(keys.VerifierUnavailable):
        cached.verify(KEY)
    assert cached.verify(KEY).username == "d"


def test_chain_prefers_static_then_remote():
    v, session = remote(FakeResponse(200, {"valid": False}))
    chain = keys.ChainVerifier([keys.StaticVerifier({"sk_sel_devkey_0123456789abcdef": ("dev", "p")}), v])
    assert chain.verify("sk_sel_devkey_0123456789abcdef").username == "dev"
    assert session.calls == []
    assert chain.verify(KEY) is None and len(session.calls) == 1


def test_parse_dev_keys():
    assert parse_dev_keys(" sk_a=diana:proj , sk_b=bob ") == {"sk_a": ("diana", "proj"),
                                                             "sk_b": ("bob", "default")}
    with pytest.raises(ValueError):
        parse_dev_keys("sk_a=")


def _gate(principal=None, error=None, rate=100, burst=100, clock=None):
    class V:
        def verify(self, key):
            if error:
                raise error
            return principal
    return Gate(V(), RateLimiter(rate, burst, **({"clock": clock} if clock else {})))


def test_gate_outcomes():
    ok = keys.Principal("d", "p", True)
    assert _gate(ok).admit(f"Bearer {KEY}") == ok
    cases = [
        (_gate(ok), None, "unauthenticated"),
        (_gate(None), f"Bearer {KEY}", "unauthenticated"),
        (_gate(keys.Principal("d", "p", False)), f"Bearer {KEY}", "not_entitled"),
        (_gate(error=keys.VerifierUnavailable("x")), f"Bearer {KEY}", "unavailable"),
    ]
    for gate, header, reason in cases:
        with pytest.raises(Denied) as e:
            gate.admit(header)
        assert e.value.reason == reason


def test_rate_limit_per_key_with_retry_after():
    clock = Clock()
    gate = _gate(keys.Principal("d", "p", True), rate=1, burst=2, clock=clock)
    gate.admit(f"Bearer {KEY}")
    gate.admit(f"Bearer {KEY}")
    with pytest.raises(Denied) as e:
        gate.admit(f"Bearer {KEY}")
    assert e.value.reason == "rate_limited" and e.value.retry_after == 1
    gate.admit(f"Bearer sk_sel_other_abcdefghijklmnop")   # other keys unaffected
    clock.t += 1
    gate.admit(f"Bearer {KEY}")

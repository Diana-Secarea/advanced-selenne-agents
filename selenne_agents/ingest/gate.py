"""The admission check shared by the HTTP and gRPC front doors:
bearer key -> verified principal -> entitlement -> rate limit."""

import logging
import math

from . import keys as _keys

log = logging.getLogger("ingest.gate")

UNAUTHENTICATED = "unauthenticated"
NOT_ENTITLED = "not_entitled"
UNAVAILABLE = "unavailable"
RATE_LIMITED = "rate_limited"


class Denied(Exception):
    def __init__(self, reason, message, retry_after=None):
        super().__init__(message)
        self.reason = reason
        self.message = message
        self.retry_after = retry_after


class Gate:
    def __init__(self, verifier, limiter):
        self.verifier = verifier
        self.limiter = limiter

    def admit(self, authorization):
        key = _keys.parse_bearer(authorization)
        if not key:
            raise Denied(UNAUTHENTICATED, "missing or malformed ingestion key "
                                          "(expected 'Authorization: Bearer sk_sel_…')")
        try:
            principal = self.verifier.verify(key)
        except _keys.VerifierUnavailable as e:
            log.warning("key verification unavailable for %s: %s", _keys.redact(key), e)
            raise Denied(UNAVAILABLE, "key verification temporarily unavailable", retry_after=5)
        if not principal:
            raise Denied(UNAUTHENTICATED, "unknown or revoked ingestion key")
        if not principal.entitled:
            raise Denied(NOT_ENTITLED, "Selenne Agents add-on is not active on this account")
        wait = self.limiter.take(_keys.digest(key))
        if wait > 0:
            raise Denied(RATE_LIMITED, "rate limit exceeded for this key",
                         retry_after=max(1, math.ceil(wait)))
        return principal

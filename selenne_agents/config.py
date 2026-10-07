"""Runtime settings, read once from the environment (see .env.example)."""

import os
from dataclasses import dataclass, field

MIB = 1024 * 1024


def _int(name, default):
    return int(os.environ.get(name, default))


def _float(name, default):
    return float(os.environ.get(name, default))


def _bool(name, default="0"):
    return os.environ.get(name, default).strip().lower() in ("1", "true", "yes", "on")


def parse_dev_keys(raw):
    """SELENNE_AGENTS_DEV_KEYS="sk_sel_x=user:project,sk_sel_y=user2:proj"
    -> {key: (username, project)}. For local runs and the skeleton demo only."""
    keys = {}
    for item in (raw or "").split(","):
        item = item.strip()
        if not item:
            continue
        key, _, owner = item.partition("=")
        username, _, project = owner.partition(":")
        if not key or not username:
            raise ValueError(f"bad SELENNE_AGENTS_DEV_KEYS entry: {item.split('=')[0][:12]}…")
        keys[key.strip()] = (username.strip(), (project or "default").strip())
    return keys


@dataclass(frozen=True)
class Settings:
    # No built-in default: database credentials only ever come from the environment.
    database_url: str = ""
    # Selenne's internal key-verification endpoint and its shared secret.
    selenne_verify_url: str = ""
    selenne_internal_secret: str = ""
    # Selenne's session probe; the console forwards the browser's session
    # cookie here to learn who is signed in (and whether Agents is enabled).
    selenne_me_url: str = "http://127.0.0.1:5000/api/auth/me"
    session_cache_ttl: float = 30.0
    dev_keys: dict = field(default_factory=dict)

    key_cache_ttl: float = 60.0       # a revoked key stops working within this
    key_negative_ttl: float = 10.0    # unknown keys are re-asked this often
    rate_per_sec: float = 20.0        # requests per second, per key
    rate_burst: int = 40

    # Ingest transactions are cut off after this (Postgres transaction_timeout;
    # the client gets a retryable 503). The aggregator re-reads rows committed
    # up to agg_overlap seconds late, so agg_overlap must stay above it — that
    # pair is what guarantees no span is ever skipped.
    ingest_txn_timeout: float = 30.0
    agg_overlap: float = 60.0

    max_body_bytes: int = 5 * MIB           # on the wire (compressed)
    max_decompressed_bytes: int = 20 * MIB  # after gzip — zip-bomb guard

    bind: str = "127.0.0.1"
    http_port: int = 4318
    grpc_port: int = 4317
    console_port: int = 4319
    http_threads: int = 8
    grpc_workers: int = 8
    trust_proxy: bool = False

    def __post_init__(self):
        if self.agg_overlap <= self.ingest_txn_timeout:
            raise ValueError(f"AGG_OVERLAP ({self.agg_overlap:g}s) must be greater than "
                             f"INGEST_TXN_TIMEOUT ({self.ingest_txn_timeout:g}s), or late "
                             "ingest commits can be skipped by the aggregator")

    def require_database(self):
        if not self.database_url:
            raise SystemExit("SELENNE_AGENTS_DATABASE_URL is not set — docker compose "
                             "builds it from .env; see .env.example")
        return self.database_url

    @classmethod
    def from_env(cls):
        return cls(
            database_url=os.environ.get("SELENNE_AGENTS_DATABASE_URL", "").strip(),
            selenne_verify_url=os.environ.get("SELENNE_VERIFY_URL", "").strip(),
            selenne_internal_secret=os.environ.get("SELENNE_INTERNAL_SECRET", "").strip(),
            selenne_me_url=os.environ.get("SELENNE_ME_URL", cls.selenne_me_url).strip(),
            session_cache_ttl=_float("CONSOLE_SESSION_CACHE_TTL", cls.session_cache_ttl),
            dev_keys=parse_dev_keys(os.environ.get("SELENNE_AGENTS_DEV_KEYS", "")),
            key_cache_ttl=_float("INGEST_KEY_CACHE_TTL", cls.key_cache_ttl),
            key_negative_ttl=_float("INGEST_KEY_NEGATIVE_TTL", cls.key_negative_ttl),
            rate_per_sec=_float("INGEST_RATE_PER_SEC", cls.rate_per_sec),
            rate_burst=_int("INGEST_RATE_BURST", cls.rate_burst),
            ingest_txn_timeout=_float("INGEST_TXN_TIMEOUT", cls.ingest_txn_timeout),
            agg_overlap=_float("AGG_OVERLAP", cls.agg_overlap),
            max_body_bytes=_int("INGEST_MAX_BODY_BYTES", cls.max_body_bytes),
            max_decompressed_bytes=_int("INGEST_MAX_DECOMPRESSED_BYTES", cls.max_decompressed_bytes),
            bind=os.environ.get("INGEST_BIND", cls.bind),
            http_port=_int("INGEST_HTTP_PORT", cls.http_port),
            grpc_port=_int("INGEST_GRPC_PORT", cls.grpc_port),
            console_port=_int("CONSOLE_PORT", cls.console_port),
            http_threads=_int("INGEST_HTTP_THREADS", cls.http_threads),
            grpc_workers=_int("INGEST_GRPC_WORKERS", cls.grpc_workers),
            trust_proxy=_bool("TRUST_PROXY"),
        )

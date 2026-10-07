import pytest

from selenne_agents.config import Settings


def test_overlap_must_exceed_ingest_transaction_timeout():
    assert Settings().agg_overlap > Settings().ingest_txn_timeout
    with pytest.raises(ValueError, match="AGG_OVERLAP"):
        Settings(ingest_txn_timeout=60, agg_overlap=60)


def test_from_env_reads_both(monkeypatch):
    monkeypatch.setenv("INGEST_TXN_TIMEOUT", "10")
    monkeypatch.setenv("AGG_OVERLAP", "20")
    s = Settings.from_env()
    assert (s.ingest_txn_timeout, s.agg_overlap) == (10, 20)
    monkeypatch.setenv("AGG_OVERLAP", "5")
    with pytest.raises(ValueError):
        Settings.from_env()

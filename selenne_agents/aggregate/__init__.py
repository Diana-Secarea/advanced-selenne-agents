"""The aggregator: turns raw spans, host events and alerts into
agent_sessions and agent_processes. The SQL lives in store/aggregates.py;
this package only drives it (see worker.py)."""

from .worker import Aggregator, build_online_indexes

__all__ = ["Aggregator", "build_online_indexes"]

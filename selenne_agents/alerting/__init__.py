"""Alerts for Selenne Agents: rules over spans and host events, stored in this
stack's own database and logged to its own files — never into Selenne's
Wazuh-fed alerting."""

import hashlib
import json
import logging

from . import rules

log = logging.getLogger("alerts")


def _host_ref(row):
    if row.get("event_id"):
        return f"host:{row['host']}:{row['event_id']}"
    # no sensor id: a content hash still makes retries idempotent
    digest = hashlib.sha256(json.dumps(row.get("detail"), sort_keys=True, default=str)
                            .encode()).hexdigest()[:24]
    return f"host:{row['host']}:{digest}"


def for_spans(rows):
    out = []
    for r in rows:
        for a in rules.check_span(r):
            out.append({"alert": a, "source_ref": f"span:{r['trace_id']}:{r['span_id']}",
                        "trace_id": r["trace_id"], "span_id": r["span_id"],
                        "service_name": r.get("service_name"), "host":
                            (r.get("resource") or {}).get("host.name"),
                        "ts_ns": r["start_ns"]})
    return out


def for_host_events(rows):
    out = []
    for r in rows:
        for a in rules.check_host_event(r):
            out.append({"alert": a, "source_ref": _host_ref(r), "trace_id": None,
                        "span_id": None, "service_name": None, "host": r["host"],
                        "ts_ns": r["ts_ns"]})
    return out


def record(store, principal, found):
    """Store and log alerts. Never raises: a detection failure must not cost
    the customer their data, which is already stored by now."""
    if not found:
        return 0
    try:
        new = store.insert_alerts(principal, found)
    except Exception:            # noqa: BLE001
        log.exception("could not store %d alerts for %s/%s", len(found),
                      principal.username, principal.project)
        return 0
    for f in found:
        a = f["alert"]
        log.info("alert %s %s/%s %s", a.rule_id, principal.username, principal.project, a.title,
                 extra={"fields": {"event": "alert", "rule_id": a.rule_id, "level": a.level,
                                   "score": a.score, "label": rules.label_for(a.score),
                                   "username": principal.username, "project": principal.project,
                                   "source_ref": f["source_ref"], "tags": a.tags}})
    return new

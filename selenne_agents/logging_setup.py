"""Logging for the Selenne Agents containers.

Two sinks per service:
  * stderr — human-readable, for `docker compose logs`
  * LOG_DIR/<service>.json — one JSON object per line, for anyone who wants to
    ship Agents activity somewhere (rotating, 10 MB x 5)

These files are Selenne Agents' own. They live in this stack's volume, apart
from Selenne's collector-facing logs (selenne-audit.json, flask_access.log),
so OTel ingestion never feeds the SIEM's Wazuh alerting. Records are
namespaced "selenne_agents", never "selenne", so even a collector pointed here
by mistake matches none of Selenne's rules.

Structured fields ride on the record: log.info("msg", extra={"fields": {...}}).
"""

import json
import logging
import os
import socket
import sys
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path

_HOSTNAME = socket.gethostname()


class JsonLineFormatter(logging.Formatter):
    def __init__(self, service):
        super().__init__()
        self.service = service

    def format(self, record):
        body = {"service": self.service, "logger": record.name,
                "level": record.levelname, "message": record.getMessage()}
        body.update(getattr(record, "fields", None) or {})
        if record.exc_info:
            body["exception"] = self.formatException(record.exc_info)
        doc = {"timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
               "host": _HOSTNAME, "selenne_agents": body}
        return json.dumps(doc, default=str, ensure_ascii=False)


def setup_logging(service):
    level = getattr(logging, os.environ.get("LOG_LEVEL", "INFO").upper(), logging.INFO)
    root = logging.getLogger()
    root.setLevel(level)
    root.handlers.clear()

    console = logging.StreamHandler(sys.stderr)
    console.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root.addHandler(console)

    log_dir = os.environ.get("LOG_DIR", "").strip()
    if log_dir:
        path = Path(log_dir) / f"{service}.json"
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            handler = RotatingFileHandler(path, maxBytes=10 * 1024 * 1024, backupCount=5)
        except OSError as exc:
            # Loud, not fatal: ingestion keeps working with stderr logging only.
            logging.getLogger(service).error("cannot open log file %s (%s) — "
                                             "logging to stderr only", path, exc)
        else:
            handler.setFormatter(JsonLineFormatter(service))
            root.addHandler(handler)

    for noisy in ("urllib3", "waitress.queue"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

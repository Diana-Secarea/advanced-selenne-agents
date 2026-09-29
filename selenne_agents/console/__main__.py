"""python -m selenne_agents.console — serves selenne.app/agents/ on
CONSOLE_PORT (nginx forwards /agents/ here)."""

import logging

import waitress

from ..config import Settings
from ..logging_setup import setup_logging
from ..store import PostgresStore
from .app import create_console_app
from .selenne_session import SelenneSessions


def main():
    setup_logging("console")
    settings = Settings.from_env()
    # The ingest service owns the schema; the console only reads.
    store = PostgresStore(settings.database_url, maxconn=8)
    sessions = SelenneSessions(settings.selenne_me_url, ttl=settings.session_cache_ttl,
                               internal_secret=settings.selenne_internal_secret)
    logging.getLogger("console").info("console on %s:%d, auth via %s",
                                      settings.bind, settings.console_port, settings.selenne_me_url)
    waitress.serve(create_console_app(settings, sessions, store), host=settings.bind,
                   port=settings.console_port, threads=settings.http_threads,
                   ident="selenne-agents-console")


if __name__ == "__main__":
    main()

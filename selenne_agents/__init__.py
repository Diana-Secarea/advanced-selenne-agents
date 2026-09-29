"""Selenne Agents — monitoring and security for AI agents.

Runs in its own container next to Selenne and shares its accounts: users,
sessions, API keys and entitlements live in Selenne's users.db and are read
through Selenne's HTTP endpoints, never by opening that file here. Selenne
code is copied in where useful (RAG client), never imported.
"""

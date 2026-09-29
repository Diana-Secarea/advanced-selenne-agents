"""selenne.app/agents/ — the AI Agents console.

Served by this container behind the same nginx origin as the SIEM, so the
browser sends Selenne's session cookie here too. Nothing about the user is
stored locally: every request's cookie is checked against Selenne's
/api/auth/me (cached briefly), and data is filtered to that username.
"""

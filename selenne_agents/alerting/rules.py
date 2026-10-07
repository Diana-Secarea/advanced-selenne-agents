"""Detection rules v0 — deterministic checks run on every ingested batch.

The stand-in until per-agent scoring and reconciliation exist (build steps
5–6). Each rule looks at what a span or host event *contains* (tool
arguments, prompts, results, paths, commands) and produces an alert shaped
like Selenne's: rule id, level 0–15, score 0–100, label, tags.

Tags map to OWASP Top 10 for LLM Applications (2025) and MITRE ATLAS.

Evidence is a short excerpt around the match with secrets masked, so an
alert never becomes a second copy of the credential it reports.
"""

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

EXCERPT = 90          # chars kept on each side of a match
MAX_SCAN = 65536      # chars scanned per field


@dataclass
class Alert:
    rule_id: str
    level: int
    score: int
    title: str
    tags: list
    evidence: dict = field(default_factory=dict)


def label_for(score):
    if score >= 90:
        return "CRITICAL"
    if score >= 75:
        return "HIGH"
    if score >= 50:
        return "POSSIBLE"
    return "NORMAL"


# --- patterns ---------------------------------------------------------------

_SENSITIVE_PATH = re.compile(
    r"(?:~|/home/[^/\s\"']+|/root|/Users/[^/\s\"']+)/\.ssh/[\w.-]+"
    r"|\bid_(?:rsa|dsa|ecdsa|ed25519)\b"
    r"|/etc/(?:shadow|sudoers|gshadow)\b"
    r"|\.aws/credentials\b|\.kube/config\b|\.docker/config\.json\b"
    r"|\.git-credentials\b|\.netrc\b|\.pgpass\b"
    r"|(?:^|[\s\"'/=])\.env(?:\.[\w-]+)?(?=$|[\s\"'])",
    re.I)

_SECRETS = [
    # not \b: a key glued to other text ("key:xAKIA…") must still be caught
    ("AWS access key", re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])")),
    ("private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("API secret key", re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("Selenne ingestion key", re.compile(r"\bsk_sel_[A-Za-z0-9_-]{16,}\b")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
]

_INJECTION = re.compile(
    r"ignore (?:all |any )?(?:the )?(?:previous|prior|above|earlier) (?:instructions|prompts|rules)"
    r"|disregard (?:all |any )?(?:the )?(?:previous|prior|above|earlier|system) (?:instructions|prompt|rules)"
    r"|forget (?:all |everything )?(?:your|the) (?:previous |prior )?(?:instructions|rules)"
    r"|you are now (?:in )?(?:developer|dan|jailbreak|unrestricted) mode"
    r"|(?:reveal|print|show|repeat) (?:me )?(?:your|the) (?:system|hidden|initial) (?:prompt|instructions)"
    r"|new instructions?:\s"
    r"|<\s*/?\s*(?:system|im_start|im_end)\s*>",
    re.I)

_EXEC_TOOL = re.compile(r"(?:^|[._-])(?:exec|shell|bash|sh|cmd|terminal|subprocess|run_?command|"
                        r"code_?interpreter|python_?repl|powershell)(?:$|[._-])", re.I)
_DANGEROUS_CMD = re.compile(
    r"(?:curl|wget)[^|;\n]{0,200}\|\s*(?:ba|z)?sh\b"
    r"|\brm\s+-[a-z]*r[a-z]*f?\s+(?:/|~|\$HOME)(?:\s|$)"
    r"|\bnc\b[^\n]{0,80}\s-[a-z]*e\b"
    r"|base64\s+(?:-d|--decode)[^\n]{0,80}\|\s*(?:ba)?sh\b"
    r"|\bchmod\s+(?:\+x|[0-7]*7[0-7]{2})\s+/tmp/"
    r"|/dev/tcp/\d"
    r"|\bmkfifo\b[^\n]{0,80}\bnc\b",
    re.I)

_URL = re.compile(r"\bhttps?://[^\s\"'<>)\]]+", re.I)
_EXFIL_HOSTS = ("pastebin.com", "transfer.sh", "webhook.site", "requestbin", "ngrok",
                "pipedream.net", "burpcollaborator", "interact.sh", "oast.",
                "hastebin", "ghostbin", "file.io", "0x0.st")

_HOST_EXEC = re.compile(r"(?:^|/)(?:curl|wget|nc|ncat|netcat|socat|ssh|scp|bash|sh|zsh|"
                        r"python3?|perl|ruby|powershell|pwsh)$", re.I)


# --- helpers ------------------------------------------------------------------

def _mask(secret):
    s = str(secret)
    return s[:4] + "…" + s[-2:] if len(s) > 10 else "…"


def _window(text, start, end):
    a, b = max(0, start - EXCERPT), min(len(text), end + EXCERPT)
    return ("…" if a else "") + text[a:b] + ("…" if b < len(text) else "")


# Hidden in evidence but not alerted on by themselves (AG-102): an
# Authorization header or a password in a URL is normal plumbing, yet must
# not be copied into an alert. Same set as the sensor's own masking.
_MASK_ONLY = [
    re.compile(r"\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}", re.I),
    re.compile(r"(?<=://)([^/\s:@]+):[^/\s@]+(?=@)"),
]


def _mask_all_secrets(text):
    for _, rx in _SECRETS:
        text = rx.sub(lambda m: _mask(m.group(0)), text)
    text = _MASK_ONLY[0].sub(lambda m: _mask(m.group(0)), text)
    return _MASK_ONLY[1].sub(lambda m: m.group(1) + ":…", text)


def _fields(span):
    """(field_name, text) for everything worth scanning in a span."""
    out = [("name", span.get("name") or "")]

    def walk(prefix, v):
        if isinstance(v, str):
            out.append((prefix, v[:MAX_SCAN]))
        elif isinstance(v, dict):
            for k, x in v.items():
                walk(f"{prefix}.{k}" if prefix else str(k), x)
        elif isinstance(v, list):
            for i, x in enumerate(v[:200]):
                walk(f"{prefix}[{i}]", x)

    walk("attributes", span.get("attributes") or {})
    for i, ev in enumerate(span.get("events") or []):
        walk(f"events[{i}].{ev.get('name') or 'event'}", ev.get("attributes") or {})
    if span.get("status_message"):
        out.append(("status.message", span["status_message"][:MAX_SCAN]))
    return out


def _tool_name(span):
    a = span.get("attributes") or {}
    return a.get("gen_ai.tool.name") or (span.get("name") if a.get("gen_ai.operation.name") == "execute_tool" else None)


def _is_public_host(host):
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return None          # a name, not an IP
    return ip.is_global


# --- span rules -----------------------------------------------------------------

def check_span(span):
    """All alerts for one normalised span row (one per rule at most)."""
    alerts = {}
    fields = _fields(span)
    tool = _tool_name(span)

    def add(alert):
        cur = alerts.get(alert.rule_id)
        if not cur or alert.score > cur.score:
            alerts[alert.rule_id] = alert

    for name, raw in fields:
        # Every rule reads the masked text, so no excerpt window can cut a
        # secret in half and leak the part that no longer matches a pattern.
        text = _mask_all_secrets(raw)
        m = _SENSITIVE_PATH.search(text)
        if m:
            add(Alert("AG-101", 12, 85, "Agent touched a credential or secrets file",
                      ["owasp:LLM02", "owasp:LLM06", "atlas:AML.T0057"],
                      {"field": name, "match": m.group(0).strip(),
                       "excerpt": _window(text, m.start(), m.end())}))
        for kind, rx in _SECRETS:
            m = rx.search(raw)
            if m:
                at = text.find(_mask(m.group(0)))
                add(Alert("AG-102", 11, 80, f"Secret in agent data ({kind})",
                          ["owasp:LLM02", "atlas:AML.T0057"],
                          {"field": name, "match": kind,
                           "excerpt": _window(text, max(at, 0), max(at, 0) + 8)}))
                break
        m = _INJECTION.search(text)
        if m:
            add(Alert("AG-103", 10, 72, "Prompt-injection phrasing in agent input or tool output",
                      ["owasp:LLM01", "atlas:AML.T0051"],
                      {"field": name, "match": m.group(0),
                       "excerpt": _window(text, m.start(), m.end())}))
        m = _DANGEROUS_CMD.search(text)
        if m:
            add(Alert("AG-104", 13, 92, "Dangerous shell command in agent activity",
                      ["owasp:LLM06", "atlas:AML.T0053"],
                      {"field": name, "match": m.group(0),
                       "excerpt": _window(text, m.start(), m.end())}))
        for um in _URL.finditer(text):
            host = (urlparse(um.group(0)).hostname or "").lower()
            reason = None
            if any(x in host for x in _EXFIL_HOSTS):
                reason = "known paste/exfiltration service"
            elif _is_public_host(host):
                reason = "raw public IP address"
            if reason:
                add(Alert("AG-105", 11, 78, f"Agent reached out to a suspicious endpoint ({reason})",
                          ["owasp:LLM02", "owasp:LLM06"],
                          {"field": name, "match": host,
                           "excerpt": _window(text, um.start(), um.end())}))
                break

    if tool and _EXEC_TOOL.search(tool) and "AG-104" not in alerts:
        add(Alert("AG-106", 7, 55, f"Agent used a code/shell execution tool ({tool})",
                  ["owasp:LLM06"], {"field": "gen_ai.tool.name", "match": tool, "excerpt": tool}))

    if span.get("status_code") == "error":
        msg = span.get("status_message") or f"{span.get('name') or 'step'} ended with status error (no message)"
        add(Alert("AG-107", 3, 25, "Agent step failed" + (f" ({tool})" if tool else ""),
                  ["ops:error"], {"field": "status", "match": "error",
                                  "excerpt": _mask_all_secrets(msg)[:2 * EXCERPT]}))
    return list(alerts.values())


# --- host event rules (sensor) ------------------------------------------------------

def check_host_event(ev):
    d = ev.get("detail") or {}
    kind = ev.get("kind")
    out = []
    path = str(d.get("path") or "")
    if kind == "open" and path:
        m = _SENSITIVE_PATH.search(path)
        if m:
            out.append(Alert("AG-201", 12, 85, "Agent process opened a credential or secrets file",
                             ["owasp:LLM02", "owasp:LLM06", "atlas:AML.T0057"],
                             {"field": "path", "match": m.group(0).strip(), "excerpt": path}))
    if kind == "exec":
        exe = str(d.get("exe") or d.get("comm") or "")
        argv = d.get("argv")
        cmdline = " ".join(map(str, argv)) if isinstance(argv, list) else str(argv or exe)
        m = _DANGEROUS_CMD.search(cmdline)
        if m:
            out.append(Alert("AG-202", 13, 92, "Agent process ran a dangerous command",
                             ["owasp:LLM06"], {"field": "argv", "match": m.group(0),
                                               "excerpt": _mask_all_secrets(cmdline)[:4 * EXCERPT]}))
        # the agent's own main process (python3 running it) is expected; the
        # sensor marks it agent_root. What the agent starts is what counts.
        elif _HOST_EXEC.search(exe) and not d.get("agent_root"):
            out.append(Alert("AG-203", 6, 45, f"Agent process started {exe.rsplit('/', 1)[-1]}",
                             ["owasp:LLM06"], {"field": "exe", "match": exe,
                                               "excerpt": _mask_all_secrets(cmdline)[:4 * EXCERPT]}))
    if kind == "connect":
        daddr = str(d.get("daddr") or "")
        if _is_public_host(daddr):
            out.append(Alert("AG-204", 4, 30, "Agent process connected to a public address",
                             ["ops:egress"], {"field": "daddr", "match": daddr,
                                              "excerpt": f"{daddr}:{d.get('dport', '?')}"}))
    return out


RULES = {
    "AG-101": "Credential or secrets file in agent activity",
    "AG-102": "Secret in agent data",
    "AG-103": "Prompt-injection phrasing",
    "AG-104": "Dangerous shell command",
    "AG-105": "Suspicious outbound endpoint",
    "AG-106": "Code/shell execution tool used",
    "AG-107": "Agent step failed",
    "AG-201": "Process opened a secrets file (sensor)",
    "AG-202": "Process ran a dangerous command (sensor)",
    "AG-203": "Process started a network/shell binary (sensor)",
    "AG-204": "Process connected to a public address (sensor)",
    "AG-301": "Program started outside any tool call (unexplained)",
    "AG-302": "Connection made outside any step (unexplained)",
    "AG-303": "File opened outside any step (unexplained)",
}


# --- unexplained host activity (reconciliation) ------------------------------
# The aggregator finds host events from an instrumented agent that none of its
# spans accounts for: the machine shows it, the agent never reported it. That
# gap is the deviation — not what the activity was.

def check_unexplained(ev):
    """The AG-30x alert for one unexplained host event (see store.reconcile_tick)."""
    d = ev.get("detail") or {}
    kind = ev.get("kind")
    tags = ["recon:unexplained", "owasp:LLM06"]
    if kind == "exec":
        argv = d.get("argv")
        cmdline = " ".join(map(str, argv)) if isinstance(argv, list) else str(argv or d.get("exe") or "")
        return Alert("AG-301", 10, 70, "Agent started a program outside any tool call", tags,
                     {"field": "argv", "match": str(d.get("exe") or ""),
                      "excerpt": _mask_all_secrets(cmdline)[:4 * EXCERPT]})
    if kind == "connect":
        dest = f"{d.get('daddr', '?')}:{d.get('dport', '?')}"
        what = f"{d['dest_service']} ({dest})" if d.get("dest_service") else dest
        return Alert("AG-302", 9, 60, "Agent connected somewhere outside any step",
                     tags + ["ops:egress"], {"field": "daddr", "match": dest,
                                             "excerpt": f"{what} · {d.get('scope', '')}".strip(" ·")})
    if kind == "open":
        path = str(d.get("path") or "")
        return Alert("AG-303", 6, 45, "Agent opened a file outside any step", tags,
                     {"field": "path", "match": path, "excerpt": path[:4 * EXCERPT]})
    return None

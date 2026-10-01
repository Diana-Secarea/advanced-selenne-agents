"""Backup for the import-linter contract in .importlinter: walks every .py
file in the repo, so it also covers scripts/ and tests/, prefix matches
(wazuh*), sys.path hacks and string imports that lint-imports can't see."""

import ast
import configparser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKIP = {".venv", "venv", ".git", "__pycache__", ".pytest_cache"}


def _forbidden():
    cfg = configparser.ConfigParser()
    cfg.read(ROOT / ".importlinter")
    raw = cfg["importlinter:contract:no-selenne-imports"]["forbidden_modules"]
    return {m.strip() for m in raw.split() if m.strip()}


FORBIDDEN = _forbidden()


def _is_forbidden(module):
    top = (module or "").split(".")[0]
    return top in FORBIDDEN or top.lower().startswith("wazuh")


def _sources():
    for path in ROOT.rglob("*.py"):
        if not SKIP.intersection(path.relative_to(ROOT).parts):
            yield path


def _violations(path):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            names = [node.module]
        elif isinstance(node, ast.Call):
            fn = node.func
            name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
            if name in ("insert", "append") and isinstance(fn, ast.Attribute) \
                    and ast.unparse(fn.value) == "sys.path":
                yield node.lineno, "sys.path is modified"
                continue
            if name not in ("import_module", "__import__") or not node.args \
                    or not isinstance(node.args[0], ast.Constant):
                continue
            names = [node.args[0].value]
        else:
            continue
        for n in names:
            if isinstance(n, str) and _is_forbidden(n):
                yield node.lineno, f"imports {n}"


def test_forbidden_list_loaded():
    assert {"rag_core", "ai_engine", "scheduled_agent", "server", "auth"} <= FORBIDDEN


def test_no_selenne_imports():
    found = [f"{p.relative_to(ROOT)}:{line}: {why}"
             for p in _sources() for line, why in _violations(p)]
    assert not found, "Selenne code must be copied, not imported:\n" + "\n".join(found)

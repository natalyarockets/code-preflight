"""Detect hardcoded secrets, API keys, and .env files."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from la_analyzer.analyzer.models import Evidence, SecretFinding, SecretsReport

# Patterns for variable names that look like secrets
_SECRET_NAME_RE = re.compile(
    r"(api[_-]?key|secret[_-]?key|token|password|passwd|auth[_-]?token|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|bearer|credential)",
    re.IGNORECASE,
)

# Patterns for token-like string values
_TOKEN_PATTERNS = [
    re.compile(r"sk-[a-zA-Z0-9]{20,}"),           # OpenAI
    re.compile(r"sk-ant-[a-zA-Z0-9-]{20,}"),       # Anthropic
    re.compile(r"ghp_[a-zA-Z0-9]{36}"),             # GitHub PAT
    re.compile(r"gho_[a-zA-Z0-9]{36}"),             # GitHub OAuth
    re.compile(r"glpat-[a-zA-Z0-9_-]{20,}"),        # GitLab
    re.compile(r"xoxb-[0-9]{10,}-[a-zA-Z0-9-]+"),   # Slack bot
    re.compile(r"xoxp-[0-9]{10,}-[a-zA-Z0-9-]+"),   # Slack user
    re.compile(r"AKIA[0-9A-Z]{16}"),                 # AWS access key
    re.compile(r"sk_live_[a-zA-Z0-9]{20,}"),         # Stripe secret key
    re.compile(r"rk_live_[a-zA-Z0-9]{20,}"),         # Stripe restricted key
    re.compile(r"SG\.[a-zA-Z0-9_-]{20,}"),           # SendGrid
    re.compile(r"AC[a-f0-9]{32}"),                    # Twilio account SID
    re.compile(r"dd-[a-zA-Z0-9]{30,}"),              # Datadog
    re.compile(r"[a-f0-9]{32}-us[0-9]+"),            # Mailchimp
    re.compile(r"[a-zA-Z0-9+/]{40,}={0,2}"),         # Base64-ish long secrets (loose)
]

# Minimum length for a string to be considered secret-like
_MIN_SECRET_LEN = 16


def scan_secrets(workspace: Path, py_files: list[Path], all_files: list[Path]) -> SecretsReport:
    findings: list[SecretFinding] = []
    suggested_vars: set[str] = set()
    seen: set[str] = set()  # dedup by (file, line)

    # Check for .env files
    for fpath in all_files:
        if fpath.name in (".env", ".env.local", ".env.production", ".env.development"):
            rel = str(fpath.relative_to(workspace))
            findings.append(SecretFinding(
                kind="dotenv_file",
                name_hint=fpath.name,
                value_redacted=f"<{fpath.name} file>",
                evidence=[Evidence(file=rel, line=1, snippet=f"Dotenv file found: {fpath.name}")],
                confidence=0.95,
            ))
            # Parse .env to suggest var names
            try:
                for line in fpath.read_text(errors="replace").splitlines():
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        var_name = line.split("=", 1)[0].strip()
                        if var_name:
                            suggested_vars.add(var_name)
            except Exception:
                pass

    # AST scan of Python files
    for fpath in py_files:
        rel = str(fpath.relative_to(workspace))
        try:
            source = fpath.read_text(errors="replace")
            tree = ast.parse(source, filename=rel)
        except SyntaxError:
            continue

        for node in ast.walk(tree):
            # Variable assignments: API_KEY = "sk-..."
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    name = _target_name(target)
                    if name and _SECRET_NAME_RE.search(name):
                        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                            val = node.value.value
                            if len(val) >= 8:
                                key = f"{rel}:{node.lineno}"
                                if key not in seen:
                                    seen.add(key)
                                    findings.append(SecretFinding(
                                        kind="hardcoded_key",
                                        name_hint=name,
                                        value_redacted=_redact(val),
                                        evidence=[Evidence(
                                            file=rel, line=node.lineno,
                                            snippet=_snippet(source, node.lineno),
                                        )],
                                        confidence=0.9,
                                    ))
                                    suggested_vars.add(name.upper())

            # os.environ.get / os.getenv calls → not secrets themselves, but indicate expected env vars
            if isinstance(node, ast.Call):
                attr = _call_chain(node)
                if attr in ("os.environ.get", "os.getenv"):
                    arg = _first_str_arg(node)
                    if arg:
                        suggested_vars.add(arg)

            # Dict literals with secret-like keys: {"api_key": "sk-..."}
            if isinstance(node, ast.Dict):
                for k, v in zip(node.keys, node.values):
                    if (
                        isinstance(k, ast.Constant) and isinstance(k.value, str)
                        and _SECRET_NAME_RE.search(k.value)
                        and isinstance(v, ast.Constant) and isinstance(v.value, str)
                        and len(v.value) >= 8
                    ):
                        key = f"{rel}:{node.lineno}:{k.value}"
                        if key not in seen:
                            seen.add(key)
                            findings.append(SecretFinding(
                                kind="hardcoded_key",
                                name_hint=k.value,
                                value_redacted=_redact(v.value),
                                evidence=[Evidence(
                                    file=rel, line=node.lineno,
                                    snippet=_snippet(source, node.lineno),
                                )],
                                confidence=0.85,
                            ))
                            suggested_vars.add(k.value.upper())

            # Keyword args with secret-like names: client(api_key="sk-...")
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if (
                        kw.arg and _SECRET_NAME_RE.search(kw.arg)
                        and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str)
                        and len(kw.value.value) >= 8
                    ):
                        key = f"{rel}:{kw.value.lineno}:{kw.arg}"
                        if key not in seen:
                            seen.add(key)
                            findings.append(SecretFinding(
                                kind="hardcoded_key",
                                name_hint=kw.arg,
                                value_redacted=_redact(kw.value.value),
                                evidence=[Evidence(
                                    file=rel, line=kw.value.lineno,
                                    snippet=_snippet(source, kw.value.lineno),
                                )],
                                confidence=0.9,
                            ))
                            suggested_vars.add(kw.arg.upper())

            # Look for token-like string constants
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                val = node.value
                if len(val) >= _MIN_SECRET_LEN:
                    for pat in _TOKEN_PATTERNS[:-1]:  # Skip the loose base64 pattern
                        if pat.fullmatch(val) or pat.search(val):
                            key = f"{rel}:{node.lineno}"
                            if key not in seen:
                                seen.add(key)
                                findings.append(SecretFinding(
                                    kind="token_like",
                                    name_hint=None,
                                    value_redacted=_redact(val),
                                    evidence=[Evidence(
                                        file=rel, line=node.lineno,
                                        snippet=_snippet(source, node.lineno),
                                    )],
                                    confidence=0.75,
                                ))
                            break

    return SecretsReport(
        findings=findings,
        suggested_env_vars=sorted(suggested_vars),
    )


def _redact(value: str) -> str:
    """Redact secret value, keeping last 4 chars."""
    if len(value) <= 4:
        return "****"
    return "*" * (len(value) - 4) + value[-4:]


def _target_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _call_chain(node: ast.Call) -> str:
    """Build dotted call chain like os.environ.get."""
    parts: list[str] = []
    cur = node.func
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return ".".join(reversed(parts))


def _first_str_arg(node: ast.Call) -> str | None:
    if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
        return node.args[0].value
    return None


def _snippet(source: str, lineno: int) -> str:
    lines = source.splitlines()
    if 0 < lineno <= len(lines):
        return lines[lineno - 1].strip()[:160]
    return ""

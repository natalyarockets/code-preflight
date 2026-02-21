"""Detect hardcoded secrets, API keys, and .env files.

Uses detect-secrets library when available for entropy-based and pattern-based
detection. Falls back to built-in AST scanner if detect-secrets is not installed.
"""

from __future__ import annotations

import ast
import logging
import re
from pathlib import Path

from la_analyzer.analyzer.models import Evidence, SecretFinding, SecretsReport

log = logging.getLogger(__name__)

# Patterns for variable names that look like secrets
_SECRET_NAME_RE = re.compile(
    r"(api[_-]?key|secret[_-]?key|token|password|passwd|auth[_-]?token|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|bearer|credential)",
    re.IGNORECASE,
)

# Patterns for token-like string values (used in fallback mode)
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

    # ── .env file detection (always runs, detect-secrets doesn't do this) ──
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
            seen.add(f"{rel}:1")
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

    # ── os.environ.get / os.getenv tracking (always runs) ──
    for fpath in py_files:
        try:
            source = fpath.read_text(errors="replace")
            tree = ast.parse(source)
        except (SyntaxError, Exception):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                attr = _call_chain(node)
                if attr in ("os.environ.get", "os.getenv"):
                    arg = _first_str_arg(node)
                    if arg:
                        suggested_vars.add(arg)

    # ── Secret value detection: try detect-secrets, fall back to AST ──
    ds_findings = _detect_secrets_scan(workspace, py_files, all_files)
    if ds_findings is not None:
        # detect-secrets succeeded -- merge with AST name-based detection
        ast_findings = _ast_name_scan(workspace, py_files)
        findings.extend(_merge_findings(ds_findings, ast_findings, seen))
        # Collect suggested vars from AST name findings
        for f in ast_findings:
            if f.name_hint:
                suggested_vars.add(f.name_hint.upper())
    else:
        # Fallback: full AST scan (names + token patterns)
        findings.extend(_ast_full_scan(workspace, py_files, seen))
        for f in findings:
            if f.name_hint and f.kind == "hardcoded_key":
                suggested_vars.add(f.name_hint.upper())

    return SecretsReport(
        findings=findings,
        suggested_env_vars=sorted(suggested_vars),
    )


# ── detect-secrets integration ────────────────────────────────────────────


def _detect_secrets_scan(
    workspace: Path, py_files: list[Path], all_files: list[Path]
) -> list[SecretFinding] | None:
    """Scan files with detect-secrets. Returns None if not installed."""
    try:
        from detect_secrets import settings as ds_settings
        from detect_secrets.core.scan import scan_file
        from detect_secrets.settings import transient_settings
    except ImportError:
        log.info("detect-secrets not installed, using built-in scanner")
        return None

    findings: list[SecretFinding] = []

    # Scan all files that might contain secrets (Python + config files)
    scannable = set(py_files)
    for f in all_files:
        if f.suffix in (".py", ".yaml", ".yml", ".json", ".toml", ".cfg", ".ini", ".conf"):
            scannable.add(f)
        # Skip .env files -- handled separately above
        if f.name.startswith(".env"):
            scannable.discard(f)

    # Use default plugin settings (all detectors enabled)
    default_plugins = [
        {"name": "ArtifactoryDetector"},
        {"name": "AWSKeyDetector"},
        {"name": "AzureStorageKeyDetector"},
        {"name": "BasicAuthDetector"},
        {"name": "CloudantDetector"},
        {"name": "DiscordBotTokenDetector"},
        {"name": "GitHubTokenDetector"},
        {"name": "HexHighEntropyString", "limit": 3.0},
        {"name": "Base64HighEntropyString", "limit": 4.5},
        {"name": "IbmCloudIamDetector"},
        {"name": "IbmCosHmacDetector"},
        {"name": "JwtTokenDetector"},
        {"name": "KeywordDetector"},
        {"name": "MailchimpDetector"},
        {"name": "NpmDetector"},
        {"name": "PrivateKeyDetector"},
        {"name": "SendGridDetector"},
        {"name": "SlackDetector"},
        {"name": "SoftlayerDetector"},
        {"name": "SquareOAuthDetector"},
        {"name": "StripeDetector"},
        {"name": "TwilioKeyDetector"},
    ]

    try:
        with transient_settings({"plugins_used": default_plugins}):
            for fpath in sorted(scannable):
                try:
                    secrets = scan_file(str(fpath))
                except Exception:
                    continue

                rel = str(fpath.relative_to(workspace))

                for secret in secrets:
                    line = secret.line_number
                    secret_value = secret.secret_value or ""
                    plugin_name = type(secret).__name__

                    findings.append(SecretFinding(
                        kind="token_like",
                        name_hint=_detect_secrets_hint(plugin_name),
                        value_redacted=_redact(secret_value) if secret_value else "****",
                        evidence=[Evidence(
                            file=rel,
                            line=line,
                            snippet=_snippet_from_file(fpath, line),
                        )],
                        confidence=0.85,
                    ))
    except Exception:
        log.exception("detect-secrets scan failed, falling back to built-in scanner")
        return None

    return findings


def _detect_secrets_hint(plugin_name: str) -> str | None:
    """Map detect-secrets plugin name to a human-readable hint."""
    hints = {
        "AWSKeyDetector": "AWS key",
        "AzureStorageKeyDetector": "Azure storage key",
        "GitHubTokenDetector": "GitHub token",
        "StripeDetector": "Stripe key",
        "SlackDetector": "Slack token",
        "SendGridDetector": "SendGrid key",
        "TwilioKeyDetector": "Twilio key",
        "PrivateKeyDetector": "private key",
        "JwtTokenDetector": "JWT token",
        "BasicAuthDetector": "basic auth",
        "KeywordDetector": "secret keyword",
        "NpmDetector": "npm token",
        "MailchimpDetector": "Mailchimp key",
    }
    return hints.get(plugin_name)


# ── AST-based scanners ──────────────────────────────────────────────────


def _ast_name_scan(workspace: Path, py_files: list[Path]) -> list[SecretFinding]:
    """AST scan for secret-like variable names with string values."""
    findings: list[SecretFinding] = []
    seen: set[str] = set()

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

    return findings


def _ast_full_scan(
    workspace: Path, py_files: list[Path], seen: set[str]
) -> list[SecretFinding]:
    """Full AST scan: variable names + token patterns. Used when detect-secrets is unavailable."""
    findings: list[SecretFinding] = []

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
                                    if name:
                                        pass  # suggested_vars handled by caller

            # Dict literals with secret-like keys
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

            # Keyword args with secret-like names
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

    return findings


# ── Merge + dedup ──────────────────────────────────────────────────────────


def _merge_findings(
    ds_findings: list[SecretFinding],
    ast_findings: list[SecretFinding],
    seen: set[str],
) -> list[SecretFinding]:
    """Merge detect-secrets and AST findings, deduplicating by (file, line)."""
    merged: list[SecretFinding] = []
    merged_keys: set[str] = set(seen)

    # AST name-based findings first (higher signal: they have name_hint)
    for f in ast_findings:
        if f.evidence:
            key = f"{f.evidence[0].file}:{f.evidence[0].line}"
            if key not in merged_keys:
                merged_keys.add(key)
                merged.append(f)

    # Then detect-secrets findings
    for f in ds_findings:
        if f.evidence:
            key = f"{f.evidence[0].file}:{f.evidence[0].line}"
            if key not in merged_keys:
                merged_keys.add(key)
                merged.append(f)

    return merged


# ── Helpers ────────────────────────────────────────────────────────────────


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


def _snippet_from_file(fpath: Path, lineno: int) -> str:
    """Read a single line from a file for snippet."""
    try:
        lines = fpath.read_text(errors="replace").splitlines()
        if 0 < lineno <= len(lines):
            return lines[lineno - 1].strip()[:160]
    except Exception:
        pass
    return ""

"""Detect credentials that could leak at runtime via logs, prompts, HTTP, or files."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from la_analyzer.security.models import Evidence, CredentialLeakRisk

# Variable names that likely hold secrets
_SECRET_VAR_RE = re.compile(
    r"(api[_-]?key|secret[_-]?key|token|password|passwd|auth[_-]?token|"
    r"access[_-]?key|private[_-]?key|client[_-]?secret|bearer|credential|"
    r"api_secret|db_password|database_url|connection_string)",
    re.IGNORECASE,
)

# Logging / print calls
_LOG_FUNCS = {"print", "pprint"}
_LOG_ATTRS = {"info", "debug", "warning", "error", "critical", "exception", "log", "write"}

# HTTP call attrs — split by ambiguity to avoid false positives
_HTTP_ATTRS_CLEAR = {"post", "put", "patch", "request", "send"}
_HTTP_ATTRS_AMBIGUOUS = {"get", "delete"}  # also common on dicts, ORMs, etc.
_HTTP_LIBS = {"requests", "httpx", "aiohttp", "urllib3", "http"}

# File write attrs
_WRITE_ATTRS = {"write", "dump", "dumps", "to_json", "to_csv"}

# LLM call attrs
_LLM_ATTRS = {"create", "generate", "complete", "chat"}


def scan_credential_leaks(workspace: Path, py_files: list[Path]) -> list[CredentialLeakRisk]:
    """Scan for credentials flowing to unsafe sinks."""
    risks: list[CredentialLeakRisk] = []
    seen: set[str] = set()

    for fpath in py_files:
        rel = str(fpath.relative_to(workspace))
        try:
            source = fpath.read_text(errors="replace")
            tree = ast.parse(source, filename=rel)
        except SyntaxError:
            continue

        # Collect file-level imports for context-sensitive checks
        file_imports: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    file_imports.add(alias.name.split(".")[0])
            if isinstance(node, ast.ImportFrom) and node.module:
                file_imports.add(node.module.split(".")[0])

        # Collect secret-named variables in this file
        secret_vars: set[str] = set()

        for node in ast.walk(tree):
            # Track assignments with secret-like names
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    name = _target_name(target)
                    if name and _SECRET_VAR_RE.search(name):
                        secret_vars.add(name)

            # os.environ.get("KEY") or os.getenv("KEY") assigned to a variable
            # Only flag if the variable name or the env var name looks secret
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                call = _call_chain(node.value)
                if call in ("os.environ.get", "os.getenv"):
                    for target in node.targets:
                        name = _target_name(target)
                        if not name:
                            continue
                        # Check if variable name looks like a secret
                        if _SECRET_VAR_RE.search(name):
                            secret_vars.add(name)
                            continue
                        # Check if the env var name (first string arg) looks like a secret
                        if (node.value.args and isinstance(node.value.args[0], ast.Constant)
                                and isinstance(node.value.args[0].value, str)
                                and _SECRET_VAR_RE.search(node.value.args[0].value)):
                            secret_vars.add(name)

            # Function parameters with secret-like names
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for arg in node.args.args:
                    if _SECRET_VAR_RE.search(arg.arg):
                        secret_vars.add(arg.arg)

        # Check for os.environ iteration (always, regardless of secret_vars)
        # Pattern: os.environ.items() / .values() / .keys() / .copy()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                func_attr = node.func
                method = func_attr.attr
                if method in ("items", "values", "keys", "copy"):
                    inner = func_attr.value
                    if (isinstance(inner, ast.Attribute) and
                            inner.attr == "environ" and
                            isinstance(inner.value, ast.Name) and
                            inner.value.id == "os"):
                        key = f"{rel}:{node.lineno}:environ_dump"
                        if key not in seen:
                            seen.add(key)
                            risks.append(CredentialLeakRisk(
                                credential_name="os.environ",
                                leak_target="log_output",
                                description="os.environ is iterated/dumped — may expose all environment secrets",
                                evidence=[Evidence(
                                    file=rel, line=node.lineno,
                                    snippet=_snippet(source, node.lineno),
                                )],
                                severity="high",
                            ))

        if not secret_vars:
            continue

        # Second pass: check where secret vars flow
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            ev = Evidence(file=rel, line=node.lineno, snippet=_snippet(source, node.lineno))
            names_in_call = _collect_names(node)
            leaked_vars = names_in_call & secret_vars

            if not leaked_vars:
                continue

            cred_name = ", ".join(sorted(leaked_vars))
            key = f"{rel}:{node.lineno}:{cred_name}"
            if key in seen:
                continue

            func_name = ""
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr

            # Check 1: secrets in print/logging calls
            if func_name in _LOG_FUNCS or func_name in _LOG_ATTRS:
                seen.add(key)
                risks.append(CredentialLeakRisk(
                    credential_name=cred_name,
                    leak_target="log_output",
                    description=f"Secret variable(s) {cred_name} passed to {func_name}() — may appear in logs",
                    evidence=[ev],
                ))
                continue

            # Check 2: secrets in HTTP request calls
            # For ambiguous methods (get/delete), require an HTTP library import
            is_http = (func_name in _HTTP_ATTRS_CLEAR or
                       (func_name in _HTTP_ATTRS_AMBIGUOUS and bool(file_imports & _HTTP_LIBS)))
            if is_http:
                seen.add(key)
                risks.append(CredentialLeakRisk(
                    credential_name=cred_name,
                    leak_target="http_request",
                    description=f"Secret variable(s) {cred_name} used in HTTP {func_name}() call",
                    evidence=[ev],
                    severity="high",
                ))
                continue

            # Check 3: secrets in LLM prompt construction
            if func_name in _LLM_ATTRS:
                seen.add(key)
                risks.append(CredentialLeakRisk(
                    credential_name=cred_name,
                    leak_target="llm_prompt",
                    description=f"Secret variable(s) {cred_name} passed to LLM {func_name}() call",
                    evidence=[ev],
                ))
                continue

            # Check 4: secrets in file write calls
            if func_name in _WRITE_ATTRS:
                seen.add(key)
                risks.append(CredentialLeakRisk(
                    credential_name=cred_name,
                    leak_target="output_file",
                    description=f"Secret variable(s) {cred_name} written to file via {func_name}()",
                    evidence=[ev],
                ))
                continue

        # Check for f-strings containing secrets in logging/print context
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr

                if func_name not in _LOG_FUNCS and func_name not in _LOG_ATTRS:
                    continue

                for arg in ast.walk(node):
                    if isinstance(arg, ast.JoinedStr):
                        for val in arg.values:
                            if isinstance(val, ast.FormattedValue):
                                fstr_names = set()
                                for n in ast.walk(val):
                                    if isinstance(n, ast.Name):
                                        fstr_names.add(n.id)
                                leaked = fstr_names & secret_vars
                                if leaked:
                                    cred = ", ".join(sorted(leaked))
                                    key = f"{rel}:{arg.lineno}:{cred}"
                                    if key not in seen:
                                        seen.add(key)
                                        risks.append(CredentialLeakRisk(
                                            credential_name=cred,
                                            leak_target="log_output",
                                            description=f"Secret {cred} interpolated in f-string passed to {func_name}()",
                                            evidence=[Evidence(
                                                file=rel, line=arg.lineno,
                                                snippet=_snippet(source, arg.lineno),
                                            )],
                                        ))

    return risks


def _target_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _call_chain(node: ast.Call) -> str:
    parts: list[str] = []
    cur = node.func
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return ".".join(reversed(parts))


def _collect_names(node: ast.AST) -> set[str]:
    names: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            names.add(child.id)
    return names


def _snippet(source: str, lineno: int) -> str:
    lines = source.splitlines()
    if 0 < lineno <= len(lines):
        return lines[lineno - 1].strip()[:160]
    return ""

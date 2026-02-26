"""Detect credentials that could leak at runtime via logs, prompts, HTTP, or files."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from la_analyzer.analyzer.models import Evidence
from la_analyzer.security.models import SecurityFinding
from la_analyzer.utils import snippet

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


def scan_credential_leaks(workspace: Path, py_files: list[Path]) -> list[SecurityFinding]:
    """Scan for credentials flowing to unsafe sinks."""
    risks: list[SecurityFinding] = []
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
                            risks.append(SecurityFinding(
                                category="credential_leak",
                                title="Credential leak: os.environ → log_output",
                                credential_name="os.environ",
                                leak_target="log_output",
                                description="os.environ is iterated/dumped — may expose all environment secrets",
                                evidence=[Evidence(
                                    file=rel, line=node.lineno,
                                    snippet=snippet(source, node.lineno),
                                )],
                                severity="high",
                            ))

        if not secret_vars:
            continue

        # Second pass: check where secret vars flow
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            ev = Evidence(file=rel, line=node.lineno, snippet=snippet(source, node.lineno))
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
                risks.append(SecurityFinding(
                    category="credential_leak",
                    title=f"Credential leak: {cred_name} → log_output",
                    credential_name=cred_name,
                    leak_target="log_output",
                    description=f"Secret variable(s) {cred_name} passed to {func_name}() — may appear in logs",
                    evidence=[ev],
                    severity="high",
                ))
                continue

            # Check 2: secrets in HTTP request calls
            # For ambiguous methods (get/delete), require an HTTP library import
            is_http = (func_name in _HTTP_ATTRS_CLEAR or
                       (func_name in _HTTP_ATTRS_AMBIGUOUS and bool(file_imports & _HTTP_LIBS)))
            if is_http:
                # Distinguish: secret only in headers= keyword (legitimate auth)
                # vs secret in body/URL/other positions (potential leak)
                only_in_headers = _secret_only_in_headers(node, leaked_vars)
                body_auth = _secret_as_api_auth_in_body(node, leaked_vars)
                seen.add(key)
                if only_in_headers:
                    # Secret used as HTTP auth header — expected, legitimate service auth. Not a finding.
                    pass
                elif body_auth:
                    risks.append(SecurityFinding(
                        category="credential_leak",
                        title=f"Credential leak: {cred_name} → http_request",
                        credential_name=cred_name,
                        leak_target="http_request",
                        description=(
                            f"API key {cred_name} sent in request body for {func_name}() call "
                            f"(standard for this API, but prefer header-based auth)"
                        ),
                        evidence=[ev],
                        severity="medium",
                    ))
                else:
                    risks.append(SecurityFinding(
                        category="credential_leak",
                        title=f"Credential leak: {cred_name} → http_request",
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
                risks.append(SecurityFinding(
                    category="credential_leak",
                    title=f"Credential leak: {cred_name} → llm_prompt",
                    credential_name=cred_name,
                    leak_target="llm_prompt",
                    description=f"Secret variable(s) {cred_name} passed to LLM {func_name}() call",
                    evidence=[ev],
                    severity="high",
                ))
                continue

            # Check 4: secrets in file write calls
            if func_name in _WRITE_ATTRS:
                seen.add(key)
                risks.append(SecurityFinding(
                    category="credential_leak",
                    title=f"Credential leak: {cred_name} → output_file",
                    credential_name=cred_name,
                    leak_target="output_file",
                    description=f"Secret variable(s) {cred_name} written to file via {func_name}()",
                    evidence=[ev],
                    severity="high",
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
                                        risks.append(SecurityFinding(
                                            category="credential_leak",
                                            title=f"Credential leak: {cred} → log_output",
                                            credential_name=cred,
                                            leak_target="log_output",
                                            description=f"Secret {cred} interpolated in f-string passed to {func_name}()",
                                            evidence=[Evidence(
                                                file=rel, line=arg.lineno,
                                                snippet=snippet(source, arg.lineno),
                                            )],
                                            severity="high",
                                        ))

    return risks


def _secret_only_in_headers(call: ast.Call, secret_vars: set[str]) -> bool:
    """Check if secret vars appear ONLY in the headers= keyword arg.

    headers={"Api-Key": API_KEY} is legitimate auth, not a leak.
    """
    # Find the headers keyword
    headers_kw = None
    for kw in call.keywords:
        if kw.arg == "headers":
            headers_kw = kw
            break

    if headers_kw is None:
        return False

    # Check that secrets appear in headers but NOT in other parts of the call
    names_in_headers = _collect_names(headers_kw)
    secrets_in_headers = names_in_headers & secret_vars

    if not secrets_in_headers:
        return False

    # Check that no secrets appear outside of headers
    # Collect names from all other args/keywords
    names_outside: set[str] = set()
    for arg in call.args:
        names_outside |= _collect_names(arg)
    for kw in call.keywords:
        if kw.arg != "headers":
            names_outside |= _collect_names(kw)

    secrets_outside = names_outside & secret_vars
    return len(secrets_outside) == 0


# Dict key names that indicate API authentication (body-based auth)
_API_AUTH_KEYS = {
    "api_key", "apikey", "api-key", "apiKey",
    "token", "access_token", "accessToken", "access-token",
    "secret_key", "secretKey", "secret-key",
    "auth_key", "authKey", "auth-key",
    "authorization",
}


def _secret_as_api_auth_in_body(call: ast.Call, secret_vars: set[str]) -> bool:
    """Check if secrets appear only as auth keys in a json= body argument.

    json={"api_key": secret} is standard body-based API auth (e.g. Tavily, some
    search APIs). It's less secure than header auth but not a credential leak.
    """
    json_kw = None
    for kw in call.keywords:
        if kw.arg == "json":
            json_kw = kw
            break

    if json_kw is None:
        return False

    # json= must be a dict literal to inspect key names
    if not isinstance(json_kw.value, ast.Dict):
        return False

    # Check that all secret vars in the dict are under auth-like keys
    secrets_in_auth_keys: set[str] = set()
    secrets_in_other_keys: set[str] = set()

    for key_node, val_node in zip(json_kw.value.keys, json_kw.value.values):
        val_names = _collect_names(val_node)
        leaked = val_names & secret_vars
        if not leaked:
            continue

        key_str = ""
        if isinstance(key_node, ast.Constant) and isinstance(key_node.value, str):
            key_str = key_node.value

        if key_str.lower().replace("-", "_") in {k.lower().replace("-", "_") for k in _API_AUTH_KEYS}:
            secrets_in_auth_keys |= leaked
        else:
            secrets_in_other_keys |= leaked

    if not secrets_in_auth_keys:
        return False

    # Ensure secrets don't also appear in non-auth positions
    names_outside: set[str] = set()
    for arg in call.args:
        names_outside |= _collect_names(arg)
    for kw in call.keywords:
        if kw.arg != "json":
            names_outside |= _collect_names(kw)

    return len(secrets_in_other_keys) == 0 and len(names_outside & secret_vars) == 0


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



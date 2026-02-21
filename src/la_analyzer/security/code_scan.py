"""Detect dangerous code patterns via Bandit (preferred) + platform-specific AST checks."""

from __future__ import annotations

import ast
import json
import logging
import subprocess
from pathlib import Path

from la_analyzer.security.models import Evidence, SecurityFinding

log = logging.getLogger(__name__)

# ── Bandit test_id -> our category mapping ────────────────────────────────────

_BANDIT_CATEGORY: dict[str, str] = {
    "B101": "resource",     # assert usage
    "B102": "injection",    # exec
    "B103": "resource",     # set_bad_file_permissions
    "B104": "resource",     # hardcoded_bind_all
    "B105": "secrets",      # hardcoded_password_string
    "B106": "secrets",      # hardcoded_password_funcarg
    "B107": "secrets",      # hardcoded_password_default
    "B108": "resource",     # hardcoded_tmp_directory
    "B110": "resource",     # try_except_pass
    "B112": "resource",     # try_except_continue
    "B201": "injection",    # flask_debug_true
    "B301": "injection",    # pickle
    "B302": "injection",    # marshal
    "B303": "injection",    # insecure hash (md5/sha1)
    "B304": "injection",    # insecure cipher
    "B305": "injection",    # insecure cipher mode
    "B306": "injection",    # mktemp_q
    "B307": "injection",    # eval
    "B308": "injection",    # mark_safe
    "B310": "egress",       # urllib_urlopen
    "B311": "injection",    # random
    "B312": "egress",       # telnetlib
    "B313": "injection",    # xml_bad_cElementTree
    "B314": "injection",    # xml_bad_ElementTree
    "B315": "injection",    # xml_bad_expat_builder
    "B316": "injection",    # xml_bad_expat
    "B317": "injection",    # xml_bad_sax
    "B318": "injection",    # xml_bad_minidom
    "B319": "injection",    # xml_bad_pulldom
    "B320": "injection",    # xml_bad_etree
    "B321": "egress",       # ftp_related
    "B323": "egress",       # unverified_context (SSL)
    "B324": "injection",    # hashlib_insecure
    "B403": "injection",    # pickle import
    "B404": "injection",    # subprocess import
    "B501": "egress",       # request_with_no_cert_validation
    "B502": "egress",       # ssl_with_bad_version
    "B503": "egress",       # ssl_with_bad_defaults
    "B504": "egress",       # ssl_with_no_version
    "B505": "secrets",      # weak_cryptographic_key
    "B506": "injection",    # yaml_load
    "B507": "egress",       # ssh_no_host_key_verification
    "B601": "injection",    # paramiko_calls
    "B602": "injection",    # subprocess_popen_with_shell
    "B603": "injection",    # subprocess_without_shell
    "B604": "injection",    # any_other_function_with_shell
    "B605": "injection",    # start_process_with_shell
    "B606": "injection",    # start_process_with_no_shell
    "B607": "injection",    # start_process_with_partial_path
    "B608": "injection",    # hardcoded_sql_expressions
    "B609": "injection",    # linux_commands_wildcard
    "B610": "injection",    # django_extra_used
    "B611": "injection",    # django_rawsql_used
    "B612": "injection",    # logging_config_insecure_listen
    "B701": "injection",    # jinja2_autoescape_false
    "B702": "injection",    # use_of_mako_templates
    "B703": "injection",    # django_mark_safe
}

# Bandit test_ids that warrant critical severity (shell execution / code injection)
_CRITICAL_TESTS = {"B602", "B605", "B606"}

# Bandit test_ids that should be at least high severity
_HIGH_TESTS = {"B102", "B301", "B302", "B307", "B506"}

# Bandit test_ids to suppress — nearly always noise in internal tools
_SUPPRESS_TESTS = {"B311", "B110", "B101"}


def scan_code(workspace: Path, py_files: list[Path]) -> list[SecurityFinding]:
    """Scan Python files for dangerous patterns.

    Tries Bandit first (subprocess) for broad coverage, then always runs
    supplemental AST checks for platform-specific patterns Bandit doesn't cover
    (dynamic imports, native code, network bypass).
    """
    findings: list[SecurityFinding] = []
    seen: set[str] = set()

    # Phase 1: Bandit (broad security scan)
    bandit_ran = False
    try:
        bandit_findings = _bandit_scan(workspace)
        bandit_ran = True
        findings.extend(bandit_findings)
    except FileNotFoundError:
        log.info("Bandit not installed, using built-in fallback scanner")
    except subprocess.TimeoutExpired:
        log.warning("Bandit timed out, using built-in fallback scanner")

    # Phase 2: If Bandit didn't run, use full fallback for patterns it would have covered
    if not bandit_ran:
        findings.extend(_fallback_core_scan(workspace, py_files))

    # Build seen set from existing findings for dedup with platform scan
    for f in findings:
        if f.evidence:
            seen.add(f"{f.evidence[0].file}:{f.evidence[0].line}:{f.title}")

    # Phase 3: Always run platform-specific checks (Bandit doesn't know about these)
    for f in _platform_scan(workspace, py_files):
        key = f"{f.evidence[0].file}:{f.evidence[0].line}:{f.title}" if f.evidence else f.title
        if key not in seen:
            seen.add(key)
            findings.append(f)

    return findings


# ── Bandit integration ──────────────────────────────────────────────────────


def _bandit_scan(workspace: Path) -> list[SecurityFinding]:
    """Run bandit -r <workspace> -f json and map results to SecurityFinding."""
    result = subprocess.run(
        [
            "bandit", "-r", str(workspace),
            "-f", "json",
            "--severity-level", "low",
            "-x", ".venv,venv,node_modules,__pycache__,.git",
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )

    # Bandit exits 1 when findings exist, 0 when clean -- both are valid
    if not result.stdout:
        return []

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        log.warning("Bandit produced invalid JSON output")
        return []

    findings: list[SecurityFinding] = []
    seen: set[str] = set()
    # Cache source files for snippet extraction
    source_cache: dict[str, str] = {}

    for item in data.get("results", []):
        test_id = item.get("test_id", "")

        # Skip noise findings
        if test_id in _SUPPRESS_TESTS:
            continue

        filename = item.get("filename", "")
        line = item.get("line_number", 0)
        issue_text = item.get("issue_text", "")
        bandit_severity = item.get("issue_severity", "LOW").upper()

        # Make path relative to workspace
        try:
            rel_path = str(Path(filename).relative_to(workspace))
        except ValueError:
            rel_path = filename

        # Dedup by file:line:test_id
        key = f"{rel_path}:{line}:{test_id}"
        if key in seen:
            continue
        seen.add(key)

        # Map severity
        if test_id in _CRITICAL_TESTS:
            severity = "critical"
        elif test_id in _HIGH_TESTS or bandit_severity == "HIGH":
            severity = "high"
        elif bandit_severity == "MEDIUM":
            severity = "medium"
        else:
            severity = "low"

        category = _BANDIT_CATEGORY.get(test_id, "injection")

        # Extract snippet from the actual source line, not Bandit's context
        snippet = _read_source_line(workspace, rel_path, line, source_cache)

        findings.append(SecurityFinding(
            category=category,
            severity=severity,
            title=f"{test_id}: {issue_text}",
            description=issue_text,
            evidence=[Evidence(
                file=rel_path,
                line=line,
                snippet=snippet,
            )],
            recommendation=_bandit_recommendation(test_id),
        ))

    return findings


def _bandit_recommendation(test_id: str) -> str:
    """Return actionable recommendation for common Bandit test IDs."""
    recs = {
        "B102": "Replace exec() with a safer alternative or ensure input is validated.",
        "B301": "Use json or a safe serialization format instead of pickle.",
        "B302": "Use json or a safe serialization format instead of marshal.",
        "B303": "Use SHA-256 or stronger hash algorithm.",
        "B307": "Replace eval() with ast.literal_eval() or a safer parser.",
        "B501": "Enable certificate verification for HTTPS requests.",
        "B506": "Use yaml.safe_load() or pass Loader=yaml.SafeLoader.",
        "B602": "Avoid shell=True in subprocess calls. Pass arguments as a list.",
        "B603": "Review command construction for injection risks.",
        "B605": "Avoid os.system/os.popen. Use subprocess with shell=False.",
        "B606": "Review command arguments for injection risks.",
        "B608": "Use parameterized queries instead of string formatting for SQL.",
    }
    return recs.get(test_id, "Review whether this pattern is necessary for this app's function.")


# ── Platform-specific checks (always run) ──────────────────────────────────

# These patterns are specific to the LA platform and not covered by Bandit:
# - Dynamic imports that bypass import patching
# - Native code execution (ctypes, cffi)
# - Direct network access that bypasses gateway


_PLATFORM_IMPORTS: dict[str, tuple[str, str, str]] = {
    "ctypes": ("high", "Native code execution via ctypes", "ctypes allows calling C functions directly, bypassing Python sandbox"),
    "cffi": ("high", "Native code execution via cffi", "cffi allows calling C functions directly, bypassing Python sandbox"),
    "multiprocessing": ("medium", "Multiprocessing usage", "multiprocessing can exhaust system resources if not bounded"),
}

_NETWORK_IMPORTS: dict[str, tuple[str, str, str]] = {
    "socket": ("medium", "Direct socket access", "socket module enables raw network access, bypassing gateway controls"),
    "urllib": ("low", "Direct HTTP access via urllib", "urllib can make HTTP requests bypassing the gateway"),
    "http.client": ("low", "Direct HTTP access via http.client", "http.client can make HTTP requests bypassing the gateway"),
}


def _platform_scan(workspace: Path, py_files: list[Path]) -> list[SecurityFinding]:
    """Check for platform-specific patterns that Bandit doesn't cover."""
    findings: list[SecurityFinding] = []
    seen: set[str] = set()

    for fpath in py_files:
        rel = str(fpath.relative_to(workspace))
        try:
            source = fpath.read_text(errors="replace")
            tree = ast.parse(source, filename=rel)
        except SyntaxError:
            continue

        for node in ast.walk(tree):
            # Dynamic import calls: __import__(), importlib.import_module()
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id == "__import__":
                    key = f"{rel}:{node.lineno}:__import__"
                    if key not in seen:
                        seen.add(key)
                        findings.append(SecurityFinding(
                            category="injection",
                            severity="high",
                            title="Dynamic import bypass via __import__()",
                            description="__import__() bypasses static import patching",
                            evidence=[Evidence(
                                file=rel, line=node.lineno,
                                snippet=_snippet(source, node.lineno),
                            )],
                            recommendation="Use standard import statements instead.",
                        ))

                if isinstance(node.func, ast.Attribute) and node.func.attr == "import_module":
                    receiver = _get_value_name(node.func.value)
                    if receiver == "importlib":
                        key = f"{rel}:{node.lineno}:importlib.import_module"
                        if key not in seen:
                            seen.add(key)
                            findings.append(SecurityFinding(
                                category="injection",
                                severity="high",
                                title="Dynamic import via importlib.import_module()",
                                description="importlib.import_module() bypasses static import patching",
                                evidence=[Evidence(
                                    file=rel, line=node.lineno,
                                    snippet=_snippet(source, node.lineno),
                                )],
                                recommendation="Use standard import statements instead.",
                            ))

            # Platform-specific imports
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = []
                if isinstance(node, ast.Import):
                    names = [a.name for a in node.names]
                elif node.module:
                    names = [node.module]

                for name in names:
                    root = name.split(".")[0]
                    full = name
                    lookup = (
                        _PLATFORM_IMPORTS.get(root)
                        or _NETWORK_IMPORTS.get(root)
                        or _NETWORK_IMPORTS.get(full)
                    )
                    if lookup:
                        key = f"{rel}:{node.lineno}:{root}"
                        if key not in seen:
                            seen.add(key)
                            sev, title, desc = lookup
                            findings.append(SecurityFinding(
                                category="injection",
                                severity=sev,
                                title=title,
                                description=desc,
                                evidence=[Evidence(
                                    file=rel, line=node.lineno,
                                    snippet=_snippet(source, node.lineno),
                                )],
                                recommendation=f"Review whether {root} usage is necessary for this app's function.",
                            ))

    return findings


# ── Fallback core scanner (when Bandit is unavailable) ──────────────────────

# Covers the core dangerous patterns: exec, eval, subprocess, os.system,
# pickle, yaml.load. Used when Bandit is not installed.

_DANGEROUS_CALLS: dict[str, tuple[str, str, str]] = {
    "exec": ("high", "Dynamic code execution via exec()", "exec() can run arbitrary code at runtime"),
    "eval": ("high", "Dynamic code execution via eval()", "eval() can evaluate arbitrary expressions"),
    "compile": ("medium", "Dynamic code compilation", "compile() can prepare code for exec/eval"),
}

_DANGEROUS_ATTR_CALLS: dict[str, tuple[str, str, str, frozenset[str] | None]] = {
    "system": ("critical", "Shell command execution via os.system()", "os.system() runs shell commands with no isolation", frozenset({"os"})),
    "popen": ("critical", "Shell command execution via os.popen()", "os.popen() runs shell commands and returns output", frozenset({"os"})),
    "rmtree": ("high", "Recursive directory deletion", "shutil.rmtree() can destroy filesystem contents", frozenset({"shutil"})),
    "remove": ("medium", "File deletion via os.remove()", "os.remove() deletes files from the filesystem", frozenset({"os"})),
    "unlink": ("medium", "File deletion via os.unlink()", "os.unlink() deletes files from the filesystem", frozenset({"os"})),
    "loads": ("medium", "Deserialization call", "pickle/yaml deserialization can execute arbitrary code", None),
}

_SUBPROCESS_ATTRS = {"run", "call", "check_call", "check_output", "Popen"}


def _fallback_core_scan(workspace: Path, py_files: list[Path]) -> list[SecurityFinding]:
    """Built-in AST scanner for core patterns when Bandit is unavailable."""
    findings: list[SecurityFinding] = []
    seen: set[str] = set()

    for fpath in py_files:
        rel = str(fpath.relative_to(workspace))
        try:
            source = fpath.read_text(errors="replace")
            tree = ast.parse(source, filename=rel)
        except SyntaxError:
            continue

        file_imports: set[str] = set()

        for node in ast.walk(tree):
            # Track imports
            if isinstance(node, ast.Import):
                for alias in node.names:
                    file_imports.add(alias.name.split(".")[0])
            if isinstance(node, ast.ImportFrom) and node.module:
                file_imports.add(node.module.split(".")[0])

            # Check call nodes
            if isinstance(node, ast.Call):
                # Direct calls: exec(), eval()
                if isinstance(node.func, ast.Name) and node.func.id in _DANGEROUS_CALLS:
                    key = f"{rel}:{node.lineno}:{node.func.id}"
                    if key not in seen:
                        seen.add(key)
                        sev, title, desc = _DANGEROUS_CALLS[node.func.id]
                        findings.append(SecurityFinding(
                            category="injection",
                            severity=sev,
                            title=title,
                            description=desc,
                            evidence=[Evidence(
                                file=rel, line=node.lineno,
                                snippet=_snippet(source, node.lineno),
                            )],
                            recommendation="Replace with a safer alternative or ensure input is properly validated.",
                        ))

                # Attribute calls: os.system(), subprocess.run(), etc.
                if isinstance(node.func, ast.Attribute):
                    attr = node.func.attr

                    # subprocess.*
                    if attr in _SUBPROCESS_ATTRS and "subprocess" in file_imports:
                        key = f"{rel}:{node.lineno}:subprocess.{attr}"
                        if key not in seen:
                            seen.add(key)
                            findings.append(SecurityFinding(
                                category="injection",
                                severity="critical",
                                title=f"Shell command execution via subprocess.{attr}()",
                                description=f"subprocess.{attr}() runs external processes with potential shell access",
                                evidence=[Evidence(
                                    file=rel, line=node.lineno,
                                    snippet=_snippet(source, node.lineno),
                                )],
                                recommendation="Review command construction for injection risks. Avoid shell=True.",
                            ))

                    # General dangerous attr calls
                    elif attr in _DANGEROUS_ATTR_CALLS:
                        sev, title, desc, expected_receivers = _DANGEROUS_ATTR_CALLS[attr]
                        if expected_receivers is not None:
                            receiver = _get_value_name(node.func.value)
                            if receiver not in expected_receivers:
                                continue
                        key = f"{rel}:{node.lineno}:{attr}"
                        if key not in seen:
                            seen.add(key)
                            if attr == "loads":
                                parent_name = _get_value_name(node.func.value)
                                if parent_name in ("pickle", "yaml", "_yaml", "marshal"):
                                    sev = "high"
                                    title = f"Unsafe deserialization via {parent_name}.loads()"
                                    desc = f"{parent_name}.loads() can execute arbitrary code during deserialization"
                                else:
                                    continue
                            findings.append(SecurityFinding(
                                category="injection",
                                severity=sev,
                                title=title,
                                description=desc,
                                evidence=[Evidence(
                                    file=rel, line=node.lineno,
                                    snippet=_snippet(source, node.lineno),
                                )],
                                recommendation="Review whether this operation is necessary and properly bounded.",
                            ))

                    # yaml.load without SafeLoader
                    if attr == "load" and "yaml" in file_imports:
                        has_safe_loader = False
                        for kw in node.keywords:
                            if kw.arg == "Loader":
                                if isinstance(kw.value, ast.Attribute) and "Safe" in kw.value.attr:
                                    has_safe_loader = True
                                elif isinstance(kw.value, ast.Name) and "Safe" in kw.value.id:
                                    has_safe_loader = True
                        if not has_safe_loader:
                            key = f"{rel}:{node.lineno}:yaml.load"
                            if key not in seen:
                                seen.add(key)
                                findings.append(SecurityFinding(
                                    category="injection",
                                    severity="high",
                                    title="Unsafe YAML deserialization",
                                    description="yaml.load() without SafeLoader can execute arbitrary Python code",
                                    evidence=[Evidence(
                                        file=rel, line=node.lineno,
                                        snippet=_snippet(source, node.lineno),
                                    )],
                                    recommendation="Use yaml.safe_load() or pass Loader=yaml.SafeLoader.",
                                ))

    return findings


# ── Helpers ──────────────────────────────────────────────────────────────────


def _get_value_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _read_source_line(
    workspace: Path, rel_path: str, lineno: int, cache: dict[str, str],
) -> str:
    """Read the actual source line for a finding, caching file contents."""
    if rel_path not in cache:
        try:
            cache[rel_path] = (workspace / rel_path).read_text(errors="replace")
        except OSError:
            cache[rel_path] = ""
    return _snippet(cache[rel_path], lineno)


def _snippet(source: str, lineno: int) -> str:
    lines = source.splitlines()
    if 0 < lineno <= len(lines):
        return lines[lineno - 1].strip()[:160]
    return ""

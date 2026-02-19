"""Detect dangerous code patterns that could escape the sandbox or abuse the platform."""

from __future__ import annotations

import ast
from pathlib import Path

from la_analyzer.security.models import Evidence, SecurityFinding

# ── Dangerous call patterns ──────────────────────────────────────────────────

_DANGEROUS_CALLS: dict[str, tuple[str, str, str]] = {
    # name: (severity, title, description)
    "exec": ("high", "Dynamic code execution via exec()", "exec() can run arbitrary code at runtime"),
    "eval": ("high", "Dynamic code execution via eval()", "eval() can evaluate arbitrary expressions"),
    "compile": ("medium", "Dynamic code compilation", "compile() can prepare code for exec/eval"),
    "__import__": ("high", "Dynamic import bypass", "__import__() bypasses static import patching"),
}

_DANGEROUS_ATTR_CALLS: dict[str, tuple[str, str, str, frozenset[str] | None]] = {
    # attr name: (severity, title, description, expected_receivers | None)
    "system": ("critical", "Shell command execution via os.system()", "os.system() runs shell commands with no isolation", frozenset({"os"})),
    "popen": ("critical", "Shell command execution via os.popen()", "os.popen() runs shell commands and returns output", frozenset({"os"})),
    "rmtree": ("high", "Recursive directory deletion", "shutil.rmtree() can destroy filesystem contents", frozenset({"shutil"})),
    "remove": ("medium", "File deletion via os.remove()", "os.remove() deletes files from the filesystem", frozenset({"os"})),
    "unlink": ("medium", "File deletion via os.unlink()", "os.unlink() deletes files from the filesystem", frozenset({"os"})),
    "import_module": ("high", "Dynamic import via importlib", "importlib.import_module() bypasses static import patching", frozenset({"importlib"})),
    "loads": ("medium", "Deserialization call", "pickle/yaml deserialization can execute arbitrary code", None),  # receiver checked below
}

# subprocess module calls
_SUBPROCESS_ATTRS = {"run", "call", "check_call", "check_output", "Popen"}

# Dangerous imports
_DANGEROUS_IMPORTS: dict[str, tuple[str, str, str]] = {
    "ctypes": ("high", "Native code execution via ctypes", "ctypes allows calling C functions directly, bypassing Python sandbox"),
    "cffi": ("high", "Native code execution via cffi", "cffi allows calling C functions directly, bypassing Python sandbox"),
    "multiprocessing": ("medium", "Multiprocessing usage", "multiprocessing can exhaust system resources if not bounded"),
}

# Imports that indicate direct network access (bypassing gateway)
_NETWORK_IMPORTS: dict[str, tuple[str, str, str]] = {
    "socket": ("medium", "Direct socket access", "socket module enables raw network access, bypassing gateway controls"),
    "urllib": ("low", "Direct HTTP access via urllib", "urllib can make HTTP requests bypassing the gateway"),
    "http.client": ("low", "Direct HTTP access via http.client", "http.client can make HTTP requests bypassing the gateway"),
}


def scan_code(workspace: Path, py_files: list[Path]) -> list[SecurityFinding]:
    """Scan Python files for dangerous patterns. Returns SecurityFinding list."""
    findings: list[SecurityFinding] = []
    seen: set[str] = set()  # dedup by file:line

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

            # Check dangerous imports
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = []
                if isinstance(node, ast.Import):
                    names = [a.name for a in node.names]
                elif node.module:
                    names = [node.module]

                for name in names:
                    root = name.split(".")[0]
                    full = name
                    lookup = _DANGEROUS_IMPORTS.get(root) or _NETWORK_IMPORTS.get(root) or _NETWORK_IMPORTS.get(full)
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

            # Check call nodes
            if isinstance(node, ast.Call):
                # Direct calls: exec(), eval(), __import__()
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
                        # Verify receiver matches expected module (skip false positives
                        # like my_cache.remove() or queue.system())
                        if expected_receivers is not None:
                            receiver = _get_value_name(node.func.value)
                            if receiver not in expected_receivers:
                                continue
                        key = f"{rel}:{node.lineno}:{attr}"
                        if key not in seen:
                            seen.add(key)
                            # Refine: pickle.loads vs yaml.load
                            if attr == "loads":
                                parent_name = _get_value_name(node.func.value)
                                if parent_name in ("pickle", "yaml", "_yaml", "marshal"):
                                    sev = "high"
                                    title = f"Unsafe deserialization via {parent_name}.loads()"
                                    desc = f"{parent_name}.loads() can execute arbitrary code during deserialization"
                                else:
                                    continue  # json.loads is fine
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


def _get_value_name(node: ast.expr) -> str:
    """Get the name of a node (for checking parent in attr calls)."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _snippet(source: str, lineno: int) -> str:
    lines = source.splitlines()
    if 0 < lineno <= len(lines):
        return lines[lineno - 1].strip()[:160]
    return ""

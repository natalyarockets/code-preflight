"""Estimate resource abuse risk from code analysis patterns."""

from __future__ import annotations

import ast
from pathlib import Path

from la_analyzer.security.models import Evidence, SecurityFinding


def scan_resource_abuse(workspace: Path, py_files: list[Path]) -> list[SecurityFinding]:
    """Detect patterns that could exhaust system resources."""
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
            if isinstance(node, ast.Import):
                for alias in node.names:
                    file_imports.add(alias.name.split(".")[0])
            if isinstance(node, ast.ImportFrom) and node.module:
                file_imports.add(node.module.split(".")[0])

        for node in ast.walk(tree):
            # Detect while True without obvious break
            if isinstance(node, ast.While):
                if _is_always_true(node.test) and not _has_break(node):
                    key = f"{rel}:{node.lineno}:infinite_loop"
                    if key not in seen:
                        seen.add(key)
                        findings.append(SecurityFinding(
                            category="resource",
                            severity="medium",
                            title="Potential infinite loop",
                            description="while True loop without a visible break/return — may run indefinitely",
                            evidence=[Evidence(
                                file=rel, line=node.lineno,
                                snippet=_snippet(source, node.lineno),
                            )],
                            recommendation="Ensure the loop has a bounded exit condition.",
                        ))

            # Fork bomb / unbounded multiprocessing
            if isinstance(node, ast.Call):
                attr = _call_attr(node)

                # multiprocessing.Pool() or Process() without bounds
                if attr in ("Pool", "Process") and "multiprocessing" in file_imports:
                    key = f"{rel}:{node.lineno}:multiprocessing"
                    if key not in seen:
                        seen.add(key)
                        findings.append(SecurityFinding(
                            category="resource",
                            severity="medium",
                            title="Multiprocessing usage",
                            description=f"multiprocessing.{attr}() — spawns additional processes that could exhaust resources",
                            evidence=[Evidence(
                                file=rel, line=node.lineno,
                                snippet=_snippet(source, node.lineno),
                            )],
                            recommendation="Ensure process/pool count is bounded.",
                        ))

                # os.fork()
                if (isinstance(node.func, ast.Attribute) and
                        isinstance(node.func.value, ast.Name) and
                        node.func.value.id == "os" and node.func.attr == "fork"):
                    key = f"{rel}:{node.lineno}:fork"
                    if key not in seen:
                        seen.add(key)
                        findings.append(SecurityFinding(
                            category="resource",
                            severity="high",
                            title="Process forking via os.fork()",
                            description="os.fork() creates new processes — risk of fork bomb",
                            evidence=[Evidence(
                                file=rel, line=node.lineno,
                                snippet=_snippet(source, node.lineno),
                            )],
                            recommendation="Avoid os.fork() in managed environments.",
                        ))

                # Detect HTTP calls inside loops (tight loop network calls)
                _HTTP_LIBS = {"requests", "httpx", "aiohttp", "urllib3"}
                _HTTP_RECEIVERS = {"requests", "httpx", "aiohttp", "urllib3", "session", "client", "http"}
                if attr in ("get", "post", "put", "delete", "request"):
                    # Only flag if receiver looks like an HTTP library
                    receiver = None
                    if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                        receiver = node.func.value.id
                    if receiver in _HTTP_RECEIVERS and file_imports & _HTTP_LIBS:
                        parent = _find_parent_loop(tree, node)
                        if parent:
                            key = f"{rel}:{node.lineno}:network_loop"
                            if key not in seen:
                                seen.add(key)
                                findings.append(SecurityFinding(
                                    category="resource",
                                    severity="low",
                                    title="Network call inside loop",
                                    description=f"HTTP {attr}() called inside a loop — may cause excessive external requests",
                                    evidence=[Evidence(
                                        file=rel, line=node.lineno,
                                        snippet=_snippet(source, node.lineno),
                                    )],
                                    recommendation="Consider rate limiting or batching requests.",
                                ))

            # Detect reading entire large files into memory
            if isinstance(node, ast.Call):
                call_name = _full_call_name(node)
                if "read" in call_name and not any(kw.arg == "chunksize" for kw in node.keywords):
                    # .read() without arguments reads entire file
                    if isinstance(node.func, ast.Attribute) and node.func.attr == "read" and not node.args:
                        key = f"{rel}:{node.lineno}:full_read"
                        if key not in seen:
                            seen.add(key)
                            findings.append(SecurityFinding(
                                category="resource",
                                severity="info",
                                title="Full file read into memory",
                                description=".read() without size limit loads entire file into memory",
                                evidence=[Evidence(
                                    file=rel, line=node.lineno,
                                    snippet=_snippet(source, node.lineno),
                                )],
                                recommendation="Consider reading in chunks for large files.",
                            ))

    return findings


def _is_always_true(node: ast.expr) -> bool:
    """Check if a condition is always true (True, 1, non-empty string)."""
    if isinstance(node, ast.Constant):
        return bool(node.value)
    if isinstance(node, ast.NameConstant):  # Python 3.7 compat
        return bool(node.value)
    return False


def _has_break(node: ast.While) -> bool:
    """Check if a while loop body contains break or return at its own scope.

    Only counts break/return that would actually exit this loop — ignores
    break statements inside nested for/while loops.
    """
    return _has_break_in_body(node.body)


def _has_break_in_body(stmts: list[ast.stmt]) -> bool:
    """Recursively check statements for break/return, stopping at nested loops."""
    for stmt in stmts:
        if isinstance(stmt, (ast.Break, ast.Return)):
            return True
        # Don't recurse into nested loops — their breaks don't exit the outer loop
        if isinstance(stmt, (ast.For, ast.While)):
            continue
        # Recurse into if/else/try/with bodies (break there DOES exit the outer loop)
        for field_name in ("body", "orelse", "finalbody", "handlers"):
            child_body = getattr(stmt, field_name, None)
            if isinstance(child_body, list):
                if field_name == "handlers":
                    # ExceptHandler nodes have their own .body
                    for handler in child_body:
                        if hasattr(handler, "body") and _has_break_in_body(handler.body):
                            return True
                elif _has_break_in_body(child_body):
                    return True
    return False


def _find_parent_loop(tree: ast.Module, target: ast.AST) -> ast.AST | None:
    """Find if target node is inside a loop."""
    # Simple approach: walk the tree, track loop nesting
    for node in ast.walk(tree):
        if isinstance(node, (ast.For, ast.While)):
            for child in ast.walk(node):
                if child is target:
                    return node
    return None




def _call_attr(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    if isinstance(node.func, ast.Name):
        return node.func.id
    return None


def _full_call_name(node: ast.Call) -> str:
    parts: list[str] = []
    cur = node.func
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return ".".join(reversed(parts))


def _snippet(source: str, lineno: int) -> str:
    lines = source.splitlines()
    if 0 < lineno <= len(lines):
        return lines[lineno - 1].strip()[:160]
    return ""

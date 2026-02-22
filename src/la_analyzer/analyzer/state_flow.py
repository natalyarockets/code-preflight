"""Track which state dict keys each graph node reads and writes.

Detects TypedDict state classes, identifies node functions (those that accept
the state type or are registered via graph.add_node()), and extracts read/write
patterns from state.get("key"), state["key"], and return {"key": val}.
"""

from __future__ import annotations

import ast
from pathlib import Path

from la_analyzer.analyzer.models import (
    NodeStateFlow,
    StateAccess,
    StateFlowReport,
)


def scan_state_flow(
    workspace: Path,
    py_files: list[Path],
) -> StateFlowReport:
    """Scan Python files for state flow patterns (LangGraph-style)."""
    state_class = ""
    state_keys: list[str] = []
    node_flows: list[NodeStateFlow] = []

    for fpath in py_files:
        rel = str(fpath.relative_to(workspace))
        try:
            source = fpath.read_text(errors="replace")
            tree = ast.parse(source, filename=rel)
        except SyntaxError:
            continue

        # Step 1: Detect state class (TypedDict or annotated-only class)
        file_state_class, file_state_keys = _detect_state_class(tree)
        if file_state_class and not state_class:
            state_class = file_state_class
            state_keys = file_state_keys

        # Collect add_node registrations for this file
        registered_funcs = _collect_add_node_registrations(tree)

        # Collect function defs
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            # Step 2: Identify node functions
            is_node = False

            # Check if first param type-annotates to state class
            if file_state_class and node.args.args:
                first_arg = node.args.args[0]
                if first_arg.annotation:
                    ann_name = _annotation_name(first_arg.annotation)
                    if ann_name == file_state_class:
                        is_node = True

            # Check if registered via graph.add_node()
            if node.name in registered_funcs:
                is_node = True

            if not is_node:
                continue

            # Step 3: Extract reads and writes
            reads: list[str] = []
            writes: list[str] = []
            accesses: list[StateAccess] = []

            # Determine the state parameter name
            state_param = node.args.args[0].arg if node.args.args else "state"

            _extract_reads(node, state_param, reads, accesses)
            _extract_writes(node, writes, accesses)

            if reads or writes:
                end_line = node.end_lineno or node.lineno
                node_flows.append(NodeStateFlow(
                    function=node.name,
                    file=rel,
                    line_start=node.lineno,
                    line_end=end_line,
                    reads=list(dict.fromkeys(reads)),
                    writes=list(dict.fromkeys(writes)),
                    accesses=accesses,
                ))

    return StateFlowReport(
        state_class=state_class,
        state_keys=state_keys,
        node_flows=node_flows,
    )


# ── Helpers ───────────────────────────────────────────────────────────────


def _detect_state_class(tree: ast.AST) -> tuple[str, list[str]]:
    """Detect a TypedDict subclass or state-like annotated class."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue

        # Check if it's a TypedDict subclass
        is_typed_dict = False
        for base in node.bases:
            base_name = _annotation_name(base)
            if base_name in ("TypedDict", "typing.TypedDict", "typing_extensions.TypedDict"):
                is_typed_dict = True
                break

        # Also check keyword bases: class State(TypedDict, total=False)
        if not is_typed_dict:
            for kw in node.keywords:
                pass  # keywords don't indicate TypedDict base

        if is_typed_dict:
            keys = _extract_class_field_names(node)
            return node.name, keys

        # Heuristic: class with "State" in name and only annotations
        if "state" in node.name.lower():
            body_is_annotations = all(
                isinstance(stmt, (ast.AnnAssign, ast.Pass, ast.Expr))
                for stmt in node.body
            )
            if body_is_annotations:
                keys = _extract_class_field_names(node)
                if keys:
                    return node.name, keys

    return "", []


def _extract_class_field_names(node: ast.ClassDef) -> list[str]:
    """Extract field names from class body (AnnAssign targets)."""
    keys: list[str] = []
    for stmt in node.body:
        if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            keys.append(stmt.target.id)
    return keys


def _collect_add_node_registrations(tree: ast.AST) -> set[str]:
    """Find function names registered via graph.add_node("name", func)."""
    registered: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Attribute) and node.func.attr == "add_node":
            # graph.add_node("name", func) -- func is at arg index 1
            if len(node.args) >= 2 and isinstance(node.args[1], ast.Name):
                registered.add(node.args[1].id)
    return registered


def _annotation_name(ann: ast.expr) -> str:
    """Extract the simple name from a type annotation."""
    if isinstance(ann, ast.Name):
        return ann.id
    if isinstance(ann, ast.Attribute):
        return ann.attr
    if isinstance(ann, ast.Subscript):
        return _annotation_name(ann.value)
    return ""


def _extract_reads(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    state_param: str,
    reads: list[str],
    accesses: list[StateAccess],
) -> None:
    """Extract state read patterns from function body."""
    for node in ast.walk(func_node):
        # state.get("key")
        if (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "get"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == state_param):
            if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                key = node.args[0].value
                reads.append(key)
                accesses.append(StateAccess(key=key, access="read", line=node.lineno))

        # state["key"]
        if (isinstance(node, ast.Subscript)
                and isinstance(node.value, ast.Name)
                and node.value.id == state_param
                and isinstance(node.slice, ast.Constant)
                and isinstance(node.slice.value, str)):
            key = node.slice.value
            reads.append(key)
            accesses.append(StateAccess(key=key, access="read", line=node.lineno))


def _extract_writes(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    writes: list[str],
    accesses: list[StateAccess],
) -> None:
    """Extract state write patterns from function body (return dict literals)."""
    for node in ast.walk(func_node):
        if not isinstance(node, ast.Return):
            continue
        if node.value is None:
            continue

        dict_node = node.value

        # Direct return of dict literal: return {"key": val}
        if isinstance(dict_node, ast.Dict):
            _extract_dict_keys(dict_node, writes, accesses)
            continue

        # Variable assigned as dict then returned: x = {...}; return x
        if isinstance(dict_node, ast.Name):
            # Look backwards in function body for assignment
            var_name = dict_node.id
            for stmt in ast.walk(func_node):
                if (isinstance(stmt, ast.Assign)
                        and len(stmt.targets) == 1
                        and isinstance(stmt.targets[0], ast.Name)
                        and stmt.targets[0].id == var_name
                        and isinstance(stmt.value, ast.Dict)):
                    _extract_dict_keys(stmt.value, writes, accesses)


def _extract_dict_keys(
    dict_node: ast.Dict,
    writes: list[str],
    accesses: list[StateAccess],
) -> None:
    """Extract string keys from a dict literal."""
    for k in dict_node.keys:
        if isinstance(k, ast.Constant) and isinstance(k.value, str):
            key = k.value
            writes.append(key)
            accesses.append(StateAccess(key=key, access="write", line=dict_node.lineno))

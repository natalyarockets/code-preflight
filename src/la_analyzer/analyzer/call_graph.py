"""Build a project-wide call graph from Python ASTs.

Parses all function/method definitions and call sites, resolves cross-file
imports, and computes BFS reachability from entrypoints.
"""

from __future__ import annotations

import ast
import logging
from collections import defaultdict, deque
from pathlib import Path

from la_analyzer.analyzer.models import (
    CallEdge,
    CallGraph,
    DetectionReport,
    FunctionNode,
)

log = logging.getLogger(__name__)


def build_call_graph(
    workspace: Path,
    py_files: list[Path],
    detection: DetectionReport,
) -> CallGraph:
    """Build a CallGraph for the project.

    Args:
        workspace: Project root.
        py_files: Python files to scan.
        detection: Detection report (for entrypoint info).

    Returns:
        CallGraph with functions, edges, and entrypoint_ids.
    """
    functions: dict[str, FunctionNode] = {}
    edges: list[CallEdge] = []

    # Pass 1: collect all function/method definitions
    file_trees: dict[str, ast.AST] = {}
    imports_map: dict[str, dict[str, str]] = {}  # file -> {local_name: "target_file::func"}

    for fpath in py_files:
        try:
            source = fpath.read_text(errors="replace")
            tree = ast.parse(source, filename=str(fpath))
        except SyntaxError:
            continue

        rel = str(fpath.relative_to(workspace))
        file_trees[rel] = tree

        # Collect function defs
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                parent_class = _find_parent_class(tree, node)
                if parent_class:
                    name = f"{parent_class}.{node.name}"
                else:
                    name = node.name
                fid = f"{rel}::{name}"
                end_line = node.end_lineno or node.lineno
                functions[fid] = FunctionNode(
                    id=fid,
                    file=rel,
                    name=name,
                    line_start=node.lineno,
                    line_end=end_line,
                )

        # Collect imports for cross-file resolution
        imports_map[rel] = _collect_imports(tree, rel, workspace, py_files)

    # Build name -> [fid] index for resolution
    name_to_fids: dict[str, list[str]] = defaultdict(list)
    for fid, fn in functions.items():
        # Index by short name (e.g. "process_data")
        short = fn.name.split(".")[-1]
        name_to_fids[short].append(fid)

    # Pass 2: extract call sites and build edges
    for rel, tree in file_trees.items():
        file_imports = imports_map.get(rel, {})
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            call_name = _extract_call_name(node)
            if not call_name:
                continue

            # Find which function this call is inside
            caller_id = _find_enclosing_function(rel, node.lineno, functions)
            if not caller_id:
                # Top-level call -- attribute to a synthetic "<module>" node
                caller_id = f"{rel}::<module>"
                if caller_id not in functions:
                    functions[caller_id] = FunctionNode(
                        id=caller_id, file=rel, name="<module>",
                        line_start=1, line_end=99999,
                    )

            # Resolve the callee
            callee_id = _resolve_call(
                call_name, rel, file_imports, name_to_fids, functions,
            )
            if callee_id:
                edges.append(CallEdge(caller=caller_id, callee=callee_id))

    # Mark entrypoints
    entrypoint_ids = _identify_entrypoints(detection, functions, workspace)
    for eid in entrypoint_ids:
        if eid in functions:
            functions[eid].is_entrypoint = True

    return CallGraph(
        functions=list(functions.values()),
        edges=edges,
        entrypoint_ids=entrypoint_ids,
    )


def reachable_from(
    entrypoint_id: str,
    graph: CallGraph,
) -> set[str]:
    """BFS from an entrypoint, returning all reachable function IDs."""
    adjacency: dict[str, list[str]] = defaultdict(list)
    for edge in graph.edges:
        adjacency[edge.caller].append(edge.callee)

    visited: set[str] = set()
    queue = deque([entrypoint_id])
    while queue:
        current = queue.popleft()
        if current in visited:
            continue
        visited.add(current)
        for neighbor in adjacency.get(current, []):
            if neighbor not in visited:
                queue.append(neighbor)
    return visited


# ── Helpers ───────────────────────────────────────────────────────────────


def _find_parent_class(tree: ast.AST, target: ast.AST) -> str | None:
    """Find the class that contains `target`, if any."""
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for child in ast.walk(node):
                if child is target and child is not node:
                    return node.name
    return None


def _collect_imports(
    tree: ast.AST,
    current_file: str,
    workspace: Path,
    py_files: list[Path],
) -> dict[str, str]:
    """Map imported names to their likely target file::function."""
    result: dict[str, str] = {}
    py_rel = {str(f.relative_to(workspace)) for f in py_files}

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            # Convert module path to file path
            parts = node.module.split(".")
            candidates = [
                "/".join(parts) + ".py",
                "/".join(parts) + "/__init__.py",
            ]
            target_file = None
            for c in candidates:
                if c in py_rel:
                    target_file = c
                    break

            if target_file and node.names:
                for alias in node.names:
                    local_name = alias.asname or alias.name
                    result[local_name] = f"{target_file}::{alias.name}"

    return result


def _extract_call_name(node: ast.Call) -> str | None:
    """Extract a simple call name from a Call node."""
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        # e.g. obj.method() -- return "method"
        return node.func.attr
    return None


def _find_enclosing_function(
    file: str,
    line: int,
    functions: dict[str, FunctionNode],
) -> str | None:
    """Find the function that contains `line` in `file`."""
    best: FunctionNode | None = None
    for fn in functions.values():
        if fn.file != file:
            continue
        if fn.name == "<module>":
            continue
        if fn.line_start <= line <= fn.line_end:
            # Prefer the tightest enclosing function (nested)
            if best is None or fn.line_start > best.line_start:
                best = fn
    return best.id if best else None


def _resolve_call(
    call_name: str,
    current_file: str,
    file_imports: dict[str, str],
    name_to_fids: dict[str, list[str]],
    functions: dict[str, FunctionNode],
) -> str | None:
    """Resolve a call name to a FunctionNode.id."""
    # 1. Check if the name was imported
    if call_name in file_imports:
        target = file_imports[call_name]
        if target in functions:
            return target
        # The import might reference a function by a different qualified name
        # Try matching by target file + short name
        parts = target.split("::")
        if len(parts) == 2:
            target_file, target_name = parts
            # Try direct match
            direct = f"{target_file}::{target_name}"
            if direct in functions:
                return direct

    # 2. Local function in the same file
    local_id = f"{current_file}::{call_name}"
    if local_id in functions:
        return local_id

    # 3. Global name match (ambiguous -- pick same-file first, then any)
    candidates = name_to_fids.get(call_name, [])
    if not candidates:
        return None
    # Prefer same file
    for c in candidates:
        if c.startswith(current_file + "::"):
            return c
    # Fall back to first match
    return candidates[0]


def _identify_entrypoints(
    detection: DetectionReport,
    functions: dict[str, FunctionNode],
    workspace: Path,
) -> list[str]:
    """Map detected entrypoint candidates to FunctionNode IDs."""
    entrypoint_ids: list[str] = []

    for candidate in detection.entrypoint_candidates:
        if candidate.kind == "command":
            # "python main.py" -> look for main.py::<module>
            parts = candidate.value.split()
            if len(parts) >= 2:
                script = parts[-1]
            else:
                script = candidate.value
            module_id = f"{script}::<module>"
            if module_id in functions:
                entrypoint_ids.append(module_id)

        elif candidate.kind == "module":
            # "mypackage.main" -> "mypackage/main.py::<module>"
            mod_path = candidate.value.replace(".", "/") + ".py"
            module_id = f"{mod_path}::<module>"
            if module_id in functions:
                entrypoint_ids.append(module_id)

    # Also mark files with if __name__ == "__main__" as entrypoints
    for fid, fn in functions.items():
        if fn.name == "<module>" and fn.is_entrypoint:
            if fid not in entrypoint_ids:
                entrypoint_ids.append(fid)

    return entrypoint_ids

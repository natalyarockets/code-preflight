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

# Callback registration: method.attr -> index of the callable argument
_CALLBACK_METHODS = {
    "add_node": 1,      # LangGraph: graph.add_node("name", func)
    "add_job": 0,       # APScheduler: scheduler.add_job(func, ...)
    "on": 1,            # Event emitters: emitter.on("event", handler)
    "register": 0,      # Generic: registry.register(handler)
    "connect": 1,       # Django signals: signal.connect(handler)
}

# Free function calls that register callables
_CALLBACK_FREE_FUNCS = {
    "path": 1,          # Django: path("url/", view_func)
    "re_path": 1,       # Django: re_path(r"^url/", view_func)
}

# Decorator attrs that register callables (extends _ROUTE_DECORATOR_ATTRS)
_CALLBACK_DECORATOR_ATTRS = {
    "task",             # Celery: @app.task / @celery.task
    "on_event",         # Starlette: @app.on_event("startup")
}


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

    # HTTP verb decorator attributes — covers FastAPI, Flask, Starlette, etc.
    _ROUTE_DECORATOR_ATTRS = {
        "get", "post", "put", "patch", "delete", "head", "options",
        "route", "api_route", "websocket",
    }

    # Pass 2: extract call sites and decorator-registered routes, build edges
    for rel, tree in file_trees.items():
        file_imports = imports_map.get(rel, {})

        # Ensure a <module> node exists for this file (decorator edges target it)
        module_id = f"{rel}::<module>"
        if module_id not in functions:
            functions[module_id] = FunctionNode(
                id=module_id, file=rel, name="<module>",
                line_start=1, line_end=99999,
            )

        for node in ast.walk(tree):
            # Decorator-registered route handlers: @app.get("/path") def handler()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for dec in node.decorator_list:
                    dec_node = dec.func if isinstance(dec, ast.Call) and hasattr(dec, "func") else dec
                    if (isinstance(dec_node, ast.Attribute)
                            and dec_node.attr in _ROUTE_DECORATOR_ATTRS | _CALLBACK_DECORATOR_ATTRS):
                        callee_id = f"{rel}::{node.name}"
                        if callee_id in functions:
                            edges.append(CallEdge(caller=module_id, callee=callee_id))

            if not isinstance(node, ast.Call):
                continue

            # Callback registration: obj.add_node("name", func) or path("url", view)
            if isinstance(node.func, ast.Attribute) and node.func.attr in _CALLBACK_METHODS:
                arg_idx = _CALLBACK_METHODS[node.func.attr]
                if len(node.args) > arg_idx:
                    arg = node.args[arg_idx]
                    if isinstance(arg, ast.Name):
                        target = _resolve_call(arg.id, rel, file_imports, name_to_fids, functions)
                        if target:
                            edges.append(CallEdge(caller=module_id, callee=target))
            elif isinstance(node.func, ast.Name) and node.func.id in _CALLBACK_FREE_FUNCS:
                arg_idx = _CALLBACK_FREE_FUNCS[node.func.id]
                if len(node.args) > arg_idx:
                    arg = node.args[arg_idx]
                    if isinstance(arg, ast.Name):
                        target = _resolve_call(arg.id, rel, file_imports, name_to_fids, functions)
                        if target:
                            edges.append(CallEdge(caller=module_id, callee=target))

            # Find which function this call is inside
            caller_id = _find_enclosing_function(rel, node.lineno, functions)
            if not caller_id:
                caller_id = module_id

            # Walk lambda bodies: extract calls inside lambdas and attribute
            # them to the enclosing function.
            # e.g. retry_with_backoff(lambda: llm.invoke(prompt)) — the
            # llm.invoke() call is inside the lambda, invisible to ast.walk
            # because ast.walk does visit Lambda children. But the call's
            # lineno equals the lambda's lineno, so _find_enclosing_function
            # already works. The issue is that _extract_call_name + _resolve
            # only fires on ast.Call nodes found by ast.walk — and ast.walk
            # DOES walk into lambdas. So actually the issue is that
            # llm.invoke() extracts "invoke" which doesn't resolve to any
            # project function. We need to surface these unresolved method
            # calls too. But first: let's extract calls from lambda args
            # explicitly so they get proper caller attribution.
            for arg in node.args:
                if isinstance(arg, ast.Lambda):
                    for lnode in ast.walk(arg.body):
                        if isinstance(lnode, ast.Call):
                            lresult = _extract_call_name(lnode)
                            if lresult:
                                lname, l_is_plain = lresult
                                callee_id = _resolve_call(
                                    lname, rel, file_imports,
                                    name_to_fids, functions, l_is_plain,
                                )
                                if callee_id:
                                    edges.append(CallEdge(
                                        caller=caller_id, callee=callee_id,
                                    ))

            call_result = _extract_call_name(node)
            if not call_result:
                continue
            call_name, is_plain = call_result

            # Resolve the callee
            callee_id = _resolve_call(
                call_name, rel, file_imports, name_to_fids, functions, is_plain,
            )
            if callee_id:
                edges.append(CallEdge(caller=caller_id, callee=callee_id))

    # Import-execution edges: importing a module runs its <module> code
    for rel, file_imports in imports_map.items():
        source_module = f"{rel}::<module>"
        seen_targets: set[str] = set()
        for target_ref in file_imports.values():
            target_file = target_ref.split("::")[0]
            if target_file not in seen_targets and target_file in file_trees:
                seen_targets.add(target_file)
                target_module = f"{target_file}::<module>"
                edges.append(CallEdge(caller=source_module, callee=target_module))

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


def _extract_call_name(node: ast.Call) -> tuple[str, bool] | None:
    """Extract call name and whether it is a plain (non-attribute) call.

    Returns (name, is_plain_call) or None.
    is_plain_call=True  for direct calls: ``func()``
    is_plain_call=False for method calls: ``obj.method()``

    Method calls on unknown receivers must not be resolved to module-level
    functions — we have no type information to know if the receiver is the
    same object.  The is_plain_call flag lets _resolve_call skip the local
    function lookup for attribute calls.
    """
    if isinstance(node.func, ast.Name):
        return node.func.id, True
    if isinstance(node.func, ast.Attribute):
        return node.func.attr, False
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
    is_plain_call: bool = True,
) -> str | None:
    """Resolve a call name to a FunctionNode.id.

    is_plain_call should be False for attribute/method calls (``obj.method()``).
    In that case we skip local function resolution: without type information we
    cannot know whether the receiver matches a locally defined function, and a
    naive name match produces false edges (e.g. ``page.extract_text()`` ->
    ``main.py::extract_text``).
    """
    # 1. Check if the name was imported (always safe — imports are explicit)
    if call_name in file_imports:
        target = file_imports[call_name]
        if target in functions:
            return target
        # The import might reference a function by a different qualified name
        # Try matching by target file + short name
        parts = target.split("::")
        if len(parts) == 2:
            target_file, target_name = parts
            direct = f"{target_file}::{target_name}"
            if direct in functions:
                return direct

    # 2 & 3 only apply to plain (non-attribute) calls.  For method calls on
    # arbitrary receivers, skip: we'd need type inference to resolve correctly.
    if not is_plain_call:
        return None

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
            value = candidate.value
            # "uvicorn main:app" -> look for main.py::<module>
            if value.startswith("uvicorn "):
                module_part = value.split()[1].split(":")[0]  # "main" from "main:app"
                script = module_part.replace(".", "/") + ".py"
            else:
                # "python main.py" -> look for main.py::<module>
                parts = value.split()
                if len(parts) >= 2:
                    script = parts[-1]
                else:
                    script = value
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

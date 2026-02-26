"""FastAPI adapter: emit route nodes and auth guard edges."""

from __future__ import annotations

import ast
import re

from la_analyzer.ir.capability_registry import (
    AUTH_GUARD_CLASSES,
    AUTH_GUARD_FUNC_RE,
    Capability,
    SourceTrust,
)
from la_analyzer.ir.nodes import EffectEdge, EffectNode

# FastAPI HTTP method decorators
_ROUTE_DECORATORS = frozenset({
    "get", "post", "put", "patch", "delete", "head", "options", "websocket", "route",
})


def emit_route_facts(
    tree: ast.Module,
    source: str,
    rel: str,
    var_capability_map: dict[str, Capability],
    graph,  # EffectGraph
    registry: dict,  # CAPABILITY_REGISTRY
) -> None:
    """Emit route nodes and auth guard edges for FastAPI route handlers."""

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        route_info = _get_route_decorator(node)
        if not route_info:
            continue

        method, path = route_info
        func_name = node.name
        route_id = f"{rel}::{node.lineno}::route::{func_name}"

        route_node = EffectNode(
            id=route_id,
            kind="route",
            file=rel,
            line=node.lineno,
            name=func_name,
            metadata={
                "http_method": method,
                "path": path,
            },
        )
        graph.add_node(route_node)

        # Check for auth guards in function parameters
        has_auth = _check_auth_guards(node, rel, route_id, graph)

        if not has_auth:
            route_node.metadata["unguarded"] = True

        # Check for Request.headers usage → emit HEADER_CONTROLLED sources
        _emit_header_sources(node, source, rel, route_id, graph)

        # Check if handler returns state dict directly
        _check_state_overexposure(node, rel, route_id, var_capability_map, graph)


def _get_route_decorator(node: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[str, str] | None:
    """Return (method, path) if the function has a FastAPI route decorator."""
    for dec in node.decorator_list:
        method, path = _parse_route_decorator(dec)
        if method:
            return method, path
    return None


def _parse_route_decorator(dec: ast.expr) -> tuple[str, str]:
    """Parse a decorator and return (method, path) or ('', '')."""
    # @router.get("/path") or @app.post("/path")
    if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute):
        attr = dec.func.attr
        if attr in _ROUTE_DECORATORS:
            path = ""
            if dec.args and isinstance(dec.args[0], ast.Constant):
                path = str(dec.args[0].value)
            elif dec.keywords:
                for kw in dec.keywords:
                    if kw.arg == "path" and isinstance(kw.value, ast.Constant):
                        path = str(kw.value.value)
            return attr.upper(), path

    # @app.get — without call (rare but possible)
    if isinstance(dec, ast.Attribute) and dec.attr in _ROUTE_DECORATORS:
        return dec.attr.upper(), ""

    return "", ""


def _check_auth_guards(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    rel: str,
    route_id: str,
    graph,
) -> bool:
    """Check if the route handler has auth guards. Returns True if guarded."""
    has_auth = False

    # In FastAPI: `token: str = Depends(oauth2)` — the Depends() call is the
    # *default value*, not the annotation.
    # Collect all default values for both positional and keyword-only args.
    all_defaults: list[ast.expr] = []
    all_defaults.extend(func_node.args.defaults)
    all_defaults.extend(
        d for d in func_node.args.kw_defaults if d is not None
    )

    for default_expr in all_defaults:
        for subnode in ast.walk(default_expr):
            if isinstance(subnode, ast.Call):
                call_name = _get_name(subnode.func)
                if call_name in ("Depends", "Security"):
                    dep_arg = subnode.args[0] if subnode.args else None
                    if dep_arg is not None:
                        # dep_arg may be a Name (variable) or a Call (constructor)
                        dep_name = _get_name(dep_arg)
                        # Also get the type name if dep_arg is a Call
                        if isinstance(dep_arg, ast.Call):
                            dep_name = _get_name(dep_arg.func) or dep_name
                        if dep_name and _is_auth_guard(dep_name):
                            has_auth = True
                            guard_id = f"{rel}::{func_node.lineno}::guard::auth"
                            guard_node = EffectNode(
                                id=guard_id,
                                kind="guard",
                                file=rel,
                                line=func_node.lineno,
                                name=dep_name,
                                metadata={"auth_type": "depends"},
                            )
                            graph.add_node(guard_node)
                            graph.add_edge(EffectEdge(
                                src=guard_id,
                                dst=route_id,
                                kind="guarded_by",
                                file=rel,
                                line=func_node.lineno,
                            ))
                        # Do not treat arbitrary Depends(...) as auth. Only auth-like
                        # names/classes should create guard edges; otherwise we risk
                        # false negatives by suppressing truly unauthenticated routes.

    # Also check annotations for Security(...) patterns
    for arg in func_node.args.args + func_node.args.kwonlyargs:
        ann = arg.annotation
        if ann is None:
            continue
        for subnode in ast.walk(ann):
            if isinstance(subnode, ast.Call):
                call_name = _get_name(subnode.func)
                if call_name in ("Depends", "Security"):
                    dep_arg = subnode.args[0] if subnode.args else None
                    if dep_arg is not None:
                        dep_name = _get_name(dep_arg)
                        if dep_name and _is_auth_guard(dep_name):
                            has_auth = True

    # Also check function body for early auth checks
    for child in ast.walk(func_node):
        if isinstance(child, ast.Call):
            call_name = _get_name(child.func)
            if call_name and _is_auth_guard(call_name):
                has_auth = True
                break

    return has_auth


def _is_auth_guard(name: str) -> bool:
    """Return True if name looks like an auth guard."""
    # Check against known auth classes
    base = name.split(".")[-1]
    if base in AUTH_GUARD_CLASSES:
        return True
    # Check against function name pattern
    if AUTH_GUARD_FUNC_RE.search(name):
        return True
    return False


def _emit_header_sources(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    source: str,
    rel: str,
    route_id: str,
    graph,
) -> None:
    """Detect request.headers.get() calls and emit HEADER_CONTROLLED source nodes."""
    for child in ast.walk(func_node):
        if not isinstance(child, ast.Call):
            continue

        call_chain = _get_attr_chain(child.func)
        if not call_chain:
            continue

        if "headers" in call_chain and ("get" in call_chain or call_chain.endswith(".headers")):
            src_id = f"{rel}::{child.lineno}::source::header"
            src_node = EffectNode(
                id=src_id,
                kind="source",
                file=rel,
                line=child.lineno,
                name="request.headers",
                source_trust=SourceTrust.HEADER_CONTROLLED,
                metadata={"route_id": route_id},
            )
            graph.add_node(src_node)
            graph.add_edge(EffectEdge(
                src=route_id,
                dst=src_id,
                kind="data_flows_to",
                file=rel,
                line=child.lineno,
            ))


def _check_state_overexposure(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    rel: str,
    route_id: str,
    var_capability_map: dict[str, Capability],
    graph,
) -> None:
    """Check if a route handler returns the full graph state."""
    for child in ast.walk(func_node):
        if not isinstance(child, ast.Return):
            continue
        if child.value is None:
            continue

        # Check for direct state return: return state or return {"key": state["key"]}
        return_names = set()
        for n in ast.walk(child.value):
            if isinstance(n, ast.Name):
                return_names.add(n.id)

        for var_name in return_names:
            cap = var_capability_map.get(var_name)
            if cap == Capability.STATE_STORE:
                graph.get_node(route_id)
                n = graph.get_node(route_id)
                if n:
                    n.metadata["state_overexposure"] = True
                    n.metadata["state_var"] = var_name

        # Also detect common snapshot patterns like {"current_state": state_values}
        if isinstance(child.value, ast.Dict):
            for k, v in zip(child.value.keys, child.value.values):
                key_name = k.value if isinstance(k, ast.Constant) and isinstance(k.value, str) else None
                if not key_name or "state" not in key_name.lower():
                    continue
                value_names = {n.id for n in ast.walk(v) if isinstance(n, ast.Name)}
                if not any("state" in name.lower() for name in value_names):
                    continue
                n = graph.get_node(route_id)
                if n:
                    n.metadata["state_overexposure"] = True
                    # Prefer the concrete variable if available, else the response key.
                    state_var = next((nm for nm in value_names if "state" in nm.lower()), key_name)
                    n.metadata["state_var"] = state_var


def _get_name(node: ast.expr | None) -> str | None:
    """Get name from a Name or Attribute node."""
    if node is None:
        return None
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _get_attr_chain(node: ast.expr) -> str:
    """Get dotted attribute chain as string."""
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return ".".join(reversed(parts))

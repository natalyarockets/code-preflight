"""LangGraph adapter: emit store nodes for checkpointers and state reads."""

from __future__ import annotations

import ast

from la_analyzer.ir.capability_registry import Capability, SinkKind, SourceTrust
from la_analyzer.ir.nodes import EffectEdge, EffectNode

# LangGraph checkpointer constructor names
_CHECKPOINTER_CLASSES = frozenset({
    "AsyncSqliteSaver",
    "SqliteSaver",
    "PostgresSaver",
    "MemorySaver",
    "InMemoryStore",
    "AsyncPostgresSaver",
})


def emit_langgraph_facts(
    tree: ast.Module,
    source: str,
    rel: str,
    var_capability_map: dict[str, Capability],
    graph,  # EffectGraph
) -> None:
    """Emit store nodes for LangGraph checkpointers and state reads."""

    # Walk for checkpointer constructions
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            _check_checkpointer_assign(node, source, rel, var_capability_map, graph)
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            _check_checkpointer_annassign(node, source, rel, var_capability_map, graph)

        # graph.compile(checkpointer=...) → link store to graph runtime
        if isinstance(node, ast.Call):
            _check_compile_call(node, rel, var_capability_map, graph)

        # state.get("key") in graph node functions → emit DB_RESULT source
        if isinstance(node, ast.Call):
            _check_state_read(node, rel, var_capability_map, graph)


def _check_checkpointer_assign(
    node: ast.Assign,
    source: str,
    rel: str,
    var_capability_map: dict[str, Capability],
    graph,
) -> None:
    """Check: saver = AsyncSqliteSaver.from_conn_string(...) or similar."""
    if not isinstance(node.value, ast.Call):
        return

    call = node.value
    class_name = _get_constructor_name(call)
    if class_name not in _CHECKPOINTER_CLASSES:
        return

    store_id = f"{rel}::{node.lineno}::store::{class_name}"
    store_node = EffectNode(
        id=store_id,
        kind="store",
        file=rel,
        line=node.lineno,
        name=class_name,
        capability=Capability.STATE_STORE,
        sink_kind=SinkKind.LOCAL_PERSISTENCE,
        metadata={"class": class_name},
    )
    graph.add_node(store_node)

    # Register the variable name
    for target in node.targets:
        if isinstance(target, ast.Name):
            var_capability_map[target.id] = Capability.STATE_STORE


def _check_checkpointer_annassign(
    node: ast.AnnAssign,
    source: str,
    rel: str,
    var_capability_map: dict[str, Capability],
    graph,
) -> None:
    """Check annotated assignment: saver: AsyncSqliteSaver = ..."""
    if not isinstance(node.value, ast.Call):
        return

    call = node.value
    class_name = _get_constructor_name(call)
    if class_name not in _CHECKPOINTER_CLASSES:
        return

    store_id = f"{rel}::{node.lineno}::store::{class_name}"
    store_node = EffectNode(
        id=store_id,
        kind="store",
        file=rel,
        line=node.lineno,
        name=class_name,
        capability=Capability.STATE_STORE,
        sink_kind=SinkKind.LOCAL_PERSISTENCE,
        metadata={"class": class_name},
    )
    graph.add_node(store_node)

    if isinstance(node.target, ast.Name):
        var_capability_map[node.target.id] = Capability.STATE_STORE


def _check_compile_call(
    node: ast.Call,
    rel: str,
    var_capability_map: dict[str, Capability],
    graph,
) -> None:
    """Check graph.compile(checkpointer=saver) → link store to runtime."""
    if not isinstance(node.func, ast.Attribute):
        return
    if node.func.attr != "compile":
        return

    checkpointer_var = None
    for kw in node.keywords:
        if kw.arg == "checkpointer" and isinstance(kw.value, ast.Name):
            checkpointer_var = kw.value.id
            break

    if checkpointer_var and var_capability_map.get(checkpointer_var) == Capability.STATE_STORE:
        # Find the store node for this var
        store_node_id = None
        for nid, n in graph._nodes.items():
            if n.kind == "store" and n.file == rel:
                store_node_id = nid
                break

        if store_node_id:
            runtime_id = f"{rel}::{node.lineno}::var::graph_compiled"
            graph.add_edge(EffectEdge(
                src=store_node_id,
                dst=runtime_id,
                kind="constructs",
                file=rel,
                line=node.lineno,
            ))


def _check_state_read(
    node: ast.Call,
    rel: str,
    var_capability_map: dict[str, Capability],
    graph,
) -> None:
    """Detect state.get("key") in graph node functions → emit DB_RESULT source."""
    if not isinstance(node.func, ast.Attribute):
        return
    if node.func.attr != "get":
        return
    if not isinstance(node.func.value, ast.Name):
        return

    receiver = node.func.value.id
    # "state" is the conventional name; also check if capability is STATE_STORE
    if receiver == "state" or var_capability_map.get(receiver) == Capability.STATE_STORE:
        key = None
        if node.args and isinstance(node.args[0], ast.Constant):
            key = str(node.args[0].value)

        src_id = f"{rel}::{node.lineno}::source::state_read"
        src_node = EffectNode(
            id=src_id,
            kind="source",
            file=rel,
            line=node.lineno,
            name=f"state.get({key or '?'})",
            source_trust=SourceTrust.DB_RESULT,
            metadata={"state_key": key, "receiver": receiver},
        )
        graph.add_node(src_node)


def _get_constructor_name(call: ast.Call) -> str:
    """Get class name from a constructor call, including Class.from_conn_string(...)."""
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        # AsyncSqliteSaver.from_conn_string(...) → "AsyncSqliteSaver"
        if isinstance(call.func.value, ast.Name):
            return call.func.value.id
    return ""

"""Multi-pass AST walker: emits IR facts from Python source files.

Passes:
  1. Imports — build module_alias_map
  2. Abstract env construction — per-scope variable tracking
  3. Calls with abstract typing — emit sink/source nodes
  4. Conditional effect detection
  5. Decorators — @traceable etc.
  6. FastAPI routes (via adapter)
  7. LangGraph state (via adapter)
"""

from __future__ import annotations

import ast
import logging
from pathlib import Path

from la_analyzer.ir.abstract_values import (
    FACTORY_SUMMARIES,
    WRAPPER_FUNCS,
    AbstractEnv,
    AbstractValue,
    Effect,
    Literal,
    Object,
    Tainted,
    Unknown,
    UnknownStr,
    get_capability,
    get_object,
    get_taint,
    is_tainted,
    join_values,
)
from la_analyzer.ir.capability_registry import (
    CAPABILITY_REGISTRY,
    SOURCE_PATTERNS,
    Capability,
    SinkKind,
    SourceTrust,
    lookup_by_constructor,
    lookup_by_module,
)
from la_analyzer.ir.graph import EffectGraph
from la_analyzer.ir.nodes import EffectEdge, EffectNode

log = logging.getLogger(__name__)


def analyze_file(
    fpath: Path,
    workspace: Path,
    graph: EffectGraph,
) -> dict[str, Capability]:
    """Analyze a single Python file and emit IR facts into the graph.

    Returns: var_capability_map (var_name → Capability) for cross-file use.
    """
    rel = str(fpath.relative_to(workspace))
    try:
        source = fpath.read_text(errors="replace")
        tree = ast.parse(source, filename=rel)
    except SyntaxError:
        return {}

    # Pass 1: Imports
    module_alias_map, file_imports = _pass1_imports(tree)

    # Pass 2+3+4: Per-scope abstract env + calls
    var_capability_map: dict[str, Capability] = {}
    _pass_scopes(tree, source, rel, module_alias_map, file_imports, var_capability_map, graph)

    # Pass 5: Decorators
    _pass5_decorators(tree, source, rel, module_alias_map, graph)

    # Pass 6: FastAPI routes
    try:
        from la_analyzer.ir.adapters.fastapi import emit_route_facts
        emit_route_facts(tree, source, rel, var_capability_map, graph, CAPABILITY_REGISTRY)
    except Exception:
        log.debug("FastAPI adapter failed for %s", rel, exc_info=True)

    # Pass 7: LangGraph state
    try:
        from la_analyzer.ir.adapters.langgraph import emit_langgraph_facts
        emit_langgraph_facts(tree, source, rel, var_capability_map, graph)
    except Exception:
        log.debug("LangGraph adapter failed for %s", rel, exc_info=True)

    return var_capability_map


def _pass1_imports(tree: ast.Module) -> tuple[dict[str, str], set[str]]:
    """Pass 1: Collect import aliases and which capability-registry modules are imported.

    Returns:
        module_alias_map: local_name → canonical_module_name
        file_imports: set of root module names imported
    """
    module_alias_map: dict[str, str] = {}
    file_imports: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                local = alias.asname or root
                module_alias_map[local] = alias.name
                file_imports.add(root)

        elif isinstance(node, ast.ImportFrom) and node.module:
            root = node.module.split(".")[0]
            file_imports.add(root)
            for alias in node.names:
                local = alias.asname or alias.name
                module_alias_map[local] = f"{node.module}.{alias.name}"

    return module_alias_map, file_imports


def _pass_scopes(
    tree: ast.Module,
    source: str,
    rel: str,
    module_alias_map: dict[str, str],
    file_imports: set[str],
    var_capability_map: dict[str, Capability],
    graph: EffectGraph,
) -> None:
    """Process module-level and all function scopes."""
    # Module-level scope
    _analyze_scope(
        tree, source, rel, "<module>",
        module_alias_map, file_imports, var_capability_map, graph,
    )
    # Function scopes
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _analyze_scope(
                node, source, rel, node.name,
                module_alias_map, file_imports, var_capability_map, graph,
            )


def _analyze_scope(
    scope: ast.AST,
    source: str,
    rel: str,
    func_name: str,
    module_alias_map: dict[str, str],
    file_imports: set[str],
    var_capability_map: dict[str, Capability],
    graph: EffectGraph,
) -> None:
    """Analyze a single scope: build abstract env, emit nodes."""
    env: AbstractEnv = {}

    # Pass 2: Build abstract env from assignments
    _build_abstract_env(scope, env, module_alias_map, file_imports)

    # Propagate capabilities to shared map
    for var_name, values in env.items():
        cap = get_capability(values)
        if cap:
            var_capability_map[var_name] = cap

    # Pass 3: Analyze calls with abstract typing
    _analyze_calls(scope, source, rel, func_name, env, module_alias_map, file_imports, graph)

    # Pass 4: Detect conditional effects
    _detect_conditional_effects(scope, source, rel, env, graph)

    # Taint propagation: BFS within scope
    _propagate_taint(scope, env, rel, graph)


def _build_abstract_env(
    scope: ast.AST,
    env: AbstractEnv,
    module_alias_map: dict[str, str],
    file_imports: set[str],
) -> None:
    """Pass 2: Walk assignments and build AbstractEnv for the scope."""
    for node in ast.walk(scope):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    values = _eval_expr(node.value, env, module_alias_map, file_imports)
                    env[target.id] = values
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            if isinstance(node.target, ast.Name):
                values = _eval_expr(node.value, env, module_alias_map, file_imports)
                env[node.target.id] = values
        # Tuple unpacking: a, b = some_call()
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Tuple):
                    for elt in target.elts:
                        if isinstance(elt, ast.Name):
                            env[elt.id] = [Unknown()]


def _eval_expr(
    expr: ast.expr,
    env: AbstractEnv,
    module_alias_map: dict[str, str],
    file_imports: set[str],
) -> list[AbstractValue]:
    """Evaluate an expression to a list of AbstractValues."""
    if isinstance(expr, ast.Constant):
        return [Literal(expr.value)]

    if isinstance(expr, ast.Name):
        name = expr.id
        if name in env:
            return list(env[name])
        # Check if it's a None/True/False constant
        if name in ("None", "True", "False"):
            return [Literal({"None": None, "True": True, "False": False}[name])]
        return [Unknown()]

    if isinstance(expr, ast.Call):
        return _eval_call(expr, env, module_alias_map, file_imports)

    if isinstance(expr, ast.JoinedStr):
        # f-string: check if any formatted value is tainted
        for val in expr.values:
            if isinstance(val, ast.FormattedValue):
                child_vals = _eval_expr(val.value, env, module_alias_map, file_imports)
                tainted = get_taint(child_vals)
                if tainted:
                    return [Tainted(trust=tainted.trust,
                                   sources=tainted.sources | frozenset(["f-string"]))]
        return [UnknownStr()]

    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        left = _eval_expr(expr.left, env, module_alias_map, file_imports)
        right = _eval_expr(expr.right, env, module_alias_map, file_imports)
        return join_values(left, right)

    if isinstance(expr, ast.Lambda):
        # Lambda: check if body is a sink call
        return _eval_lambda(expr, env, module_alias_map, file_imports)

    if isinstance(expr, ast.Attribute):
        # x.y → get capability of x, then return Unknown
        return [Unknown()]

    if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
        return [Unknown()]

    if isinstance(expr, ast.Dict):
        return [Unknown()]

    return [Unknown()]


def _eval_call(
    call: ast.Call,
    env: AbstractEnv,
    module_alias_map: dict[str, str],
    file_imports: set[str],
) -> list[AbstractValue]:
    """Evaluate a call expression."""
    func_name = _get_call_name(call)

    # Check registry constructors
    if func_name:
        entry = lookup_by_constructor(func_name)
        if entry:
            return [Object(capability=entry.capability, service_name=entry.service_name)]

    # Check source patterns
    attr_chain = _get_attr_chain(call.func)
    if attr_chain:
        for pattern, trust in SOURCE_PATTERNS.items():
            if attr_chain == pattern or attr_chain.endswith(f".{pattern}"):
                return [Tainted(trust=trust, sources=frozenset([attr_chain]))]

    # Common source calls
    if func_name in ("getenv", "os.getenv") or attr_chain in (
        "os.getenv", "os.environ.get", "environ.get"
    ):
        return [Tainted(trust=SourceTrust.OPERATOR_CONTROLLED,
                       sources=frozenset(["os.getenv"]))]

    if attr_chain and "headers" in attr_chain and ".get" in attr_chain:
        return [Tainted(trust=SourceTrust.HEADER_CONTROLLED,
                       sources=frozenset([attr_chain]))]

    if attr_chain and attr_chain.endswith(".json"):
        return [Tainted(trust=SourceTrust.EXTERNAL_UNTRUSTED,
                       sources=frozenset([attr_chain]))]
    if attr_chain and attr_chain.endswith((".text", ".content")):
        # Could be response.text or other
        receiver_name = attr_chain.rsplit(".", 1)[0] if "." in attr_chain else ""
        if receiver_name in ("response", "resp", "r", "res"):
            return [Tainted(trust=SourceTrust.EXTERNAL_UNTRUSTED,
                           sources=frozenset([attr_chain]))]

    # Factory summaries
    if func_name and func_name in FACTORY_SUMMARIES:
        return [FACTORY_SUMMARIES[func_name]]

    # Ends-with match for factory summaries
    if func_name:
        for pattern, val in FACTORY_SUMMARIES.items():
            if func_name.endswith(pattern):
                return [val]

    return [Unknown()]


def _eval_lambda(
    lam: ast.Lambda,
    env: AbstractEnv,
    module_alias_map: dict[str, str],
    file_imports: set[str],
) -> list[AbstractValue]:
    """Evaluate a lambda expression — check if body is a sink call."""
    for node in ast.walk(lam.body):
        if not isinstance(node, ast.Call):
            continue

        receiver_cap = _get_receiver_capability(node.func, env)
        if receiver_cap is None:
            continue

        entry = None
        for name, e in CAPABILITY_REGISTRY.items():
            if e.capability == receiver_cap:
                entry = e
                break

        if entry is None:
            continue

        method = _get_call_method(node)
        if method and method in entry.sink_methods:
            return [Effect(sink_kind=entry.sink_kind)]

    return [Unknown()]


def _analyze_calls(
    scope: ast.AST,
    source: str,
    rel: str,
    func_name: str,
    env: AbstractEnv,
    module_alias_map: dict[str, str],
    file_imports: set[str],
    graph: EffectGraph,
) -> None:
    """Pass 3: Walk calls and emit source/sink nodes."""
    for node in ast.walk(scope):
        if not isinstance(node, ast.Call):
            continue

        attr_chain = _get_attr_chain(node.func)
        call_name = _get_call_name(node)
        line = node.lineno

        # ── Source detection ──────────────────────────────────────────────
        for pattern, trust in SOURCE_PATTERNS.items():
            if attr_chain and (attr_chain == pattern or attr_chain.endswith(f".{pattern}")):
                src_id = f"{rel}::{line}::source::{pattern}"
                src_node = EffectNode(
                    id=src_id,
                    kind="source",
                    file=rel,
                    line=line,
                    name=pattern,
                    source_trust=trust,
                    metadata={"func": func_name},
                )
                graph.add_node(src_node)
                break

        # ── Module-level init calls (sentry_sdk.init, etc.) ──────────────
        if attr_chain:
            root_mod = attr_chain.split(".")[0]
            module_entry = lookup_by_module(root_mod)
            if module_entry and module_entry.implicit_egress_on_init:
                # Check if this is an .init() call
                method = attr_chain.split(".")[-1] if "." in attr_chain else ""
                if method in ("init", "init_app", "configure"):
                    sink_id = f"{rel}::{line}::sink::{root_mod}_init"
                    sink_node = EffectNode(
                        id=sink_id,
                        kind="sink",
                        file=rel,
                        line=line,
                        name=f"{root_mod}.{method}",
                        capability=module_entry.capability,
                        sink_kind=module_entry.sink_kind,
                        confidence=0.95,
                        metadata={
                            "service": module_entry.service_name,
                            "func": func_name,
                            "implicit_egress": True,
                        },
                    )
                    graph.add_node(sink_node)

        # ── Receiver capability-based sink detection ──────────────────────
        if isinstance(node.func, ast.Attribute):
            receiver_cap = _get_receiver_capability(node.func, env)
            method = node.func.attr

            if receiver_cap is not None:
                # FALSE-POSITIVE GUARD: GRAPH_RUNTIME ainvoke/invoke is NOT an LLM sink
                if receiver_cap == Capability.GRAPH_RUNTIME:
                    continue

                # Find the matching entry
                for entry_name, entry in CAPABILITY_REGISTRY.items():
                    if entry.capability != receiver_cap:
                        continue
                    if method not in entry.sink_methods:
                        continue

                    sink_id = f"{rel}::{line}::sink::{method}"
                    sink_node = EffectNode(
                        id=sink_id,
                        kind="sink",
                        file=rel,
                        line=line,
                        name=method,
                        capability=entry.capability,
                        sink_kind=entry.sink_kind,
                        confidence=0.9,
                        metadata={
                            "service": entry.service_name,
                            "func": func_name,
                        },
                    )
                    graph.add_node(sink_node)

                    # Emit source→sink edges from any tainted args
                    _emit_taint_edges(node, rel, line, sink_id, env, graph)
                    break

        # ── Wrapper function unwrapping ───────────────────────────────────
        if call_name and call_name in WRAPPER_FUNCS:
            _unwrap_wrapper_call(node, source, rel, func_name, env, module_alias_map,
                                 file_imports, graph)


def _unwrap_wrapper_call(
    call: ast.Call,
    source: str,
    rel: str,
    func_name: str,
    env: AbstractEnv,
    module_alias_map: dict[str, str],
    file_imports: set[str],
    graph: EffectGraph,
) -> None:
    """Analyze lambda/callable args inside wrapper functions for effects."""
    for arg in call.args:
        if isinstance(arg, ast.Lambda):
            # Check if lambda body contains a sink call
            for node in ast.walk(arg.body):
                if not isinstance(node, ast.Call):
                    continue
                if not isinstance(node.func, ast.Attribute):
                    continue

                receiver_cap = _get_receiver_capability(node.func, env)
                if receiver_cap is None or receiver_cap == Capability.GRAPH_RUNTIME:
                    continue

                method = node.func.attr
                for entry_name, entry in CAPABILITY_REGISTRY.items():
                    if entry.capability != receiver_cap:
                        continue
                    if method not in entry.sink_methods:
                        continue

                    sink_id = f"{rel}::{node.lineno}::sink::{method}_wrapped"
                    sink_node = EffectNode(
                        id=sink_id,
                        kind="sink",
                        file=rel,
                        line=node.lineno,
                        name=method,
                        capability=entry.capability,
                        sink_kind=entry.sink_kind,
                        confidence=0.85,
                        metadata={
                            "service": entry.service_name,
                            "func": func_name,
                            "wrapped": True,
                        },
                    )
                    graph.add_node(sink_node)
                    _emit_taint_edges(node, rel, node.lineno, sink_id, env, graph)
                    break


def _detect_conditional_effects(
    scope: ast.AST,
    source: str,
    rel: str,
    env: AbstractEnv,
    graph: EffectGraph,
) -> None:
    """Pass 4: Mark sink nodes inside env-guarded if blocks as conditional."""
    for node in ast.walk(scope):
        # if env_var != "prod": return  (early exit guard)
        if isinstance(node, ast.If):
            is_guard = _is_env_guard(node.test, env)
            if is_guard:
                # Find sink nodes in the body (the non-guarded branch)
                for child in ast.walk(node):
                    for n_id, n in graph._nodes.items():
                        if n.kind == "sink" and n.file == rel and n.line == getattr(child, "lineno", -1):
                            n.metadata["conditional"] = True
                            n.metadata["condition_hint"] = "env_var check"

        # try/except around calls → mark as conditional
        if isinstance(node, ast.Try):
            for child in ast.walk(node):
                for n_id, n in graph._nodes.items():
                    if n.kind == "sink" and n.file == rel and n.line == getattr(child, "lineno", -1):
                        n.metadata["conditional"] = True
                        n.metadata["condition_hint"] = "try/except"


def _is_env_guard(test: ast.expr, env: AbstractEnv) -> bool:
    """Check if a test expression is an env-var guard like `env_var != "prod"`."""
    if isinstance(test, ast.Compare):
        left = test.left
        if isinstance(left, ast.Name) and left.id in env:
            vals = env[left.id]
            if any(isinstance(v, Tainted) and v.trust == SourceTrust.OPERATOR_CONTROLLED
                   for v in vals):
                return True
    return False


def _pass5_decorators(
    tree: ast.Module,
    source: str,
    rel: str,
    module_alias_map: dict[str, str],
    graph: EffectGraph,
) -> None:
    """Pass 5: Detect decorators from registered modules with decorator_sink."""
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        for dec in node.decorator_list:
            dec_name = _get_decorator_name(dec)
            if not dec_name:
                continue

            # Check if this decorator name matches a registry entry with decorator_sink
            for reg_key, entry in CAPABILITY_REGISTRY.items():
                if entry.decorator_sink is None:
                    continue

                # Check if the decorator module matches
                canonical = module_alias_map.get(dec_name.split(".")[0])
                if canonical and reg_key in canonical:
                    _emit_decorator_sink(dec, node, rel, entry, graph)
                    break

                # Also check by decorator name directly (e.g. "traceable" from langsmith)
                if dec_name == "traceable" and reg_key == "langsmith":
                    _emit_decorator_sink(dec, node, rel, entry, graph)
                    break


def _emit_decorator_sink(
    dec: ast.expr,
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    rel: str,
    entry,
    graph: EffectGraph,
) -> None:
    """Emit a sink node for a decorator."""
    line = dec.lineno if hasattr(dec, "lineno") else func_node.lineno
    sink_id = f"{rel}::{line}::sink::decorator_{func_node.name}"
    dec_id = f"{rel}::{line}::decorator::{func_node.name}"

    dec_node = EffectNode(
        id=dec_id,
        kind="decorator",
        file=rel,
        line=line,
        name=func_node.name,
        capability=entry.capability,
        sink_kind=entry.decorator_sink,
        metadata={"service": entry.service_name},
    )
    graph.add_node(dec_node)

    func_id = f"{rel}::{func_node.lineno}::function::{func_node.name}"
    func_node_ir = EffectNode(
        id=func_id,
        kind="function",
        file=rel,
        line=func_node.lineno,
        name=func_node.name,
    )
    graph.add_node(func_node_ir)

    graph.add_edge(EffectEdge(
        src=dec_id,
        dst=func_id,
        kind="wraps",
        file=rel,
        line=line,
    ))


def _propagate_taint(
    scope: ast.AST,
    env: AbstractEnv,
    rel: str,
    graph: EffectGraph,
) -> None:
    """BFS taint propagation: variables assigned from tainted exprs inherit taint.

    Emits data_flows_to edges from source nodes to sink nodes.
    """
    # Find all sink nodes in this file
    sink_nodes = [n for n in graph.all_nodes() if n.kind == "sink" and n.file == rel]
    source_nodes = [n for n in graph.all_nodes() if n.kind == "source" and n.file == rel]

    if not sink_nodes or not source_nodes:
        return

    # For each tainted var in env, check if it appears in calls near sink nodes
    tainted_vars: set[str] = set()
    for var_name, values in env.items():
        if is_tainted(values):
            tainted_vars.add(var_name)

    if not tainted_vars:
        return

    # Walk the scope looking for sink calls that reference tainted vars
    for node in ast.walk(scope):
        if not isinstance(node, ast.Call):
            continue

        call_names = _collect_names(node)
        tainted_in_call = call_names & tainted_vars
        if not tainted_in_call:
            continue

        # Find any sink at this line
        for sink in sink_nodes:
            if abs(sink.line - node.lineno) <= 2:
                # Find source nodes for tainted vars
                for var_name in tainted_in_call:
                    for src in source_nodes:
                        if var_name in src.name or src.name in var_name:
                            edge = EffectEdge(
                                src=src.id,
                                dst=sink.id,
                                kind="data_flows_to",
                                file=rel,
                                line=node.lineno,
                                confidence=0.8,
                            )
                            graph.add_edge(edge)
                            break


def _emit_taint_edges(
    call: ast.Call,
    rel: str,
    line: int,
    sink_id: str,
    env: AbstractEnv,
    graph: EffectGraph,
) -> None:
    """Emit data_flows_to edges from source nodes to sink for tainted arguments."""
    arg_names = _collect_names(call)
    source_nodes = [n for n in graph.all_nodes() if n.kind == "source" and n.file == rel]

    for var_name in arg_names:
        if var_name not in env:
            continue
        values = env[var_name]
        taint = get_taint(values)
        if taint is None:
            continue

        # Find a source node that matches
        for src in source_nodes:
            if (src.source_trust == taint.trust
                    or any(s in src.name for s in taint.sources)):
                graph.add_edge(EffectEdge(
                    src=src.id,
                    dst=sink_id,
                    kind="data_flows_to",
                    file=rel,
                    line=line,
                    confidence=0.85,
                ))
                break


# ── AST helpers ──────────────────────────────────────────────────────────


def _get_call_name(call: ast.Call) -> str | None:
    """Get the simple function name from a call."""
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    return None


def _get_call_method(call: ast.Call) -> str | None:
    """Get just the method name from a call."""
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
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
    elif isinstance(cur, ast.Subscript):
        pass  # Skip subscript receivers
    return ".".join(reversed(parts)) if parts else ""


def _get_receiver_capability(
    func: ast.expr,
    env: AbstractEnv,
) -> Capability | None:
    """Get the capability of the receiver in an attribute call."""
    if not isinstance(func, ast.Attribute):
        return None

    receiver = func.value
    receiver_name = None

    if isinstance(receiver, ast.Name):
        receiver_name = receiver.id
    elif isinstance(receiver, ast.Attribute):
        # Chained: self.llm.invoke → check self.llm
        if isinstance(receiver.value, ast.Name):
            # Try the full chain first
            chain = f"{receiver.value.id}.{receiver.attr}"
            if chain in env:
                return get_capability(env[chain])
            # Then try just the attribute
            receiver_name = receiver.attr

    if receiver_name and receiver_name in env:
        return get_capability(env[receiver_name])

    return None


def _get_decorator_name(dec: ast.expr) -> str | None:
    """Get the name/chain of a decorator."""
    if isinstance(dec, ast.Name):
        return dec.id
    if isinstance(dec, ast.Attribute):
        chain = _get_attr_chain(dec)
        return chain or None
    if isinstance(dec, ast.Call):
        return _get_decorator_name(dec.func)
    return None


def _collect_names(node: ast.AST) -> set[str]:
    """Collect all Name references within an AST subtree."""
    names: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            names.add(child.id)
    return names

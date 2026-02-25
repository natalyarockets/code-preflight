"""Detect LLM call sites and trace which variables flow into prompts.

For each LLM call (invoke, create, completion, etc.), identifies the prompt
argument and traces variable references backward through f-strings, .format(),
concatenation, and simple assignment chains.
"""

from __future__ import annotations

import ast
from pathlib import Path

from la_analyzer.analyzer.models import (
    Evidence,
    PromptSurface,
    PromptSurfaceReport,
    PromptVariable,
)

# LLM SDK method names that indicate a call site
_LLM_METHODS = {
    "invoke",          # LangChain
    "ainvoke",         # LangChain async
    "create",          # OpenAI / Anthropic .messages.create / .chat.completions.create
    "completion",      # litellm.completion()
    "acompletion",     # litellm.acompletion()
    "generate",        # various
    "generate_content",  # Google generativeai
    "chat",            # cohere.chat()
    "run",             # various agent.run()
    "predict",         # LangChain legacy
}

# LLM SDK libraries -- a call is only considered an LLM call if the file
# imports one of these.
_LLM_LIBS = {
    "openai", "anthropic", "langchain", "langchain_openai",
    "langchain_anthropic", "langchain_community", "langchain_core",
    "litellm", "cohere", "google", "replicate", "groq", "together",
    "huggingface_hub",
}

# Keyword arg names that carry prompt content
_PROMPT_KWARGS = {"content", "messages", "prompt", "input", "text", "query"}


def scan_prompt_surfaces(
    workspace: Path,
    py_files: list[Path],
) -> PromptSurfaceReport:
    """Scan Python files for LLM call sites and trace prompt variables."""
    surfaces: list[PromptSurface] = []

    for fpath in py_files:
        rel = str(fpath.relative_to(workspace))
        try:
            source = fpath.read_text(errors="replace")
            tree = ast.parse(source, filename=rel)
        except SyntaxError:
            continue

        # Check if file imports any LLM library
        if not _has_llm_imports(tree):
            continue

        # Collect string constant assignments: NAME = "literal" (module-level only)
        str_constants = _collect_string_constants(tree)

        # Find all function bodies (for scoping variable lookups)
        func_bodies = _collect_function_scopes(tree)

        # Build var→capability map to detect GRAPH_RUNTIME receivers
        graph_runtime_vars = _collect_graph_runtime_vars(tree)

        # Walk the AST looking for LLM call sites
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            method = _get_llm_method(node)
            if not method:
                continue

            # GRAPH_RUNTIME guard: skip ainvoke/invoke on graph app vars
            if method in ("invoke", "ainvoke") and _is_graph_runtime_receiver(node, graph_runtime_vars):
                continue

            # Find enclosing function
            func_name = _find_enclosing_func(tree, node)

            # Trace prompt arguments
            prompt_vars: list[PromptVariable] = []
            constants: list[str] = []

            # Look for prompt content in keyword args and positional args
            prompt_exprs = _extract_prompt_exprs(node)

            # Get the function body scope for backward tracing
            scope_assignments = func_bodies.get(func_name, {})

            for expr in prompt_exprs:
                _trace_expression(
                    expr, scope_assignments, str_constants,
                    prompt_vars, constants, depth=0,
                )

            # Also check lambda bodies wrapping LLM calls
            _check_lambda_args(node, scope_assignments, str_constants,
                               prompt_vars, constants, method)

            if prompt_vars or constants:
                ev = Evidence(
                    file=rel, line=node.lineno,
                    snippet=_snippet(source, node.lineno),
                    function_name=func_name if func_name != "<module>" else None,
                )
                surfaces.append(PromptSurface(
                    function=func_name,
                    file=rel,
                    line=node.lineno,
                    llm_method=method,
                    prompt_variables=_dedupe_vars(prompt_vars),
                    string_constants=list(dict.fromkeys(constants)),
                    evidence=[ev],
                ))

    return PromptSurfaceReport(surfaces=surfaces)


# ── Helpers ───────────────────────────────────────────────────────────────


def _has_llm_imports(tree: ast.AST) -> bool:
    """Check if the file imports any known LLM library."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in _LLM_LIBS:
                    return True
        if isinstance(node, ast.ImportFrom) and node.module:
            if node.module.split(".")[0] in _LLM_LIBS:
                return True
    return False


def _collect_string_constants(tree: ast.AST) -> dict[str, str]:
    """Collect module-level string constant assignments: NAME = 'literal'.

    Only walks direct children of the module node (not into function bodies)
    to avoid confusing local assignments with module-level constants.
    """
    constants: dict[str, str] = {}
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if (isinstance(target, ast.Name)
                    and isinstance(node.value, ast.Constant)
                    and isinstance(node.value.value, str)):
                constants[target.id] = node.value.value
    return constants


def _collect_function_scopes(tree: ast.AST) -> dict[str, dict[str, ast.expr]]:
    """Map function_name -> {var_name: assigned_expression} for local assignments."""
    scopes: dict[str, dict[str, ast.expr]] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            assignments: dict[str, ast.expr] = {}
            for child in ast.walk(node):
                if isinstance(child, ast.Assign) and len(child.targets) == 1:
                    target = child.targets[0]
                    if isinstance(target, ast.Name):
                        assignments[target.id] = child.value
            scopes[node.name] = assignments
    return scopes


def _get_llm_method(node: ast.Call) -> str | None:
    """If this Call is an LLM method, return the method name."""
    if isinstance(node.func, ast.Attribute) and node.func.attr in _LLM_METHODS:
        return node.func.attr
    if isinstance(node.func, ast.Name) and node.func.id in _LLM_METHODS:
        return node.func.id
    return None


def _find_enclosing_func(tree: ast.AST, target_node: ast.AST) -> str:
    """Find the function name enclosing the target node."""
    # Build parent map
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            child._parent = node  # type: ignore[attr-defined]

    current = target_node
    while hasattr(current, "_parent"):
        current = current._parent  # type: ignore[attr-defined]
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return current.name
    return "<module>"


def _extract_prompt_exprs(node: ast.Call) -> list[ast.expr]:
    """Extract expressions that carry prompt content from a call."""
    exprs: list[ast.expr] = []

    # Check keyword args matching prompt-related names
    for kw in node.keywords:
        if kw.arg in _PROMPT_KWARGS:
            # If it's a list of messages, dig into dict literals for "content" keys
            if isinstance(kw.value, ast.List):
                for elt in kw.value.elts:
                    _extract_content_from_message(elt, exprs)
            else:
                exprs.append(kw.value)

    # For invoke(), first positional arg is the prompt
    if isinstance(node.func, ast.Attribute) and node.func.attr in ("invoke", "ainvoke", "predict"):
        if node.args:
            arg = node.args[0]
            if isinstance(arg, ast.List):
                for elt in arg.elts:
                    _extract_content_from_message(elt, exprs)
            else:
                exprs.append(arg)

    # For completion/create without matched kwargs, check first positional
    if not exprs and node.args:
        # Don't grab the first arg blindly -- only if no kwargs matched
        pass

    return exprs


def _extract_content_from_message(node: ast.expr, exprs: list[ast.expr]) -> None:
    """Extract 'content' value from a message dict literal or HumanMessage()."""
    if isinstance(node, ast.Dict):
        for k, v in zip(node.keys, node.values):
            if isinstance(k, ast.Constant) and k.value == "content" and v:
                exprs.append(v)
    elif isinstance(node, ast.Call):
        # HumanMessage(content=...) / SystemMessage(content=...)
        for kw in node.keywords:
            if kw.arg == "content":
                exprs.append(kw.value)
        # HumanMessage("prompt text") -- positional
        if node.args:
            exprs.append(node.args[0])


def _trace_expression(
    expr: ast.expr,
    scope: dict[str, ast.expr],
    str_constants: dict[str, str],
    out_vars: list[PromptVariable],
    out_constants: list[str],
    depth: int,
) -> None:
    """Trace an expression using a worklist to find variable references and constants.

    The depth parameter is kept for API compatibility but is ignored — the worklist
    uses a node_budget and visited_names set for cycle prevention instead.
    """
    _trace_worklist(expr, scope, str_constants, out_vars, out_constants, node_budget=50)


def _trace_worklist(
    start_expr: ast.expr,
    scope: dict[str, ast.expr],
    str_constants: dict[str, str],
    out_vars: list[PromptVariable],
    out_constants: list[str],
    *,
    node_budget: int = 50,
) -> None:
    """Worklist-based expression tracer. Replaces the depth-limited recursive version."""
    stack: list[tuple[ast.expr, str]] = [(start_expr, "param")]  # (expr, origin_hint)
    visited_names: set[str] = set()
    budget = node_budget

    while stack and budget > 0:
        budget -= 1
        expr, origin = stack.pop()

        if isinstance(expr, ast.JoinedStr):
            # f-string: push all FormattedValue children
            for val in expr.values:
                if isinstance(val, ast.FormattedValue):
                    stack.append((val.value, "f-string"))

        elif isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
            stack.append((expr.left, origin))
            stack.append((expr.right, origin))

        elif (isinstance(expr, ast.Call)
              and isinstance(expr.func, ast.Attribute)
              and expr.func.attr == "format"):
            stack.append((expr.func.value, origin))
            for kw in expr.keywords:
                if kw.arg:
                    out_vars.append(PromptVariable(name=kw.arg, origin="format"))
            for arg in expr.args:
                if isinstance(arg, ast.Name):
                    out_vars.append(PromptVariable(name=arg.id, origin="format"))

        elif isinstance(expr, ast.Name):
            name = expr.id
            if name in visited_names:
                continue
            visited_names.add(name)

            if name in str_constants:
                out_constants.append(name)
            elif name in scope:
                stack.append((scope[name], origin))
            else:
                out_vars.append(PromptVariable(name=name, origin=origin))

        elif isinstance(expr, ast.Constant) and isinstance(expr.value, str):
            pass  # Inline string literal — not a named variable, skip

        elif isinstance(expr, ast.List):
            for elt in expr.elts:
                stack.append((elt, origin))

        elif isinstance(expr, ast.Tuple):
            for elt in expr.elts:
                stack.append((elt, origin))

        elif isinstance(expr, ast.Dict):
            for v in expr.values:
                if v:
                    stack.append((v, origin))


def _check_lambda_args(
    node: ast.Call,
    scope: dict[str, ast.expr],
    str_constants: dict[str, str],
    out_vars: list[PromptVariable],
    out_constants: list[str],
    parent_method: str,
) -> None:
    """Check lambda arguments for nested LLM calls."""
    for arg in node.args:
        if isinstance(arg, ast.Lambda):
            for lnode in ast.walk(arg.body):
                if isinstance(lnode, ast.Call):
                    method = _get_llm_method(lnode)
                    if method:
                        prompt_exprs = _extract_prompt_exprs(lnode)
                        for expr in prompt_exprs:
                            _trace_expression(expr, scope, str_constants,
                                              out_vars, out_constants, depth=0)


def _collect_graph_runtime_vars(tree: ast.AST) -> set[str]:
    """Collect variable names that hold LangGraph StateGraph/CompiledStateGraph instances."""
    _GRAPH_RUNTIME_CONSTRUCTORS = {
        "StateGraph", "CompiledStateGraph", "MessageGraph",
        "Graph",  # generic langgraph graph
    }
    graph_vars: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            call_name = None
            if isinstance(node.value.func, ast.Name):
                call_name = node.value.func.id
            elif isinstance(node.value.func, ast.Attribute):
                call_name = node.value.func.attr
            if call_name in _GRAPH_RUNTIME_CONSTRUCTORS:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        graph_vars.add(target.id)
        # Also: compiled = graph.compile(...)
        elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            if (isinstance(node.value.func, ast.Attribute)
                    and node.value.func.attr == "compile"):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        graph_vars.add(target.id)

    return graph_vars


def _is_graph_runtime_receiver(call: ast.Call, graph_runtime_vars: set[str]) -> bool:
    """Return True if the call receiver is a known graph runtime variable."""
    if not isinstance(call.func, ast.Attribute):
        return False

    receiver = call.func.value
    name = None
    if isinstance(receiver, ast.Name):
        name = receiver.id
    elif isinstance(receiver, ast.Attribute):
        name = receiver.attr

    if name is None:
        return False

    # Check against explicit graph vars
    if name in graph_runtime_vars:
        return True

    # Heuristic: variable name contains graph/workflow/app but not llm/model
    name_lower = name.lower()
    graph_hints = {"graph", "workflow", "compiled", "agent_graph", "state_graph"}
    llm_hints = {"llm", "model", "client", "chat"}
    for h in graph_hints:
        if h in name_lower:
            return True
    for h in llm_hints:
        if h in name_lower:
            return False

    return False


def _dedupe_vars(variables: list[PromptVariable]) -> list[PromptVariable]:
    """Deduplicate variables by name, keeping first occurrence."""
    seen: set[str] = set()
    result: list[PromptVariable] = []
    for v in variables:
        if v.name not in seen:
            seen.add(v.name)
            result.append(v)
    return result


def _snippet(source: str, lineno: int) -> str:
    lines = source.splitlines()
    if 0 < lineno <= len(lines):
        return lines[lineno - 1].strip()[:160]
    return ""

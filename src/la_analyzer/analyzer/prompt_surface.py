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

        # Collect string constant assignments: NAME = "literal"
        str_constants = _collect_string_constants(tree)

        # Find all function bodies (for scoping variable lookups)
        func_bodies = _collect_function_scopes(tree)

        # Walk the AST looking for LLM call sites
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            method = _get_llm_method(node)
            if not method:
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
    """Collect module-level string constant assignments: NAME = 'literal'."""
    constants: dict[str, str] = {}
    for node in ast.walk(tree):
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
    """Recursively trace an expression to find variable references and constants."""
    if depth > 3:
        return

    if isinstance(expr, ast.JoinedStr):
        # f-string: extract FormattedValue variable names
        for val in expr.values:
            if isinstance(val, ast.FormattedValue):
                _trace_expression(val.value, scope, str_constants,
                                  out_vars, out_constants, depth + 1)
    elif isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        # String concatenation: a + b + "..."
        _trace_expression(expr.left, scope, str_constants,
                          out_vars, out_constants, depth + 1)
        _trace_expression(expr.right, scope, str_constants,
                          out_vars, out_constants, depth + 1)
    elif isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute) and expr.func.attr == "format":
        # "...".format(key=val, ...) or "...".format(val, ...)
        _trace_expression(expr.func.value, scope, str_constants,
                          out_vars, out_constants, depth + 1)
        for kw in expr.keywords:
            if kw.arg:
                out_vars.append(PromptVariable(name=kw.arg, origin="format"))
        for arg in expr.args:
            if isinstance(arg, ast.Name):
                out_vars.append(PromptVariable(name=arg.id, origin="format"))
    elif isinstance(expr, ast.Name):
        name = expr.id
        # Check if it resolves to a string constant
        if name in str_constants:
            out_constants.append(name)
        elif name in scope:
            # Recurse into the assigned expression
            _trace_expression(scope[name], scope, str_constants,
                              out_vars, out_constants, depth + 1)
        else:
            out_vars.append(PromptVariable(name=name, origin="param"))
    elif isinstance(expr, ast.Constant) and isinstance(expr.value, str):
        # Inline string literal -- not a named constant, skip
        pass
    elif isinstance(expr, ast.List):
        for elt in expr.elts:
            _trace_expression(elt, scope, str_constants,
                              out_vars, out_constants, depth + 1)
    elif isinstance(expr, ast.Dict):
        for v in expr.values:
            if v:
                _trace_expression(v, scope, str_constants,
                                  out_vars, out_constants, depth + 1)


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

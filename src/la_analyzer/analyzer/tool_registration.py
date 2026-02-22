"""Detect functions registered as LLM-callable tools and classify their capabilities.

Patterns detected:
- @tool / @tool() decorators (LangChain, smolagents)
- .bind_tools([func1, func2])
- tools=[{"type": "function", "function": {"name": ...}}] (OpenAI schema)
- StructuredTool.from_function(func=my_func)
"""

from __future__ import annotations

import ast
from pathlib import Path

from la_analyzer.analyzer.models import (
    Evidence,
    RegisteredTool,
    ToolCapability,
    ToolRegistrationReport,
)

# Method/function calls that indicate network access
_NETWORK_CALLS = {
    "get", "post", "put", "patch", "delete", "head", "options", "request",
    "fetch", "urlopen",
}
_NETWORK_MODULES = {"requests", "httpx", "aiohttp", "urllib", "urllib3"}

# File operations
_FILE_READ_CALLS = {"read", "read_text", "read_bytes", "read_csv", "read_excel",
                     "read_json", "read_parquet", "read_feather", "load"}
_FILE_WRITE_CALLS = {"write", "write_text", "write_bytes", "to_csv", "to_excel",
                      "to_json", "to_parquet", "save", "dump"}

# Database operations
_DB_CALLS = {"execute", "executemany", "query", "fetch", "fetchone", "fetchall",
             "fetchrow", "find", "find_one", "insert", "update", "delete_one",
             "aggregate"}
_DB_RECEIVERS = {"cursor", "cur", "conn", "connection", "db", "session",
                 "engine", "collection", "table"}

# Dangerous operations
_SUBPROCESS_CALLS = {"run", "call", "Popen", "check_output", "check_call",
                     "system", "exec", "eval", "execfile"}
_SUBPROCESS_MODULES = {"subprocess", "os"}


def scan_tool_registrations(
    workspace: Path,
    py_files: list[Path],
) -> ToolRegistrationReport:
    """Scan Python files for LLM tool registrations."""
    tools: list[RegisteredTool] = []

    for fpath in py_files:
        rel = str(fpath.relative_to(workspace))
        try:
            source = fpath.read_text(errors="replace")
            tree = ast.parse(source, filename=rel)
        except SyntaxError:
            continue

        # Collect function definitions for reference
        func_defs: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func_defs[node.name] = node

        # Pattern 1 & 2: @tool / @tool() decorated functions
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for dec in node.decorator_list:
                is_tool = False
                if isinstance(dec, ast.Name) and dec.id == "tool":
                    is_tool = True
                elif isinstance(dec, ast.Call):
                    if isinstance(dec.func, ast.Name) and dec.func.id == "tool":
                        is_tool = True
                    elif isinstance(dec.func, ast.Attribute) and dec.func.attr == "tool":
                        is_tool = True

                if is_tool:
                    params = [
                        a.arg for a in node.args.args
                        if a.arg != "self"
                    ]
                    docstring = ast.get_docstring(node) or ""
                    caps = _classify_capabilities(node, source)
                    ev = Evidence(
                        file=rel, line=node.lineno,
                        snippet=_snippet(source, node.lineno),
                        function_name=node.name,
                    )
                    tools.append(RegisteredTool(
                        name=node.name,
                        file=rel,
                        line=node.lineno,
                        registration="@tool",
                        docstring=docstring,
                        parameters=params,
                        capabilities=caps,
                        evidence=[ev],
                    ))
                    break  # Only count one @tool per function

        # Pattern 3: .bind_tools([func1, func2])
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Attribute) and node.func.attr == "bind_tools":
                if node.args and isinstance(node.args[0], ast.List):
                    for elt in node.args[0].elts:
                        if isinstance(elt, ast.Name) and elt.id in func_defs:
                            fdef = func_defs[elt.id]
                            params = [
                                a.arg for a in fdef.args.args
                                if a.arg != "self"
                            ]
                            docstring = ast.get_docstring(fdef) or ""
                            caps = _classify_capabilities(fdef, source)
                            ev = Evidence(
                                file=rel, line=node.lineno,
                                snippet=_snippet(source, node.lineno),
                                function_name=elt.id,
                            )
                            tools.append(RegisteredTool(
                                name=elt.id,
                                file=rel,
                                line=fdef.lineno,
                                registration="bind_tools",
                                docstring=docstring,
                                parameters=params,
                                capabilities=caps,
                                evidence=[ev],
                            ))

        # Pattern 4: tools=[{"type": "function", "function": {"name": "search"}}]
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            for kw in node.keywords:
                if kw.arg == "tools" and isinstance(kw.value, ast.List):
                    for elt in kw.value.elts:
                        name = _extract_openai_tool_name(elt)
                        if name:
                            ev = Evidence(
                                file=rel, line=elt.lineno if hasattr(elt, "lineno") else node.lineno,
                                snippet=_snippet(source, node.lineno),
                            )
                            # Try to find matching function def for capabilities
                            caps: list[ToolCapability] = []
                            params: list[str] = []
                            docstring = ""
                            if name in func_defs:
                                fdef = func_defs[name]
                                caps = _classify_capabilities(fdef, source)
                                params = [a.arg for a in fdef.args.args if a.arg != "self"]
                                docstring = ast.get_docstring(fdef) or ""
                            tools.append(RegisteredTool(
                                name=name,
                                file=rel,
                                line=elt.lineno if hasattr(elt, "lineno") else node.lineno,
                                registration="tools_schema",
                                docstring=docstring,
                                parameters=params,
                                capabilities=caps,
                                evidence=[ev],
                            ))

        # Pattern 5: StructuredTool.from_function(func=my_func)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if (isinstance(node.func, ast.Attribute)
                    and node.func.attr == "from_function"
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "StructuredTool"):
                func_name = None
                for kw in node.keywords:
                    if kw.arg == "func" and isinstance(kw.value, ast.Name):
                        func_name = kw.value.id
                if func_name and func_name in func_defs:
                    fdef = func_defs[func_name]
                    params = [a.arg for a in fdef.args.args if a.arg != "self"]
                    docstring = ast.get_docstring(fdef) or ""
                    caps = _classify_capabilities(fdef, source)
                    ev = Evidence(
                        file=rel, line=node.lineno,
                        snippet=_snippet(source, node.lineno),
                        function_name=func_name,
                    )
                    tools.append(RegisteredTool(
                        name=func_name,
                        file=rel,
                        line=fdef.lineno,
                        registration="from_function",
                        docstring=docstring,
                        parameters=params,
                        capabilities=caps,
                        evidence=[ev],
                    ))

    return ToolRegistrationReport(tools=tools)


# ── Capability classification ────────────────────────────────────────────


def _classify_capabilities(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    source: str,
) -> list[ToolCapability]:
    """Classify what a tool function can do by analyzing its body."""
    caps: list[ToolCapability] = []
    seen_kinds: set[str] = set()

    for node in ast.walk(func_node):
        if not isinstance(node, ast.Call):
            continue

        call_name = _call_name(node)
        receiver = _get_receiver(node)
        line = getattr(node, "lineno", 0)

        # Network
        if (call_name in _NETWORK_CALLS and receiver in _NETWORK_MODULES) or receiver in _NETWORK_MODULES:
            if "network" not in seen_kinds:
                seen_kinds.add("network")
                caps.append(ToolCapability(kind="network", detail=f"{receiver}.{call_name}" if receiver else call_name, line=line))

        # File read
        if call_name in _FILE_READ_CALLS or (call_name == "open" and _is_read_mode(node)):
            kind = "file_read"
            if kind not in seen_kinds:
                seen_kinds.add(kind)
                caps.append(ToolCapability(kind=kind, detail=call_name, line=line))

        # File write
        if call_name in _FILE_WRITE_CALLS or (call_name == "open" and _is_write_mode(node)):
            kind = "file_write"
            if kind not in seen_kinds:
                seen_kinds.add(kind)
                caps.append(ToolCapability(kind=kind, detail=call_name, line=line))

        # Database
        if call_name in _DB_CALLS and receiver in _DB_RECEIVERS:
            if "database" not in seen_kinds:
                seen_kinds.add("database")
                caps.append(ToolCapability(kind="database", detail=f"{receiver}.{call_name}", line=line))

        # Subprocess / dangerous
        if (call_name in _SUBPROCESS_CALLS
                and (receiver in _SUBPROCESS_MODULES or call_name in ("exec", "eval"))):
            if "subprocess" not in seen_kinds:
                seen_kinds.add("subprocess")
                caps.append(ToolCapability(kind="subprocess", detail=f"{receiver}.{call_name}" if receiver else call_name, line=line))

    return caps


def _extract_openai_tool_name(node: ast.expr) -> str | None:
    """Extract tool name from OpenAI function-calling schema dict literal."""
    if not isinstance(node, ast.Dict):
        return None
    # Look for {"type": "function", "function": {"name": "search"}}
    for k, v in zip(node.keys, node.values):
        if isinstance(k, ast.Constant) and k.value == "function" and isinstance(v, ast.Dict):
            for k2, v2 in zip(v.keys, v.values):
                if (isinstance(k2, ast.Constant) and k2.value == "name"
                        and isinstance(v2, ast.Constant) and isinstance(v2.value, str)):
                    return v2.value
    return None


def _call_name(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    if isinstance(node.func, ast.Name):
        return node.func.id
    return None


def _get_receiver(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Attribute):
        if isinstance(node.func.value, ast.Name):
            return node.func.value.id
        if isinstance(node.func.value, ast.Attribute):
            # Recurse for chained: os.path.join -> return root
            cur = node.func.value
            while isinstance(cur, ast.Attribute):
                cur = cur.value
            if isinstance(cur, ast.Name):
                return cur.id
    return None


def _is_read_mode(node: ast.Call) -> bool:
    """Check if open() call is in read mode."""
    # Default mode is "r" for open()
    if len(node.args) < 2:
        # Check kwargs
        for kw in node.keywords:
            if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                return "r" in str(kw.value.value) and "w" not in str(kw.value.value)
        return True  # default is read
    if isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str):
        mode = node.args[1].value
        return "r" in mode and "w" not in mode
    return False


def _is_write_mode(node: ast.Call) -> bool:
    """Check if open() call is in write mode."""
    if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
        mode = str(node.args[1].value)
        return "w" in mode or "a" in mode
    for kw in node.keywords:
        if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
            mode = str(kw.value.value)
            return "w" in mode or "a" in mode
    return False


def _snippet(source: str, lineno: int) -> str:
    lines = source.splitlines()
    if 0 < lineno <= len(lines):
        return lines[lineno - 1].strip()[:160]
    return ""

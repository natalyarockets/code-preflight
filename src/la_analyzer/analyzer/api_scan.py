"""Detect FastAPI route handlers and extract inputs/outputs from signatures."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from la_analyzer.analyzer.models import APIRoute, Evidence, IOInput, IOOutput

# HTTP methods recognized on app/router decorators
_ROUTE_METHODS = {"get", "post", "put", "patch", "delete"}

# Parameter names to always skip (injected by framework, not user input)
_SKIP_PARAMS = {"self", "cls", "db", "session", "request", "response", "current_user"}

# Scalar types that indicate query/path params (not Pydantic bodies)
_SCALAR_TYPES = {"str", "int", "float", "bool", "bytes"}

# Path template variable pattern: {param_name}
_PATH_VAR_RE = re.compile(r"\{(\w+)\}")


def scan_api(
    workspace: Path, py_files: list[Path]
) -> tuple[list[IOInput], list[IOOutput], list[APIRoute]]:
    """Scan Python files for FastAPI route handlers.

    Returns (inputs, outputs, api_routes) to merge into the IOReport.
    """
    inputs: list[IOInput] = []
    outputs: list[IOOutput] = []
    routes: list[APIRoute] = []
    input_counter = 0
    output_counter = 0

    for fpath in py_files:
        rel = str(fpath.relative_to(workspace))
        try:
            source = fpath.read_text(errors="replace")
            tree = ast.parse(source, filename=rel)
        except SyntaxError:
            continue

        # Pass 1: find FastAPI() / APIRouter() variable names + prefixes
        app_vars = _find_app_vars(tree)
        if not app_vars:
            continue

        # Pass 2: extract routes from decorated functions
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            route_info = _match_route_decorator(node, app_vars)
            if route_info is None:
                continue

            method, route_path = route_info
            path_vars = set(_PATH_VAR_RE.findall(route_path))

            route_input_ids: list[str] = []
            route_output_ids: list[str] = []

            # Parse function parameters
            for param_name, annotation in _iter_params(node):
                if param_name in _SKIP_PARAMS:
                    continue
                if _has_depends_default(node, param_name):
                    continue

                ann_name = _annotation_name(annotation)

                if ann_name == "UploadFile" or _has_file_default(node, param_name):
                    inp_id = f"api_input_{input_counter}"
                    input_counter += 1
                    inputs.append(IOInput(
                        id=inp_id,
                        label=_label_upload(param_name),
                        kind="upload",
                        format="unknown",
                        evidence=[Evidence(
                            file=rel, line=node.lineno,
                            snippet=_snippet(source, node.lineno),
                        )],
                        confidence=0.85,
                    ))
                    route_input_ids.append(inp_id)

                elif ann_name and ann_name not in _SCALAR_TYPES and ann_name != "UploadFile":
                    # Pydantic model body
                    inp_id = f"api_input_{input_counter}"
                    input_counter += 1
                    inputs.append(IOInput(
                        id=inp_id,
                        label=_label_camel(ann_name),
                        kind="json_body",
                        format="json",
                        evidence=[Evidence(
                            file=rel, line=node.lineno,
                            snippet=_snippet(source, node.lineno),
                        )],
                        confidence=0.85,
                    ))
                    route_input_ids.append(inp_id)

                elif param_name in path_vars:
                    inp_id = f"api_input_{input_counter}"
                    input_counter += 1
                    inputs.append(IOInput(
                        id=inp_id,
                        label=_label_underscore(param_name),
                        kind="path_param",
                        format="unknown",
                        evidence=[Evidence(
                            file=rel, line=node.lineno,
                            snippet=_snippet(source, node.lineno),
                        )],
                        confidence=0.7,
                    ))
                    route_input_ids.append(inp_id)

                else:
                    # Query param (scalar or unannotated, not in path)
                    inp_id = f"api_input_{input_counter}"
                    input_counter += 1
                    inputs.append(IOInput(
                        id=inp_id,
                        label=_label_underscore(param_name),
                        kind="query_param",
                        format="unknown",
                        evidence=[Evidence(
                            file=rel, line=node.lineno,
                            snippet=_snippet(source, node.lineno),
                        )],
                        confidence=0.7,
                    ))
                    route_input_ids.append(inp_id)

            # Check for response_model kwarg on decorator
            resp_model = _response_model_from_decorator(node, app_vars)
            if resp_model:
                out_id = f"api_output_{output_counter}"
                output_counter += 1
                outputs.append(IOOutput(
                    id=out_id,
                    label=_label_camel(resp_model),
                    kind="response_model",
                    format="json",
                    evidence=[Evidence(
                        file=rel, line=node.lineno,
                        snippet=_snippet(source, node.lineno),
                    )],
                    confidence=0.8,
                ))
                route_output_ids.append(out_id)

            # Check return type annotation
            elif node.returns and not resp_model:
                ret_name = _annotation_name(node.returns)
                if ret_name and ret_name not in _SCALAR_TYPES and ret_name not in {"None", "dict", "list"}:
                    out_id = f"api_output_{output_counter}"
                    output_counter += 1
                    outputs.append(IOOutput(
                        id=out_id,
                        label=_label_camel(ret_name),
                        kind="response_model",
                        format="json",
                        evidence=[Evidence(
                            file=rel, line=node.lineno,
                            snippet=_snippet(source, node.lineno),
                        )],
                        confidence=0.8,
                    ))
                    route_output_ids.append(out_id)

            routes.append(APIRoute(
                method=method.upper(),
                path=route_path,
                handler=node.name,
                file=rel,
                line=node.lineno,
                input_ids=route_input_ids,
                output_ids=route_output_ids,
            ))

    return inputs, outputs, routes


# ── Pass 1 helpers ────────────────────────────────────────────────────────

def _find_app_vars(tree: ast.Module) -> dict[str, str]:
    """Return {var_name: prefix} for FastAPI()/APIRouter() assignments.

    prefix is "" for FastAPI(), or the prefix kwarg for APIRouter(prefix="/api").
    """
    app_vars: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not isinstance(node.value, ast.Call):
            continue
        func = node.value
        call_name = _call_simple_name(func)
        if call_name not in ("FastAPI", "APIRouter"):
            continue
        prefix = ""
        if call_name == "APIRouter":
            for kw in func.keywords:
                if kw.arg == "prefix" and isinstance(kw.value, ast.Constant):
                    prefix = str(kw.value.value)
        for target in node.targets:
            if isinstance(target, ast.Name):
                app_vars[target.id] = prefix
    return app_vars


def _call_simple_name(node: ast.Call) -> str | None:
    """Get the simple name of a Call (e.g. 'FastAPI' from FastAPI(...))."""
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


# ── Pass 2 helpers ────────────────────────────────────────────────────────

def _match_route_decorator(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    app_vars: dict[str, str],
) -> tuple[str, str] | None:
    """If the function has a route decorator, return (method, full_path)."""
    for dec in node.decorator_list:
        if not isinstance(dec, ast.Call):
            continue
        if not isinstance(dec.func, ast.Attribute):
            continue
        attr = dec.func.attr
        if attr not in _ROUTE_METHODS:
            continue
        # Check the object is a known app/router var
        obj = dec.func.value
        if isinstance(obj, ast.Name) and obj.id in app_vars:
            route_path = _first_str_arg(dec) or "/"
            prefix = app_vars[obj.id]
            full_path = prefix + route_path
            return attr, full_path
    return None


def _iter_params(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[tuple[str, ast.expr | None]]:
    """Yield (param_name, annotation_node_or_None) for each parameter."""
    result: list[tuple[str, ast.expr | None]] = []
    for arg in node.args.args:
        result.append((arg.arg, arg.annotation))
    return result


def _has_depends_default(
    node: ast.FunctionDef | ast.AsyncFunctionDef, param_name: str
) -> bool:
    """Check if a parameter has a Depends(...) default."""
    args = node.args
    # defaults align right with args
    num_args = len(args.args)
    num_defaults = len(args.defaults)
    offset = num_args - num_defaults
    for i, arg in enumerate(args.args):
        if arg.arg != param_name:
            continue
        default_idx = i - offset
        if default_idx < 0:
            return False
        default = args.defaults[default_idx]
        if isinstance(default, ast.Call):
            name = _call_simple_name(default)
            if name == "Depends":
                return True
        return False
    return False


def _has_file_default(
    node: ast.FunctionDef | ast.AsyncFunctionDef, param_name: str
) -> bool:
    """Check if a parameter has a File(...) default."""
    args = node.args
    num_args = len(args.args)
    num_defaults = len(args.defaults)
    offset = num_args - num_defaults
    for i, arg in enumerate(args.args):
        if arg.arg != param_name:
            continue
        default_idx = i - offset
        if default_idx < 0:
            return False
        default = args.defaults[default_idx]
        if isinstance(default, ast.Call):
            name = _call_simple_name(default)
            if name == "File":
                return True
        return False
    return False


def _annotation_name(ann: ast.expr | None) -> str | None:
    """Extract a simple type name from an annotation node."""
    if ann is None:
        return None
    if isinstance(ann, ast.Name):
        return ann.id
    if isinstance(ann, ast.Attribute):
        return ann.attr
    # Handle Optional[X], list[X], etc. — extract inner type name
    if isinstance(ann, ast.Subscript):
        if isinstance(ann.value, ast.Name) and ann.value.id in ("Optional", "List", "list"):
            return _annotation_name(ann.slice)
    return None


def _response_model_from_decorator(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    app_vars: dict[str, str],
) -> str | None:
    """Extract response_model=ClassName from route decorator kwargs."""
    for dec in node.decorator_list:
        if not isinstance(dec, ast.Call):
            continue
        if not isinstance(dec.func, ast.Attribute):
            continue
        if dec.func.attr not in _ROUTE_METHODS:
            continue
        obj = dec.func.value
        if not (isinstance(obj, ast.Name) and obj.id in app_vars):
            continue
        for kw in dec.keywords:
            if kw.arg == "response_model":
                return _annotation_name(kw.value)
    return None


def _first_str_arg(node: ast.Call) -> str | None:
    if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
        return node.args[0].value
    return None


# ── Label helpers ─────────────────────────────────────────────────────────

def _label_camel(name: str) -> str:
    """Split CamelCase: 'ApplianceCreate' → 'Appliance Create'."""
    parts = re.sub(r"([a-z])([A-Z])", r"\1 \2", name)
    return re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", parts)


def _label_underscore(name: str) -> str:
    """Split underscore: 'household_id' → 'Household Id'."""
    return name.replace("_", " ").title()


def _label_upload(name: str) -> str:
    """Label for upload param: 'image' → 'Image Upload'."""
    return _label_underscore(name) + " Upload"


def _snippet(source: str, lineno: int) -> str:
    lines = source.splitlines()
    if 0 < lineno <= len(lines):
        return lines[lineno - 1].strip()[:160]
    return ""

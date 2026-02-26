"""Detect file I/O patterns (inputs/outputs) via AST + regex."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from la_analyzer.analyzer.models import (
    Evidence,
    HardcodedPath,
    IOInput,
    IOOutput,
    IOReport,
)
from la_analyzer.utils import snippet

# Map extensions to format labels
_EXT_TO_FORMAT = {
    ".csv": "csv",
    ".json": "json",
    ".xlsx": "excel",
    ".xls": "excel",
    ".pdf": "pdf",
    ".zip": "zip",
    ".png": "png",
    ".jpg": "jpeg",
    ".jpeg": "jpeg",
    ".html": "html",
    ".htm": "html",
    ".md": "markdown",
    ".wav": "audio",
    ".mp3": "audio",
    ".flac": "audio",
    ".jsonl": "json",
    ".parquet": "parquet",
    ".txt": "text",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".xml": "xml",
}

# Pandas read functions → format
_PANDAS_READERS = {
    "read_csv": "csv",
    "read_json": "json",
    "read_excel": "excel",
    "read_parquet": "parquet",
    "read_table": "csv",
    "read_xml": "xml",
}

# Pandas write methods → format
_PANDAS_WRITERS = {
    "to_csv": "csv",
    "to_json": "json",
    "to_excel": "excel",
    "to_parquet": "parquet",
    "to_html": "html",
    "to_xml": "xml",
}

# Regex fallback for paths
_PATH_PATTERN = re.compile(
    r"""["']([A-Za-z0-9_./ \\-]+\.(csv|jsonl?|xlsx?|pdf|zip|png|jpg|html?|md|txt|wav|mp3))["']"""
)


def _label_from_path(path_lit: str | None) -> str:
    """Derive a human-readable label from a file path literal.

    'data/salesforce_export.csv' → 'Salesforce Export'
    '/outputs/insights.json'     → 'Insights'
    'test_data.csv'              → 'Test Data'
    """
    if not path_lit:
        return ""
    stem = Path(path_lit).stem  # 'salesforce_export'
    # Replace underscores/hyphens with spaces, then title-case
    return stem.replace("_", " ").replace("-", " ").title()


def _label_from_arg(arg_name: str) -> str:
    """Derive a human-readable label from an argparse flag name.

    '--input-data'        → 'Input Data'
    '--input-transcripts' → 'Input Transcripts'
    '--output'            → 'Output'
    """
    if not arg_name:
        return ""
    cleaned = arg_name.lstrip("-")
    return cleaned.replace("-", " ").replace("_", " ").title()


def scan_io(workspace: Path, py_files: list[Path]) -> IOReport:
    inputs: list[IOInput] = []
    outputs: list[IOOutput] = []
    hardcoded: list[HardcodedPath] = []
    _input_counter = 0
    _output_counter = 0
    seen_input_paths: set[str] = set()
    seen_output_paths: set[str] = set()

    for fpath in py_files:
        rel = str(fpath.relative_to(workspace))
        try:
            source = fpath.read_text(errors="replace")
            tree = ast.parse(source, filename=rel)
        except SyntaxError:
            # Fall back to regex for unparseable files
            _input_counter, _output_counter = _regex_fallback(
                source, rel, inputs, outputs, hardcoded,
                seen_input_paths, seen_output_paths,
                _input_counter, _output_counter,
            )
            continue

        # Build a map of simple assignments: var_name → AST node
        # Used to resolve `path_var = dir / "file.ext"` when we see `open(path_var, "w")`
        assigns: dict[str, ast.expr] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                target = node.targets[0]
                if isinstance(target, ast.Name):
                    assigns[target.id] = node.value

        for node in ast.walk(tree):
            # open(...) calls
            if isinstance(node, ast.Call) and _call_name(node) == "open":
                path_lit = _first_str_arg(node)
                is_computed = False
                # If the first arg is a computed path, extract filename
                if not path_lit and node.args:
                    arg = node.args[0]
                    path_lit = _extract_filename_from_expr(arg)
                    # Try resolving variable reference
                    if not path_lit and isinstance(arg, ast.Name) and arg.id in assigns:
                        path_lit = _extract_filename_from_expr(assigns[arg.id])
                    if path_lit:
                        is_computed = True
                mode = _get_mode_arg(node)
                ev = Evidence(
                    file=rel, line=node.lineno,
                    snippet=snippet(source, node.lineno),
                )
                if mode and any(c in mode for c in "wxa"):
                    fmt = _format_from_path(path_lit)
                    if path_lit and path_lit not in seen_output_paths:
                        seen_output_paths.add(path_lit)
                        outputs.append(IOOutput(
                            id=f"output_{_output_counter}",
                            label=_label_from_path(path_lit),
                            format=fmt, path_literal=path_lit,
                            evidence=[ev], confidence=0.8,
                        ))
                        _output_counter += 1
                    elif not path_lit:
                        # Computed path — still an output
                        outputs.append(IOOutput(
                            id=f"output_{_output_counter}",
                            label="File Output",
                            format=fmt, path_literal=None,
                            evidence=[ev], confidence=0.5,
                        ))
                        _output_counter += 1
                    if path_lit and not is_computed:
                        hardcoded.append(HardcodedPath(path=path_lit, evidence=[ev]))
                else:
                    fmt = _format_from_path(path_lit)
                    if path_lit and path_lit not in seen_input_paths:
                        seen_input_paths.add(path_lit)
                        inputs.append(IOInput(
                            id=f"input_{_input_counter}",
                            label=_label_from_path(path_lit),
                            kind="file", format=fmt, path_literal=path_lit,
                            evidence=[ev], confidence=0.8,
                        ))
                        _input_counter += 1
                    if path_lit and not is_computed:
                        hardcoded.append(HardcodedPath(path=path_lit, evidence=[ev]))

            # pd.read_* calls
            if isinstance(node, ast.Call):
                attr = _call_attr(node)
                if attr in _PANDAS_READERS:
                    path_lit = _first_str_arg(node)
                    fmt = _PANDAS_READERS[attr]
                    if path_lit and fmt == "unknown":
                        fmt = _format_from_path(path_lit)
                    ev = Evidence(
                        file=rel, line=node.lineno,
                        snippet=snippet(source, node.lineno),
                    )
                    if path_lit and path_lit not in seen_input_paths:
                        seen_input_paths.add(path_lit)
                        inputs.append(IOInput(
                            id=f"input_{_input_counter}",
                            label=_label_from_path(path_lit),
                            kind="file", format=fmt, path_literal=path_lit,
                            evidence=[ev], confidence=0.9,
                        ))
                        _input_counter += 1
                    if path_lit:
                        hardcoded.append(HardcodedPath(path=path_lit, evidence=[ev]))

            # .to_csv(), .to_json(), savefig()
            if isinstance(node, ast.Call):
                attr = _call_attr(node)
                if attr in _PANDAS_WRITERS or attr == "savefig":
                    path_lit = _first_str_arg(node)
                    if attr in _PANDAS_WRITERS:
                        fmt = _PANDAS_WRITERS[attr]
                    else:
                        fmt = _format_from_path(path_lit) if path_lit else "png"
                    ev = Evidence(
                        file=rel, line=node.lineno,
                        snippet=snippet(source, node.lineno),
                    )
                    if path_lit and path_lit not in seen_output_paths:
                        seen_output_paths.add(path_lit)
                        outputs.append(IOOutput(
                            id=f"output_{_output_counter}",
                            label=_label_from_path(path_lit),
                            format=fmt, path_literal=path_lit,
                            evidence=[ev], confidence=0.85,
                        ))
                        _output_counter += 1
                    elif not path_lit:
                        outputs.append(IOOutput(
                            id=f"output_{_output_counter}",
                            label=f"{attr} Output",
                            format=fmt, path_literal=None,
                            evidence=[ev], confidence=0.5,
                        ))
                        _output_counter += 1
                    if path_lit:
                        hardcoded.append(HardcodedPath(path=path_lit, evidence=[ev]))

            # write_text() / write_bytes() — path is the receiver, not the first arg
            if isinstance(node, ast.Call):
                attr = _call_attr(node)
                if attr in ("write_text", "write_bytes"):
                    # Try to extract path from Path("literal").write_text()
                    path_lit = _extract_path_literal(node)
                    is_computed = False
                    # Try resolving receiver variable: summary_path.write_text()
                    if not path_lit and isinstance(node.func, ast.Attribute):
                        receiver = node.func.value
                        if isinstance(receiver, ast.Name) and receiver.id in assigns:
                            path_lit = _extract_filename_from_expr(assigns[receiver.id])
                            if path_lit:
                                is_computed = True
                    fmt = _format_from_path(path_lit) if path_lit else "unknown"
                    ev = Evidence(
                        file=rel, line=node.lineno,
                        snippet=snippet(source, node.lineno),
                    )
                    if path_lit and path_lit not in seen_output_paths:
                        seen_output_paths.add(path_lit)
                        outputs.append(IOOutput(
                            id=f"output_{_output_counter}",
                            label=_label_from_path(path_lit),
                            format=fmt, path_literal=path_lit,
                            evidence=[ev], confidence=0.85,
                        ))
                        _output_counter += 1
                    elif not path_lit:
                        outputs.append(IOOutput(
                            id=f"output_{_output_counter}",
                            label="File Output",
                            format=fmt, path_literal=None,
                            evidence=[ev], confidence=0.5,
                        ))
                        _output_counter += 1
                    if path_lit and not is_computed:
                        hardcoded.append(HardcodedPath(path=path_lit, evidence=[ev]))

            # argparse add_argument with default file paths or directories
            if isinstance(node, ast.Call) and _call_attr(node) == "add_argument":
                default_val = _get_keyword_str(node, "default")
                if default_val:
                    arg_name = _first_str_arg(node) or ""
                    fmt = _format_from_path(default_val)
                    # Accept paths with known extensions OR directory paths
                    # when the flag name suggests I/O (e.g. --output /outputs)
                    is_output = any(
                        kw in arg_name.lower()
                        for kw in ("output", "out", "dest", "save", "write", "export")
                    )
                    is_input = not is_output
                    is_dir_default = fmt == "unknown" and (
                        default_val.startswith("/") or default_val.startswith(".")
                        or default_val.endswith("/")
                    )
                    if fmt != "unknown" or (is_dir_default and (is_output or is_input)):
                        ev = Evidence(
                            file=rel, line=node.lineno,
                            snippet=snippet(source, node.lineno),
                        )
                        # For directory defaults, use "directory" format
                        if fmt == "unknown" and is_dir_default:
                            fmt = "directory"
                        # Prefer: help text → path-derived label → arg flag name
                        help_text = _get_keyword_str(node, "help")
                        label = help_text or _label_from_path(default_val) or _label_from_arg(arg_name)
                        if is_output:
                            if default_val not in seen_output_paths:
                                seen_output_paths.add(default_val)
                                outputs.append(IOOutput(
                                    id=f"output_{_output_counter}",
                                    label=label,
                                    format=fmt, path_literal=default_val,
                                    evidence=[ev], confidence=0.7,
                                ))
                                _output_counter += 1
                        else:
                            if default_val not in seen_input_paths:
                                seen_input_paths.add(default_val)
                                inputs.append(IOInput(
                                    id=f"input_{_input_counter}",
                                    label=label,
                                    kind="file", format=fmt, path_literal=default_val,
                                    evidence=[ev], confidence=0.7,
                                ))
                                _input_counter += 1
                        if default_val not in seen_input_paths and default_val not in seen_output_paths:
                            hardcoded.append(HardcodedPath(path=default_val, evidence=[ev]))

            # csv.reader / csv.DictReader / csv.writer / csv.DictWriter
            if isinstance(node, ast.Call):
                cname = _call_name(node)
                attr = _call_attr(node)
                is_csv_read = (cname in ("DictReader",) or
                               attr in ("reader", "DictReader"))
                is_csv_write = (cname in ("DictWriter",) or
                                attr in ("writer", "DictWriter"))
                if is_csv_read or is_csv_write:
                    # Path is usually inside the file handle arg, not extractable
                    ev = Evidence(
                        file=rel, line=node.lineno,
                        snippet=snippet(source, node.lineno),
                    )
                    if is_csv_write:
                        csv_id = f"output_{_output_counter}"
                        if csv_id not in seen_output_paths:
                            outputs.append(IOOutput(
                                id=csv_id, label="CSV Output",
                                format="csv", path_literal=None,
                                evidence=[ev], confidence=0.6,
                            ))
                            _output_counter += 1
                    else:
                        csv_id = f"input_{_input_counter}"
                        if csv_id not in seen_input_paths:
                            inputs.append(IOInput(
                                id=csv_id, label="CSV Input",
                                kind="file", format="csv", path_literal=None,
                                evidence=[ev], confidence=0.6,
                            ))
                            _input_counter += 1

            # json.load() / json.dump()
            if isinstance(node, ast.Call):
                attr = _call_attr(node)
                if attr == "load" and isinstance(node.func, ast.Attribute):
                    receiver = _call_name_of_value(node.func.value)
                    if receiver == "json":
                        ev = Evidence(
                            file=rel, line=node.lineno,
                            snippet=snippet(source, node.lineno),
                        )
                        json_id = f"input_{_input_counter}"
                        inputs.append(IOInput(
                            id=json_id, label="JSON Input",
                            kind="file", format="json", path_literal=None,
                            evidence=[ev], confidence=0.6,
                        ))
                        _input_counter += 1
                elif attr == "dump" and isinstance(node.func, ast.Attribute):
                    receiver = _call_name_of_value(node.func.value)
                    if receiver == "json":
                        ev = Evidence(
                            file=rel, line=node.lineno,
                            snippet=snippet(source, node.lineno),
                        )
                        json_id = f"output_{_output_counter}"
                        outputs.append(IOOutput(
                            id=json_id, label="JSON Output",
                            format="json", path_literal=None,
                            evidence=[ev], confidence=0.6,
                        ))
                        _output_counter += 1

            # .iterdir(), .glob(), os.listdir(), os.scandir() — directory input
            if isinstance(node, ast.Call):
                attr = _call_attr(node)
                cname = _call_name(node)
                is_dir_iter = (
                    attr in ("iterdir", "glob", "rglob")
                    or attr in ("listdir", "scandir")
                    or cname in ("listdir", "scandir")
                )
                if is_dir_iter:
                    ev = Evidence(
                        file=rel, line=node.lineno,
                        snippet=snippet(source, node.lineno),
                    )
                    dir_path = _extract_path_literal(node)
                    dir_label = dir_path or "File Upload"
                    dir_id = f"input_{_input_counter}"
                    inputs.append(IOInput(
                        id=dir_id, label=dir_label,
                        kind="directory", format="unknown",
                        path_literal=dir_path,
                        evidence=[ev], confidence=0.6,
                    ))
                    _input_counter += 1

            # Path(...).read_text() / read_bytes()
            if isinstance(node, ast.Call):
                attr = _call_attr(node)
                if attr in ("read_text", "read_bytes"):
                    # Try to find the Path(...) literal
                    path_lit = _extract_path_literal(node)
                    ev = Evidence(
                        file=rel, line=node.lineno,
                        snippet=snippet(source, node.lineno),
                    )
                    if path_lit and path_lit not in seen_input_paths:
                        seen_input_paths.add(path_lit)
                        inputs.append(IOInput(
                            id=f"input_{_input_counter}",
                            label=_label_from_path(path_lit),
                            kind="file", format=_format_from_path(path_lit),
                            path_literal=path_lit,
                            evidence=[ev], confidence=0.7,
                        ))
                        _input_counter += 1
                    if path_lit:
                        hardcoded.append(HardcodedPath(path=path_lit, evidence=[ev]))

        # Regex fallback for any string literals that look like file paths
        _input_counter, _output_counter = _regex_fallback(
            source, rel, inputs, outputs, hardcoded,
            seen_input_paths, seen_output_paths,
            _input_counter, _output_counter,
        )

    # ── Post-processing dedup ─────────────────────────────────────────────
    # Remove entries that are strictly less informative than other entries.
    inputs = _dedup_entries(inputs)
    outputs = _dedup_entries(outputs)

    # Remove directory outputs when we have concrete file outputs.
    # A directory (e.g. argparse --output="/outputs") is just a container,
    # not a real artifact.
    if any(o.format != "directory" for o in outputs):
        outputs = [o for o in outputs if o.format != "directory"]

    # Classify output roles: debug/logging artifacts vs primary results
    for out in outputs:
        out.role = _classify_output_role(out)

    # Enrich inputs with accepted formats and descriptions
    _enrich_inputs(workspace, py_files, inputs)

    return IOReport(inputs=inputs, outputs=outputs, hardcoded_paths=hardcoded)


def _enrich_inputs(workspace: Path, py_files: list[Path], inputs: list[IOInput]) -> None:
    """Enrich inputs with accepted_formats, field names, and descriptions."""
    all_extensions: list[str] = []
    all_fields: list[str] = []

    for fpath in py_files:
        try:
            source = fpath.read_text(errors="replace")
            tree = ast.parse(source, filename=str(fpath))
        except SyntaxError:
            continue
        all_extensions.extend(_find_extension_sets(tree))
        all_fields.extend(_find_field_references(tree))

    accepted = sorted(set(all_extensions))
    fields = list(dict.fromkeys(all_fields))  # dedupe preserving order

    for inp in inputs:
        if inp.kind == "directory" and accepted and not inp.accepted_formats:
            inp.accepted_formats = accepted

        inp.description = _build_input_description(inp, accepted, fields)


def _find_extension_sets(tree: ast.Module) -> list[str]:
    """Find string literals that look like file extensions in set/list literals."""
    extensions: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Set, ast.List)):
            elts = node.elts
            ext_elts = [
                e.value for e in elts
                if isinstance(e, ast.Constant)
                and isinstance(e.value, str)
                and e.value.startswith(".")
                and len(e.value) <= 6
            ]
            if len(ext_elts) >= 2 and len(ext_elts) >= len(elts) * 0.7:
                extensions.extend(ext_elts)
    return extensions


# Field names to skip — these are framework/infrastructure fields, not data columns
_SKIP_FIELDS = {
    "id", "text", "metadata", "embedding", "values", "source",
    "status", "type", "key", "name", "file", "path",
    "chunk_index", "char_start", "char_end",
}


def _is_data_field(field: str) -> bool:
    """Return True if a string looks like a data column, not infra/config."""
    if field in _SKIP_FIELDS:
        return False
    if field.startswith("_"):
        return False
    # Skip ALL_CAPS (env vars, constants)
    if field == field.upper() and len(field) > 2:
        return False
    # Skip very short or very long
    if len(field) < 2 or len(field) > 40:
        return False
    return True


def _find_field_references(tree: ast.Module) -> list[str]:
    """Find column/field names accessed via df["col"], row["field"], data.get("key").

    Only captures subscript/get accesses on data-like receivers (not os.environ,
    dict constructors, etc.)
    """
    fields: list[str] = []

    # Build set of names assigned from os.environ / os.environ.get
    env_vars: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Subscript):
            # os.environ["KEY"]
            if isinstance(node.value, ast.Attribute) and node.value.attr == "environ":
                continue  # skip this access entirely
        if isinstance(node, ast.Call):
            # os.environ.get("KEY")
            if isinstance(node.func, ast.Attribute) and node.func.attr == "get":
                if isinstance(node.func.value, ast.Attribute) and node.func.value.attr == "environ":
                    continue

    for node in ast.walk(tree):
        # df["column_name"] or row["field"]
        if isinstance(node, ast.Subscript):
            if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
                # Skip os.environ["KEY"]
                if isinstance(node.value, ast.Attribute) and node.value.attr == "environ":
                    continue
                field = node.slice.value
                if _is_data_field(field):
                    fields.append(field)
        # data.get("field") — but NOT os.environ.get("KEY")
        if isinstance(node, ast.Call) and _call_attr(node) == "get":
            if isinstance(node.func, ast.Attribute):
                # Skip os.environ.get()
                if isinstance(node.func.value, ast.Attribute) and node.func.value.attr == "environ":
                    continue
            if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                field = node.args[0].value
                if _is_data_field(field):
                    fields.append(field)
    return fields


def _build_input_description(inp: IOInput, global_accepted: list[str], fields: list[str]) -> str:
    """Build a human-readable description for an input.

    Focuses on what the user needs to know: expected fields, content type.
    Does NOT repeat format/extension info (shown separately via pills).
    """
    parts: list[str] = []

    # For CSV/tabular inputs, show expected column names
    if inp.format in ("csv", "excel", "parquet") and fields:
        shown = fields[:8]
        parts.append(f"Expected fields: {', '.join(shown)}")

    # For directory inputs, describe what to upload
    if inp.kind == "directory":
        parts.append("Upload one or more files to process")

    # For single-file inputs with a known format, say what kind
    if inp.kind == "file" and inp.format != "unknown" and not fields:
        fmt_hint = {
            "csv": "Upload a CSV with your data",
            "json": "Upload a JSON data file",
            "pdf": "Upload a PDF document",
            "excel": "Upload an Excel spreadsheet",
            "text": "Upload a text file",
        }.get(inp.format)
        if fmt_hint:
            parts.append(fmt_hint)

    return ". ".join(parts) if parts else ""


_ARTIFACT_STEMS = {
    "summary", "log", "logs", "debug", "index", "chunks", "temp", "tmp",
    "cache", "checkpoint", "metadata", "stats", "metrics", "trace",
    "manifest", "status", "progress",
}


def _classify_output_role(out: IOOutput) -> str:
    """Classify an output as 'primary' (user-facing result) or 'artifact' (debug/log).

    Heuristics based on filename — users can override in the flow editor.
    """
    if not out.path_literal:
        # No path and unknown format → not useful to show
        if out.format == "unknown":
            return "artifact"
        return "primary"
    stem = Path(out.path_literal).stem.lower().replace("-", "_")
    # Check if stem matches or starts/ends with artifact patterns
    if stem in _ARTIFACT_STEMS:
        return "artifact"
    for pattern in _ARTIFACT_STEMS:
        if stem.startswith(pattern + "_") or stem.endswith("_" + pattern):
            return "artifact"
    return "primary"


def _regex_fallback(
    source: str, rel: str,
    inputs: list[IOInput], outputs: list[IOOutput],
    hardcoded: list[HardcodedPath],
    seen_in: set[str], seen_out: set[str],
    ic: int, oc: int,
) -> tuple[int, int]:
    """Supplement AST detection with regex for path literals we may have missed."""
    for m in _PATH_PATTERN.finditer(source):
        path_lit = m.group(1)
        if path_lit in seen_in or path_lit in seen_out:
            continue
        lineno = source[:m.start()].count("\n") + 1
        ev = Evidence(file=rel, line=lineno, snippet=source.splitlines()[lineno - 1].strip()[:160])
        # Heuristic: not already tracked
        if path_lit not in seen_in and path_lit not in seen_out:
            hardcoded.append(HardcodedPath(path=path_lit, evidence=[ev]))
    return ic, oc


def _dedup_entries(entries: list) -> list:
    """Remove pathless entries when a higher-confidence entry of the same format exists.

    Example: csv.DictReader(f) with no path is redundant when we already have
    a csv input from argparse with path="data/salesforce_accounts.csv".
    Similarly, json.dump() with no path is redundant when open("analysis.json", "w")
    was already detected.
    """
    # Collect formats that have at least one path-bearing entry
    formats_with_paths: set[str] = set()
    for entry in entries:
        if entry.path_literal and entry.format != "unknown":
            formats_with_paths.add(entry.format)

    # Keep entries that either have a path or whose format has no path-bearing entry
    return [
        entry for entry in entries
        if entry.path_literal or entry.format not in formats_with_paths
    ]


def _call_name(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Name):
        return node.func.id
    return None


def _call_attr(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def _call_name_of_value(node: ast.expr) -> str | None:
    """Get the name of the value a method is called on: json.load → 'json'."""
    if isinstance(node, ast.Name):
        return node.id
    return None


def _first_str_arg(node: ast.Call) -> str | None:
    if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
        return node.args[0].value
    return None


def _get_keyword_str(node: ast.Call, keyword: str) -> str | None:
    for kw in node.keywords:
        if kw.arg == keyword and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
            return kw.value.value
    return None


def _get_mode_arg(node: ast.Call) -> str | None:
    # Positional second arg
    if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
        return str(node.args[1].value)
    # Keyword mode=
    for kw in node.keywords:
        if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
            return str(kw.value.value)
    return None


def _extract_path_literal(node: ast.Call) -> str | None:
    """Try to extract path from `Path("...").read_text()`."""
    if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Call):
        inner = node.func.value
        if _call_name(inner) == "Path" or _call_attr(inner) == "Path":
            return _first_str_arg(inner)
    return None


def _extract_filename_from_expr(node: ast.expr) -> str | None:
    """Extract a filename from computed path expressions.

    Handles:
      - os.path.join(dir, "file.json") → "file.json"
      - dir / "file.json" (Path division) → "file.json"
      - Name variable (tries to resolve simple assignments)
    """
    if isinstance(node, ast.Call):
        call_name = ""
        if isinstance(node.func, ast.Attribute):
            call_name = node.func.attr
        if call_name == "join" and len(node.args) >= 2:
            for arg in reversed(node.args):
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    return arg.value
    # dir / "filename.ext" → BinOp with Div
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        if isinstance(node.right, ast.Constant) and isinstance(node.right.value, str):
            return node.right.value
    return None

# Keep old name for backward compat with any callers
_extract_filename_from_call = _extract_filename_from_expr


def _format_from_path(path: str | None) -> str:
    if not path:
        return "unknown"
    for ext, fmt in _EXT_TO_FORMAT.items():
        if path.lower().endswith(ext):
            return fmt
    return "unknown"



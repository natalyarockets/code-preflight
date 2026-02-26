"""Trace data flow from file inputs to LLM calls — enterprise-critical scanner."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from la_analyzer.analyzer.models import Evidence
from la_analyzer.security.models import SecurityFinding
from la_analyzer.utils import snippet

# Names that indicate LLM SDK usage
_LLM_CALL_METHODS = {"create", "generate", "complete", "chat", "invoke", "ainvoke"}
_LLM_LIBS = {
    "openai", "anthropic",
    "langchain", "langchain_core", "langchain_openai", "langchain_anthropic",
    "langchain_community",
}

# Names that indicate file reading
_FILE_READ_FUNCS = {"open", "read_csv", "read_json", "read_excel", "read_parquet",
                     "read_text", "read_bytes", "read_table", "load",
                     "DictReader", "reader"}

# HTTP libraries and receiver names for sink detection
_HTTP_LIBS = {"requests", "httpx", "aiohttp", "urllib3"}
_HTTP_RECEIVERS = {"requests", "httpx", "aiohttp", "urllib3", "session", "client", "http"}
_HTTP_SINK_METHODS = {"post", "put", "patch", "request", "send"}

# Output file write methods
_FILE_WRITE_METHODS = {"to_csv", "to_json", "to_excel", "to_parquet", "write",
                        "write_text", "write_bytes", "dump"}

# Cloud / vector-database / NoSQL SDK write methods.
# These are specific enough to indicate a write to an external store
# when one of _CLOUD_DB_LIBS is imported (the import gate prevents false positives).
_DB_WRITE_METHODS = {
    "upsert", "insert", "insert_one", "insert_many", "put_item",
    "add_documents", "add_texts", "from_documents", "from_texts",
    "bulk_write",
}
# SDK module roots that indicate cloud/database egress (not pure-Python libs)
_CLOUD_DB_LIBS = {
    "pinecone", "pymongo", "motor", "redis", "weaviate", "chromadb",
    "qdrant_client", "elasticsearch", "opensearchpy", "supabase",
    "psycopg2", "asyncpg", "sqlalchemy", "databases",
}

# PII-indicative field names (subset for data flow context)
_PII_FIELD_RE = re.compile(
    r"(?:(?<=_)|\b)(email|ssn|social_security|phone|address|dob|date_of_birth|"
    r"first_name|last_name|full_name|contact_name|contact_email|contact_phone|"
    r"name|salary|revenue|annual_revenue|deal_value|deal_size|deal_amount|"
    r"account_number|patient|diagnosis|credit_card|password)(?=_|\b)",
    re.IGNORECASE,
)


def scan_data_flow(
    workspace: Path,
    py_files: list[Path],
) -> list[SecurityFinding]:
    """Analyze data flow from file reads to LLM calls."""
    risks: list[SecurityFinding] = []
    # Dedup key: (file, line, category, sink) — sink discriminates findings at the
    # same line that differ by target (e.g. output_file vs http at line 42).
    seen_risks: set[tuple[str, int, str, str]] = set()

    for fpath in py_files:
        rel = str(fpath.relative_to(workspace))
        try:
            source = fpath.read_text(errors="replace")
            tree = ast.parse(source, filename=rel)
        except SyntaxError:
            continue

        # Collect per-function context
        file_imports: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    file_imports.add(alias.name.split(".")[0])
            if isinstance(node, ast.ImportFrom) and node.module:
                file_imports.add(node.module.split(".")[0])

        has_llm = bool(file_imports & _LLM_LIBS)

        # Analyze each function scope (and module level)
        scopes: list[ast.AST] = [tree]
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                scopes.append(node)

        for scope in scopes:
            _analyze_scope(scope, source, rel, has_llm, file_imports, risks, seen_risks)

        # Cross-function analysis: detect file reads in one function flowing
        # to external sinks (LLM, HTTP, output file) in another.
        _analyze_cross_function(tree, source, rel, file_imports, risks, seen_risks)

    return risks


def _analyze_scope(
    scope: ast.AST,
    source: str,
    rel: str,
    has_llm: bool,
    file_imports: set[str],
    risks: list[SecurityFinding],
    seen_risks: set[tuple[str, int, str, str]] | None = None,
) -> None:
    """Analyze a single scope (function or module) for data flow patterns."""
    # Track variables that hold file data
    file_data_vars: set[str] = set()
    # Track variables with PII-related names
    pii_vars: set[str] = set()
    # Track LLM call sites
    llm_calls: list[tuple[ast.Call, int]] = []
    # Track file reads
    file_reads: list[tuple[str, int, str | None]] = []  # (var_name, line, path)

    for node in ast.walk(scope):
        # Detect `with open(...) as var:` — only mark READ opens as file data.
        # Write-mode handles (open("out.csv", "w") as f) are sinks, not sources.
        if isinstance(node, ast.With):
            for item in node.items:
                if isinstance(item.context_expr, ast.Call):
                    call_name = _full_call_name(item.context_expr)
                    if "open" in call_name.split(".") and _is_read_open(item.context_expr):
                        var = item.optional_vars
                        if isinstance(var, ast.Name):
                            file_data_vars.add(var.id)
                            path_arg = _first_str_arg(item.context_expr)
                            file_reads.append((var.id, item.context_expr.lineno, path_arg))

        # Detect file reads assigned to variables
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            var_name = _target_name(target)
            if var_name and isinstance(node.value, ast.Call):
                call_name = _full_call_name(node.value)
                # pd.read_csv(...), open(...).read(), Path(...).read_text()
                call_parts = set(call_name.split("."))
                if call_parts & _FILE_READ_FUNCS:
                    file_data_vars.add(var_name)
                    path_arg = _extract_file_path(node.value)
                    file_reads.append((var_name, node.lineno, path_arg))

                    # Check if the path hints at PII data
                    if path_arg and _PII_FIELD_RE.search(path_arg):
                        pii_vars.add(var_name)

            # Track variables with PII-suggestive names
            if var_name and _PII_FIELD_RE.search(var_name):
                pii_vars.add(var_name)

            # Propagate file data taint through any expression referencing tainted vars:
            # processed = df.dropna()  →  processed inherits df's taint
            # prompt = f"Analyze: {row}"  →  prompt inherits row's taint
            if var_name:
                value_names = _collect_names(node.value)
                if value_names & file_data_vars:
                    file_data_vars.add(var_name)

        # For-loop variable taint: for row in reader → row inherits taint
        if isinstance(node, ast.For):
            if isinstance(node.iter, ast.Name) and node.iter.id in file_data_vars:
                target_name = _target_name(node.target)
                if target_name:
                    file_data_vars.add(target_name)

        # Detect LLM API calls — match the actual method name (last segment),
        # not substrings, to avoid false positives like generate_email()
        if isinstance(node, ast.Call):
            call_name = _full_call_name(node)
            method_name = call_name.rsplit(".", 1)[-1]
            if method_name in _LLM_CALL_METHODS and has_llm:
                # Guard: ainvoke/invoke on a graph/StateGraph variable is NOT an LLM call
                if method_name in ("invoke", "ainvoke") and _is_graph_runtime_call(node):
                    pass
                else:
                    llm_calls.append((node, node.lineno))

        # Detect variables that reference file data via subscript
        if isinstance(node, ast.Subscript):
            if isinstance(node.value, ast.Name) and node.value.id in file_data_vars:
                if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
                    field = node.slice.value
                    if _PII_FIELD_RE.search(field):
                        pii_vars.add(f"{node.value.id}[{field}]")

        # Detect .get() access on file data variables: row.get("email")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if (node.func.attr == "get"
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id in file_data_vars
                    and node.args):
                arg = node.args[0]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    field = arg.value
                    if _PII_FIELD_RE.search(field):
                        pii_vars.add(f"{node.func.value.id}[{field}]")

    # ── HTTP sink detection ──────────────────────────────────────────────
    # Track HTTP calls that send file/PII data to external APIs
    has_http_lib = bool(file_imports & _HTTP_LIBS)
    if has_http_lib and (file_data_vars or pii_vars):
        for node in ast.walk(scope):
            if not isinstance(node, ast.Call):
                continue
            if not isinstance(node.func, ast.Attribute):
                continue
            method = node.func.attr
            if method not in _HTTP_SINK_METHODS:
                continue
            receiver = None
            if isinstance(node.func.value, ast.Name):
                receiver = node.func.value.id
            if receiver not in _HTTP_RECEIVERS:
                continue
            # Check if arguments reference file_data_vars or pii_vars
            call_names = _collect_names(node)
            tainted = call_names & (file_data_vars | {v.split("[")[0] for v in pii_vars})
            if tainted:
                pii_in_path = []
                for var in tainted:
                    for pv in pii_vars:
                        if var in pv or pv.startswith(f"{var}["):
                            field = pv.split("[")[-1].rstrip("]") if "[" in pv else pv
                            pii_in_path.append(field)
                severity = "high" if pii_in_path else "medium"
                key = (rel, node.lineno, "data_flow", "http")
                if seen_risks is None or key not in seen_risks:
                    if seen_risks is not None:
                        seen_risks.add(key)
                    source_desc = _resolve_source(tainted, file_reads)
                    ev = Evidence(file=rel, line=node.lineno, snippet=snippet(source, node.lineno))
                    risks.append(SecurityFinding(
                        category="data_flow",
                        title="File data flows to HTTP API",
                        data_source=source_desc,
                        data_sink="HTTP API call",
                        pii_fields=pii_in_path,
                        description=f"File/PII data ({', '.join(sorted(tainted))}) sent via HTTP {method}()",
                        evidence=[ev],
                        severity=severity,
                    ))

    # ── Output file sink detection ────────────────────────────────────────
    # Track file writes where sensitive data flows out
    if file_data_vars or pii_vars:
        for node in ast.walk(scope):
            if not isinstance(node, ast.Call):
                continue
            if not isinstance(node.func, ast.Attribute):
                continue
            method = node.func.attr
            if method not in _FILE_WRITE_METHODS:
                continue
            # Check receiver and args for tainted data
            call_names = _collect_names(node)
            tainted = call_names & (file_data_vars | {v.split("[")[0] for v in pii_vars})
            if tainted:
                pii_in_path = []
                for var in tainted:
                    for pv in pii_vars:
                        if var in pv or pv.startswith(f"{var}["):
                            field = pv.split("[")[-1].rstrip("]") if "[" in pv else pv
                            pii_in_path.append(field)
                severity = "high" if pii_in_path else "low"
                key = (rel, node.lineno, "data_flow", "output_file")
                if seen_risks is None or key not in seen_risks:
                    if seen_risks is not None:
                        seen_risks.add(key)
                    source_desc = _resolve_source(tainted, file_reads)
                    ev = Evidence(file=rel, line=node.lineno, snippet=snippet(source, node.lineno))
                    risks.append(SecurityFinding(
                        category="data_flow",
                        title="File data written to output",
                        data_source=source_desc,
                        data_sink="output file",
                        pii_fields=pii_in_path,
                        description=f"File data ({', '.join(sorted(tainted))}) written to output file via {method}()",
                        evidence=[ev],
                        severity=severity,
                    ))

    # ── Database / cloud SDK sink detection ──────────────────────────────
    has_db_lib = bool(file_imports & _CLOUD_DB_LIBS)
    if has_db_lib and (file_data_vars or pii_vars):
        for node in ast.walk(scope):
            if not isinstance(node, ast.Call):
                continue
            if not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr not in _DB_WRITE_METHODS:
                continue
            call_names = _collect_names(node)
            tainted = call_names & (file_data_vars | {v.split("[")[0] for v in pii_vars})
            if tainted:
                pii_in_path = []
                for var in tainted:
                    for pv in pii_vars:
                        if var in pv or pv.startswith(f"{var}["):
                            field = pv.split("[")[-1].rstrip("]") if "[" in pv else pv
                            pii_in_path.append(field)
                severity = "high" if pii_in_path else "medium"
                key = (rel, node.lineno, "data_flow", "database")
                if seen_risks is None or key not in seen_risks:
                    if seen_risks is not None:
                        seen_risks.add(key)
                    source_desc = _resolve_source(tainted, file_reads)
                    ev = Evidence(file=rel, line=node.lineno, snippet=snippet(source, node.lineno))
                    risks.append(SecurityFinding(
                        category="data_flow",
                        title="File data flows to database/cloud API",
                        data_source=source_desc,
                        data_sink="database/cloud API",
                        pii_fields=pii_in_path,
                        description=f"File/PII data ({', '.join(sorted(tainted))}) sent to cloud/database via {node.func.attr}()",
                        evidence=[ev],
                        severity=severity,
                    ))

    if not llm_calls:
        return

    # Check if file data flows to LLM calls
    for call_node, call_line in llm_calls:
        # Gather all names referenced in the LLM call args
        call_names = _collect_names(call_node)
        ev = Evidence(file=rel, line=call_line, snippet=snippet(source, call_line))

        # Check 1: file data variable directly in LLM call
        file_vars_in_call = call_names & file_data_vars
        if file_vars_in_call:
            pii_in_path = []
            for var in file_vars_in_call:
                for pii_var in pii_vars:
                    if var in pii_var or pii_var.startswith(f"{var}["):
                        field = pii_var.split("[")[-1].rstrip("]") if "[" in pii_var else pii_var
                        pii_in_path.append(field)

            # NOTE: We do NOT merge classified_fields here. The data flow
            # scanner reports only what it actually traces through the code
            # (variable names, subscript keys in the call site). The global
            # classification list would add noise from unrelated code.

            source_desc = "uploaded/read file data"
            for var, line, path in file_reads:
                if var in file_vars_in_call:
                    source_desc = f"file: {path or 'unknown'}"
                    break

            severity = "high" if pii_in_path else "medium"
            key = (rel, call_line, "data_flow", "llm")
            if seen_risks is None or key not in seen_risks:
                if seen_risks is not None:
                    seen_risks.add(key)
                risks.append(SecurityFinding(
                    category="data_flow",
                    title="File data flows to LLM",
                    data_source=source_desc,
                    data_sink="LLM API call",
                    pii_fields=pii_in_path,
                    description=f"File data ({', '.join(file_vars_in_call)}) is passed to an LLM API call",
                    evidence=[ev],
                    severity=severity,
                ))

        # Check 2: f-string or format with PII vars in LLM call context
        fstrings_in_call = _find_fstrings_with_vars(call_node, source)
        for fstr_vars, fstr_line in fstrings_in_call:
            pii_in_fstr = [v for v in fstr_vars if _PII_FIELD_RE.search(v)]
            if pii_in_fstr:
                key2 = (rel, fstr_line, "data_flow", "llm_fstr")
                if seen_risks is None or key2 not in seen_risks:
                    if seen_risks is not None:
                        seen_risks.add(key2)
                    ev2 = Evidence(file=rel, line=fstr_line, snippet=snippet(source, fstr_line))
                    risks.append(SecurityFinding(
                        category="data_flow",
                        title="File data in LLM prompt",
                        data_source="variable in f-string",
                        data_sink="LLM prompt",
                        pii_fields=pii_in_fstr,
                        description=f"PII-named variables ({', '.join(pii_in_fstr)}) embedded in LLM prompt string",
                        evidence=[ev2],
                        severity="high",
                    ))

        # Check 3: f-strings with PII fields anywhere in the function scope
        # (not just inside the call).  Catches patterns where data is formatted
        # into an intermediate variable (e.g. account_lines) that is later
        # passed to the LLM via another variable (e.g. prompt).
        # Only runs for function scopes — module scope would walk into unrelated
        # functions and produce false positives.
        if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        scope_fstrings = _find_fstrings_with_vars(scope, source)
        for fstr_vars, fstr_line in scope_fstrings:
            pii_in_scope = [v for v in fstr_vars if _PII_FIELD_RE.search(v)]
            if pii_in_scope:
                key3 = (rel, fstr_line, "data_flow", "llm_scope_fstr")
                if seen_risks is None or key3 not in seen_risks:
                    if seen_risks is not None:
                        seen_risks.add(key3)
                    ev3 = Evidence(file=rel, line=fstr_line, snippet=snippet(source, fstr_line))
                    risks.append(SecurityFinding(
                        category="data_flow",
                        title="File data in LLM prompt",
                        data_source="formatted data in scope",
                        data_sink="LLM prompt (same function)",
                        pii_fields=pii_in_scope,
                        description=f"Sensitive fields ({', '.join(pii_in_scope)}) formatted in function that calls LLM",
                        evidence=[ev3],
                        severity="high",
                    ))

        # Check 4: direct open().read() chained into messages
        for arg_node in ast.walk(call_node):
            if isinstance(arg_node, ast.Call):
                inner_name = _full_call_name(arg_node)
                if "read" in inner_name and ("open" in inner_name or "read_text" in inner_name):
                    key3 = (rel, arg_node.lineno, "data_flow", "llm_inline")
                    if seen_risks is None or key3 not in seen_risks:
                        if seen_risks is not None:
                            seen_risks.add(key3)
                        ev3 = Evidence(file=rel, line=arg_node.lineno, snippet=snippet(source, arg_node.lineno))
                        risks.append(SecurityFinding(
                            category="data_flow",
                            title="File data in LLM prompt",
                            data_source="inline file read",
                            data_sink="LLM prompt",
                            pii_fields=[],
                            description="Entire file contents read directly into LLM call arguments",
                            evidence=[ev3],
                            severity="medium",
                        ))


def _sink_label(sink_kind: str) -> str:
    """Human-readable label for a sink kind."""
    return {
        "llm": "LLM API call",
        "http": "HTTP API call",
        "database": "database/cloud API",
        "output_file": "output file",
    }.get(sink_kind, sink_kind)


def _sink_severity(sink_kind: str, has_pii: bool) -> str:
    """Severity based on data sensitivity and sink type.

    HIGH:   PII confirmed flowing to any sink
    MEDIUM: no PII, external service (LLM, HTTP, database/cloud)
    LOW:    no PII, local output file
    """
    if has_pii:
        return "high"
    return "low" if sink_kind == "output_file" else "medium"


def _analyze_cross_function(
    tree: ast.Module,
    source: str,
    rel: str,
    file_imports: set[str],
    risks: list[SecurityFinding],
    seen_risks: set[tuple[str, int, str, str]],
) -> None:
    """Detect data flow across function boundaries to any external sink.

    Catches patterns like:
        def load_data():
            return pd.read_csv("users.csv")
        def analyze():
            data = load_data()
            client.chat.completions.create(messages=[{"content": str(data)}])

    or:
        def main():
            data = load_data()
            requests.post(url, json={"payload": data})

    Strategy: find functions that return file data, then check if their return
    values are used in functions that send to any external sink (LLM, HTTP, output file).
    """
    has_http_lib = bool(file_imports & _HTTP_LIBS)
    has_db_lib = bool(file_imports & _CLOUD_DB_LIBS)

    # Pass 1: identify functions that read files and return data
    file_reader_funcs: set[str] = set()
    # Pass 2: identify functions that call any external sink
    # Maps func_name → list of (sink_kind, call_line)
    external_sink_funcs: dict[str, list[tuple[str, int]]] = {}

    for node in ast.iter_child_nodes(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        func_name = node.name
        has_file_read = False
        has_return = False
        sink_calls: list[tuple[str, int]] = []

        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                call_name = _full_call_name(child)
                call_parts = set(call_name.split("."))
                # File reader detection
                if call_parts & _FILE_READ_FUNCS:
                    has_file_read = True
                # LLM sink
                method_name = call_name.rsplit(".", 1)[-1]
                if method_name in _LLM_CALL_METHODS:
                    if not (method_name in ("invoke", "ainvoke") and _is_graph_runtime_call(child)):
                        sink_calls.append(("llm", child.lineno))
                # HTTP sink
                if (has_http_lib
                        and isinstance(child.func, ast.Attribute)
                        and child.func.attr in _HTTP_SINK_METHODS):
                    receiver = None
                    if isinstance(child.func.value, ast.Name):
                        receiver = child.func.value.id
                    if receiver in _HTTP_RECEIVERS:
                        sink_calls.append(("http", child.lineno))
                # Database / cloud SDK sink
                if (has_db_lib
                        and isinstance(child.func, ast.Attribute)
                        and child.func.attr in _DB_WRITE_METHODS):
                    sink_calls.append(("database", child.lineno))
                # Output file sink
                if (isinstance(child.func, ast.Attribute)
                        and child.func.attr in _FILE_WRITE_METHODS):
                    sink_calls.append(("output_file", child.lineno))
            if isinstance(child, ast.Return) and child.value is not None:
                has_return = True

        if has_file_read and has_return:
            file_reader_funcs.add(func_name)
        if sink_calls:
            external_sink_funcs[func_name] = sink_calls

    if not file_reader_funcs or not external_sink_funcs:
        return

    # Pass 3: in sink-calling functions, check if they also call a file-reader function
    for node in ast.iter_child_nodes(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name not in external_sink_funcs:
            continue

        called_funcs: set[str] = set()
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Name):
                    called_funcs.add(child.func.id)

        overlap = called_funcs & file_reader_funcs
        if overlap:
            for sink_kind, sink_line in external_sink_funcs[node.name]:
                key = (rel, sink_line, "data_flow", sink_kind)
                if key not in seen_risks:
                    seen_risks.add(key)
                    ev = Evidence(file=rel, line=sink_line, snippet=snippet(source, sink_line))
                    label = _sink_label(sink_kind)
                    severity = _sink_severity(sink_kind, has_pii=False)
                    risks.append(SecurityFinding(
                        category="data_flow",
                        title=f"File data flows to {label}",
                        data_source=f"file data via {', '.join(sorted(overlap))}()",
                        data_sink=label,
                        pii_fields=[],
                        description=(
                            f"Function {node.name}() calls {', '.join(sorted(overlap))}() "
                            f"(which reads files) and sends data to {label}"
                        ),
                        evidence=[ev],
                        severity=severity,
                    ))

    # Pass 4: detect file data flowing via parameters across functions.
    # Pattern: main() calls load_data() → passes result as arg to analyze(data) → external sink.
    # Includes multi-role orchestrators (functions that both write output directly AND pass file
    # data to other sink-calling functions) — duplicates are prevented by the dedup key.
    for node in ast.iter_child_nodes(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        # Seed: variables that directly receive return values from file-reader functions.
        file_data_vars: set[str] = set()
        for child in ast.walk(node):
            if isinstance(child, ast.Assign) and len(child.targets) == 1:
                var_name = _target_name(child.targets[0])
                if var_name and isinstance(child.value, ast.Call):
                    if isinstance(child.value.func, ast.Name) and child.value.func.id in file_reader_funcs:
                        file_data_vars.add(var_name)

        if not file_data_vars:
            continue

        # Propagate taint through derived variables until fixed point.
        # Covers multi-step chains like:
        #   text = extract_text(path)          # seeded above
        #   chunks = chunk_text(text, ...)      # derived: text in call_names
        #   all_chunks.extend(chunks)           # list mutation: chunks is tainted
        #   embedded = embed_llm(all_chunks)    # propagates to embedded
        changed = True
        while changed:
            changed = False
            for child in ast.walk(node):
                if isinstance(child, ast.Assign) and len(child.targets) == 1:
                    var_name = _target_name(child.targets[0])
                    if var_name and var_name not in file_data_vars:
                        if _collect_names(child.value) & file_data_vars:
                            file_data_vars.add(var_name)
                            changed = True
                if isinstance(child, ast.Expr) and isinstance(child.value, ast.Call):
                    call = child.value
                    if (isinstance(call.func, ast.Attribute)
                            and call.func.attr in ("extend", "append")
                            and isinstance(call.func.value, ast.Name)):
                        list_var = call.func.value.id
                        if list_var not in file_data_vars:
                            arg_tainted = any(
                                _collect_names(a) & file_data_vars for a in call.args
                            )
                            if arg_tainted:
                                file_data_vars.add(list_var)
                                changed = True

        # Check if any file data var is passed as argument to an external-sink-calling function
        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue
            if not isinstance(child.func, ast.Name):
                continue
            called_name = child.func.id
            if called_name not in external_sink_funcs:
                continue
            arg_names = {a.id for a in child.args if isinstance(a, ast.Name)}
            kw_names = {kw.value.id for kw in child.keywords
                        if isinstance(kw.value, ast.Name)}
            passed_data = (arg_names | kw_names) & file_data_vars
            if passed_data:
                for sink_kind, sink_line in external_sink_funcs[called_name]:
                    key = (rel, sink_line, "data_flow", sink_kind)
                    if key not in seen_risks:
                        seen_risks.add(key)
                        ev = Evidence(file=rel, line=sink_line, snippet=snippet(source, sink_line))
                        label = _sink_label(sink_kind)
                        severity = _sink_severity(sink_kind, has_pii=False)
                        risks.append(SecurityFinding(
                            category="data_flow",
                            title=f"File data flows to {label}",
                            data_source=f"file data via parameter ({', '.join(sorted(passed_data))})",
                            data_sink=label,
                            pii_fields=[],
                            description=(
                                f"File data from {', '.join(sorted(file_reader_funcs))}() "
                                f"flows via parameter to {called_name}() which calls {label}"
                            ),
                            evidence=[ev],
                            severity=severity,
                        ))


def _target_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Tuple):
        # Take first element for unpacking
        if node.elts and isinstance(node.elts[0], ast.Name):
            return node.elts[0].id
    return None


def _full_call_name(node: ast.Call) -> str:
    """Build a dotted call chain."""
    parts: list[str] = []
    cur: ast.expr = node.func
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return ".".join(reversed(parts))


def _collect_names(node: ast.AST) -> set[str]:
    """Collect all Name references within an AST subtree."""
    names: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            names.add(child.id)
    return names


def _is_read_open(call_node: ast.Call) -> bool:
    """Return True if open() is in read mode (default or explicit 'r'/'rb').

    Write ('w', 'a', 'x') and mixed write ('w+', 'r+') modes indicate a sink
    (output file), not a source of file data, so the handle should not be
    treated as a tainted variable.
    """
    _WRITE_MODES = {"w", "a", "x", "wb", "ab", "xb", "w+", "a+", "x+"}
    # Positional mode: open(path, "w")
    if len(call_node.args) >= 2:
        mode_arg = call_node.args[1]
        if isinstance(mode_arg, ast.Constant) and isinstance(mode_arg.value, str):
            return mode_arg.value not in _WRITE_MODES
    # Keyword mode: open(path, mode="w")
    for kw in call_node.keywords:
        if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
            return kw.value.value not in _WRITE_MODES
    # No mode argument → default is "r" (read)
    return True


def _find_fstrings_with_vars(node: ast.AST, source: str) -> list[tuple[list[str], int]]:
    """Find f-strings (JoinedStr) in subtree, return var names and line numbers."""
    results: list[tuple[list[str], int]] = []
    for child in ast.walk(node):
        if isinstance(child, ast.JoinedStr):
            var_names: list[str] = []
            for val in child.values:
                if isinstance(val, ast.FormattedValue):
                    for n in ast.walk(val):
                        if isinstance(n, ast.Name):
                            var_names.append(n.id)
                        if isinstance(n, ast.Subscript):
                            if isinstance(n.slice, ast.Constant) and isinstance(n.slice.value, str):
                                var_names.append(n.slice.value)
                        # .get() in f-string: f"{a.get('email')}"
                        if (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                                and n.func.attr == "get" and n.args):
                            arg = n.args[0]
                            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                                var_names.append(arg.value)
            if var_names:
                results.append((var_names, child.lineno))
    return results


def _first_str_arg(node: ast.Call) -> str | None:
    if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
        return node.args[0].value
    return None


def _extract_file_path(node: ast.Call) -> str | None:
    """Extract file path from a call, handling nested open() calls.

    Handles: pd.read_csv("file.csv"), csv.DictReader(open("file.csv")),
    json.load(open("data.json")), etc.
    """
    path = _first_str_arg(node)
    if path:
        return path
    # Nested open() call as first arg: csv.DictReader(open("file.csv"))
    if node.args and isinstance(node.args[0], ast.Call):
        inner = node.args[0]
        inner_name = _full_call_name(inner)
        if "open" in inner_name.split("."):
            return _first_str_arg(inner)
    return None


def _resolve_source(
    tainted_vars: set[str],
    file_reads: list[tuple[str, int, str | None]],
) -> str:
    """Look up the actual file path for tainted variables."""
    for var, _line, path in file_reads:
        if var in tainted_vars and path:
            return f"file: {path}"
    return "uploaded/read file data"


def _is_graph_runtime_call(node: ast.Call) -> bool:
    """Return True if the call looks like a LangGraph graph runtime invoke, not an LLM call.

    Heuristic: receiver name contains 'graph', 'app', 'workflow', or 'chain' but NOT
    common LLM client variable names.
    """
    if not isinstance(node.func, ast.Attribute):
        return False
    receiver = node.func.value
    name = None
    if isinstance(receiver, ast.Name):
        name = receiver.id
    elif isinstance(receiver, ast.Attribute):
        name = receiver.attr

    if name is None:
        return False

    name_lower = name.lower()
    # Graph runtime indicators
    graph_indicators = {"graph", "app", "workflow", "agent_graph", "compiled",
                        "state_graph", "langgraph"}
    llm_indicators = {"llm", "model", "client", "chat", "openai", "anthropic",
                      "groq", "cohere", "claude"}

    for ind in graph_indicators:
        if ind in name_lower:
            return True
    for ind in llm_indicators:
        if ind in name_lower:
            return False

    return False



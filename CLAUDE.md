# Code Preflight — Agent Instructions

This file is read by Claude Code and other coding agents at the start of every session.
**Follow these rules before writing any code.**

---

## Before touching any file

1. **Read every file you will modify.** Do not edit from memory or assumption.
2. **Trace all call sites** for any interface you change (function signature, field name, model field, property type). Use Grep to find every import and every usage before you touch it.
3. **State the impact** before implementing: "This change affects X, Y, Z. I will also update those."

If you skip steps 1–3 you will introduce regressions. This has happened repeatedly on this project.

---

## Architecture invariants

These are hard rules. If you think you need to break one, stop and ask.

### SecurityReport
- `findings: list[SecurityFinding]` is the **one canonical list**. Every finding from every scanner ends up here.
- `deploy_blocked`, `requires_review`, `gate_status`, `gate_message`, all severity counts, and `ir_query_count` are **`@computed_field`** derived from `findings`. Do not store them as mutable fields.
- `data_flow_risks`, `credential_leak_risks`, `agent_findings` are **plain `@property`** (not `@computed_field`). They are NOT serialized by `model_dump()`. They are filtered views only — never the authoritative list for anything.
- **`projection.py` must iterate `security.findings` exactly once.** It must never iterate `data_flow_risks` or `credential_leak_risks` — those are the same findings and will cause double/triple counting. If you change filtered view types, immediately check `projection.py`.
- `gate_status`/`gate_message` live on the model. Renderers read them; they do not re-derive gate wording.

### Data flow scanner (`security/data_flow.py`)
- `scan_data_flow()` takes only `(workspace, py_files)`. No `data_classifications` parameter — that pathway was removed because `classified_fields` was never used to emit findings.
- Dedup key is `(file, line, category, sink_id)` — four elements. Do not regress to `(file, line)`.
- Pass 4 does **not** skip functions in `external_sink_funcs` (multi-role orchestrator fix).

### I/O pipeline (`analyzer/io_scan.py`, `analyzer/service.py`)
- `scan_io()` does **detection only** — no normalization inside.
- `_finalize_io_report(io_report, workspace, py_files)` runs **once** in `service.py` after all three I/O sources (scan_io + notebooks + API) have been merged.
- Hardcoded paths are merged by path string using `dict[str, HardcodedPath]`. Never append-only.
- `seen_input_paths`/`seen_output_paths` track **path literals only**. Generated IDs (`"input_0"`, `"output_0"`) use separate `seen_input_ids`/`seen_output_ids` sets.

### Egress (`analyzer/egress_scan.py`, `analyzer/models.py`)
- `EgressReport` has one field: `outbound_calls: list[OutboundCall]`. No `suggested_gateway_needs`, no `models_found`, no gateway recommendations. These were Living Apps residue and have been deleted.

### Analysis result (`analyzer/models.py`, `analyzer/service.py`)
- `AnalysisResult` has no `manifest_path`, `porting_plan`, or `porting_plan_path`. These were deleted.
- `py_file_count: int` is set in `service.py` from `len(py_files)`. `count_py_files()` in `_helpers.py` reads it directly.

### Secrets (`analyzer/models.py`, `analyzer/secrets_scan.py`, `scanner.py`)
- `SecretFinding` has `origin: str` with values `"ast_name"`, `"dotenv"`, `"detect_secrets"`, `"token_pattern"`.
- Toolchain counts: detect-secrets tool counts `origin == "detect_secrets"` findings; LA secrets scanner counts everything else.

### Dependency scanning (`scanner.py`)
- Requirements passed to `scan_vulnerabilities()` preserve version spec: `f"{d.name}{d.spec}" if d.spec else d.name`. Do not regress to `d.name` only.

### Renderers (`render/markdown.py`, `render/pdf.py`, `render/_helpers.py`)
- Entrypoint matrix counting lives in `compute_entrypoint_metrics(ep)` in `_helpers.py`. Both renderers call it. Never re-implement inline.
- Gate wording (`BLOCKED`, `REVIEW REQUIRED`, `PASS`) comes from `s.gate_message`. Never duplicate inline strings in renderers.
- Egress rows are formatted inline per renderer (markdown bold vs plain text). No shared helper needed.
- `top_risks()` returns `list[str]`. Renderers call it; they do not re-derive top risks.

### Toolchain counts (`scanner.py`)
- "LA code scanner" counts: `origin not in ("bandit", "ir_query")` AND `category not in ("deps", "data_flow", "credential_leak", "agent", "secrets")`. IR findings are counted by "Effect graph scanner" only.
- "Effect graph scanner" counts: `origin == "ir_query"`.
- "detect-secrets" counts: `SecretFinding.origin == "detect_secrets"`. "LA secrets scanner" counts everything else.

### IR system (`ir/`)
- `data_flow_risks`/`credential_leak_risks` filtered views have no place in IR queries. IR queries operate on `security.findings` via `existing_findings` parameter.
- Secrets conversion happens **before** IR queries in `security/__init__.py` so IR severity fusion sees the full finding set.
- `GRAPH_RUNTIME` capability prevents false positives on `graph_app.ainvoke()`.

---

## Change protocol

**When changing a model field or function signature:**
1. `grep -r "field_name\|function_name" src/ tests/` before touching anything
2. List every file that needs updating
3. Update all of them in the same change
4. Run `python -m pytest tests/ -q` — all 288 tests must pass

**When adding a new scanner or finding category:**
1. Add origin field value to the canonical list in `SecretFinding` or set `origin=` on `SecurityFinding`
2. Add a toolchain entry in `scanner._build_toolchain()`
3. Add a test in `tests/`

**When changing the projection layer:**
1. Re-read `projection.py` in full before editing
2. Confirm `_collect_effects()` still iterates `security.findings` exactly once
3. Run the integration test and check entrypoint matrix counts

---

## What has gone wrong before (do not repeat)

- Changed `data_flow_risks` from `@computed_field` to `@property` without updating `projection.py` → tripled findings in entrypoint matrix
- Passed `data_classifications` as dicts via `.model_dump()` to `scan_data_flow()` → unnecessary type round-trip
- Kept `SuggestedGatewayNeeds`, `manifest_generator.py`, `porting_plan.py` around after their feature was removed → dead code confused later passes
- Used `d.name` only when building requirements for pip-audit → unpinned scans, reduced accuracy
- Used same set for path literals and generated IDs in io_scan dedup → semantically invalid checks
- Appended new `HardcodedPath` per occurrence instead of merging by path → inflated count
- Ran I/O normalization before all I/O sources were merged → notebook/API entries bypassed dedup
- Argparse default path values gated on `seen_*` sets that were just populated → paths never reached `hardcoded_dict`
- `_regex_fallback()` called with `hardcoded` instead of `hardcoded_dict` → NameError on any unparseable file
- Used `livingapps_gateway` in `_LLM_LIBS` — Living Apps residue, removed
- "LA code scanner" toolchain count included IR findings → double-counted with "Effect graph scanner"

---

## Project structure (quick reference)

```
src/la_analyzer/
  cli.py                      entry point
  scanner.py                  top-level scan() orchestrator
  analyzer/
    service.py                analyze_repo() — Phase 1
    models.py                 AnalysisResult, IOReport, EgressReport, etc.
    io_scan.py                I/O detection (scan_io + _finalize_io_report)
    egress_scan.py            outbound call detection
    secrets_scan.py           built-in secret scanner
    projection.py             Phase 3: call graph + entrypoint effects
  security/
    __init__.py               run_security_review() — Phase 2
    models.py                 SecurityFinding, SecurityReport
    data_flow.py              file→LLM/HTTP/DB taint tracing
    credential_leak.py        secrets in logs/prompts/HTTP
    code_scan.py              Bandit + built-in code patterns
  ir/
    __init__.py               build_effect_graph()
    capability_registry.py    data-only: constructor → CapabilityEntry
    queries.py                graph queries → SecurityFinding[]
  render/
    _helpers.py               shared: top_risks, compute_entrypoint_metrics, etc.
    markdown.py               Markdown renderer
    pdf.py                    PDF renderer
```

---

## Testing

```bash
pip install -e ".[dev]"
python -m pytest tests/ -q   # must be 288 passing
```

Do not ship a change that reduces the test count or introduces failures.

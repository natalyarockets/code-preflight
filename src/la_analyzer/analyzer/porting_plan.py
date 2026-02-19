"""Generate a porting plan from analysis results."""

from __future__ import annotations

from la_analyzer.analyzer.models import (
    ChangeFile,
    DetectionReport,
    EgressReport,
    IOReport,
    PortingPlan,
    RequiredChange,
    SecretsReport,
)


def generate_porting_plan(
    detection: DetectionReport,
    io_report: IOReport,
    egress: EgressReport,
    secrets: SecretsReport,
) -> PortingPlan:
    required: list[RequiredChange] = []
    optional: list[RequiredChange] = []

    # 1. Hardcoded input paths → replace with configurable inputs
    for hp in io_report.hardcoded_paths:
        # Check if it's an input path
        is_input = any(
            inp.path_literal == hp.path for inp in io_report.inputs
        )
        if is_input:
            required.append(RequiredChange(
                type="replace_hardcoded_input",
                description=f"Replace hardcoded input path '{hp.path}' with a configurable input from /inputs",
                files=[
                    ChangeFile(file=e.file, line=e.line, snippet=e.snippet)
                    for e in hp.evidence
                ],
                suggested_fix=(
                    f"Read from /inputs/ directory or accept path via environment variable / CLI arg "
                    f"instead of hardcoded '{hp.path}'"
                ),
            ))

    # 2. Standardize output paths
    for out in io_report.outputs:
        if out.path_literal:
            required.append(RequiredChange(
                type="standardize_outputs",
                description=f"Redirect output '{out.path_literal}' to write to /outputs/ directory",
                files=[
                    ChangeFile(file=e.file, line=e.line, snippet=e.snippet)
                    for e in out.evidence
                ],
                suggested_fix=f"Write to /outputs/{_basename(out.path_literal)} instead of '{out.path_literal}'",
            ))

    # 3. Route LLM calls via gateway
    for call in egress.outbound_calls:
        if call.kind == "llm_sdk":
            required.append(RequiredChange(
                type="route_llm_via_gateway",
                description=f"Route {call.library} SDK calls through the Living Apps LLM gateway",
                files=[
                    ChangeFile(file=e.file, line=e.line, snippet=e.snippet)
                    for e in call.evidence
                ],
                suggested_fix=(
                    f"Configure {call.library} client to use the platform LLM gateway base URL "
                    f"(injected via LLM_GATEWAY_URL env var)"
                ),
            ))

    # 4. Route non-LLM external calls via proxy
    _non_llm_kinds = {"http", "database", "cloud", "baas"}
    seen_ext: set[str] = set()
    for call in egress.outbound_calls:
        if call.kind in _non_llm_kinds and call.library not in seen_ext:
            seen_ext.add(call.library)
            required.append(RequiredChange(
                type="route_external_via_proxy",
                description=f"Configure {call.library} to use platform-managed connection credentials",
                files=[
                    ChangeFile(file=e.file, line=e.line, snippet=e.snippet)
                    for e in call.evidence
                ],
                suggested_fix=(
                    f"Inject {call.library} connection details via environment variables "
                    f"managed by the platform"
                ),
            ))

    # 5. Remove embedded secrets
    for finding in secrets.findings:
        if finding.kind in ("hardcoded_key", "token_like"):
            required.append(RequiredChange(
                type="remove_embedded_secret",
                description=f"Remove hardcoded secret ({finding.name_hint or 'token'}) and use env var injection",
                files=[
                    ChangeFile(file=e.file, line=e.line, snippet=e.snippet)
                    for e in finding.evidence
                ],
                suggested_fix=(
                    f"Replace with os.environ['{finding.name_hint or 'SECRET_KEY'}'] — "
                    f"the platform will inject secrets as env vars"
                ),
            ))

    # 5. Choose entrypoint if multiple candidates
    if len(detection.entrypoint_candidates) > 1:
        optional.append(RequiredChange(
            type="choose_entrypoint",
            description=(
                f"Multiple entrypoint candidates found ({len(detection.entrypoint_candidates)}). "
                f"Confirm the primary entrypoint."
            ),
            files=[
                ChangeFile(file=e.file, line=e.line, snippet=e.snippet)
                for c in detection.entrypoint_candidates
                for e in c.evidence[:1]
            ],
            suggested_fix=f"Best candidate: {detection.entrypoint_candidates[0].value}",
        ))

    # 6. Web API notes
    n_routes = len(io_report.api_routes)
    if n_routes:
        optional.append(RequiredChange(
            type="choose_entrypoint",
            description=(
                f"Web API detected with {n_routes} route(s). "
                f"Use uvicorn entrypoint instead of batch wrapper."
            ),
            files=[
                ChangeFile(file=r.file, line=r.line, snippet=f"{r.method} {r.path}")
                for r in io_report.api_routes[:5]
            ],
            suggested_fix="uvicorn app.main:app --host 0.0.0.0 --port 8000",
        ))

    # Summary
    parts: list[str] = []
    n_inputs = sum(1 for c in required if c.type == "replace_hardcoded_input")
    n_outputs = sum(1 for c in required if c.type == "standardize_outputs")
    n_llm = sum(1 for c in required if c.type == "route_llm_via_gateway")
    n_secrets = sum(1 for c in required if c.type == "remove_embedded_secret")
    n_ext = sum(1 for c in required if c.type == "route_external_via_proxy")

    if n_inputs:
        parts.append(f"{n_inputs} hardcoded input path(s) to replace")
    if n_outputs:
        parts.append(f"{n_outputs} output path(s) to standardize")
    if n_llm:
        parts.append(f"{n_llm} LLM call(s) to route via gateway")
    if n_ext:
        parts.append(f"{n_ext} external service(s) to configure")
    if n_secrets:
        parts.append(f"{n_secrets} embedded secret(s) to remove")
    if not parts:
        parts.append("No required changes detected")

    has_api_routes = bool(io_report.api_routes)
    wrapper_recommended = bool(io_report.hardcoded_paths) and not has_api_routes

    return PortingPlan(
        summary="; ".join(parts) + ".",
        required_changes=required,
        optional_changes=optional,
        wrapper_recommended=wrapper_recommended,
        wrapper_entrypoint_path="livingapps_entrypoint.py" if wrapper_recommended else "",
    )


def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]

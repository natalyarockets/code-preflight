"""Effect projection: map findings to reachable code per entrypoint.

For each entrypoint, collects reachable functions from the call graph and
maps existing findings (security, I/O, egress) to those functions by
file:line range. Produces an EntrypointProjection with a complete effect
list per entrypoint, plus unreachable_findings for findings in dead code.
"""

from __future__ import annotations

import logging
from pathlib import Path

from la_analyzer.analyzer.call_graph import build_call_graph, reachable_from
from la_analyzer.analyzer.models import (
    AnalysisResult,
    CallGraph,
    DetectionReport,
    EntrypointProjection,
    FunctionNode,
    ProjectedEffect,
    ProjectionReport,
)
from la_analyzer.security.models import SecurityReport

log = logging.getLogger(__name__)


def build_projection(
    workspace: Path,
    py_files: list[Path],
    analysis: AnalysisResult,
    security: SecurityReport | None = None,
) -> ProjectionReport:
    """Build effect projections for all detected entrypoints.

    Args:
        workspace: Project root.
        py_files: Python files in the project.
        analysis: AnalysisResult from analyze_repo().
        security: Optional SecurityReport from run_security_review().

    Returns:
        ProjectionReport with per-entrypoint projections and unreachable findings.
    """
    graph = build_call_graph(workspace, py_files, analysis.detection)

    # Build a function lookup for line-range matching
    fn_lookup = {fn.id: fn for fn in graph.functions}

    # Collect all findings as ProjectedEffects
    all_effects = _collect_effects(analysis, security)

    # Map each effect to the function(s) it belongs to
    effect_to_functions: dict[int, list[str]] = {}
    for i, effect in enumerate(all_effects):
        matching = _find_functions_for_effect(effect, graph.functions)
        effect_to_functions[i] = matching

    # For each entrypoint, compute reachable set and filter effects
    projections: list[EntrypointProjection] = []
    claimed_effects: set[int] = set()

    for eid in graph.entrypoint_ids:
        reachable = reachable_from(eid, graph)
        fn = fn_lookup.get(eid)
        label = fn.name if fn else eid

        # Find the candidate label from detection report
        for c in analysis.detection.entrypoint_candidates:
            if c.kind == "command":
                parts = c.value.split()
                script = parts[-1] if len(parts) >= 2 else c.value
                if eid == f"{script}::<module>":
                    label = c.value
                    break
            elif c.kind == "module":
                mod_path = c.value.replace(".", "/") + ".py"
                if eid == f"{mod_path}::<module>":
                    label = c.value
                    break

        ep_effects: list[ProjectedEffect] = []
        for i, effect in enumerate(all_effects):
            fn_ids = effect_to_functions[i]
            # Effect is reachable if ANY of its matching functions are reachable
            if any(fid in reachable for fid in fn_ids):
                ep_effects.append(effect)
                claimed_effects.add(i)
            # Also include effects in the entrypoint file's <module> scope
            elif not fn_ids and _effect_in_file(effect, eid):
                ep_effects.append(effect)
                claimed_effects.add(i)

        projections.append(EntrypointProjection(
            entrypoint_id=eid,
            entrypoint_label=label,
            reachable_functions=sorted(reachable),
            effects=ep_effects,
        ))

    # Unreachable = effects not claimed by any entrypoint
    unreachable = [
        all_effects[i] for i in range(len(all_effects))
        if i not in claimed_effects
    ]

    return ProjectionReport(
        projections=projections,
        unreachable_findings=unreachable,
        call_graph=graph,
    )


def enrich_evidence_with_functions(
    graph: CallGraph,
    analysis: AnalysisResult,
    security: SecurityReport | None = None,
) -> None:
    """Post-processor: add function_name to all Evidence objects.

    Mutates evidence objects in-place. Does not modify any scanner code.
    """
    fn_by_file: dict[str, list[FunctionNode]] = {}
    for fn in graph.functions:
        fn_by_file.setdefault(fn.file, []).append(fn)

    def _enrich(evidence_list):
        for ev in evidence_list:
            if ev.function_name:
                continue
            candidates = fn_by_file.get(ev.file, [])
            best = _best_enclosing(ev.line, candidates)
            if best and best.name != "<module>":
                ev.function_name = best.name

    # Analysis evidence
    for inp in analysis.io.inputs:
        _enrich(inp.evidence)
    for out in analysis.io.outputs:
        _enrich(out.evidence)
    for hp in analysis.io.hardcoded_paths:
        _enrich(hp.evidence)
    for call in analysis.egress.outbound_calls:
        _enrich(call.evidence)
    for sf in analysis.secrets.findings:
        _enrich(sf.evidence)

    # Security evidence
    if security:
        for f in security.findings:
            _enrich(f.evidence)
        for dc in security.data_classifications:
            _enrich(dc.evidence)
        for df in security.data_flow_risks:
            _enrich(df.evidence)
        for cl in security.credential_leak_risks:
            _enrich(cl.evidence)


# ── Helpers ───────────────────────────────────────────────────────────────


def _collect_effects(
    analysis: AnalysisResult,
    security: SecurityReport | None,
) -> list[ProjectedEffect]:
    """Flatten all findings into ProjectedEffect list."""
    effects: list[ProjectedEffect] = []

    # I/O inputs
    for inp in analysis.io.inputs:
        for ev in inp.evidence:
            effects.append(ProjectedEffect(
                source="io", title=f"Input: {inp.id} ({inp.kind})",
                file=ev.file, line=ev.line,
                function_name=ev.function_name,
                detail=inp.description or inp.label,
            ))

    # I/O outputs
    for out in analysis.io.outputs:
        for ev in out.evidence:
            effects.append(ProjectedEffect(
                source="io", title=f"Output: {out.id} ({out.kind})",
                file=ev.file, line=ev.line,
                function_name=ev.function_name,
                detail=out.label,
            ))

    # Egress
    for call in analysis.egress.outbound_calls:
        for ev in call.evidence:
            effects.append(ProjectedEffect(
                source="egress",
                title=f"Egress: {call.library} ({call.kind})",
                file=ev.file, line=ev.line,
                function_name=ev.function_name,
                detail=", ".join(call.domains) if call.domains else "",
            ))

    # Secrets
    for sf in analysis.secrets.findings:
        for ev in sf.evidence:
            effects.append(ProjectedEffect(
                source="secret",
                title=f"Secret: {sf.kind}",
                severity="high",
                file=ev.file, line=ev.line,
                function_name=ev.function_name,
                detail=sf.name_hint or "",
            ))

    # Prompt surfaces
    for ps in analysis.prompt_surface.surfaces:
        for ev in ps.evidence:
            vars_str = ", ".join(v.name for v in ps.prompt_variables)
            effects.append(ProjectedEffect(
                source="prompt",
                title=f"Prompt: {ps.llm_method}() with {len(ps.prompt_variables)} variable(s)",
                severity="info",
                file=ev.file, line=ev.line,
                function_name=ev.function_name or ps.function,
                detail=vars_str,
            ))

    # Tool registrations
    for tool in analysis.tool_registration.tools:
        for ev in tool.evidence:
            cap_kinds = ", ".join(c.kind for c in tool.capabilities) if tool.capabilities else "compute"
            effects.append(ProjectedEffect(
                source="tool",
                title=f"Tool: {tool.name} ({tool.registration})",
                severity="info",
                file=ev.file, line=ev.line,
                function_name=ev.function_name or tool.name,
                detail=f"capabilities: {cap_kinds}",
            ))

    # State flows
    for nf in analysis.state_flow.node_flows:
        reads = ", ".join(nf.reads[:5])
        writes = ", ".join(nf.writes[:5])
        effects.append(ProjectedEffect(
            source="state",
            title=f"State: {nf.function} reads [{reads}] writes [{writes}]",
            severity="info",
            file=nf.file, line=nf.line_start,
            function_name=nf.function,
            detail=f"reads: {reads}; writes: {writes}",
        ))

    # Security findings
    if security:
        for f in security.findings:
            for ev in f.evidence:
                effects.append(ProjectedEffect(
                    source="security",
                    title=f.title,
                    severity=f.severity,
                    file=ev.file, line=ev.line,
                    function_name=ev.function_name,
                    detail=f.description,
                ))
        for df in security.data_flow_risks:
            for ev in df.evidence:
                effects.append(ProjectedEffect(
                    source="security",
                    title=f"Data flow: {df.data_source} -> {df.data_sink}",
                    severity=df.severity,
                    file=ev.file, line=ev.line,
                    function_name=ev.function_name,
                    detail=df.description,
                ))
        for cl in security.credential_leak_risks:
            for ev in cl.evidence:
                effects.append(ProjectedEffect(
                    source="security",
                    title=f"Credential leak: {cl.credential_name}",
                    severity=cl.severity,
                    file=ev.file, line=ev.line,
                    function_name=ev.function_name,
                    detail=cl.description,
                ))

    return effects


def _find_functions_for_effect(
    effect: ProjectedEffect,
    functions: list[FunctionNode],
) -> list[str]:
    """Find function IDs whose file:line range contains this effect."""
    result: list[str] = []
    for fn in functions:
        if fn.file == effect.file and fn.line_start <= effect.line <= fn.line_end:
            result.append(fn.id)
    return result


def _effect_in_file(effect: ProjectedEffect, entrypoint_id: str) -> bool:
    """Check if an effect is in the same file as the entrypoint."""
    # entrypoint_id is like "main.py::<module>"
    file_part = entrypoint_id.split("::")[0]
    return effect.file == file_part


def _best_enclosing(line: int, candidates: list[FunctionNode]) -> FunctionNode | None:
    """Find the tightest enclosing function for a line."""
    best: FunctionNode | None = None
    for fn in candidates:
        if fn.line_start <= line <= fn.line_end:
            if best is None or fn.line_start > best.line_start:
                best = fn
    return best

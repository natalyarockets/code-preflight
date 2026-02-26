"""Render scan results as a Markdown report -- security-first layout."""

from __future__ import annotations

from la_analyzer.render._helpers import (
    count_py_files,
    executive_summary,
    leak_label,
    sev_order,
    strip_bandit_prefix,
    top_risks,
)
from la_analyzer.scanner import ScanResult


def render_markdown(result: ScanResult) -> str:
    """Produce a full Markdown report from a ScanResult.

    Layout:
    1. Title
    2. Executive summary (If You Deploy This As-Is)
    3. Security summary card (gate + severity + top risks)
    4. Trust boundaries (egress only)
    5. Project structure (condensed)
    6. LLM prompt analysis
    7. Tool registration map
    8. State flow
    9. Entrypoint effect matrix
    10. Security findings (detailed)
    11. Call graph (mermaid)
    12. Scan toolchain appendix
    """
    sections: list[str] = []
    name = result.project_path.name

    # 1. Title
    sections.append(f"# {name} -- Static Runtime Projection and Safety Audit\n")

    # 1b. Executive summary
    sections.append(_render_executive_summary(result))

    # 2. Security summary card
    sections.append(_render_summary_card(result))

    # 3. Trust boundaries
    sections.append(_render_trust_boundaries(result))

    # 4. Condensed structural summary
    sections.append(_render_structural_summary(result))

    # 5. LLM Prompt Analysis
    sections.append(_render_prompt_surfaces(result))

    # 6. Tool Registration Map
    sections.append(_render_tool_registrations(result))

    # 7. State Flow
    sections.append(_render_state_flow(result))

    # 8. Entrypoint effect matrix
    sections.append(_render_entrypoint_matrix(result))

    # 9. Detailed security findings
    sections.append(_render_security_findings(result))

    # 10. Call graph (mermaid)
    sections.append(_render_mermaid_call_graph(result))

    # 11. Scan toolchain audit trail
    sections.append(_render_toolchain(result))

    return "\n".join(s for s in sections if s)


# ── 1b. Executive Summary ─────────────────────────────────────────────────


def _render_executive_summary(result: ScanResult) -> str:
    bullets = executive_summary(result)
    if not bullets:
        return ""

    lines: list[str] = []
    lines.append("## If You Deploy This As-Is\n")
    for b in bullets:
        lines.append(f"- {b}")
    lines.append("")
    return "\n".join(lines)


# ── 2. Security Summary Card ───────────────────────────────────────────────


def _render_summary_card(result: ScanResult) -> str:
    s = result.security
    a = result.analysis
    lines: list[str] = []

    lines.append("## Security Summary\n")

    # Gate decision
    if s:
        if s.deploy_blocked:
            lines.append("> **BLOCKED** -- Critical findings should be resolved before deployment.\n")
        elif s.requires_review:
            lines.append("> **REVIEW REQUIRED** -- High-severity findings should be reviewed.\n")
        else:
            lines.append("> **PASS** -- No critical or high-severity findings.\n")

        # Severity counts
        lines.append(
            f"| Critical | High | Medium | Low |\n"
            f"|---|---|---|---|\n"
            f"| {s.critical_count} | {s.high_count} | {s.medium_count} | {s.low_count} |\n"
        )

        # Top risks as actionable sentences
        top_risks_ = top_risks(result)
        if top_risks_:
            lines.append(f"**High / critical findings ({len(top_risks_)}):**\n")
            for risk in top_risks_:
                lines.append(f"- {risk}")
            lines.append("")
    else:
        lines.append("Security scan was not run. Use `la-scan` without `--no-security` for full results.\n")

    return "\n".join(lines)


# ── 3. Trust Boundary Summary ──────────────────────────────────────────────


def _render_trust_boundaries(result: ScanResult) -> str:
    a = result.analysis
    s = result.security
    lines: list[str] = []

    if not a.egress.outbound_calls:
        return ""

    lines.append("## Trust Boundaries -- What Leaves This Repo\n")
    lines.append("### Data Egress\n")
    for call in a.egress.outbound_calls:
        domains = ", ".join(call.domains) if call.domains else "unknown"
        loc = f"`{call.evidence[0].file}:{call.evidence[0].line}`" if call.evidence else ""
        lines.append(f"- **{call.kind}** via `{call.library}` -> {domains} {loc}")
    lines.append("")

    return "\n".join(lines)


# ── 3b. LLM Prompt Analysis ───────────────────────────────────────────────


def _render_prompt_surfaces(result: ScanResult) -> str:
    ps = result.analysis.prompt_surface
    if not ps.surfaces:
        return ""

    lines: list[str] = []
    lines.append("## LLM Prompt Analysis\n")
    lines.append("| Function | Method | Variables | Constants | Location |")
    lines.append("|---|---|---|---|---|")

    for s in ps.surfaces:
        vars_str = ", ".join(f"`{v.name}`" for v in s.prompt_variables) or "-"
        consts_str = ", ".join(f"`{c}`" for c in s.string_constants) or "-"
        lines.append(f"| `{s.function}` | {s.llm_method} | {vars_str} | {consts_str} | `{s.file}:{s.line}` |")

    lines.append("")
    return "\n".join(lines)


# ── 3c. Tool Registration Map ────────────────────────────────────────────


def _render_tool_registrations(result: ScanResult) -> str:
    tr = result.analysis.tool_registration
    if not tr.tools:
        return ""

    lines: list[str] = []
    lines.append("## Registered Tools\n")
    lines.append("| Tool | Registration | Parameters | Capabilities | Location |")
    lines.append("|---|---|---|---|---|")

    for t in tr.tools:
        params = ", ".join(f"`{p}`" for p in t.parameters) or "-"
        caps = ", ".join(f"{c.kind}" for c in t.capabilities) or "compute"
        lines.append(f"| `{t.name}` | {t.registration} | {params} | {caps} | `{t.file}:{t.line}` |")

    lines.append("")
    return "\n".join(lines)


# ── 3d. State Flow ───────────────────────────────────────────────────────


def _render_state_flow(result: ScanResult) -> str:
    sf = result.analysis.state_flow
    if not sf.node_flows:
        return ""

    lines: list[str] = []
    lines.append("## State Flow\n")

    if sf.state_class:
        keys_str = ", ".join(f"`{k}`" for k in sf.state_keys)
        lines.append(f"**State class**: `{sf.state_class}` with keys: {keys_str}\n")

    lines.append("| Node | Reads | Writes | Location |")
    lines.append("|---|---|---|---|")

    for nf in sf.node_flows:
        reads = ", ".join(f"`{r}`" for r in nf.reads) or "-"
        writes = ", ".join(f"`{w}`" for w in nf.writes) or "-"
        lines.append(f"| `{nf.function}` | {reads} | {writes} | `{nf.file}:{nf.line_start}` |")

    lines.append("")
    return "\n".join(lines)


# ── 4. Entrypoint Effect Matrix ────────────────────────────────────────────


def _render_entrypoint_matrix(result: ScanResult) -> str:
    p = result.projection
    if not p or not p.projections:
        return ""

    lines: list[str] = []
    lines.append("## Entrypoint Effect Matrix\n")
    lines.append("| Entrypoint | Reachable | Reads | Writes | Sends To | Secrets | PII | LLM | Prompts | Tools |")
    lines.append("|---|---|---|---|---|---|---|---|---|---|")

    for ep in p.projections:
        reads = 0
        writes = 0
        sends = 0
        secrets = 0
        pii = 0
        llm = 0
        prompts = 0
        tools = 0

        for eff in ep.effects:
            src = eff.source.lower()
            title_lower = eff.title.lower()
            if src == "io":
                if "read" in title_lower or "input" in title_lower:
                    reads += 1
                elif "write" in title_lower or "output" in title_lower or "artifact" in title_lower:
                    writes += 1
            elif src == "egress":
                if "llm" in title_lower:
                    llm += 1
                else:
                    sends += 1
            elif src == "secret":
                secrets += 1
            elif src == "security":
                if "pii" in title_lower or "data" in title_lower:
                    pii += 1
            elif src == "prompt":
                prompts += 1
            elif src == "tool":
                tools += 1

        label = ep.entrypoint_label
        reachable = len(ep.reachable_functions)
        lines.append(
            f"| `{label}` | {reachable} | {reads} | {writes} | {sends} | {secrets} | {pii} | {llm} | {prompts} | {tools} |"
        )

    lines.append("")

    # Unreachable findings (dead code)
    if p.unreachable_findings:
        lines.append(f"**{len(p.unreachable_findings)} finding(s) outside call graph (config files, unused code)**\n")

    return "\n".join(lines)


# ── 5. Detailed Security Findings ──────────────────────────────────────────


def _render_security_findings(result: ScanResult) -> str:
    s = result.security
    if not s:
        return ""

    lines: list[str] = []

    has_content = (
        s.findings or s.data_flow_risks or s.credential_leak_risks
        or s.data_classifications
        or (s.agent_scan and s.agent_scan.findings)
    )
    if not has_content:
        return ""

    lines.append("---\n")
    lines.append("## Security Findings\n")

    # Code / vuln / resource findings
    if s.findings:
        for f in sorted(s.findings, key=lambda x: sev_order(x.severity)):
            icon = _sev_icon(f.severity)
            title = strip_bandit_prefix(f.title)
            lines.append(f"### {icon} {title}\n")
            lines.append(f"**Severity**: {f.severity} | **Category**: {f.category}\n")
            lines.append(f"{f.description}\n")
            if f.recommendation:
                lines.append(f"**Recommendation**: {f.recommendation}\n")
            if f.evidence:
                for e in f.evidence:
                    lines.append(f"  - `{e.file}:{e.line}` {e.snippet}")
                lines.append("")

    # Data classifications
    if s.data_classifications:
        lines.append("### Data Classifications\n")
        for dc in s.data_classifications:
            fields = ", ".join(f"`{f}`" for f in dc.fields_detected[:10])
            lines.append(f"- **{dc.category}** ({dc.confidence:.0%}): {fields}")
        lines.append("")

    # Data flow risks
    if s.data_flow_risks:
        lines.append("### Data Flow Risks\n")
        for df in sorted(s.data_flow_risks, key=lambda x: sev_order(x.severity)):
            icon = _sev_icon(df.severity)
            pii = ", ".join(f"`{f}`" for f in df.pii_fields_in_path) if df.pii_fields_in_path else "none"
            lines.append(f"- {icon} **{df.data_source}** -> **{df.data_sink}** (PII: {pii})")
            lines.append(f"  {df.description}")
            if df.evidence:
                for e in df.evidence:
                    lines.append(f"  - `{e.file}:{e.line}` {e.snippet}")
        lines.append("")

    # Credential leak risks
    if s.credential_leak_risks:
        lines.append("### Credential Leak Risks\n")
        for cl in s.credential_leak_risks:
            icon = _sev_icon(cl.severity)
            lines.append(f"- {icon} `{cl.credential_name}` -> **{cl.leak_target}**: {cl.description}")
            if cl.evidence:
                for e in cl.evidence:
                    lines.append(f"  - `{e.file}:{e.line}` {e.snippet}")
        lines.append("")

    # Agent & skill security
    if s.agent_scan and s.agent_scan.findings:
        lines.append("### Agent & Skill Security\n")
        for af in sorted(s.agent_scan.findings, key=lambda x: sev_order(x.severity)):
            icon = _sev_icon(af.severity)
            lines.append(f"- {icon} **{af.title}**")
            lines.append(f"  Category: {af.category} | File: `{af.file}:{af.line}`")
            lines.append(f"  {af.description}")
            if af.recommendation:
                lines.append(f"  Recommendation: {af.recommendation}")
        lines.append("")

    # Entrypoint projections (detailed, after summary matrix)
    p = result.projection
    if p and p.projections:
        lines.append("### Per-Entrypoint Details\n")
        for ep in p.projections:
            lines.append(f"#### {ep.entrypoint_label}\n")
            lines.append(f"Reachable functions: {len(ep.reachable_functions)}\n")
            if ep.effects:
                lines.append("| Source | Effect | Severity | Location |")
                lines.append("|---|---|---|---|")
                for eff in sorted(ep.effects, key=lambda x: sev_order(x.severity)):
                    fn = f" ({eff.function_name})" if eff.function_name else ""
                    lines.append(
                        f"| {eff.source} | {strip_bandit_prefix(eff.title)} | {eff.severity} | `{eff.file}:{eff.line}`{fn} |"
                    )
                lines.append("")
            else:
                lines.append("No projected effects.\n")

        if p.unreachable_findings:
            lines.append("#### Findings Outside Call Graph\n")
            lines.append("| Source | Effect | Severity | Location |")
            lines.append("|---|---|---|---|")
            for eff in sorted(p.unreachable_findings, key=lambda x: sev_order(x.severity)):
                fn = f" ({eff.function_name})" if eff.function_name else ""
                lines.append(
                    f"| {eff.source} | {strip_bandit_prefix(eff.title)} | {eff.severity} | `{eff.file}:{eff.line}`{fn} |"
                )
            lines.append("")

    return "\n".join(lines)


# ── 6. Call Graph (Mermaid) ────────────────────────────────────────────────


def _render_mermaid_call_graph(result: ScanResult) -> str:
    p = result.projection
    if not p or not p.call_graph or not p.call_graph.edges:
        return ""

    lines: list[str] = []
    lines.append("## Call Graph\n")
    lines.append("```mermaid")
    lines.append("flowchart LR")

    # Collect unique node IDs from edges
    used_nodes: set[str] = set()
    for edge in p.call_graph.edges:
        used_nodes.add(edge.caller)
        used_nodes.add(edge.callee)

    # Define nodes with labels
    node_map: dict[str, str] = {}
    for fn in p.call_graph.functions:
        if fn.id in used_nodes:
            safe_id = _mermaid_safe_id(fn.id)
            node_map[fn.id] = safe_id
            label = fn.name
            if fn.is_entrypoint:
                # Entrypoints get stadium shape
                lines.append(f"    {safe_id}([{label}])")
            else:
                lines.append(f"    {safe_id}[{label}]")

    # Edges
    for edge in p.call_graph.edges:
        caller_id = node_map.get(edge.caller)
        callee_id = node_map.get(edge.callee)
        if caller_id and callee_id:
            lines.append(f"    {caller_id} --> {callee_id}")

    lines.append("```\n")
    return "\n".join(lines)


def _mermaid_safe_id(node_id: str) -> str:
    """Convert a FunctionNode.id to a mermaid-safe identifier."""
    return node_id.replace(".", "_").replace("::", "__").replace("/", "_").replace("-", "_")


# ── 7. Condensed Structural Summary ───────────────────────────────────────


def _render_structural_summary(result: ScanResult) -> str:
    a = result.analysis
    lines: list[str] = []

    lines.append("---\n")
    lines.append("## Project Structure\n")

    # Basic info
    lines.append(
        f"**Project**: `{result.project_path}` | "
        f"**Archetypes**: {', '.join(f'{at.type} ({at.confidence:.0%})' for at in a.detection.archetypes) or 'none'} | "
        f"**Python files**: {count_py_files(a)} | "
        f"**Dependencies**: {len(a.deps.dependencies)}\n"
    )

    # Entrypoints (compact)
    if a.detection.entrypoint_candidates:
        eps = []
        for c in a.detection.entrypoint_candidates:
            loc = f" ({c.evidence[0].file})" if c.evidence else ""
            eps.append(f"`{c.value}` ({c.kind}, {c.confidence:.0%}{loc})")
        lines.append(f"**Entrypoints**: {', '.join(eps)}\n")

    # Dependencies (compact)
    if a.deps.dependencies:
        dep_list = ", ".join(f"`{d.name}`" for d in a.deps.dependencies[:20])
        if len(a.deps.dependencies) > 20:
            dep_list += f" ... +{len(a.deps.dependencies) - 20} more"
        lines.append(f"**Dependencies**: {dep_list}")
        if a.deps.python_version_hint:
            lines.append(f" (Python {a.deps.python_version_hint})")
        lines.append("\n")

    # I/O (compact)
    if a.io.inputs or a.io.outputs:
        inputs = ", ".join(f"`{i.id}` ({i.kind})" for i in a.io.inputs[:10])
        outputs = ", ".join(f"`{o.id}` ({o.kind})" for o in a.io.outputs[:10])
        if inputs:
            lines.append(f"**Inputs**: {inputs}\n")
        if outputs:
            lines.append(f"**Outputs**: {outputs}\n")

    # Hardcoded paths
    if a.io.hardcoded_paths:
        paths = ", ".join(f"`{hp.path}`" for hp in a.io.hardcoded_paths[:5])
        if len(a.io.hardcoded_paths) > 5:
            paths += f" ... +{len(a.io.hardcoded_paths) - 5} more"
        lines.append(f"**Hardcoded paths**: {paths}\n")

    # API routes (compact)
    if a.io.api_routes:
        routes = ", ".join(f"`{r.method} {r.path}`" for r in a.io.api_routes[:10])
        lines.append(f"**API routes**: {routes}\n")

    # Egress summary
    if a.egress.outbound_calls:
        egress = ", ".join(f"`{c.library}` ({c.kind})" for c in a.egress.outbound_calls[:10])
        lines.append(f"**External connections**: {egress}\n")
        gw = a.egress.suggested_gateway_needs
        if gw.needs_llm_gateway:
            models = ", ".join(gw.requested_models) if gw.requested_models else "unknown"
            lines.append(f"LLM gateway recommended. Models: {models}\n")

    lines.append('*For full structural details, use `--format json`*\n')

    return "\n".join(lines)


# ── 8. Scan Toolchain ─────────────────────────────────────────────────────


def _render_toolchain(result: ScanResult) -> str:
    if not result.toolchain:
        return ""

    lines: list[str] = []
    lines.append("## Scan Toolchain\n")
    lines.append("| Tool | Version | Status | Findings | What It Checks |")
    lines.append("|------|---------|--------|----------|----------------|")

    for t in result.toolchain:
        findings_str = str(t.findings) if t.findings >= 0 else "-"
        lines.append(f"| {t.name} | {t.version} | {t.status} | {findings_str} | {t.description} |")

    lines.append("")
    return "\n".join(lines)


# ── 9. Recommendations ────────────────────────────────────────────────────


def _render_recommendations(result: ScanResult) -> str:
    a = result.analysis
    if not a.porting_plan.required_changes and not a.porting_plan.optional_changes:
        return ""

    lines: list[str] = []
    lines.append("## Recommendations\n")
    if a.porting_plan.summary:
        lines.append(f"{a.porting_plan.summary}\n")
    if a.porting_plan.required_changes:
        lines.append("### Required Changes\n")
        for ch in a.porting_plan.required_changes:
            lines.append(f"- **{ch.type}**: {ch.description}")
            if ch.suggested_fix:
                lines.append(f"  - Fix: {ch.suggested_fix}")
        lines.append("")
    if a.porting_plan.optional_changes:
        lines.append("### Optional Changes\n")
        for ch in a.porting_plan.optional_changes:
            lines.append(f"- **{ch.type}**: {ch.description}")
        lines.append("")

    return "\n".join(lines)


# ── Helpers ──────────────────────────────────────────────────────────────


def _sev_icon(severity: str) -> str:
    return {
        "critical": "[CRITICAL]",
        "high": "[HIGH]",
        "medium": "[MEDIUM]",
        "low": "[LOW]",
        "info": "[INFO]",
    }.get(severity, "[-]")

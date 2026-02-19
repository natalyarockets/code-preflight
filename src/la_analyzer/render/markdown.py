"""Render scan results as a Markdown report."""

from __future__ import annotations

from la_analyzer.scanner import ScanResult


def render_markdown(result: ScanResult) -> str:
    """Produce a full Markdown report from a ScanResult."""
    sections: list[str] = []
    a = result.analysis
    s = result.security
    name = result.project_path.name

    # ── Title ────────────────────────────────────────────────────────────
    sections.append(f"# Scan Report: {name}\n")

    # ── Summary box ──────────────────────────────────────────────────────
    summary_lines = [
        f"- **Project**: `{result.project_path}`",
        f"- **Archetypes**: {', '.join(f'{a.type} ({a.confidence:.0%})' for a in a.detection.archetypes) or 'none detected'}",
        f"- **Python files scanned**: {_count_py_files(a)}",
        f"- **Dependencies**: {len(a.deps.dependencies)}",
        f"- **Inputs detected**: {len(a.io.inputs)}",
        f"- **Outputs detected**: {len(a.io.outputs)}",
        f"- **External connections**: {len(a.egress.outbound_calls)}",
        f"- **Secrets found**: {len(a.secrets.findings)}",
    ]
    if s:
        severity = _severity_badge(s)
        summary_lines.append(f"- **Security gate**: {severity}")
    sections.append("\n".join(summary_lines) + "\n")

    # ── Entrypoints ──────────────────────────────────────────────────────
    if a.detection.entrypoint_candidates:
        sections.append("## Entrypoints\n")
        rows = []
        for c in a.detection.entrypoint_candidates:
            loc = ""
            if c.evidence:
                loc = f"`{c.evidence[0].file}:{c.evidence[0].line}`"
            rows.append(f"| `{c.value}` | {c.kind} | {c.confidence:.0%} | {loc} |")
        sections.append("| Command / Module | Kind | Confidence | Location |")
        sections.append("|---|---|---|---|")
        sections.append("\n".join(rows) + "\n")

    # ── Dependencies ─────────────────────────────────────────────────────
    if a.deps.dependencies:
        sections.append("## Dependencies\n")
        dep_list = ", ".join(f"`{d.name}`" for d in a.deps.dependencies[:30])
        if len(a.deps.dependencies) > 30:
            dep_list += f" ... and {len(a.deps.dependencies) - 30} more"
        sections.append(dep_list + "\n")
        if a.deps.python_version_hint:
            sections.append(f"Python version hint: `{a.deps.python_version_hint}`\n")

    # ── Inputs & Outputs ─────────────────────────────────────────────────
    if a.io.inputs:
        sections.append("## Inputs\n")
        sections.append("| ID | Kind | Format | Description |")
        sections.append("|---|---|---|---|")
        for inp in a.io.inputs:
            desc = inp.description or inp.label or ""
            sections.append(f"| `{inp.id}` | {inp.kind} | {inp.format} | {desc} |")
        sections.append("")

    if a.io.outputs:
        sections.append("## Outputs\n")
        sections.append("| ID | Kind | Format | Role |")
        sections.append("|---|---|---|---|")
        for out in a.io.outputs:
            sections.append(f"| `{out.id}` | {out.kind} | {out.format} | {out.role} |")
        sections.append("")

    if a.io.hardcoded_paths:
        sections.append("## Hardcoded Paths\n")
        for hp in a.io.hardcoded_paths:
            loc = f"`{hp.evidence[0].file}:{hp.evidence[0].line}`" if hp.evidence else ""
            sections.append(f"- `{hp.path}` {loc}")
        sections.append("")

    # ── API Routes ───────────────────────────────────────────────────────
    if a.io.api_routes:
        sections.append("## API Routes\n")
        sections.append("| Method | Path | Handler | File |")
        sections.append("|---|---|---|---|")
        for r in a.io.api_routes:
            sections.append(f"| {r.method} | `{r.path}` | `{r.handler}` | `{r.file}:{r.line}` |")
        sections.append("")

    # ── External Connections (Egress) ────────────────────────────────────
    if a.egress.outbound_calls:
        sections.append("## External Connections\n")
        sections.append("| Kind | Library | Domains | Confidence |")
        sections.append("|---|---|---|---|")
        for call in a.egress.outbound_calls:
            domains = ", ".join(call.domains) if call.domains else "-"
            sections.append(f"| {call.kind} | `{call.library}` | {domains} | {call.confidence:.0%} |")
        sections.append("")
        gw = a.egress.suggested_gateway_needs
        if gw.needs_llm_gateway:
            sections.append(f"LLM gateway recommended. Requested models: {', '.join(gw.requested_models) or 'unknown'}\n")

    # ── Secrets ──────────────────────────────────────────────────────────
    if a.secrets.findings:
        sections.append("## Secrets Found\n")
        for sf in a.secrets.findings:
            hint = f" (`{sf.name_hint}`)" if sf.name_hint else ""
            loc = f"`{sf.evidence[0].file}:{sf.evidence[0].line}`" if sf.evidence else ""
            sections.append(f"- **{sf.kind}**{hint}: `{sf.value_redacted}` {loc}")
        sections.append("")
        if a.secrets.suggested_env_vars:
            sections.append("Suggested env vars: " + ", ".join(f"`{v}`" for v in a.secrets.suggested_env_vars) + "\n")

    # ── Security Report ──────────────────────────────────────────────────
    if s:
        sections.append("---\n")
        sections.append("## Security Review\n")
        sections.append(
            f"| Critical | High | Medium | Low |\n"
            f"|---|---|---|---|\n"
            f"| {s.critical_count} | {s.high_count} | {s.medium_count} | {s.low_count} |\n"
        )

        if s.deploy_blocked:
            sections.append("> **BLOCKED**: Critical findings must be resolved before deployment.\n")
        elif s.requires_review:
            sections.append("> **REVIEW REQUIRED**: High-severity findings need attention.\n")

        # Code / vuln / resource findings
        if s.findings:
            sections.append("### Findings\n")
            for f in sorted(s.findings, key=lambda x: _sev_order(x.severity)):
                icon = _sev_icon(f.severity)
                sections.append(f"#### {icon} {f.title}\n")
                sections.append(f"**Severity**: {f.severity} | **Category**: {f.category}\n")
                sections.append(f"{f.description}\n")
                if f.recommendation:
                    sections.append(f"**Recommendation**: {f.recommendation}\n")
                if f.evidence:
                    for e in f.evidence:
                        sections.append(f"  - `{e.file}:{e.line}` {e.snippet}")
                    sections.append("")

        # Data classifications
        if s.data_classifications:
            sections.append("### Data Classifications\n")
            for dc in s.data_classifications:
                fields = ", ".join(f"`{f}`" for f in dc.fields_detected[:10])
                sections.append(f"- **{dc.category}** ({dc.confidence:.0%}): {fields}")
            sections.append("")

        # Data flow risks
        if s.data_flow_risks:
            sections.append("### Data Flow Risks\n")
            for df in sorted(s.data_flow_risks, key=lambda x: _sev_order(x.severity)):
                icon = _sev_icon(df.severity)
                pii = ", ".join(f"`{f}`" for f in df.pii_fields_in_path) if df.pii_fields_in_path else "none"
                sections.append(f"- {icon} **{df.data_source}** -> **{df.data_sink}** (PII: {pii})")
                sections.append(f"  {df.description}")
                if df.evidence:
                    for e in df.evidence:
                        sections.append(f"  - `{e.file}:{e.line}` {e.snippet}")
            sections.append("")

        # Credential leak risks
        if s.credential_leak_risks:
            sections.append("### Credential Leak Risks\n")
            for cl in s.credential_leak_risks:
                icon = _sev_icon(cl.severity)
                sections.append(f"- {icon} `{cl.credential_name}` -> **{cl.leak_target}**: {cl.description}")
                if cl.evidence:
                    for e in cl.evidence:
                        sections.append(f"  - `{e.file}:{e.line}` {e.snippet}")
            sections.append("")

    # ── Entrypoint Projections ────────────────────────────────────────────
    p = result.projection
    if p and p.projections:
        sections.append("---\n")
        sections.append("## Entrypoint Projections\n")
        for ep in p.projections:
            sections.append(f"### {ep.entrypoint_label}\n")
            sections.append(f"Reachable functions: {len(ep.reachable_functions)}\n")
            if ep.effects:
                sections.append("| Source | Effect | Severity | Location |")
                sections.append("|---|---|---|---|")
                for eff in sorted(ep.effects, key=lambda x: _sev_order(x.severity)):
                    fn = f" ({eff.function_name})" if eff.function_name else ""
                    sections.append(
                        f"| {eff.source} | {eff.title} | {eff.severity} | `{eff.file}:{eff.line}`{fn} |"
                    )
                sections.append("")
            else:
                sections.append("No projected effects.\n")

        if p.unreachable_findings:
            sections.append("### Unreachable Findings (dead code)\n")
            sections.append("| Source | Effect | Severity | Location |")
            sections.append("|---|---|---|---|")
            for eff in sorted(p.unreachable_findings, key=lambda x: _sev_order(x.severity)):
                fn = f" ({eff.function_name})" if eff.function_name else ""
                sections.append(
                    f"| {eff.source} | {eff.title} | {eff.severity} | `{eff.file}:{eff.line}`{fn} |"
                )
            sections.append("")

    # ── Agent & Skill Security ────────────────────────────────────────────
    if s and s.agent_scan and s.agent_scan.findings:
        sections.append("---\n")
        sections.append("## Agent & Skill Security\n")
        for af in sorted(s.agent_scan.findings, key=lambda x: _sev_order(x.severity)):
            icon = _sev_icon(af.severity)
            sections.append(f"- {icon} **{af.title}**")
            sections.append(f"  Category: {af.category} | File: `{af.file}:{af.line}`")
            sections.append(f"  {af.description}")
            if af.recommendation:
                sections.append(f"  Recommendation: {af.recommendation}")
        sections.append("")

    # ── Porting Plan ─────────────────────────────────────────────────────
    if a.porting_plan.required_changes or a.porting_plan.optional_changes:
        sections.append("## Recommendations\n")
        if a.porting_plan.summary:
            sections.append(f"{a.porting_plan.summary}\n")
        if a.porting_plan.required_changes:
            sections.append("### Required Changes\n")
            for ch in a.porting_plan.required_changes:
                sections.append(f"- **{ch.type}**: {ch.description}")
                if ch.suggested_fix:
                    sections.append(f"  - Fix: {ch.suggested_fix}")
            sections.append("")
        if a.porting_plan.optional_changes:
            sections.append("### Optional Changes\n")
            for ch in a.porting_plan.optional_changes:
                sections.append(f"- **{ch.type}**: {ch.description}")
            sections.append("")

    return "\n".join(sections)


# ── Helpers ──────────────────────────────────────────────────────────────

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _sev_order(severity: str) -> int:
    return _SEV_ORDER.get(severity, 5)


def _sev_icon(severity: str) -> str:
    return {
        "critical": "[CRITICAL]",
        "high": "[HIGH]",
        "medium": "[MEDIUM]",
        "low": "[LOW]",
        "info": "[INFO]",
    }.get(severity, "[-]")


def _severity_badge(s) -> str:
    if s.deploy_blocked:
        return "BLOCKED (critical findings)"
    if s.requires_review:
        return "REVIEW REQUIRED (high findings)"
    return "PASS"


def _count_py_files(a) -> str:
    """Estimate Python file count from evidence locations."""
    files = set()
    for inp in a.io.inputs:
        for e in inp.evidence:
            if e.file.endswith(".py"):
                files.add(e.file)
    for out in a.io.outputs:
        for e in out.evidence:
            if e.file.endswith(".py"):
                files.add(e.file)
    for call in a.egress.outbound_calls:
        for e in call.evidence:
            if e.file.endswith(".py"):
                files.add(e.file)
    # If we can't count, just say "multiple"
    return str(len(files)) if files else "multiple"

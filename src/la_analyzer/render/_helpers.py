"""Shared helpers for render backends (markdown, PDF, etc.)."""

from __future__ import annotations

import re

from la_analyzer.scanner import ScanResult

# Bandit finding codes: "B608: Possible SQL injection" -> "Possible SQL injection"
_BANDIT_PREFIX_RE = re.compile(r"^B\d{3}:\s*")

# Severity rank for sorting: critical first, info last.
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def sev_order(severity: str) -> int:
    """Return numeric rank for a severity string (lower = more severe)."""
    return _SEV_ORDER.get(severity, 5)


def top_risks(result: ScanResult, max_risks: int = 5) -> list[str]:
    """Extract the top N most actionable risk descriptions."""
    s = result.security
    if not s:
        return []

    risks: list[tuple[int, str]] = []

    for cl in s.credential_leak_risks:
        prio = sev_order(cl.severity)
        loc = f" at {cl.evidence[0].file}:{cl.evidence[0].line}" if cl.evidence else ""
        risks.append((prio, f"Credential '{cl.credential_name}' exposed to {leak_label(cl.leak_target)}{loc}"))

    for df in s.data_flow_risks:
        prio = sev_order(df.severity)
        pii = ", ".join(df.pii_fields_in_path[:3]) if df.pii_fields_in_path else "file data"
        loc = f" at {df.evidence[0].file}:{df.evidence[0].line}" if df.evidence else ""
        risks.append((prio, f"{pii} flows to {df.data_sink}{loc}"))

    for f in s.findings:
        if f.severity in ("critical", "high"):
            prio = sev_order(f.severity)
            loc = f" at {f.evidence[0].file}:{f.evidence[0].line}" if f.evidence else ""
            risks.append((prio, f"{f.title}{loc}"))

    if s.agent_scan:
        for af in s.agent_scan.findings:
            if af.severity in ("critical", "high"):
                prio = sev_order(af.severity)
                risks.append((prio, f"{af.title} at {af.file}:{af.line}"))

    risks.sort(key=lambda x: x[0])
    return [r[1] for r in risks[:max_risks]]


def leak_label(target: str) -> str:
    """Human-readable label for a credential leak target."""
    return {
        "llm_prompt": "LLM prompt",
        "log_output": "log/print output",
        "http_request": "HTTP request body",
        "http_auth": "HTTP auth header",
        "output_file": "output file",
    }.get(target, target)


def count_py_files(analysis) -> str:
    """Estimate Python file count from evidence locations."""
    files: set[str] = set()
    for inp in analysis.io.inputs:
        for e in inp.evidence:
            if e.file.endswith(".py"):
                files.add(e.file)
    for out in analysis.io.outputs:
        for e in out.evidence:
            if e.file.endswith(".py"):
                files.add(e.file)
    for call in analysis.egress.outbound_calls:
        for e in call.evidence:
            if e.file.endswith(".py"):
                files.add(e.file)
    return str(len(files)) if files else "multiple"


def strip_bandit_prefix(title: str) -> str:
    """Strip Bandit finding codes (e.g. 'B608: ') from a finding title.

    These codes are meaningless to non-security-engineer audiences.
    """
    return _BANDIT_PREFIX_RE.sub("", title)


def executive_summary(result: ScanResult) -> list[str]:
    """Build plain-English deployment readiness bullets from scan data.

    Returns a list of short sentences describing what this app does
    in the real world -- framed as consequences, not observations.
    """
    a = result.analysis
    s = result.security
    bullets: list[str] = []

    # External services contacted
    egress = a.egress.outbound_calls
    if egress:
        llm_libs = [c for c in egress if c.kind == "llm_sdk"]
        http_libs = [c for c in egress if c.kind == "http"]
        db_libs = [c for c in egress if c.kind in ("database", "baas")]

        if llm_libs:
            names = sorted({c.library for c in llm_libs})
            domains = sorted({d for c in llm_libs for d in c.domains if d})
            dest = f" ({', '.join(domains)})" if domains else ""
            bullets.append(f"This app sends data to {', '.join(names)}{dest}.")

        if http_libs:
            domains = sorted({d for c in http_libs for d in c.domains if d})
            if domains:
                bullets.append(f"Makes HTTP requests to {', '.join(domains)}.")
            else:
                bullets.append("Makes outbound HTTP requests to dynamically resolved URLs.")

        if db_libs:
            names = sorted({c.library for c in db_libs})
            bullets.append(f"Connects to external data store via {', '.join(names)}.")

    # Credential exposure
    if s and s.credential_leak_risks:
        for cl in s.credential_leak_risks:
            bullets.append(
                f"Credential '{cl.credential_name}' is exposed to {leak_label(cl.leak_target)}."
            )

    # PII flow
    if s and s.data_flow_risks:
        pii_flows = [df for df in s.data_flow_risks if df.pii_fields_in_path]
        if pii_flows:
            fields = sorted({f for df in pii_flows for f in df.pii_fields_in_path[:3]})
            sinks = sorted({df.data_sink for df in pii_flows})
            bullets.append(
                f"PII fields ({', '.join(fields)}) flow to {', '.join(sinks)}."
            )

    # LLM prompts with variable content
    if a.prompt_surface.surfaces:
        count = len(a.prompt_surface.surfaces)
        all_vars = sorted({v.name for s in a.prompt_surface.surfaces for v in s.prompt_variables})
        if all_vars:
            vars_str = ", ".join(all_vars[:5])
            if len(all_vars) > 5:
                vars_str += f" +{len(all_vars) - 5} more"
            bullets.append(f"{count} LLM prompt site(s) inject runtime data ({vars_str}).")
        else:
            bullets.append(f"{count} LLM prompt site(s) detected.")

    # Registered tools
    if a.tool_registration.tools:
        count = len(a.tool_registration.tools)
        dangerous = [t for t in a.tool_registration.tools
                     if any(c.kind in ("subprocess", "network") for c in t.capabilities)]
        if dangerous:
            names = ", ".join(t.name for t in dangerous[:3])
            bullets.append(f"{count} LLM-callable tool(s) registered; {len(dangerous)} with elevated capabilities ({names}).")
        else:
            bullets.append(f"{count} LLM-callable tool(s) registered.")

    # Secrets in repo
    if a.secrets.findings:
        count = len(a.secrets.findings)
        kinds = sorted({sf.kind for sf in a.secrets.findings})
        bullets.append(f"{count} embedded secret(s) found ({', '.join(kinds)}).")

    # Gate decision -- what needs to happen
    if s:
        if s.deploy_blocked:
            bullets.append("Critical issues must be resolved before deployment.")
        elif s.requires_review:
            # Describe what triggered the review requirement
            high_findings = [f for f in s.findings if f.severity in ("critical", "high")]
            if s.credential_leak_risks:
                bullets.append("Credential routing must be reviewed before deployment.")
            elif high_findings:
                bullets.append("High-severity findings need review before deployment.")
            else:
                bullets.append("Manual review recommended before deployment.")
        else:
            bullets.append("No critical or high-severity issues detected.")

    if not bullets:
        bullets.append("No external connections or security findings detected.")

    return bullets


# Unicode -> ASCII substitutions for PDF core fonts (latin-1 only).
_UNICODE_SUBS = str.maketrans({
    "\u2014": "--",   # em dash
    "\u2013": "-",    # en dash
    "\u2018": "'",    # left single quote
    "\u2019": "'",    # right single quote
    "\u201c": '"',    # left double quote
    "\u201d": '"',    # right double quote
    "\u2026": "...",  # ellipsis
    "\u2022": "*",    # bullet
    "\u2192": "->",   # right arrow
    "\u2190": "<-",   # left arrow
    "\u2265": ">=",   # greater or equal
    "\u2264": "<=",   # less or equal
    "\u2260": "!=",   # not equal
    "\u00a0": " ",    # non-breaking space
})


def latin1(text: str) -> str:
    """Sanitize text for latin-1 PDF core fonts."""
    result = text.translate(_UNICODE_SUBS)
    return result.encode("latin-1", errors="replace").decode("latin-1")

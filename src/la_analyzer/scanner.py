"""Unified scanner: runs analysis + security review + projection in one pass."""

from __future__ import annotations

import importlib.util
import logging
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from la_analyzer.analyzer.service import analyze_repo
from la_analyzer.analyzer.models import AnalysisResult, ProjectionReport
from la_analyzer.security import run_security_review
from la_analyzer.security.models import SecurityReport
from la_analyzer.utils import discover_files

log = logging.getLogger(__name__)


@dataclass
class ToolResult:
    """Result from a single tool in the scan toolchain."""
    name: str           # "Bandit", "detect-secrets", "pip-audit", etc.
    version: str        # "1.9.3" or "built-in"
    status: str         # "ran", "skipped", "not_installed", "error"
    findings: int       # count of findings, -1 if N/A
    description: str    # what this tool checks for


@dataclass
class ScanResult:
    """Combined result from analysis + security review + projection."""
    analysis: AnalysisResult
    security: SecurityReport | None
    projection: ProjectionReport | None
    project_path: Path
    toolchain: list[ToolResult] = field(default_factory=list)


def scan(
    project_path: Path,
    *,
    output_dir: Path | None = None,
    run_security: bool = True,
    requirements: list[str] | None = None,
) -> ScanResult:
    """Run the full scan pipeline on a project directory.

    Args:
        project_path: Path to the project to scan.
        output_dir: Where to write JSON reports. Defaults to project_path/.la-analyzer/.
        run_security: Whether to run security scanners (default True).
        requirements: Explicit list of pip requirements for vuln scanning.
                      If None, extracted automatically from analysis.

    Returns:
        ScanResult with analysis, optional security report, and projection.
    """
    project_path = project_path.resolve()
    if output_dir is None:
        output_dir = project_path / ".la-analyzer"

    log.info("Scanning %s", project_path)

    # Phase 1: Static analysis
    analysis = analyze_repo(project_path, output_dir)
    log.info("Analysis complete: %d inputs, %d outputs, %d egress calls",
             len(analysis.io.inputs), len(analysis.io.outputs),
             len(analysis.egress.outbound_calls))

    # Phase 2: Security review
    security = None
    if run_security:
        # Auto-extract requirements from analysis if not provided
        if requirements is None:
            requirements = [d.name for d in analysis.deps.dependencies]

        security = run_security_review(
            workspace_dir=project_path,
            analysis_result=analysis,
            requirements=requirements,
            report_dir=output_dir,
        )
        log.info("Security review complete: %d critical, %d high",
                 security.critical_count, security.high_count)

    # Phase 3: Call graph + effect projection
    projection = None
    try:
        from la_analyzer.analyzer.projection import (
            build_projection,
            enrich_evidence_with_functions,
        )

        all_files = discover_files(project_path)
        py_files = [f for f in all_files if f.suffix == ".py"]

        projection = build_projection(project_path, py_files, analysis, security)
        enrich_evidence_with_functions(projection.call_graph, analysis, security)

        log.info(
            "Projection complete: %d entrypoints, %d unreachable findings",
            len(projection.projections), len(projection.unreachable_findings),
        )
    except Exception:
        log.exception("Projection phase failed (non-fatal)")

    result = ScanResult(
        analysis=analysis,
        security=security,
        projection=projection,
        project_path=project_path,
    )
    result.toolchain = _build_toolchain(result, run_security)
    return result


# ── Toolchain builder ────────────────────────────────────────────────────


def _get_tool_version(cmd: str) -> str | None:
    """Get version string from a CLI tool, or None if not installed."""
    path = shutil.which(cmd)
    if not path:
        return None
    try:
        out = subprocess.run(
            [cmd, "--version"], capture_output=True, text=True, timeout=10,
        )
        # bandit outputs "bandit 1.9.3 ...", pip-audit outputs "pip-audit 2.7.3", etc.
        text = (out.stdout or out.stderr).strip().split("\n")[0]
        # Extract version-like token (digits and dots)
        for token in text.split():
            if token and token[0].isdigit():
                return token
        return text  # fallback to full first line
    except Exception:
        return "unknown"


def _build_toolchain(result: ScanResult, run_security: bool) -> list[ToolResult]:
    """Build the toolchain audit trail from scan results."""
    tools: list[ToolResult] = []
    sec = result.security

    # ── External tools ────────────────────────────────────────────────

    # Bandit
    bandit_version = _get_tool_version("bandit")
    if not run_security:
        bandit_status = "skipped"
        bandit_findings = -1
    elif bandit_version is None:
        bandit_status = "not_installed"
        bandit_findings = -1
    else:
        # Bandit ran if security ran and it was installed. Count its findings
        # (category mapping from code_scan -- findings with B-prefixed titles).
        bandit_findings = 0
        if sec:
            bandit_findings = sum(
                1 for f in sec.findings if f.title[:1] == "B" and f.title[1:4].isdigit()
            )
        bandit_status = "ran"
    tools.append(ToolResult(
        name="Bandit",
        version=bandit_version or "-",
        status=bandit_status,
        findings=bandit_findings,
        description="Code security: exec, subprocess, SQL injection, insecure crypto, pickle, shell commands",
    ))

    # detect-secrets
    ds_spec = importlib.util.find_spec("detect_secrets")
    if ds_spec:
        try:
            import detect_secrets
            ds_version = getattr(detect_secrets, "__version__", "unknown")
        except Exception:
            ds_version = "unknown"
    else:
        ds_version = None
    # detect-secrets is used by the analyzer secrets_scan (always runs), not gated on run_security
    if ds_version is None:
        ds_status = "not_installed"
        ds_findings = -1
    else:
        ds_status = "ran"
        ds_findings = len(result.analysis.secrets.findings)
    tools.append(ToolResult(
        name="detect-secrets",
        version=ds_version or "-",
        status=ds_status,
        findings=ds_findings,
        description="Hardcoded secrets via entropy and pattern detection",
    ))

    # pip-audit
    pip_audit_version = _get_tool_version("pip-audit")
    if not run_security:
        pa_status = "skipped"
        pa_findings = -1
    elif pip_audit_version is None:
        pa_status = "not_installed"
        pa_findings = -1
    else:
        # Count dep-category findings (from vuln_scan)
        pa_findings = 0
        if sec:
            pa_findings = sum(
                1 for f in sec.findings
                if f.category == "deps" and "typosquat" not in f.title.lower()
            )
        pa_status = "ran"
    tools.append(ToolResult(
        name="pip-audit",
        version=pip_audit_version or "-",
        status=pa_status,
        findings=pa_findings,
        description="Known CVEs in Python dependencies (NIST NVD)",
    ))

    # ── Built-in scanners (always report) ─────────────────────────────

    # Platform code scanner
    platform_findings = 0
    if sec:
        platform_findings = sum(
            1 for f in sec.findings
            if not (f.title[:1] == "B" and f.title[1:4].isdigit())
            and f.category != "deps"
        )
    tools.append(ToolResult(
        name="LA code scanner",
        version="built-in",
        status="ran" if run_security else "skipped",
        findings=platform_findings if run_security else -1,
        description="Dynamic imports, ctypes, network bypass, resource abuse",
    ))

    # Secrets name scanner (part of analyzer -- always runs)
    tools.append(ToolResult(
        name="LA secrets scanner",
        version="built-in",
        status="ran",
        findings=len(result.analysis.secrets.findings),
        description=".env files, API key names, token patterns",
    ))

    # Data classifier
    tools.append(ToolResult(
        name="Data classifier",
        version="built-in",
        status="ran" if run_security else "skipped",
        findings=len(sec.data_classifications) if sec else -1,
        description="PII, financial, health, credential field detection",
    ))

    # Data flow tracer
    tools.append(ToolResult(
        name="Data flow tracer",
        version="built-in",
        status="ran" if run_security else "skipped",
        findings=len(sec.data_flow_risks) if sec else -1,
        description="File read to LLM/HTTP/file sink data paths",
    ))

    # Credential leak scanner
    tools.append(ToolResult(
        name="Credential leak scanner",
        version="built-in",
        status="ran" if run_security else "skipped",
        findings=len(sec.credential_leak_risks) if sec else -1,
        description="Secrets in logs, prompts, HTTP calls, output files",
    ))

    # Resource abuse scanner
    resource_findings = 0
    if sec:
        resource_findings = sum(
            1 for f in sec.findings if f.category == "resource"
        )
    tools.append(ToolResult(
        name="Resource abuse scanner",
        version="built-in",
        status="ran" if run_security else "skipped",
        findings=resource_findings if run_security else -1,
        description="Infinite loops, fork bombs, unbounded multiprocessing",
    ))

    # Agent/skill scanner
    agent_findings = 0
    if sec and sec.agent_scan:
        agent_findings = len(sec.agent_scan.findings)
    tools.append(ToolResult(
        name="Agent/skill scanner",
        version="built-in",
        status="ran" if run_security else "skipped",
        findings=agent_findings if run_security else -1,
        description="Prompt injection, overprivileged tools, credential exposure in agents",
    ))

    # Prompt surface scanner
    tools.append(ToolResult(
        name="Prompt surface scanner",
        version="built-in",
        status="ran",
        findings=len(result.analysis.prompt_surface.surfaces),
        description="LLM prompt variable tracing, string constant detection",
    ))

    # Tool registration scanner
    tools.append(ToolResult(
        name="Tool registration scanner",
        version="built-in",
        status="ran",
        findings=len(result.analysis.tool_registration.tools),
        description="LLM-callable tool detection, capability classification",
    ))

    # State flow scanner
    tools.append(ToolResult(
        name="State flow scanner",
        version="built-in",
        status="ran",
        findings=len(result.analysis.state_flow.node_flows),
        description="Graph node state read/write tracking",
    ))

    # Effect graph scanner (IR)
    ir_findings_count = 0
    if sec and hasattr(sec, "ir_findings"):
        ir_findings_count = len(sec.ir_findings)
    tools.append(ToolResult(
        name="Effect graph scanner",
        version="built-in",
        status="ran" if run_security else "skipped",
        findings=ir_findings_count if run_security else -1,
        description="Capability-typed egress, prompt injection paths, auth coverage, severity fusion",
    ))

    # Call graph + projection
    proj = result.projection
    proj_findings = 0
    if proj:
        proj_findings = len(proj.unreachable_findings)
    tools.append(ToolResult(
        name="Call graph + projection",
        version="built-in",
        status="ran" if proj is not None else "error",
        findings=proj_findings,
        description="Entrypoint reachability, dead code detection, effect mapping",
    ))

    return tools

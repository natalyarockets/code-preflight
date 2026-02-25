"""Security review orchestrator.

Usage:
    from la_analyzer.security import run_security_review

    report = run_security_review(
        workspace_dir=Path("/path/to/source"),
        analysis_result=analysis,    # from analyze_repo()
        requirements=["pandas", "requests"],
    )
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from la_analyzer.security.models import SecurityReport
from la_analyzer.security.code_scan import scan_code
from la_analyzer.security.data_classify import classify_data
from la_analyzer.security.data_flow import scan_data_flow
from la_analyzer.security.credential_leak import scan_credential_leaks
from la_analyzer.security.vuln_scan import scan_vulnerabilities
from la_analyzer.security.resource_score import scan_resource_abuse
from la_analyzer.security.agent_scan import scan_agents
from la_analyzer.utils import discover_files

log = logging.getLogger(__name__)


def run_security_review(
    *,
    workspace_dir: Path,
    analysis_result=None,
    requirements: list[str] | None = None,
    report_dir: Path | None = None,
    report_filename: str = "security_report.json",
) -> SecurityReport:
    """Run all security scanners and produce a SecurityReport.

    Args:
        workspace_dir: Path to the source code.
        analysis_result: AnalysisResult from analyze_repo() (optional, for summary stats).
        requirements: List of pip requirements (optional, for vuln scanning).
        report_dir: Directory to write the security_report.json (optional).

    Returns:
        SecurityReport with all findings.
    """
    log.info("Starting security review for %s", workspace_dir)

    # Discover files
    all_files = discover_files(workspace_dir)
    py_files = [f for f in all_files if f.suffix == ".py"]

    log.info("Scanning %d Python files in %s", len(py_files), workspace_dir)

    # Run all scanners — each wrapped so one failure doesn't kill the report
    code_findings: list = []
    data_classifications: list = []
    data_flow_risks: list = []
    credential_leaks: list = []
    vuln_findings: list = []
    resource_findings: list = []

    try:
        code_findings = scan_code(workspace_dir, py_files)
        log.info("Code scan: %d findings", len(code_findings))
    except Exception:
        log.exception("Code scan failed")

    try:
        data_classifications = classify_data(workspace_dir, py_files)
        log.info("Data classification: %d categories", len(data_classifications))
    except Exception:
        log.exception("Data classification failed")

    try:
        data_flow_risks = scan_data_flow(
            workspace_dir, py_files,
            data_classifications=[dc.model_dump() for dc in data_classifications],
        )
        log.info("Data flow: %d risks", len(data_flow_risks))
    except Exception:
        log.exception("Data flow scan failed")

    try:
        credential_leaks = scan_credential_leaks(workspace_dir, py_files)
        log.info("Credential leak: %d risks", len(credential_leaks))
    except Exception:
        log.exception("Credential leak scan failed")

    try:
        vuln_findings = scan_vulnerabilities(workspace_dir, requirements or [])
        log.info("Vuln scan: %d findings", len(vuln_findings))
    except Exception:
        log.exception("Vuln scan failed")

    try:
        resource_findings = scan_resource_abuse(workspace_dir, py_files)
        log.info("Resource abuse: %d findings", len(resource_findings))
    except Exception:
        log.exception("Resource abuse scan failed")

    # Agent / skill scan
    agent_report = None
    try:
        agent_report = scan_agents(workspace_dir, all_files)
        log.info("Agent scan: %d findings", len(agent_report.findings))
    except Exception:
        log.exception("Agent scan failed")

    # IR graph analysis
    ir_findings: list = []
    try:
        from la_analyzer.ir import build_effect_graph
        from la_analyzer.ir.queries import run_all_queries
        effect_graph = build_effect_graph(workspace_dir, py_files)
        ir_findings = run_all_queries(effect_graph, existing_findings=code_findings + vuln_findings + resource_findings)
        log.info("IR graph queries: %d findings", len(ir_findings))
    except Exception:
        log.exception("IR graph scan failed")

    # Merge all findings
    all_findings = code_findings + vuln_findings + resource_findings + ir_findings

    # Compute severity counts
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in all_findings:
        if f.severity in severity_counts:
            severity_counts[f.severity] += 1
    for r in data_flow_risks:
        if r.severity in severity_counts:
            severity_counts[r.severity] += 1
    for c in credential_leaks:
        if c.severity in severity_counts:
            severity_counts[c.severity] += 1
    if agent_report:
        for af in agent_report.findings:
            if af.severity in severity_counts:
                severity_counts[af.severity] += 1

    # Pull summary stats from existing analysis
    secrets_found = 0
    egress_endpoints = 0
    hardcoded_paths = 0
    secrets_gate_triggered = False  # True if secrets warrant review (listed in Trust Boundaries)
    if analysis_result:
        if hasattr(analysis_result, "secrets"):
            secrets_found = len(analysis_result.secrets.findings)
            for sf in analysis_result.secrets.findings:
                if sf.kind in ("hardcoded_key", "dotenv_file"):
                    secrets_gate_triggered = True
                    break
        if hasattr(analysis_result, "egress"):
            egress_endpoints = len(analysis_result.egress.outbound_calls)
        if hasattr(analysis_result, "io"):
            hardcoded_paths = len(analysis_result.io.hardcoded_paths)

    # Gate decision: counts only cover what appears in Security Findings;
    # secrets are listed in Trust Boundaries and trigger the gate separately.
    deploy_blocked = severity_counts["critical"] > 0
    requires_review = severity_counts["high"] > 0 or secrets_gate_triggered

    report = SecurityReport(
        created_at=datetime.now(timezone.utc).isoformat(),
        findings=all_findings,
        data_classifications=data_classifications,
        data_flow_risks=data_flow_risks,
        credential_leak_risks=credential_leaks,
        ir_findings=ir_findings,
        critical_count=severity_counts["critical"],
        high_count=severity_counts["high"],
        medium_count=severity_counts["medium"],
        low_count=severity_counts["low"],
        deploy_blocked=deploy_blocked,
        requires_review=requires_review,
        secrets_found=secrets_found,
        egress_endpoints=egress_endpoints,
        hardcoded_paths=hardcoded_paths,
        agent_scan=agent_report,
    )

    # Write to disk
    if report_dir:
        report_dir.mkdir(parents=True, exist_ok=True)
        report_path = report_dir / report_filename
        report_path.write_text(json.dumps(report.model_dump(), indent=2))
        log.info("Security report written to %s", report_path)

    log.info(
        "Security review complete: %d critical, %d high, %d medium, %d low | blocked=%s review=%s",
        severity_counts["critical"], severity_counts["high"],
        severity_counts["medium"], severity_counts["low"],
        deploy_blocked, requires_review,
    )

    return report

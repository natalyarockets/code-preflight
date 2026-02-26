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

from la_analyzer.analyzer.models import AnalysisResult, Evidence
from la_analyzer.security.models import SecurityReport, SecurityFinding
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
    analysis_result: AnalysisResult | None = None,
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
        SecurityReport with all findings in a single canonical list.
    """
    log.info("Starting security review for %s", workspace_dir)

    all_files = discover_files(workspace_dir)
    py_files = [f for f in all_files if f.suffix == ".py"]
    log.info("Scanning %d Python files in %s", len(py_files), workspace_dir)

    # Each scanner returns list[SecurityFinding].  Failures are non-fatal.
    all_findings: list[SecurityFinding] = []
    data_classifications: list = []

    try:
        findings = scan_code(workspace_dir, py_files)
        all_findings.extend(findings)
        log.info("Code scan: %d findings", len(findings))
    except Exception:
        log.exception("Code scan failed")

    try:
        data_classifications = classify_data(workspace_dir, py_files)
        log.info("Data classification: %d categories", len(data_classifications))
    except Exception:
        log.exception("Data classification failed")

    try:
        findings = scan_data_flow(
            workspace_dir, py_files,
            data_classifications=[dc.model_dump() for dc in data_classifications],
        )
        all_findings.extend(findings)
        log.info("Data flow: %d findings", len(findings))
    except Exception:
        log.exception("Data flow scan failed")

    try:
        findings = scan_credential_leaks(workspace_dir, py_files)
        all_findings.extend(findings)
        log.info("Credential leak: %d findings", len(findings))
    except Exception:
        log.exception("Credential leak scan failed")

    try:
        findings = scan_vulnerabilities(workspace_dir, requirements or [])
        all_findings.extend(findings)
        log.info("Vuln scan: %d findings", len(findings))
    except Exception:
        log.exception("Vuln scan failed")

    try:
        findings = scan_resource_abuse(workspace_dir, py_files)
        all_findings.extend(findings)
        log.info("Resource abuse: %d findings", len(findings))
    except Exception:
        log.exception("Resource abuse scan failed")

    try:
        agent_findings = scan_agents(workspace_dir, all_files)
        all_findings.extend(agent_findings)
        log.info("Agent scan: %d findings", len(agent_findings))
    except Exception:
        log.exception("Agent scan failed")

    # Convert analysis secrets to SecurityFindings — done BEFORE IR queries so
    # IR severity-fusion sees the full base finding set (including secrets).
    if analysis_result is not None:
        _sev_map = {"hardcoded_key": "high", "dotenv_file": "high", "token_like": "medium"}
        for sf in analysis_result.secrets.findings:
            sev = _sev_map.get(sf.kind, "low")
            label = sf.name_hint or sf.kind
            value = f" ({sf.value_redacted})" if sf.value_redacted else ""
            evidence = [
                Evidence(file=e.file, line=e.line, snippet=getattr(e, "snippet", "") or "")
                for e in sf.evidence
            ]
            all_findings.append(SecurityFinding(
                category="secrets",
                severity=sev,
                title=f"Hardcoded secret: {label}",
                description=(
                    f"{sf.kind} found in source code{value}. "
                    f"Hardcoded credentials are accessible to anyone with repository access "
                    f"and will be exposed if the code is shared or version-controlled."
                ),
                evidence=evidence,
                recommendation=(
                    f"Move to environment variable: os.environ['{sf.name_hint or 'SECRET_KEY'}']. "
                    f"Remove from source and rotate the credential if already committed."
                ),
            ))

    try:
        from la_analyzer.ir import build_effect_graph
        from la_analyzer.ir.queries import run_all_queries
        effect_graph = build_effect_graph(workspace_dir, py_files)
        # Pass the complete base finding set (including secrets) for severity fusion.
        ir_findings = run_all_queries(
            effect_graph,
            existing_findings=[f for f in all_findings if f.origin != "ir_query"],
        )
        all_findings.extend(
            f.model_copy(update={"origin": "ir_query"}) for f in ir_findings
        )
        log.info("IR graph queries: %d findings", len(ir_findings))
    except Exception:
        log.exception("IR graph scan failed")

    # Pull summary stats from analysis
    secrets_found = len(analysis_result.secrets.findings) if analysis_result else 0
    egress_endpoints = len(analysis_result.egress.outbound_calls) if analysis_result else 0
    hardcoded_paths = len(analysis_result.io.hardcoded_paths) if analysis_result else 0

    # Gate booleans (deploy_blocked, requires_review) are computed fields on
    # SecurityReport — derived from findings automatically, no need to set them.
    report = SecurityReport(
        created_at=datetime.now(timezone.utc).isoformat(),
        findings=all_findings,
        data_classifications=data_classifications,
        secrets_found=secrets_found,
        egress_endpoints=egress_endpoints,
        hardcoded_paths=hardcoded_paths,
    )

    if report_dir:
        report_dir.mkdir(parents=True, exist_ok=True)
        report_path = report_dir / report_filename
        report_path.write_text(json.dumps(report.model_dump(), indent=2))
        log.info("Security report written to %s", report_path)

    log.info(
        "Security review complete: %d critical, %d high, %d medium, %d low | blocked=%s review=%s",
        report.critical_count, report.high_count,
        report.medium_count, report.low_count,
        report.deploy_blocked, report.requires_review,
    )

    return report

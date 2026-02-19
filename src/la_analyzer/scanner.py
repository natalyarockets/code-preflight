"""Unified scanner: runs analysis + security review + projection in one pass."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

from la_analyzer.analyzer.service import analyze_repo
from la_analyzer.analyzer.models import AnalysisResult, ProjectionReport
from la_analyzer.security import run_security_review
from la_analyzer.security.models import SecurityReport
from la_analyzer.utils import discover_files

log = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """Combined result from analysis + security review + projection."""
    analysis: AnalysisResult
    security: SecurityReport | None
    projection: ProjectionReport | None
    project_path: Path


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

    return ScanResult(
        analysis=analysis,
        security=security,
        projection=projection,
        project_path=project_path,
    )

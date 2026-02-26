"""Tests for the markdown report renderer -- security-first layout."""

from pathlib import Path

from la_analyzer.analyzer.models import (
    AnalysisResult,
    CallEdge,
    CallGraph,
    DetectionReport,
    DepsReport,
    EgressReport,
    EntrypointCandidate,
    EntrypointProjection,
    Evidence,
    FunctionNode,
    IOReport,
    OutboundCall,
    ProjectedEffect,
    ProjectionReport,
    SecretFinding,
    SecretsReport,
    DescriptionReport,
)
from la_analyzer.security.models import (
    CredentialLeakRisk,
    DataClassification,
    DataFlowRisk,
    SecurityFinding,
    SecurityReport,
)
from la_analyzer.security.models import Evidence as SecEvidence
from la_analyzer.scanner import ScanResult, ToolResult
from la_analyzer.render.markdown import render_markdown


def _minimal_analysis() -> AnalysisResult:
    return AnalysisResult(
        detection=DetectionReport(),
        io=IOReport(),
        egress=EgressReport(),
        secrets=SecretsReport(),
        deps=DepsReport(),
        description=DescriptionReport(),
    )


def _minimal_security() -> SecurityReport:
    return SecurityReport()


def _make_result(
    analysis=None, security=None, projection=None
) -> ScanResult:
    return ScanResult(
        analysis=analysis or _minimal_analysis(),
        security=security,
        projection=projection,
        project_path=Path("/tmp/test-project"),
    )


# -- Summary Card Tests -------------------------------------------------------


def test_render_summary_card_at_top():
    """Summary card should appear before structural analysis."""
    security = SecurityReport(
        findings=[SecurityFinding(
            category="injection", severity="critical",
            title="Shell execution via subprocess",
            description="subprocess call detected",
            evidence=[SecEvidence(file="app.py", line=5, snippet="subprocess.run(...)")],
        )],
    )
    result = _make_result(security=security)
    md = render_markdown(result)

    # Summary card should be at the top (before Project Structure)
    summary_pos = md.find("## Security Summary")
    structure_pos = md.find("## Project Structure")
    assert summary_pos != -1
    assert structure_pos != -1
    assert summary_pos < structure_pos

    # Gate decision should be present
    assert "BLOCKED" in md

    # Severity counts table should reflect the one critical finding
    assert "| 1 | 0 | 0 | 0 |" in md


def test_render_summary_card_pass():
    """Clean scan should show PASS."""
    result = _make_result(security=_minimal_security())
    md = render_markdown(result)
    assert "PASS" in md


def test_render_summary_card_review_required():
    """High-severity findings should show REVIEW REQUIRED."""
    security = SecurityReport(findings=[SecurityFinding(
        category="injection", severity="high",
        title="exec() detected", description="exec() usage found",
    )])
    result = _make_result(security=security)
    md = render_markdown(result)
    assert "REVIEW REQUIRED" in md


def test_render_top_risks():
    """Top risks should be actionable sentences."""
    security = SecurityReport(
        findings=[CredentialLeakRisk(
            credential_name="API_KEY",
            leak_target="log_output",
            description="API_KEY printed to stdout",
            evidence=[SecEvidence(file="app.py", line=10, snippet="print(api_key)")],
            severity="critical",
        )],
    )
    result = _make_result(security=security)
    md = render_markdown(result)
    assert "API_KEY" in md
    assert "log/print output" in md


def test_top_risks_preserves_all_severe_findings_for_count_alignment():
    """Top risks should preserve all severe findings so list length matches summary counts."""
    ir_finding = SecurityFinding(
        category="auth",
        severity="high",
        title="Unauthenticated Route: GET /x",
        description="Route has no auth",
        evidence=[SecEvidence(file="app.py", line=10, snippet="GET /x")],
        origin="ir_query",
    )
    security = SecurityReport(
        findings=[ir_finding, ir_finding],
        requires_review=True,
    )
    result = _make_result(security=security)
    from la_analyzer.render._helpers import top_risks
    risks = top_risks(result)
    assert risks.count("GET /x (unauthenticated route) at app.py:10") == 2


# -- Trust Boundary Tests ------------------------------------------------------


def test_render_trust_boundaries():
    """Trust boundary section shows egress only; secrets and findings go in Security Findings."""
    analysis = _minimal_analysis()
    analysis.egress = EgressReport(outbound_calls=[OutboundCall(
        kind="llm_sdk", library="openai",
        evidence=[Evidence(file="ai.py", line=3, snippet="client = openai.OpenAI()")],
    )])

    security = SecurityReport(
        findings=[
            SecurityFinding(
                category="secrets", severity="high",
                title="Hardcoded secret: API_KEY",
                description="hardcoded_key found in source code",
                evidence=[SecEvidence(file="config.py", line=1, snippet='API_KEY = "sk-..."')],
            ),
            CredentialLeakRisk(
                credential_name="API_KEY",
                leak_target="llm_prompt",
                description="Credential in LLM prompt",
                evidence=[SecEvidence(file="ai.py", line=10, snippet="prompt = f'{api_key}'")],
            ),
            DataFlowRisk(
                data_source="customers.csv",
                data_sink="openai LLM",
                pii_fields_in_path=["email", "ssn"],
                description="PII sent to LLM",
                evidence=[SecEvidence(file="ai.py", line=15, snippet="client.create(...)")],
                severity="high",
            ),
        ],
        requires_review=True,
    )

    result = _make_result(analysis=analysis, security=security)
    md = render_markdown(result)

    # Trust Boundaries: egress only
    assert "Trust Boundaries" in md
    assert "Data Egress" in md
    assert "openai" in md
    assert "Secrets Detected" not in md
    # Secrets, credential leaks, and data flow risks all in Security Findings
    assert "Hardcoded secret" in md
    assert "credential_leak" in md
    assert "API_KEY" in md
    assert "data_flow" in md
    assert "email" in md


def test_no_trust_boundaries_for_clean_project():
    """Clean project should not have a trust boundaries section."""
    result = _make_result(security=_minimal_security())
    md = render_markdown(result)
    assert "Trust Boundaries" not in md


# -- Entrypoint Matrix Tests ---------------------------------------------------


def test_render_entrypoint_matrix():
    """Matrix table should show effect counts per entrypoint."""
    projection = ProjectionReport(
        projections=[EntrypointProjection(
            entrypoint_id="main.py::main",
            entrypoint_label="python main.py",
            reachable_functions=["main.py::main", "main.py::process", "main.py::send"],
            effects=[
                ProjectedEffect(source="io", title="File read: data.csv", file="main.py", line=5),
                ProjectedEffect(source="io", title="File write: output.csv", file="main.py", line=10),
                ProjectedEffect(source="egress", title="LLM call via openai", file="main.py", line=15),
                ProjectedEffect(source="secret", title="API_KEY", file="main.py", line=1),
            ],
        )],
        unreachable_findings=[
            ProjectedEffect(source="security", title="exec() call", severity="high", file="unused.py", line=1),
        ],
        call_graph=CallGraph(),
    )

    result = _make_result(projection=projection)
    md = render_markdown(result)

    assert "Entrypoint Effect Matrix" in md
    assert "python main.py" in md
    assert "| 3 |" in md  # reachable count
    assert "outside call graph" in md.lower()


def test_no_matrix_without_projection():
    """No projection data should produce no matrix section."""
    result = _make_result()
    md = render_markdown(result)
    assert "Entrypoint Effect Matrix" not in md


# -- Mermaid Call Graph Tests --------------------------------------------------


def test_render_mermaid_graph():
    """Call graph should render as mermaid flowchart."""
    projection = ProjectionReport(
        projections=[],
        call_graph=CallGraph(
            functions=[
                FunctionNode(id="main.py::main", file="main.py", name="main",
                           line_start=1, line_end=10, is_entrypoint=True),
                FunctionNode(id="main.py::process", file="main.py", name="process",
                           line_start=12, line_end=20),
                FunctionNode(id="main.py::send", file="main.py", name="send",
                           line_start=22, line_end=30),
            ],
            edges=[
                CallEdge(caller="main.py::main", callee="main.py::process"),
                CallEdge(caller="main.py::process", callee="main.py::send"),
            ],
            entrypoint_ids=["main.py::main"],
        ),
    )

    result = _make_result(projection=projection)
    md = render_markdown(result)

    assert "## Call Graph" in md
    assert "```mermaid" in md
    assert "flowchart LR" in md
    assert "main_py__main" in md  # mermaid-safe id
    assert "-->" in md
    assert "```" in md


def test_no_mermaid_without_edges():
    """No edges should produce no call graph section."""
    projection = ProjectionReport(
        projections=[],
        call_graph=CallGraph(functions=[], edges=[]),
    )
    result = _make_result(projection=projection)
    md = render_markdown(result)
    assert "```mermaid" not in md


# -- Structural Summary Tests --------------------------------------------------


def test_render_structural_summary_compact():
    """Structural summary should be compact, not verbose tables."""
    analysis = _minimal_analysis()
    analysis.detection.entrypoint_candidates = [
        EntrypointCandidate(
            kind="command", value="python main.py", confidence=0.9,
            evidence=[Evidence(file="main.py", line=1, snippet="")],
        ),
    ]

    result = _make_result(analysis=analysis)
    md = render_markdown(result)

    assert "## Project Structure" in md
    assert "python main.py" in md
    assert "--format json" in md  # pointer to full details


# -- Full Report Structure Tests -----------------------------------------------


def test_full_report_section_order():
    """Sections should follow the security-first layout with structure after trust boundaries."""
    security = SecurityReport(
        findings=[SecurityFinding(
            category="injection", severity="high", title="exec() usage",
            description="exec() detected",
            evidence=[SecEvidence(file="app.py", line=1, snippet="exec(x)")],
        )],
        requires_review=True,
    )
    projection = ProjectionReport(
        projections=[EntrypointProjection(
            entrypoint_id="main.py::main",
            entrypoint_label="python main.py",
            reachable_functions=["main.py::main"],
            effects=[ProjectedEffect(source="io", title="reads data", file="main.py", line=1)],
        )],
        call_graph=CallGraph(
            functions=[
                FunctionNode(id="main.py::main", file="main.py", name="main",
                           line_start=1, line_end=5, is_entrypoint=True),
                FunctionNode(id="main.py::helper", file="main.py", name="helper",
                           line_start=7, line_end=10),
            ],
            edges=[CallEdge(caller="main.py::main", callee="main.py::helper")],
        ),
    )

    result = _make_result(security=security, projection=projection)
    md = render_markdown(result)

    # Verify section order
    positions = {
        "summary": md.find("## Security Summary"),
        "matrix": md.find("## Entrypoint Effect Matrix"),
        "findings": md.find("## Security Findings"),
        "call_graph": md.find("## Call Graph"),
        "structure": md.find("## Project Structure"),
    }

    # All sections should exist
    for name, pos in positions.items():
        assert pos != -1, f"Section '{name}' not found in report"

    # Summary before structure before matrix before findings before call graph
    assert positions["summary"] < positions["structure"]
    assert positions["structure"] < positions["matrix"]
    assert positions["matrix"] < positions["findings"]
    assert positions["findings"] < positions["call_graph"]


def test_no_security_scan_still_renders():
    """Report without security scan should still render structural info."""
    result = _make_result()
    md = render_markdown(result)
    assert "Static Runtime Projection and Safety Audit" in md
    assert "Project Structure" in md


def test_title_includes_project_name():
    """Report title should include the project name."""
    result = _make_result()
    md = render_markdown(result)
    assert "test-project" in md


# -- Toolchain Tests -----------------------------------------------------------


def test_render_toolchain():
    """Toolchain table should show tool names, versions, statuses, and findings."""
    result = _make_result(security=_minimal_security())
    result.toolchain = [
        ToolResult(
            name="Bandit", version="1.9.3", status="ran",
            findings=3, description="Code security: exec, subprocess, etc.",
        ),
        ToolResult(
            name="detect-secrets", version="1.5.0", status="ran",
            findings=1, description="Hardcoded secrets via entropy and pattern detection",
        ),
        ToolResult(
            name="pip-audit", version="-", status="not_installed",
            findings=-1, description="Known CVEs in Python dependencies (NIST NVD)",
        ),
        ToolResult(
            name="LA code scanner", version="built-in", status="ran",
            findings=2, description="Dynamic imports, ctypes, network bypass",
        ),
    ]
    md = render_markdown(result)

    # Table header
    assert "## Scan Toolchain" in md
    assert "| Tool | Version | Status | Findings | What It Checks |" in md

    # Tool rows
    assert "| Bandit | 1.9.3 | ran | 3 |" in md
    assert "| detect-secrets | 1.5.0 | ran | 1 |" in md
    assert "| pip-audit | - | not_installed | - |" in md
    assert "| LA code scanner | built-in | ran | 2 |" in md

    # Should appear after Project Structure
    toolchain_pos = md.find("## Scan Toolchain")
    structure_pos = md.find("## Project Structure")
    assert toolchain_pos > structure_pos


def test_render_toolchain_empty():
    """No toolchain data should produce no toolchain section."""
    result = _make_result()
    result.toolchain = []
    md = render_markdown(result)
    assert "Scan Toolchain" not in md


def test_render_toolchain_skipped():
    """Skipped tools should show '-' for findings count."""
    result = _make_result()
    result.toolchain = [
        ToolResult(
            name="Bandit", version="1.9.3", status="skipped",
            findings=-1, description="Code security",
        ),
    ]
    md = render_markdown(result)
    assert "| Bandit | 1.9.3 | skipped | - |" in md


# ── PDF Render Tests ──────────────────────────────────────────────────────

import pytest

try:
    import fpdf  # noqa: F401
    HAS_FPDF = True
except ImportError:
    HAS_FPDF = False

pdf_tests = pytest.mark.skipif(not HAS_FPDF, reason="fpdf2 not installed")


@pdf_tests
def test_pdf_smoke(tmp_path):
    """render_pdf produces a non-zero file starting with %PDF."""
    from la_analyzer.render.pdf import render_pdf

    result = _make_result(security=_minimal_security())
    out = tmp_path / "report.pdf"
    render_pdf(result, out)
    data = out.read_bytes()
    assert len(data) > 100
    assert data[:5] == b"%PDF-"


@pdf_tests
def test_pdf_empty_data(tmp_path):
    """Empty scan result (no security, no projection) should not crash."""
    from la_analyzer.render.pdf import render_pdf

    result = _make_result()
    out = tmp_path / "empty.pdf"
    render_pdf(result, out)
    assert out.read_bytes()[:5] == b"%PDF-"


@pdf_tests
def test_pdf_full_data(tmp_path):
    """Fully populated ScanResult should produce valid PDF without crashing."""
    from la_analyzer.render.pdf import render_pdf

    analysis = _minimal_analysis()
    analysis.detection.entrypoint_candidates = [
        EntrypointCandidate(
            kind="command", value="python main.py", confidence=0.9,
            evidence=[Evidence(file="main.py", line=1, snippet="")],
        ),
    ]
    analysis.egress = EgressReport(outbound_calls=[OutboundCall(
        kind="llm_sdk", library="openai",
        evidence=[Evidence(file="ai.py", line=3, snippet="client = openai.OpenAI()")],
    )])
    analysis.secrets = SecretsReport(findings=[SecretFinding(
        kind="hardcoded_key", name_hint="API_KEY", value_redacted="****abcd",
        evidence=[Evidence(file="config.py", line=1, snippet='API_KEY = "sk-..."')],
    )])

    security = SecurityReport(
        findings=[
            SecurityFinding(
                category="injection", severity="critical",
                title="Shell execution via subprocess",
                description="subprocess call detected",
                recommendation="Use shlex.split() for argument parsing",
                evidence=[SecEvidence(file="app.py", line=5, snippet="subprocess.run(...)")],
            ),
            CredentialLeakRisk(
                credential_name="API_KEY",
                leak_target="llm_prompt",
                description="Credential in LLM prompt",
                evidence=[SecEvidence(file="ai.py", line=10, snippet="prompt = f'{api_key}'")],
            ),
            DataFlowRisk(
                data_source="customers.csv",
                data_sink="openai LLM",
                pii_fields_in_path=["email", "ssn"],
                description="PII sent to LLM",
                evidence=[SecEvidence(file="ai.py", line=15, snippet="client.create(...)")],
                severity="high",
            ),
        ],
        data_classifications=[DataClassification(
            category="pii", confidence=0.95, fields_detected=["email", "ssn"],
        )],
    )

    projection = ProjectionReport(
        projections=[EntrypointProjection(
            entrypoint_id="main.py::main",
            entrypoint_label="python main.py",
            reachable_functions=["main.py::main", "main.py::process"],
            effects=[
                ProjectedEffect(source="io", title="File read: data.csv", file="main.py", line=5),
                ProjectedEffect(source="egress", title="LLM call via openai", file="main.py", line=15),
            ],
        )],
        call_graph=CallGraph(
            functions=[
                FunctionNode(id="main.py::main", file="main.py", name="main",
                           line_start=1, line_end=10, is_entrypoint=True),
                FunctionNode(id="main.py::process", file="main.py", name="process",
                           line_start=12, line_end=20),
            ],
            edges=[CallEdge(caller="main.py::main", callee="main.py::process")],
            entrypoint_ids=["main.py::main"],
        ),
    )

    result = _make_result(analysis=analysis, security=security, projection=projection)
    result.toolchain = [
        ToolResult(name="Bandit", version="1.9.3", status="ran", findings=1,
                   description="Code security"),
        ToolResult(name="pip-audit", version="-", status="not_installed", findings=-1,
                   description="Known CVEs"),
    ]

    out = tmp_path / "full.pdf"
    render_pdf(result, out)
    data = out.read_bytes()
    assert len(data) > 500
    assert data[:5] == b"%PDF-"


@pdf_tests
def test_pdf_unicode_safety(tmp_path):
    """Unicode characters in findings should not raise encoding errors."""
    from la_analyzer.render.pdf import render_pdf

    security = SecurityReport(
        findings=[SecurityFinding(
            category="injection", severity="high",
            title="Unsafe eval() \u2014 dynamic code execution",
            description="Uses eval() with user input \u2192 RCE risk \u2265 critical",
            evidence=[SecEvidence(file="app.py", line=1, snippet='eval("2\u00b2")')],
        )],
        requires_review=True,
    )
    result = _make_result(security=security)
    out = tmp_path / "unicode.pdf"
    render_pdf(result, out)
    assert out.read_bytes()[:5] == b"%PDF-"

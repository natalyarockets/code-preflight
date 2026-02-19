"""Pydantic models for all analyzer reports."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field


# ── Shared ──────────────────────────────────────────────────────────────────

class Evidence(BaseModel):
    file: str
    line: int
    snippet: str
    function_name: str | None = None


# ── A) detection_report.json ────────────────────────────────────────────────

class PythonInfo(BaseModel):
    has_pyproject: bool = False
    has_requirements_txt: bool = False
    has_environment_yml: bool = False
    notebooks_found: int = 0


class ArchetypeMatch(BaseModel):
    type: Literal["python_batch", "fastapi_web", "streamlit_web", "unknown"]
    confidence: float


class EntrypointCandidate(BaseModel):
    kind: Literal["command", "module"]
    value: str
    confidence: float
    evidence: list[Evidence] = Field(default_factory=list)


class DetectionReport(BaseModel):
    languages: list[str] = Field(default_factory=lambda: ["python"])
    python: PythonInfo = Field(default_factory=PythonInfo)
    archetypes: list[ArchetypeMatch] = Field(default_factory=list)
    entrypoint_candidates: list[EntrypointCandidate] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


# ── B) io_report.json ──────────────────────────────────────────────────────

class IOInput(BaseModel):
    id: str
    label: str = ""
    kind: Literal["file", "text", "param", "directory", "json_body", "upload", "query_param", "path_param"]
    format: Literal["csv", "excel", "zip", "json", "pdf", "audio", "parquet", "text", "yaml", "xml", "jpeg", "unknown"] = "unknown"
    description: str = ""  # hint for the user: what to upload, accepted formats
    accepted_formats: list[str] = Field(default_factory=list)  # e.g. [".pdf", ".txt", ".csv"]
    path_literal: str | None = None
    evidence: list[Evidence] = Field(default_factory=list)
    confidence: float = 0.5


class IOOutput(BaseModel):
    id: str
    label: str = ""
    kind: Literal["artifact", "response_model"] = "artifact"
    format: Literal["csv", "excel", "json", "png", "pdf", "markdown", "html", "parquet", "text", "yaml", "xml", "jpeg", "directory", "unknown"] = "unknown"
    role: Literal["primary", "artifact"] = "primary"
    path_literal: str | None = None
    evidence: list[Evidence] = Field(default_factory=list)
    confidence: float = 0.5


class HardcodedPath(BaseModel):
    path: str
    evidence: list[Evidence] = Field(default_factory=list)


class APIRoute(BaseModel):
    method: str           # "GET", "POST", etc.
    path: str             # "/detect", "/appliances/{id}"
    handler: str          # function name
    file: str             # relative file path
    line: int
    input_ids: list[str] = Field(default_factory=list)
    output_ids: list[str] = Field(default_factory=list)


class IOReport(BaseModel):
    inputs: list[IOInput] = Field(default_factory=list)
    outputs: list[IOOutput] = Field(default_factory=list)
    hardcoded_paths: list[HardcodedPath] = Field(default_factory=list)
    api_routes: list[APIRoute] = Field(default_factory=list)


# ── C) egress_report.json ──────────────────────────────────────────────────

class OutboundCall(BaseModel):
    kind: Literal["llm_sdk", "http", "database", "cloud", "baas", "webhook", "unknown"]
    library: str = "unknown"
    domains: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    confidence: float = 0.5


class SuggestedGatewayNeeds(BaseModel):
    needs_llm_gateway: bool = False
    needs_external_api_gateway: bool = False
    requested_models: list[str] = Field(default_factory=list)


class EgressReport(BaseModel):
    outbound_calls: list[OutboundCall] = Field(default_factory=list)
    suggested_gateway_needs: SuggestedGatewayNeeds = Field(
        default_factory=SuggestedGatewayNeeds
    )


# ── D) secrets_report.json ─────────────────────────────────────────────────

class SecretFinding(BaseModel):
    kind: Literal["hardcoded_key", "dotenv_file", "token_like", "unknown"]
    name_hint: str | None = None
    value_redacted: str
    evidence: list[Evidence] = Field(default_factory=list)
    confidence: float = 0.5


class SecretsReport(BaseModel):
    findings: list[SecretFinding] = Field(default_factory=list)
    suggested_env_vars: list[str] = Field(default_factory=list)


# ── E) deps_report.json ───────────────────────────────────────────────────

class DepsSource(BaseModel):
    type: Literal["pyproject", "requirements", "environment_yml", "imports_scan"]
    path: str


class Dependency(BaseModel):
    name: str
    spec: str | None = None
    source_path: str = ""


class DepsReport(BaseModel):
    python_version_hint: str | None = None
    sources: list[DepsSource] = Field(default_factory=list)
    dependencies: list[Dependency] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


# ── F) porting_plan.json ──────────────────────────────────────────────────

class ChangeFile(BaseModel):
    file: str
    line: int | None = None
    snippet: str | None = None


class RequiredChange(BaseModel):
    type: Literal[
        "replace_hardcoded_input",
        "route_llm_via_gateway",
        "route_external_via_proxy",
        "remove_embedded_secret",
        "standardize_outputs",
        "choose_entrypoint",
    ]
    description: str
    files: list[ChangeFile] = Field(default_factory=list)
    suggested_fix: str = ""


class PortingPlan(BaseModel):
    summary: str = ""
    required_changes: list[RequiredChange] = Field(default_factory=list)
    optional_changes: list[RequiredChange] = Field(default_factory=list)
    wrapper_recommended: bool = False
    wrapper_entrypoint_path: str = "livingapps_entrypoint.py"


# ── G) description_report.json ───────────────────────────────────────────


class ModuleDocstring(BaseModel):
    file: str
    docstring: str
    is_entrypoint: bool = False


class DescriptionReport(BaseModel):
    """Extracted natural-language context: README + module docstrings.

    Post-MVP: feed this into LLM enrichment for semantic flow labels.
    """

    readme_content: str = ""
    readme_file: str = ""  # e.g. "README.md"
    module_docstrings: list[ModuleDocstring] = Field(default_factory=list)
    argparse_descriptions: list[str] = Field(default_factory=list)


# ── Top-level result ───────────────────────────────────────────────────────

class AnalysisResult(BaseModel):
    detection_report_path: str = ""
    io_report_path: str = ""
    egress_report_path: str = ""
    secrets_report_path: str = ""
    deps_report_path: str = ""
    porting_plan_path: str = ""
    description_report_path: str = ""
    manifest_path: str = ""

    detection: DetectionReport = Field(default_factory=DetectionReport)
    io: IOReport = Field(default_factory=IOReport)
    egress: EgressReport = Field(default_factory=EgressReport)
    secrets: SecretsReport = Field(default_factory=SecretsReport)
    deps: DepsReport = Field(default_factory=DepsReport)
    porting_plan: PortingPlan = Field(default_factory=PortingPlan)
    description: DescriptionReport = Field(default_factory=DescriptionReport)


# ── H) Call Graph ─────────────────────────────────────────────────────────


class FunctionNode(BaseModel):
    """A function/method definition in the project."""
    id: str                   # "file.py::func_name" or "file.py::Class.method"
    file: str
    name: str
    line_start: int
    line_end: int
    is_entrypoint: bool = False


class CallEdge(BaseModel):
    """A call from one function to another."""
    caller: str               # FunctionNode.id
    callee: str               # FunctionNode.id


class CallGraph(BaseModel):
    """Project-wide call graph."""
    functions: list[FunctionNode] = Field(default_factory=list)
    edges: list[CallEdge] = Field(default_factory=list)
    entrypoint_ids: list[str] = Field(default_factory=list)


# ── I) Entrypoint Projection ─────────────────────────────────────────────


class ProjectedEffect(BaseModel):
    """A finding/effect mapped to a specific entrypoint's execution path."""
    source: str               # "io", "egress", "security", "secret"
    title: str
    severity: str = "info"    # "critical", "high", "medium", "low", "info"
    file: str
    line: int
    function_name: str | None = None
    detail: str = ""


class EntrypointProjection(BaseModel):
    """What happens when a specific entrypoint runs."""
    entrypoint_id: str        # FunctionNode.id or entrypoint value
    entrypoint_label: str     # human-readable (e.g. "python main.py")
    reachable_functions: list[str] = Field(default_factory=list)  # FunctionNode.ids
    effects: list[ProjectedEffect] = Field(default_factory=list)


class ProjectionReport(BaseModel):
    """Projection results for all entrypoints."""
    projections: list[EntrypointProjection] = Field(default_factory=list)
    unreachable_findings: list[ProjectedEffect] = Field(default_factory=list)
    call_graph: CallGraph = Field(default_factory=CallGraph)

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
    kind: Literal["llm_sdk", "http", "database", "cloud", "baas",
                  "observability", "email", "webhook", "unknown"]
    library: str = "unknown"
    domains: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    confidence: float = 0.5


class EgressReport(BaseModel):
    outbound_calls: list[OutboundCall] = Field(default_factory=list)


# ── D) secrets_report.json ─────────────────────────────────────────────────

class SecretFinding(BaseModel):
    kind: Literal["hardcoded_key", "dotenv_file", "token_like", "unknown"]
    name_hint: str | None = None
    value_redacted: str
    evidence: list[Evidence] = Field(default_factory=list)
    confidence: float = 0.5
    origin: str = "ast_name"  # "ast_name", "dotenv", "detect_secrets", "token_pattern"


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



# ── G) description_report.json ───────────────────────────────────────────


class ModuleDocstring(BaseModel):
    file: str
    docstring: str
    is_entrypoint: bool = False


class DescriptionReport(BaseModel):
    """Extracted natural-language context: README + module docstrings."""

    readme_content: str = ""
    readme_file: str = ""  # e.g. "README.md"
    module_docstrings: list[ModuleDocstring] = Field(default_factory=list)
    argparse_descriptions: list[str] = Field(default_factory=list)


# ── G2) Prompt Surface ─────────────────────────────────────────────────


class PromptVariable(BaseModel):
    name: str                     # "aircraft_overview"
    origin: str = ""              # "f-string", "format", "concat", "param"


class PromptSurface(BaseModel):
    function: str                 # "build_fault_tree"
    file: str                     # "graph.py"
    line: int                     # line of the LLM call
    llm_method: str               # "invoke", "create", "completion"
    prompt_variables: list[PromptVariable] = Field(default_factory=list)
    string_constants: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)


class PromptSurfaceReport(BaseModel):
    surfaces: list[PromptSurface] = Field(default_factory=list)


# ── G3) Tool Registration ────────────────────────────────────────────────


class ToolCapability(BaseModel):
    kind: str          # "network", "file_read", "file_write", "database", "subprocess", "compute"
    detail: str = ""
    line: int = 0


class RegisteredTool(BaseModel):
    name: str
    file: str
    line: int
    registration: str  # "@tool", "bind_tools", "tools_schema"
    docstring: str = ""
    parameters: list[str] = Field(default_factory=list)
    capabilities: list[ToolCapability] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)


class ToolRegistrationReport(BaseModel):
    tools: list[RegisteredTool] = Field(default_factory=list)


# ── G4) State Flow ───────────────────────────────────────────────────────


class StateAccess(BaseModel):
    key: str
    access: str    # "read" or "write"
    line: int


class NodeStateFlow(BaseModel):
    function: str
    file: str
    line_start: int
    line_end: int
    reads: list[str] = Field(default_factory=list)
    writes: list[str] = Field(default_factory=list)
    accesses: list[StateAccess] = Field(default_factory=list)


class StateFlowReport(BaseModel):
    state_class: str = ""
    state_keys: list[str] = Field(default_factory=list)
    node_flows: list[NodeStateFlow] = Field(default_factory=list)


# ── Top-level result ───────────────────────────────────────────────────────

class AnalysisResult(BaseModel):
    detection_report_path: str = ""
    io_report_path: str = ""
    egress_report_path: str = ""
    secrets_report_path: str = ""
    deps_report_path: str = ""
    description_report_path: str = ""
    prompt_surface_report_path: str = ""
    tool_registration_report_path: str = ""
    state_flow_report_path: str = ""
    py_file_count: int = 0

    detection: DetectionReport = Field(default_factory=DetectionReport)
    io: IOReport = Field(default_factory=IOReport)
    egress: EgressReport = Field(default_factory=EgressReport)
    secrets: SecretsReport = Field(default_factory=SecretsReport)
    deps: DepsReport = Field(default_factory=DepsReport)
    description: DescriptionReport = Field(default_factory=DescriptionReport)
    prompt_surface: PromptSurfaceReport = Field(default_factory=PromptSurfaceReport)
    tool_registration: ToolRegistrationReport = Field(default_factory=ToolRegistrationReport)
    state_flow: StateFlowReport = Field(default_factory=StateFlowReport)


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

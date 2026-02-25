"""Pydantic models for the security review."""

from __future__ import annotations

from pydantic import BaseModel, Field


class Evidence(BaseModel):
    file: str
    line: int
    snippet: str
    function_name: str | None = None


class SecurityFinding(BaseModel):
    category: str       # "injection", "secrets", "egress", "data", "deps", "resource"
    severity: str       # "critical", "high", "medium", "low", "info"
    title: str
    description: str
    evidence: list[Evidence] = Field(default_factory=list)
    recommendation: str = ""
    auto_mitigated: bool = False  # True if patcher already handles this


class DataClassification(BaseModel):
    category: str       # "pii", "financial", "health", "credential", "public"
    confidence: float
    evidence: list[Evidence] = Field(default_factory=list)
    fields_detected: list[str] = Field(default_factory=list)


class DataFlowRisk(BaseModel):
    data_source: str    # "uploaded CSV", "hardcoded file", "API response"
    data_sink: str      # "openai", "anthropic", "http endpoint", "output file"
    pii_fields_in_path: list[str] = Field(default_factory=list)
    description: str
    evidence: list[Evidence] = Field(default_factory=list)
    severity: str       # "critical", "high", "medium"
    auto_mitigated: bool = False  # True if platform gateway manages this flow


class CredentialLeakRisk(BaseModel):
    credential_name: str
    leak_target: str    # "llm_prompt", "log_output", "http_request", "http_auth", "output_file"
    description: str
    evidence: list[Evidence] = Field(default_factory=list)
    severity: str = "critical"
    auto_mitigated: bool = False  # True if platform manages this credential


class SecurityReport(BaseModel):
    created_at: str = ""
    # Findings from all scanners
    findings: list[SecurityFinding] = Field(default_factory=list)
    data_classifications: list[DataClassification] = Field(default_factory=list)
    data_flow_risks: list[DataFlowRisk] = Field(default_factory=list)
    credential_leak_risks: list[CredentialLeakRisk] = Field(default_factory=list)
    # IR graph findings (effect graph queries)
    ir_findings: list[SecurityFinding] = Field(default_factory=list)
    # Aggregated severity counts
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    # Gate decision
    deploy_blocked: bool = False    # True if any critical finding
    requires_review: bool = False   # True if any high finding
    # Summary from existing analyzers
    secrets_found: int = 0
    egress_endpoints: int = 0
    hardcoded_paths: int = 0
    # Agent/skill scan
    agent_scan: AgentScanReport | None = None


# ── Agent / Skill scan ────────────────────────────────────────────────────


class AgentFinding(BaseModel):
    category: str       # "prompt_injection", "overprivileged_tool", "credential_exposure",
                        # "unscoped_permission", "missing_guardrail"
    severity: str       # "critical", "high", "medium", "low"
    title: str
    description: str
    file: str
    line: int = 0
    snippet: str = ""
    recommendation: str = ""


class AgentScanReport(BaseModel):
    findings: list[AgentFinding] = Field(default_factory=list)


# Rebuild SecurityReport now that AgentScanReport is defined
SecurityReport.model_rebuild()

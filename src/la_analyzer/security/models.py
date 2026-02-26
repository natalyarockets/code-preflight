"""Pydantic models for the security review."""

from __future__ import annotations

from pydantic import BaseModel, Field, computed_field

# Evidence lives in the analyzer models — one canonical definition shared by
# both subsystems.  Re-exported here so importers don't need to know the source.
from la_analyzer.analyzer.models import Evidence  # noqa: F401 (re-exported)


class SecurityFinding(BaseModel):
    category: str       # "injection", "secrets", "egress", "data", "deps", "resource",
                        # "auth", "data_flow", "credential_leak", "agent"
    severity: str       # "critical", "high", "medium", "low", "info"
    title: str
    description: str
    evidence: list[Evidence] = Field(default_factory=list)
    recommendation: str = ""
    origin: str = "security_scanner"  # "security_scanner", "ir_query", "bandit", ...
    origin_id: str | None = None

    # Optional structured fields for data_flow findings
    data_source: str | None = None      # e.g. "file: users.csv"
    data_sink: str | None = None        # e.g. "LLM API call"
    pii_fields: list[str] = Field(default_factory=list)

    # Optional structured fields for credential_leak findings
    credential_name: str | None = None  # e.g. "API_KEY"
    leak_target: str | None = None      # e.g. "log_output", "llm_prompt"


class DataClassification(BaseModel):
    category: str       # "pii", "financial", "health", "credential", "public"
    confidence: float
    evidence: list[Evidence] = Field(default_factory=list)
    fields_detected: list[str] = Field(default_factory=list)


class SecurityReport(BaseModel):
    created_at: str = ""
    # All findings from every scanner in one canonical list.
    findings: list[SecurityFinding] = Field(default_factory=list)
    data_classifications: list[DataClassification] = Field(default_factory=list)

    # Summary stats pulled from analysis (informational, not derived from findings)
    secrets_found: int = 0
    egress_endpoints: int = 0
    hardcoded_paths: int = 0

    # ── Severity counts (serialized — downstream consumers depend on these) ──

    @computed_field
    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "critical")

    @computed_field
    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "high")

    @computed_field
    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "medium")

    @computed_field
    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "low")

    @computed_field
    @property
    def ir_query_count(self) -> int:
        return sum(1 for f in self.findings if f.origin == "ir_query")

    # ── Gate decision (derived from findings; serialized) ────────────────────

    @computed_field
    @property
    def has_critical(self) -> bool:
        """True when any critical finding is present."""
        return any(f.severity == "critical" for f in self.findings)

    @computed_field
    @property
    def requires_review(self) -> bool:
        """True when any high-severity finding is present. May be True alongside has_critical; gate_status resolves the precedence."""
        return any(f.severity == "high" for f in self.findings)

    @computed_field
    @property
    def gate_status(self) -> str:
        """One of 'blocked', 'review', 'pass'."""
        if self.has_critical:
            return "blocked"
        if self.requires_review:
            return "review"
        return "pass"

    @computed_field
    @property
    def gate_message(self) -> str:
        """Human-readable gate decision sentence."""
        if self.has_critical:
            return "BLOCKED -- Critical findings must be resolved."
        if self.requires_review:
            return "REVIEW REQUIRED -- High-severity findings should be reviewed."
        return "PASS -- No critical or high-severity findings."

    # ── Filtered views — NOT serialized; use findings list for persistence ───
    # These are convenience accessors only. model_dump() will not include them.

    @property
    def data_flow_risks(self) -> list[SecurityFinding]:
        return [f for f in self.findings if f.category == "data_flow"]

    @property
    def credential_leak_risks(self) -> list[SecurityFinding]:
        return [f for f in self.findings if f.category == "credential_leak"]

    @property
    def agent_findings(self) -> list[SecurityFinding]:
        return [f for f in self.findings if f.category == "agent"]


# ── Backward-compatibility aliases ──────────────────────────────────────────
# Kept so existing tests and any downstream code that constructs these types
# directly still works without changes.

class CredentialLeakRisk(SecurityFinding):
    """Thin wrapper over SecurityFinding for backward-compatible construction."""

    def __init__(self, **data):
        data.setdefault("category", "credential_leak")
        data.setdefault("severity", "high")
        cred = data.get("credential_name", "")
        target = data.get("leak_target", "")
        data.setdefault("title", f"Credential leak: {cred} -> {target}")
        data.setdefault("description", "")
        super().__init__(**data)


class DataFlowRisk(SecurityFinding):
    """Thin wrapper over SecurityFinding for backward-compatible construction."""

    def __init__(self, **data):
        # Accept old pii_fields_in_path spelling
        if "pii_fields_in_path" in data and "pii_fields" not in data:
            data["pii_fields"] = data.pop("pii_fields_in_path")
        data.setdefault("category", "data_flow")
        data.setdefault("severity", "medium")
        sink = data.get("data_sink", "")
        data.setdefault("title", f"Sensitive data flow -> {sink}" if sink else "Sensitive data flow")
        data.setdefault("description", "")
        super().__init__(**data)

    @property
    def pii_fields_in_path(self) -> list[str]:
        return self.pii_fields

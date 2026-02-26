"""Graph queries over EffectGraph → list[SecurityFinding].

Each query returns SecurityFinding objects using the existing security model.
"""

from __future__ import annotations

import logging

from la_analyzer.ir.capability_registry import Capability, SinkKind, SourceTrust
from la_analyzer.ir.graph import EffectGraph
from la_analyzer.ir.nodes import EffectNode
from la_analyzer.security.models import Evidence, SecurityFinding

log = logging.getLogger(__name__)


def query_prompt_injection(graph: EffectGraph) -> list[SecurityFinding]:
    """Find: user/external source → data_flows_to → llm_prompt sink."""
    findings: list[SecurityFinding] = []

    untrusted_trusts = {
        SourceTrust.USER_CONTROLLED,
        SourceTrust.HEADER_CONTROLLED,
        SourceTrust.EXTERNAL_UNTRUSTED,
        SourceTrust.DB_RESULT,  # indirect/RAG/state-derived content
    }

    def is_untrusted_source(n: EffectNode) -> bool:
        return n.kind == "source" and n.source_trust in untrusted_trusts

    def is_llm_sink(n: EffectNode) -> bool:
        return n.kind == "sink" and n.sink_kind == SinkKind.LLM_PROMPT

    paths = graph.find_paths(
        source_pred=is_untrusted_source,
        sink_pred=is_llm_sink,
        edge_kinds={"data_flows_to", "reaches"},
        max_paths=20,
    )

    seen: set[tuple[str, int]] = set()
    for path in paths:
        source_node = path[0]
        sink_node = path[-1]

        key = (sink_node.file, sink_node.line)
        if key in seen:
            continue
        seen.add(key)

        # Determine severity based on source trust
        if source_node.source_trust in (SourceTrust.USER_CONTROLLED, SourceTrust.HEADER_CONTROLLED):
            severity = "high"
        else:
            severity = "medium"

        path_desc = " → ".join(n.name for n in path)
        evidence = [
            Evidence(
                file=source_node.file,
                line=source_node.line,
                snippet=f"Source: {source_node.name} ({source_node.source_trust})",
            ),
            Evidence(
                file=sink_node.file,
                line=sink_node.line,
                snippet=f"Sink: {sink_node.name} ({sink_node.metadata.get('service', '')})",
            ),
        ]

        findings.append(SecurityFinding(
            category="prompt_injection",
            severity=severity,
            title="Prompt Injection: Untrusted data flows to LLM prompt",
            description=(
                f"User-controlled or external data reaches an LLM prompt without sanitization. "
                f"Path: {path_desc}"
            ),
            evidence=evidence,
            recommendation=(
                "Sanitize or validate user input before including in LLM prompts. "
                "Use a system prompt to constrain model behavior. "
                "Consider input length limits and content filtering."
            ),
        ))

    return findings


def query_implicit_egress(graph: EffectGraph) -> list[SecurityFinding]:
    """Find observability/email sinks — implicit egress that devs may overlook."""
    findings: list[SecurityFinding] = []
    seen: set[tuple[str, int]] = set()

    target_kinds = {SinkKind.OBSERVABILITY, SinkKind.EMAIL_SMTP}

    for node in graph.nodes_matching(lambda n: n.kind == "sink" and n.sink_kind in target_kinds):
        key = (node.file, node.line)
        if key in seen:
            continue
        seen.add(key)

        service = node.metadata.get("service", "Unknown")
        is_implicit = node.metadata.get("implicit_egress", False)
        conditional = node.metadata.get("conditional", False)

        if node.sink_kind == SinkKind.OBSERVABILITY:
            title = f"Observability Egress: {service}"
            description = (
                f"{service} SDK will transmit traces/events to external servers. "
                "Ensure this is intentional and complies with data handling policies."
            )
            if is_implicit:
                description = (
                    f"{service} SDK initialized — telemetry data will be sent to {service} servers "
                    "automatically on import/init. Review what data is captured."
                )
        else:
            title = f"Email Egress: {service}"
            description = (
                f"{service} is configured for email sending. "
                "Verify authentication, rate limits, and data in email bodies."
            )

        sev = "low" if conditional else "medium"
        ev = Evidence(file=node.file, line=node.line, snippet=f"{node.name}")
        findings.append(SecurityFinding(
            category="egress",
            severity=sev,
            title=title,
            description=description,
            evidence=[ev],
            recommendation=(
                "Audit what data is sent to this endpoint. "
                "Ensure API keys are stored securely in environment variables."
            ),
        ))

    # Also check for decorator-based egress (@traceable etc.)
    for node in graph.nodes_matching(
        lambda n: n.kind == "decorator" and n.sink_kind == SinkKind.OBSERVABILITY
    ):
        key = (node.file, node.line)
        if key in seen:
            continue
        seen.add(key)

        service = node.metadata.get("service", "Unknown")
        ev = Evidence(file=node.file, line=node.line,
                      snippet=f"@traceable decorator on {node.name}")
        findings.append(SecurityFinding(
            category="egress",
            severity="medium",
            title=f"Implicit Decorator Egress: @traceable ({service})",
            description=(
                f"Function '{node.name}' is decorated with @traceable, "
                f"which automatically sends execution traces to {service}. "
                "Review what inputs/outputs are captured."
            ),
            evidence=[ev],
            recommendation=(
                f"Ensure {service} API key is set via environment variable, not hardcoded. "
                "Review the traced data for PII or sensitive information."
            ),
        ))

    return findings


def query_unauthenticated_routes(graph: EffectGraph) -> list[SecurityFinding]:
    """Find route nodes with no incoming guarded_by edge from a guard(auth) node."""
    findings: list[SecurityFinding] = []

    route_nodes = graph.nodes_matching(lambda n: n.kind == "route")

    for route in route_nodes:
        incoming = graph.incoming_edges(route.id)
        has_guard = any(e.kind == "guarded_by" for e in incoming)

        if not has_guard and route.metadata.get("unguarded", True):
            method = route.metadata.get("http_method", "HTTP")
            path = route.metadata.get("path", "unknown")

            ev = Evidence(
                file=route.file,
                line=route.line,
                snippet=f"{method} {path} handler: {route.name}",
            )
            findings.append(SecurityFinding(
                category="auth",
                severity="high",
                title=f"Unauthenticated Route: {method} {path}",
                description=(
                    f"Route handler '{route.name}' ({method} {path}) has no detected authentication "
                    "dependency. If this endpoint handles sensitive data, it should require auth."
                ),
                evidence=[ev],
                recommendation=(
                    "Add an auth dependency: `Depends(OAuth2PasswordBearer(...))` or "
                    "`Depends(get_current_user)` in the route function signature. "
                    "If this is intentionally public, document it explicitly."
                ),
            ))

    return findings


def query_sql_severity_upgrade(
    graph: EffectGraph,
    existing_findings: list[SecurityFinding],
) -> list[SecurityFinding]:
    """Re-emit SQL injection findings with upgraded severity if source is user/header controlled."""
    upgraded: list[SecurityFinding] = []

    # Find source nodes with high-risk trust levels
    risky_sources = graph.nodes_matching(
        lambda n: n.kind == "source" and n.source_trust in {
            SourceTrust.USER_CONTROLLED,
            SourceTrust.HEADER_CONTROLLED,
        }
    )

    if not risky_sources:
        return []

    # Require at least one risky-source -> DB write/persistence path. This avoids
    # over-upgrading based on mere file co-location.
    risky_db_paths = graph.find_paths(
        source_pred=lambda n: n.kind == "source" and n.source_trust in {
            SourceTrust.USER_CONTROLLED, SourceTrust.HEADER_CONTROLLED,
        },
        sink_pred=lambda n: n.kind == "sink" and n.sink_kind in {SinkKind.DB_WRITE, SinkKind.LOCAL_PERSISTENCE},
        edge_kinds={"data_flows_to", "reaches"},
        max_paths=50,
    )
    if not risky_db_paths:
        return []

    risky_sink_lines_by_file: dict[str, set[int]] = {}
    for path in risky_db_paths:
        sink = path[-1]
        risky_sink_lines_by_file.setdefault(sink.file, set()).add(sink.line)

    for finding in existing_findings:
        if finding.category != "injection":
            continue
        if "sql" not in finding.title.lower() and "sql" not in finding.description.lower():
            continue
        if finding.severity == "high":
            continue  # Already high

        # Check if any evidence is in a file with risky sources
        for ev in finding.evidence:
            sink_lines = risky_sink_lines_by_file.get(ev.file, set())
            # Only upgrade when the SQL finding is near a risky-source-reachable DB sink.
            if any(abs(ev.line - sink_line) <= 40 for sink_line in sink_lines):
                upgraded_finding = finding.model_copy(deep=True)
                upgraded_finding.severity = "high"
                upgraded_finding.description = (
                    finding.description
                    + " [UPGRADED: risky-source-reachable DB sink found near this SQL construction]"
                )
                upgraded.append(upgraded_finding)
                break

    return upgraded


def query_state_overexposure(graph: EffectGraph) -> list[SecurityFinding]:
    """Find routes that return full graph state."""
    findings: list[SecurityFinding] = []

    for node in graph.nodes_matching(lambda n: n.kind == "route"):
        if node.metadata.get("state_overexposure"):
            state_var = node.metadata.get("state_var", "state")
            method = node.metadata.get("http_method", "HTTP")
            path = node.metadata.get("path", "unknown")

            ev = Evidence(
                file=node.file,
                line=node.line,
                snippet=f"{method} {path} returns {state_var}",
            )
            findings.append(SecurityFinding(
                category="data",
                severity="medium",
                title=f"State Overexposure: {method} {path}",
                description=(
                    f"Route handler '{node.name}' appears to return the full graph state variable "
                    f"'{state_var}'. This may expose internal agent state to API clients."
                ),
                evidence=[ev],
                recommendation=(
                    "Return only the fields needed by the client. "
                    "Define a response model (Pydantic) that explicitly selects output fields."
                ),
            ))

    return findings


def run_all_queries(
    graph: EffectGraph,
    existing_findings: list[SecurityFinding] | None = None,
) -> list[SecurityFinding]:
    """Run all IR queries and return deduplicated findings."""
    existing_findings = existing_findings or []
    all_findings: list[SecurityFinding] = []

    try:
        all_findings.extend(query_prompt_injection(graph))
        log.debug("Prompt injection: %d findings", len(all_findings))
    except Exception:
        log.exception("query_prompt_injection failed")

    try:
        egress = query_implicit_egress(graph)
        all_findings.extend(egress)
        log.debug("Implicit egress: %d findings", len(egress))
    except Exception:
        log.exception("query_implicit_egress failed")

    try:
        routes = query_unauthenticated_routes(graph)
        all_findings.extend(routes)
        log.debug("Unauthenticated routes: %d findings", len(routes))
    except Exception:
        log.exception("query_unauthenticated_routes failed")

    try:
        upgraded = query_sql_severity_upgrade(graph, existing_findings)
        all_findings.extend(upgraded)
        log.debug("SQL severity upgrades: %d", len(upgraded))
    except Exception:
        log.exception("query_sql_severity_upgrade failed")

    try:
        state = query_state_overexposure(graph)
        all_findings.extend(state)
        log.debug("State overexposure: %d findings", len(state))
    except Exception:
        log.exception("query_state_overexposure failed")

    # Deduplicate by (file, line, category)
    seen: set[tuple[str, int, str]] = set()
    unique: list[SecurityFinding] = []
    for f in all_findings:
        if f.evidence:
            key = (f.evidence[0].file, f.evidence[0].line, f.category)
        else:
            key = ("", 0, f.category + f.title)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return unique

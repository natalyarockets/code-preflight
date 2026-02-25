"""Tests for IR graph queries."""

from __future__ import annotations

import pytest

from la_analyzer.ir.capability_registry import Capability, SinkKind, SourceTrust
from la_analyzer.ir.graph import EffectGraph
from la_analyzer.ir.nodes import EffectEdge, EffectNode
from la_analyzer.ir.queries import (
    query_implicit_egress,
    query_prompt_injection,
    query_sql_severity_upgrade,
    query_state_overexposure,
    query_unauthenticated_routes,
    run_all_queries,
)
from la_analyzer.security.models import Evidence, SecurityFinding


def src_node(nid: str, trust: SourceTrust, file: str = "app.py", line: int = 5) -> EffectNode:
    return EffectNode(
        id=nid, kind="source", file=file, line=line,
        name=f"source_{nid}", source_trust=trust,
    )


def sink_node(nid: str, sink_kind: SinkKind, service: str = "TestLLM",
              file: str = "app.py", line: int = 20) -> EffectNode:
    return EffectNode(
        id=nid, kind="sink", file=file, line=line,
        name="invoke", sink_kind=sink_kind,
        metadata={"service": service},
    )


def route_node(nid: str, method: str = "GET", path: str = "/api", handler: str = "handler",
               file: str = "app.py", line: int = 10, unguarded: bool = True) -> EffectNode:
    return EffectNode(
        id=nid, kind="route", file=file, line=line, name=handler,
        metadata={"http_method": method, "path": path, "unguarded": unguarded},
    )


def guard_node(nid: str, file: str = "app.py", line: int = 10) -> EffectNode:
    return EffectNode(id=nid, kind="guard", file=file, line=line, name="OAuth2PasswordBearer")


class TestQueryPromptInjection:
    def test_user_source_to_llm_sink(self):
        g = EffectGraph()
        src = src_node("s1", SourceTrust.USER_CONTROLLED)
        snk = sink_node("snk1", SinkKind.LLM_PROMPT)
        g.add_node(src)
        g.add_node(snk)
        g.add_edge(EffectEdge(src="s1", dst="snk1", kind="data_flows_to",
                               file="app.py", line=5))

        findings = query_prompt_injection(g)
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert findings[0].category == "prompt_injection"

    def test_header_source_is_high_severity(self):
        g = EffectGraph()
        g.add_node(src_node("s1", SourceTrust.HEADER_CONTROLLED))
        g.add_node(sink_node("snk1", SinkKind.LLM_PROMPT))
        g.add_edge(EffectEdge(src="s1", dst="snk1", kind="data_flows_to",
                               file="app.py", line=5))

        findings = query_prompt_injection(g)
        assert len(findings) == 1
        assert findings[0].severity == "high"

    def test_external_untrusted_is_medium_severity(self):
        g = EffectGraph()
        g.add_node(src_node("s1", SourceTrust.EXTERNAL_UNTRUSTED))
        g.add_node(sink_node("snk1", SinkKind.LLM_PROMPT))
        g.add_edge(EffectEdge(src="s1", dst="snk1", kind="data_flows_to",
                               file="app.py", line=5))

        findings = query_prompt_injection(g)
        assert len(findings) == 1
        assert findings[0].severity == "medium"

    def test_no_path_no_finding(self):
        g = EffectGraph()
        g.add_node(src_node("s1", SourceTrust.USER_CONTROLLED))
        g.add_node(sink_node("snk1", SinkKind.LLM_PROMPT))
        # No edge
        findings = query_prompt_injection(g)
        assert findings == []

    def test_internal_source_no_finding(self):
        """INTERNAL trust should not trigger prompt injection."""
        g = EffectGraph()
        src = src_node("s1", SourceTrust.INTERNAL)
        snk = sink_node("snk1", SinkKind.LLM_PROMPT)
        g.add_node(src)
        g.add_node(snk)
        g.add_edge(EffectEdge(src="s1", dst="snk1", kind="data_flows_to",
                               file="app.py", line=5))
        findings = query_prompt_injection(g)
        assert findings == []

    def test_non_llm_sink_no_finding(self):
        """HTTP egress sink should not trigger prompt injection."""
        g = EffectGraph()
        g.add_node(src_node("s1", SourceTrust.USER_CONTROLLED))
        g.add_node(sink_node("snk1", SinkKind.HTTP_EGRESS))
        g.add_edge(EffectEdge(src="s1", dst="snk1", kind="data_flows_to",
                               file="app.py", line=5))
        findings = query_prompt_injection(g)
        assert findings == []


class TestQueryImplicitEgress:
    def test_sentry_init_node(self):
        g = EffectGraph()
        snk = EffectNode(
            id="sentry_init", kind="sink", file="app.py", line=5,
            name="sentry_sdk.init",
            capability=Capability.TELEMETRY_SDK,
            sink_kind=SinkKind.OBSERVABILITY,
            metadata={"service": "Sentry", "implicit_egress": True},
        )
        g.add_node(snk)

        findings = query_implicit_egress(g)
        assert len(findings) == 1
        assert findings[0].category == "egress"
        assert "Sentry" in findings[0].title

    def test_email_sink_node(self):
        g = EffectGraph()
        snk = EffectNode(
            id="smtp_send", kind="sink", file="app.py", line=10,
            name="sendmail",
            capability=Capability.MAILER,
            sink_kind=SinkKind.EMAIL_SMTP,
            metadata={"service": "SMTP (smtplib)"},
        )
        g.add_node(snk)

        findings = query_implicit_egress(g)
        assert len(findings) == 1
        assert "Email" in findings[0].title

    def test_decorator_egress(self):
        g = EffectGraph()
        dec = EffectNode(
            id="traceable_dec", kind="decorator", file="app.py", line=3,
            name="my_func",
            capability=Capability.TELEMETRY_SDK,
            sink_kind=SinkKind.OBSERVABILITY,
            metadata={"service": "LangSmith"},
        )
        g.add_node(dec)

        findings = query_implicit_egress(g)
        assert any("traceable" in f.title.lower() or "langsmith" in f.title.lower()
                   for f in findings)

    def test_no_egress_sinks_no_findings(self):
        g = EffectGraph()
        snk = sink_node("llm_snk", SinkKind.LLM_PROMPT)
        g.add_node(snk)
        findings = query_implicit_egress(g)
        assert findings == []


class TestQueryUnauthenticatedRoutes:
    def test_unguarded_route_is_finding(self):
        g = EffectGraph()
        route = route_node("r1", method="GET", path="/api/data", unguarded=True)
        g.add_node(route)

        findings = query_unauthenticated_routes(g)
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert findings[0].category == "auth"
        assert "/api/data" in findings[0].title

    def test_guarded_route_no_finding(self):
        g = EffectGraph()
        route = route_node("r1", unguarded=True)
        guard = guard_node("g1")
        g.add_node(route)
        g.add_node(guard)
        g.add_edge(EffectEdge(src="g1", dst="r1", kind="guarded_by",
                               file="app.py", line=10))

        findings = query_unauthenticated_routes(g)
        assert findings == []

    def test_multiple_routes_counts_each(self):
        g = EffectGraph()
        for i in range(3):
            g.add_node(route_node(f"r{i}", path=f"/route{i}"))

        findings = query_unauthenticated_routes(g)
        assert len(findings) == 3


class TestQuerySqlSeverityUpgrade:
    def test_upgrades_medium_sql_when_header_source(self):
        g = EffectGraph()
        g.add_node(src_node("src1", SourceTrust.HEADER_CONTROLLED,
                             file="db.py", line=5))

        existing = [SecurityFinding(
            category="injection",
            severity="medium",
            title="B608: Possible SQL injection",
            description="SQL injection in db.py",
            evidence=[Evidence(file="db.py", line=20, snippet="cursor.execute(query)")],
        )]

        upgraded = query_sql_severity_upgrade(g, existing)
        assert len(upgraded) == 1
        assert upgraded[0].severity == "high"

    def test_no_upgrade_if_already_high(self):
        g = EffectGraph()
        g.add_node(src_node("src1", SourceTrust.HEADER_CONTROLLED,
                             file="db.py", line=5))

        existing = [SecurityFinding(
            category="injection",
            severity="high",
            title="B608: Possible SQL injection",
            description="SQL",
            evidence=[Evidence(file="db.py", line=20, snippet="")],
        )]

        upgraded = query_sql_severity_upgrade(g, existing)
        assert upgraded == []

    def test_no_upgrade_if_no_risky_source(self):
        g = EffectGraph()
        g.add_node(src_node("src1", SourceTrust.INTERNAL, file="db.py", line=5))

        existing = [SecurityFinding(
            category="injection",
            severity="medium",
            title="SQL injection",
            description="SQL",
            evidence=[Evidence(file="db.py", line=20, snippet="")],
        )]

        upgraded = query_sql_severity_upgrade(g, existing)
        assert upgraded == []

    def test_non_sql_not_upgraded(self):
        g = EffectGraph()
        g.add_node(src_node("src1", SourceTrust.HEADER_CONTROLLED, file="app.py", line=5))

        existing = [SecurityFinding(
            category="injection",
            severity="medium",
            title="Shell injection",
            description="Command injection",
            evidence=[Evidence(file="app.py", line=20, snippet="")],
        )]

        upgraded = query_sql_severity_upgrade(g, existing)
        assert upgraded == []


class TestQueryStateOverexposure:
    def test_state_overexposure_finding(self):
        g = EffectGraph()
        route = route_node("r1", method="GET", path="/state")
        route.metadata["state_overexposure"] = True
        route.metadata["state_var"] = "state"
        g.add_node(route)

        findings = query_state_overexposure(g)
        assert len(findings) == 1
        assert findings[0].category == "data"
        assert findings[0].severity == "medium"

    def test_no_overexposure_no_finding(self):
        g = EffectGraph()
        route = route_node("r1")
        g.add_node(route)

        findings = query_state_overexposure(g)
        assert findings == []


class TestRunAllQueries:
    def test_runs_without_error_on_empty_graph(self):
        g = EffectGraph()
        findings = run_all_queries(g)
        assert findings == []

    def test_deduplicates_by_file_line_category(self):
        g = EffectGraph()
        src = src_node("s1", SourceTrust.USER_CONTROLLED, file="a.py", line=1)
        snk = sink_node("snk1", SinkKind.LLM_PROMPT, file="a.py", line=10)
        g.add_node(src)
        g.add_node(snk)
        g.add_edge(EffectEdge(src="s1", dst="snk1", kind="data_flows_to",
                               file="a.py", line=5))

        findings = run_all_queries(g)
        # Should not have duplicate findings for the same (file, line, category)
        keys = [(f.evidence[0].file if f.evidence else "", f.category) for f in findings]
        assert len(keys) == len(set(keys))

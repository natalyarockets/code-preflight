"""Tests for the Python frontend (abstract interpreter + IR emitter)."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from la_analyzer.ir.capability_registry import Capability, SinkKind, SourceTrust
from la_analyzer.ir.graph import EffectGraph
from la_analyzer.ir.python_frontend import analyze_file
from la_analyzer.ir.queries import query_prompt_injection


def make_py_file(tmp_path: Path, name: str, code: str) -> Path:
    """Write Python code to a temp file and return the path."""
    f = tmp_path / name
    f.write_text(textwrap.dedent(code))
    return f


class TestConstructorCapabilityPropagation:
    def test_chat_openai_emits_llm_client_var(self, tmp_path):
        f = make_py_file(tmp_path, "llm.py", """
            from langchain_openai import ChatOpenAI

            llm = ChatOpenAI(model="gpt-4o")
        """)
        g = EffectGraph()
        caps = analyze_file(f, tmp_path, g)
        assert caps.get("llm") == Capability.LLM_CLIENT

    def test_alias_propagation(self, tmp_path):
        f = make_py_file(tmp_path, "llm.py", """
            from langchain_openai import ChatOpenAI

            base_llm = ChatOpenAI()
            my_llm = base_llm
        """)
        g = EffectGraph()
        caps = analyze_file(f, tmp_path, g)
        # Both base_llm and my_llm should inherit LLM_CLIENT
        assert caps.get("base_llm") == Capability.LLM_CLIENT
        assert caps.get("my_llm") == Capability.LLM_CLIENT

    def test_state_graph_is_graph_runtime(self, tmp_path):
        f = make_py_file(tmp_path, "graph.py", """
            from langgraph.graph import StateGraph

            graph = StateGraph(state_schema=dict)
        """)
        g = EffectGraph()
        caps = analyze_file(f, tmp_path, g)
        assert caps.get("graph") == Capability.GRAPH_RUNTIME


class TestSinkDetection:
    def test_llm_invoke_emits_sink(self, tmp_path):
        f = make_py_file(tmp_path, "llm.py", """
            from langchain_openai import ChatOpenAI

            llm = ChatOpenAI()

            def run(prompt):
                return llm.invoke(prompt)
        """)
        g = EffectGraph()
        analyze_file(f, tmp_path, g)
        sinks = [n for n in g.all_nodes() if n.kind == "sink" and n.sink_kind == SinkKind.LLM_PROMPT]
        assert len(sinks) >= 1

    def test_graph_runtime_ainvoke_no_llm_sink(self, tmp_path):
        """graph_app.ainvoke(state) should NOT produce an LLM sink."""
        f = make_py_file(tmp_path, "app.py", """
            from langgraph.graph import StateGraph

            graph = StateGraph(dict)
            graph_app = graph.compile()

            async def run(state):
                return await graph_app.ainvoke(state)
        """)
        g = EffectGraph()
        analyze_file(f, tmp_path, g)
        llm_sinks = [n for n in g.all_nodes()
                     if n.kind == "sink" and n.sink_kind == SinkKind.LLM_PROMPT]
        assert len(llm_sinks) == 0


class TestDecoratorDetection:
    def test_traceable_decorator_emits_observability_sink(self, tmp_path):
        f = make_py_file(tmp_path, "tracing.py", """
            from langsmith import traceable

            @traceable
            def my_func(x):
                return x
        """)
        g = EffectGraph()
        analyze_file(f, tmp_path, g)
        dec_nodes = [n for n in g.all_nodes()
                     if n.kind == "decorator" and n.sink_kind == SinkKind.OBSERVABILITY]
        assert len(dec_nodes) >= 1
        assert dec_nodes[0].name == "my_func"


class TestSourceDetection:
    def test_request_headers_get_is_header_controlled(self, tmp_path):
        f = make_py_file(tmp_path, "api.py", """
            from fastapi import Request

            async def handler(request: Request):
                org = request.headers.get("X-User-Org")
                return org
        """)
        g = EffectGraph()
        analyze_file(f, tmp_path, g)
        src_nodes = [n for n in g.all_nodes()
                     if n.kind == "source"
                     and n.source_trust == SourceTrust.HEADER_CONTROLLED]
        assert len(src_nodes) >= 1

    def test_os_getenv_is_operator_controlled(self, tmp_path):
        f = make_py_file(tmp_path, "config.py", """
            import os

            API_KEY = os.getenv("API_KEY", "default")
        """)
        g = EffectGraph()
        analyze_file(f, tmp_path, g)
        src_nodes = [n for n in g.all_nodes()
                     if n.kind == "source"
                     and n.source_trust == SourceTrust.OPERATOR_CONTROLLED]
        assert len(src_nodes) >= 1


class TestModuleLevelCall:
    def test_sentry_sdk_init_emits_observability_sink(self, tmp_path):
        f = make_py_file(tmp_path, "setup.py", """
            import sentry_sdk

            sentry_sdk.init(
                dsn="https://key@sentry.io/123",
                traces_sample_rate=1.0,
            )
        """)
        g = EffectGraph()
        analyze_file(f, tmp_path, g)
        obs_sinks = [n for n in g.all_nodes()
                     if n.kind == "sink" and n.sink_kind == SinkKind.OBSERVABILITY]
        assert len(obs_sinks) >= 1


class TestLambdaUnwrapping:
    def test_retry_wrapper_detects_llm_sink(self, tmp_path):
        f = make_py_file(tmp_path, "retry.py", """
            from langchain_openai import ChatOpenAI

            llm = ChatOpenAI()

            def retry_with_backoff(fn):
                return fn()

            def run(prompt):
                return retry_with_backoff(lambda: llm.invoke(prompt))
        """)
        g = EffectGraph()
        analyze_file(f, tmp_path, g)
        llm_sinks = [n for n in g.all_nodes()
                     if n.kind == "sink" and n.sink_kind == SinkKind.LLM_PROMPT]
        assert len(llm_sinks) >= 1

    def test_with_smtp_context_manager_detects_email_sink(self, tmp_path):
        f = make_py_file(tmp_path, "mail.py", """
            import smtplib

            def send(msg):
                with smtplib.SMTP("smtp.example.com", 587) as server:
                    server.send_message(msg)
        """)
        g = EffectGraph()
        analyze_file(f, tmp_path, g)
        email_sinks = [n for n in g.all_nodes()
                       if n.kind == "sink" and n.sink_kind == SinkKind.EMAIL_SMTP]
        assert len(email_sinks) >= 1


class TestTaintThroughFString:
    def test_tainted_var_tracked_through_fstring(self, tmp_path):
        f = make_py_file(tmp_path, "inject.py", """
            import os
            from fastapi import Request
            from langchain_openai import ChatOpenAI

            llm = ChatOpenAI()

            async def handle(request: Request):
                org = request.headers.get("X-User-Org")
                query = f"SELECT * FROM users WHERE org='{org}'"
                return llm.invoke(query)
        """)
        g = EffectGraph()
        analyze_file(f, tmp_path, g)
        # Should have a HEADER_CONTROLLED source node
        src_nodes = [n for n in g.all_nodes()
                     if n.kind == "source"
                     and n.source_trust == SourceTrust.HEADER_CONTROLLED]
        assert len(src_nodes) >= 1
        # Should have an LLM sink
        sinks = [n for n in g.all_nodes()
                 if n.kind == "sink" and n.sink_kind == SinkKind.LLM_PROMPT]
        assert len(sinks) >= 1


class TestStateCapability:
    def test_async_sqlite_saver_is_state_store(self, tmp_path):
        f = make_py_file(tmp_path, "db.py", """
            from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver

            saver = AsyncSqliteSaver.from_conn_string("sqlite:///state.db")
        """)
        g = EffectGraph()
        caps = analyze_file(f, tmp_path, g)
        assert caps.get("saver") == Capability.STATE_STORE
        store_nodes = [n for n in g.all_nodes() if n.kind == "store"]
        assert len(store_nodes) >= 1

    def test_langgraph_state_get_can_reach_prompt_sink(self, tmp_path):
        f = make_py_file(tmp_path, "graph_node.py", """
            from langchain_openai import ChatOpenAI

            llm = ChatOpenAI()

            def node_fn(state):
                user_issue = state.get("user_issue")
                prompt = f"Issue: {user_issue}"
                return llm.invoke(prompt)
        """)
        g = EffectGraph()
        analyze_file(f, tmp_path, g)
        findings = query_prompt_injection(g)
        assert any(f.category == "prompt_injection" for f in findings)


class TestFastAPIRouteDetection:
    def test_unauthenticated_route_detected(self, tmp_path):
        f = make_py_file(tmp_path, "routes.py", """
            from fastapi import FastAPI

            app = FastAPI()

            @app.get("/public")
            async def public_handler():
                return {"msg": "hello"}
        """)
        g = EffectGraph()
        analyze_file(f, tmp_path, g)
        routes = [n for n in g.all_nodes() if n.kind == "route"]
        assert len(routes) >= 1
        assert routes[0].metadata.get("unguarded", True) is True

    def test_authenticated_route_has_guard(self, tmp_path):
        f = make_py_file(tmp_path, "routes.py", """
            from fastapi import FastAPI, Depends
            from fastapi.security import OAuth2PasswordBearer

            app = FastAPI()
            oauth2 = OAuth2PasswordBearer(tokenUrl="token")

            @app.get("/secure")
            async def secure_handler(token: str = Depends(oauth2)):
                return {"msg": "secure"}
        """)
        g = EffectGraph()
        analyze_file(f, tmp_path, g)
        routes = [n for n in g.all_nodes() if n.kind == "route"]
        guards = [n for n in g.all_nodes() if n.kind == "guard"]
        guard_edges = [e for e in g.all_edges() if e.kind == "guarded_by"]
        assert len(routes) >= 1
        assert len(guards) >= 1
        assert len(guard_edges) >= 1

    def test_non_auth_depends_does_not_count_as_auth_guard(self, tmp_path):
        f = make_py_file(tmp_path, "routes.py", """
            from fastapi import FastAPI, Depends

            app = FastAPI()

            def get_db():
                return object()

            @app.get("/items")
            async def items(db = Depends(get_db)):
                return {"ok": True}
        """)
        g = EffectGraph()
        analyze_file(f, tmp_path, g)
        routes = [n for n in g.all_nodes() if n.kind == "route"]
        assert len(routes) == 1
        assert routes[0].metadata.get("unguarded", True) is True

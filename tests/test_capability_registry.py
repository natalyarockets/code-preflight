"""Tests for the capability registry."""

from __future__ import annotations

import pytest

from la_analyzer.ir.capability_registry import (
    CAPABILITY_REGISTRY,
    Capability,
    CapabilityEntry,
    SinkKind,
    SourceTrust,
    get_all_constructor_names,
    lookup_by_constructor,
    lookup_by_module,
)


class TestLookupByConstructor:
    def test_chat_openai(self):
        entry = lookup_by_constructor("ChatOpenAI")
        assert entry is not None
        assert entry.capability == Capability.LLM_CLIENT
        assert entry.service_name == "OpenAI (LangChain)"
        assert "invoke" in entry.sink_methods
        assert "ainvoke" in entry.sink_methods
        assert entry.sink_kind == SinkKind.LLM_PROMPT

    def test_chat_anthropic(self):
        entry = lookup_by_constructor("ChatAnthropic")
        assert entry is not None
        assert entry.capability == Capability.LLM_CLIENT

    def test_openai_direct(self):
        entry = lookup_by_constructor("OpenAI")
        assert entry is not None
        assert entry.capability == Capability.LLM_CLIENT
        assert "create" in entry.sink_methods

    def test_unknown_returns_none(self):
        assert lookup_by_constructor("SomeUnknownClass") is None

    def test_smtp(self):
        entry = lookup_by_constructor("SMTP")
        assert entry is not None
        assert entry.capability == Capability.MAILER
        assert entry.sink_kind == SinkKind.EMAIL_SMTP
        assert "sendmail" in entry.sink_methods


class TestGraphRuntime:
    def test_compiled_state_graph_has_no_sink_methods(self):
        entry = lookup_by_constructor("CompiledStateGraph")
        assert entry is not None
        assert entry.capability == Capability.GRAPH_RUNTIME
        # ainvoke should NOT be a sink method for graph runtime
        assert "ainvoke" not in entry.sink_methods
        assert "invoke" not in entry.sink_methods

    def test_state_graph_has_no_sink_methods(self):
        entry = lookup_by_constructor("StateGraph")
        assert entry is not None
        assert entry.capability == Capability.GRAPH_RUNTIME
        assert len(entry.sink_methods) == 0


class TestLookupByModule:
    def test_sentry_sdk(self):
        entry = lookup_by_module("sentry_sdk")
        assert entry is not None
        assert entry.capability == Capability.TELEMETRY_SDK
        assert entry.service_name == "Sentry"
        assert entry.implicit_egress_on_init is True
        assert entry.sink_kind == SinkKind.OBSERVABILITY
        assert "init" in entry.sink_methods

    def test_langsmith(self):
        entry = lookup_by_module("langsmith")
        assert entry is not None
        assert entry.capability == Capability.TELEMETRY_SDK
        assert entry.decorator_sink == SinkKind.OBSERVABILITY

    def test_unknown_module(self):
        assert lookup_by_module("nonexistent_lib") is None


class TestStateStore:
    def test_async_sqlite_saver(self):
        entry = lookup_by_constructor("AsyncSqliteSaver")
        assert entry is not None
        assert entry.capability == Capability.STATE_STORE
        assert entry.sink_kind == SinkKind.LOCAL_PERSISTENCE
        assert "from_conn_string" in entry.sink_methods


class TestEmbeddingClient:
    def test_openai_embeddings(self):
        entry = lookup_by_constructor("OpenAIEmbeddings")
        assert entry is not None
        assert entry.capability == Capability.EMBEDDING_CLIENT
        assert "embed_query" in entry.sink_methods


class TestGetAllConstructorNames:
    def test_returns_frozenset(self):
        names = get_all_constructor_names()
        assert isinstance(names, frozenset)
        assert "ChatOpenAI" in names
        assert "SMTP" in names
        assert "sentry_sdk" in names

    def test_adding_new_entry(self):
        """Verify that adding a new entry is possible without code changes."""
        new_entry = CapabilityEntry(
            capability=Capability.LLM_CLIENT,
            service_name="TestLLM",
            sink_methods=frozenset({"predict"}),
            sink_kind=SinkKind.LLM_PROMPT,
        )
        # Can be added to registry
        CAPABILITY_REGISTRY["TestLLMClient"] = new_entry
        assert lookup_by_constructor("TestLLMClient") is not None
        # Cleanup
        del CAPABILITY_REGISTRY["TestLLMClient"]

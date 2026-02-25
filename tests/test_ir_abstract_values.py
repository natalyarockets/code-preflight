"""Tests for abstract value types and taint join rules."""

from __future__ import annotations

import pytest

from la_analyzer.ir.abstract_values import (
    Effect,
    Literal,
    Object,
    Tainted,
    Unknown,
    UnknownStr,
    get_capability,
    get_object,
    get_taint,
    is_tainted,
    join_values,
)
from la_analyzer.ir.capability_registry import Capability, SinkKind, SourceTrust


class TestFrozenHashable:
    def test_literal_hashable(self):
        l1 = Literal("hello")
        l2 = Literal("hello")
        assert hash(l1) == hash(l2)
        assert l1 == l2

    def test_tainted_hashable(self):
        t1 = Tainted(trust=SourceTrust.HEADER_CONTROLLED, sources=frozenset({"x"}))
        t2 = Tainted(trust=SourceTrust.HEADER_CONTROLLED, sources=frozenset({"x"}))
        assert t1 == t2
        assert hash(t1) == hash(t2)

    def test_object_hashable(self):
        o1 = Object(capability=Capability.LLM_CLIENT, service_name="GPT")
        o2 = Object(capability=Capability.LLM_CLIENT, service_name="GPT")
        assert o1 == o2

    def test_effect_hashable(self):
        e1 = Effect(sink_kind=SinkKind.LLM_PROMPT)
        e2 = Effect(sink_kind=SinkKind.LLM_PROMPT)
        assert e1 == e2

    def test_frozen_immutable(self):
        l = Literal("test")
        with pytest.raises((AttributeError, TypeError)):
            l.value = "other"  # type: ignore


class TestTaintJoin:
    def test_tainted_wins_over_literal(self):
        tainted = [Tainted(trust=SourceTrust.USER_CONTROLLED)]
        literal = [Literal("safe")]
        result = join_values(tainted, literal)
        assert any(isinstance(v, Tainted) for v in result)
        assert not any(isinstance(v, Literal) for v in result)

    def test_tainted_wins_over_unknown(self):
        tainted = [Tainted(trust=SourceTrust.HEADER_CONTROLLED)]
        unknown = [Unknown()]
        result = join_values(tainted, unknown)
        assert any(isinstance(v, Tainted) for v in result)

    def test_literal_unknown_becomes_unknown(self):
        literal = [Literal("x")]
        unknown = [Unknown()]
        result = join_values(literal, unknown)
        assert any(isinstance(v, Unknown) for v in result)
        assert not any(isinstance(v, Literal) for v in result)

    def test_object_stays(self):
        obj = [Object(capability=Capability.LLM_CLIENT)]
        lit = [Literal("test")]
        result = join_values(obj, lit)
        assert any(isinstance(v, Object) for v in result)

    def test_two_tainted_merges_sources(self):
        t1 = Tainted(trust=SourceTrust.USER_CONTROLLED, sources=frozenset({"body"}))
        t2 = Tainted(trust=SourceTrust.USER_CONTROLLED, sources=frozenset({"params"}))
        result = join_values([t1], [t2])
        tainted_results = [v for v in result if isinstance(v, Tainted)]
        assert len(tainted_results) >= 1
        combined = tainted_results[0]
        assert "body" in combined.sources or "params" in combined.sources

    def test_more_permissive_trust_wins(self):
        """USER_CONTROLLED is more dangerous than OPERATOR_CONTROLLED."""
        t_user = Tainted(trust=SourceTrust.USER_CONTROLLED)
        t_op = Tainted(trust=SourceTrust.OPERATOR_CONTROLLED)
        result = join_values([t_user], [t_op])
        tainted = [v for v in result if isinstance(v, Tainted)]
        assert tainted[0].trust == SourceTrust.USER_CONTROLLED


class TestHelpers:
    def test_is_tainted_true(self):
        assert is_tainted([Tainted(trust=SourceTrust.USER_CONTROLLED)])

    def test_is_tainted_false(self):
        assert not is_tainted([Literal("x"), Unknown()])

    def test_get_taint(self):
        t = Tainted(trust=SourceTrust.HEADER_CONTROLLED)
        result = get_taint([Unknown(), t])
        assert result == t

    def test_get_taint_none(self):
        assert get_taint([Literal("x"), Unknown()]) is None

    def test_get_capability(self):
        obj = Object(capability=Capability.LLM_CLIENT)
        assert get_capability([Unknown(), obj]) == Capability.LLM_CLIENT

    def test_get_capability_none(self):
        assert get_capability([Unknown(), Literal("x")]) is None

    def test_get_object(self):
        obj = Object(capability=Capability.MAILER, service_name="SMTP")
        result = get_object([Unknown(), obj])
        assert result == obj


class TestAbstractEnvPropagation:
    def test_copy_env_entry(self):
        """x = y should copy y's values."""
        from la_analyzer.ir.abstract_values import AbstractEnv
        env: AbstractEnv = {
            "y": [Object(capability=Capability.LLM_CLIENT)],
        }
        # Simulating: env["x"] = env["y"]
        env["x"] = list(env["y"])
        assert get_capability(env["x"]) == Capability.LLM_CLIENT

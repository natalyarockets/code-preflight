"""Abstract value types for bounded static interpretation.

The Python frontend uses these to track what variables might hold at a
given point in the code, without actually executing it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Union

from la_analyzer.ir.capability_registry import Capability, SinkKind, SourceTrust


@dataclass(frozen=True)
class Literal:
    """A known constant value."""
    value: object  # str, bool, int, None — known constant


@dataclass(frozen=True)
class UnknownStr:
    """An unknown string value that is not tainted."""
    pass


@dataclass(frozen=True)
class Tainted:
    """A value that comes from a user-controlled or external source."""
    trust: SourceTrust
    sources: frozenset[str] = field(default_factory=frozenset)  # "request.headers", etc.


@dataclass(frozen=True)
class Object:
    """A value with a known object capability (e.g. LLM client instance)."""
    capability: Capability
    service_name: str = ""


@dataclass(frozen=True)
class Effect:
    """A callable that, when called, produces a side effect."""
    sink_kind: SinkKind
    conditional: bool = False      # guarded by env check or try/except
    condition_hint: str = ""       # e.g. "EMAIL_ENV == 'prod'"


@dataclass(frozen=True)
class Unknown:
    """Undetermined value."""
    pass


AbstractValue = Union[Literal, UnknownStr, Tainted, Object, Effect, Unknown]
AbstractEnv = dict[str, list[AbstractValue]]  # var name → possible values


# ── Taint join rule ───────────────────────────────────────────────────────

def join_values(values_a: list[AbstractValue], values_b: list[AbstractValue]) -> list[AbstractValue]:
    """Merge two abstract value lists (for phi nodes / if/else branches).

    Rules:
    - If any side is Tainted → result is Tainted (highest trust wins by most permissive)
    - Object stays Object unless overwritten
    - Literal + Unknown → Unknown
    - Deduplicates results
    """
    merged: list[AbstractValue] = []
    seen: set = set()

    all_vals = values_a + values_b

    # Find any tainted values — they dominate
    tainted_vals = [v for v in all_vals if isinstance(v, Tainted)]
    if tainted_vals:
        # Merge tainted sources; pick least-trusted (most permissive)
        trust_order = [
            SourceTrust.USER_CONTROLLED,
            SourceTrust.HEADER_CONTROLLED,
            SourceTrust.EXTERNAL_UNTRUSTED,
            SourceTrust.DB_RESULT,
            SourceTrust.OPERATOR_CONTROLLED,
            SourceTrust.INTERNAL,
        ]
        best_trust = min(
            (v.trust for v in tainted_vals),
            key=lambda t: trust_order.index(t) if t in trust_order else 99,
        )
        combined_sources: frozenset[str] = frozenset()
        for v in tainted_vals:
            combined_sources = combined_sources | v.sources
        merged_tainted = Tainted(trust=best_trust, sources=combined_sources)
        if merged_tainted not in seen:
            seen.add(merged_tainted)
            merged.append(merged_tainted)

    # Add Object values (capabilities persist)
    for v in all_vals:
        if isinstance(v, Object) and v not in seen:
            seen.add(v)
            merged.append(v)

    # Add Literal values only if no taint and no Unknown
    has_unknown = any(isinstance(v, Unknown) for v in all_vals)
    if not tainted_vals and not has_unknown:
        for v in all_vals:
            if isinstance(v, Literal) and v not in seen:
                seen.add(v)
                merged.append(v)

    # If nothing specific emerged, Unknown
    if not merged:
        merged.append(Unknown())

    return merged


def is_tainted(values: list[AbstractValue]) -> bool:
    """Return True if any value in the list is Tainted."""
    return any(isinstance(v, Tainted) for v in values)


def get_taint(values: list[AbstractValue]) -> Tainted | None:
    """Return the first Tainted value if any."""
    for v in values:
        if isinstance(v, Tainted):
            return v
    return None


def get_capability(values: list[AbstractValue]) -> Capability | None:
    """Return the Object capability if any value is an Object."""
    for v in values:
        if isinstance(v, Object):
            return v.capability
    return None


def get_object(values: list[AbstractValue]) -> Object | None:
    """Return the first Object value if any."""
    for v in values:
        if isinstance(v, Object):
            return v
    return None


# ── Factory summaries (interprocedural-lite) ─────────────────────────────

# Maps function names (exact match or ends-with) to AbstractValue
# Used when we see x = some_factory_func() to infer the return type
FACTORY_SUMMARIES: dict[str, AbstractValue] = {
    # Common LangGraph/LangChain factory patterns
    "get_llm": Object(capability=Capability.LLM_CLIENT, service_name="llm"),
    "get_llm_for_node": Object(capability=Capability.LLM_CLIENT, service_name="llm"),
    "create_llm": Object(capability=Capability.LLM_CLIENT, service_name="llm"),
    "build_llm": Object(capability=Capability.LLM_CLIENT, service_name="llm"),
    "load_llm": Object(capability=Capability.LLM_CLIENT, service_name="llm"),
    "get_model": Object(capability=Capability.LLM_CLIENT, service_name="llm"),
    "create_model": Object(capability=Capability.LLM_CLIENT, service_name="llm"),
}

# Wrapper functions that pass through effects from their callable arguments
WRAPPER_FUNCS: frozenset[str] = frozenset({
    "retry_with_backoff",
    "with_retry",
    "asyncio.run",
    "asyncio.gather",
    "run_in_executor",
    "loop.run_until_complete",
    "functools.partial",
    "retry",
    "backoff",
    "tenacity",
    "run_sync",
    "run_async",
})

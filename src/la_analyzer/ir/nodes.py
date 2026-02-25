"""EffectNode and EffectEdge dataclasses — pure data, no logic."""

from __future__ import annotations

from dataclasses import dataclass, field

from la_analyzer.ir.capability_registry import Capability, SinkKind, SourceTrust


@dataclass
class EffectNode:
    id: str                              # "file.py::line::kind::name"
    kind: str                            # "function"|"var"|"call"|"source"|"sink"|
                                         # "store"|"guard"|"route"|"decorator"
    file: str
    line: int
    name: str
    capability: Capability | None = None    # for "var" nodes
    source_trust: SourceTrust | None = None # for "source" nodes
    sink_kind: SinkKind | None = None       # for "sink" nodes
    confidence: float = 1.0
    metadata: dict = field(default_factory=dict)  # extra context


@dataclass
class EffectEdge:
    src: str   # EffectNode.id
    dst: str   # EffectNode.id
    kind: str  # "calls"|"data_flows_to"|"constructs"|"wraps"|"guarded_by"|"reaches"
    file: str
    line: int
    confidence: float = 1.0

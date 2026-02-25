"""Tests for EffectGraph — node/edge management and BFS path finding."""

from __future__ import annotations

import pytest

from la_analyzer.ir.capability_registry import Capability, SinkKind, SourceTrust
from la_analyzer.ir.graph import EffectGraph
from la_analyzer.ir.nodes import EffectEdge, EffectNode


def make_source(nid: str, file: str = "f.py", line: int = 1) -> EffectNode:
    return EffectNode(
        id=nid, kind="source", file=file, line=line, name=nid,
        source_trust=SourceTrust.USER_CONTROLLED,
    )


def make_sink(nid: str, file: str = "f.py", line: int = 10) -> EffectNode:
    return EffectNode(
        id=nid, kind="sink", file=file, line=line, name=nid,
        sink_kind=SinkKind.LLM_PROMPT,
    )


def make_mid(nid: str, file: str = "f.py", line: int = 5) -> EffectNode:
    return EffectNode(id=nid, kind="var", file=file, line=line, name=nid)


def edge(src: str, dst: str, kind: str = "data_flows_to") -> EffectEdge:
    return EffectEdge(src=src, dst=dst, kind=kind, file="f.py", line=1)


class TestAddNodeEdge:
    def test_add_node(self):
        g = EffectGraph()
        n = make_source("s1")
        g.add_node(n)
        assert g.get_node("s1") is n

    def test_add_edge_creates_adjacency(self):
        g = EffectGraph()
        g.add_node(make_source("a"))
        g.add_node(make_mid("b"))
        g.add_edge(edge("a", "b"))
        assert len(g.outgoing_edges("a")) == 1
        assert len(g.incoming_edges("b")) == 1

    def test_add_node_idempotent_by_id(self):
        g = EffectGraph()
        n1 = make_source("s1")
        n2 = make_source("s1")
        n2.metadata["extra"] = True
        g.add_node(n1)
        g.add_node(n2)  # second write wins
        assert g.get_node("s1").metadata.get("extra") is True

    def test_len(self):
        g = EffectGraph()
        g.add_node(make_source("a"))
        g.add_node(make_mid("b"))
        assert len(g) == 2


class TestFindPaths:
    def test_direct_path(self):
        g = EffectGraph()
        g.add_node(make_source("src"))
        g.add_node(make_sink("snk"))
        g.add_edge(edge("src", "snk"))

        paths = g.find_paths(
            lambda n: n.kind == "source",
            lambda n: n.kind == "sink",
        )
        assert len(paths) == 1
        assert [n.id for n in paths[0]] == ["src", "snk"]

    def test_two_hop_path(self):
        g = EffectGraph()
        g.add_node(make_source("src"))
        g.add_node(make_mid("mid"))
        g.add_node(make_sink("snk"))
        g.add_edge(edge("src", "mid"))
        g.add_edge(edge("mid", "snk"))

        paths = g.find_paths(
            lambda n: n.kind == "source",
            lambda n: n.kind == "sink",
        )
        assert len(paths) == 1
        assert len(paths[0]) == 3

    def test_three_hop_path(self):
        g = EffectGraph()
        g.add_node(make_source("s"))
        g.add_node(make_mid("m1"))
        g.add_node(make_mid("m2"))
        g.add_node(make_sink("snk"))
        g.add_edge(edge("s", "m1"))
        g.add_edge(edge("m1", "m2"))
        g.add_edge(edge("m2", "snk"))

        paths = g.find_paths(
            lambda n: n.kind == "source",
            lambda n: n.kind == "sink",
        )
        assert len(paths) == 1
        assert len(paths[0]) == 4

    def test_no_path(self):
        g = EffectGraph()
        g.add_node(make_source("src"))
        g.add_node(make_sink("snk"))
        # No edge
        paths = g.find_paths(
            lambda n: n.kind == "source",
            lambda n: n.kind == "sink",
        )
        assert paths == []

    def test_cycle_prevention(self):
        """BFS should not loop indefinitely when there's a cycle."""
        g = EffectGraph()
        g.add_node(make_source("s"))
        g.add_node(make_mid("a"))
        g.add_node(make_mid("b"))
        g.add_node(make_sink("snk"))
        g.add_edge(edge("s", "a"))
        g.add_edge(edge("a", "b"))
        g.add_edge(edge("b", "a"))  # cycle
        g.add_edge(edge("b", "snk"))

        paths = g.find_paths(
            lambda n: n.kind == "source",
            lambda n: n.kind == "sink",
        )
        assert len(paths) >= 1  # should still find the path

    def test_max_paths_limit(self):
        """Returns at most max_paths paths."""
        g = EffectGraph()
        g.add_node(make_source("s"))
        for i in range(10):
            snk = make_sink(f"snk{i}")
            g.add_node(snk)
            g.add_edge(edge("s", f"snk{i}"))

        paths = g.find_paths(
            lambda n: n.kind == "source",
            lambda n: n.kind == "sink",
            max_paths=3,
        )
        assert len(paths) <= 3

    def test_edge_kind_filter(self):
        """Only follows edges of specified kinds."""
        g = EffectGraph()
        g.add_node(make_source("s"))
        g.add_node(make_sink("snk"))
        g.add_edge(EffectEdge(src="s", dst="snk", kind="calls", file="f.py", line=1))

        paths = g.find_paths(
            lambda n: n.kind == "source",
            lambda n: n.kind == "sink",
            edge_kinds={"data_flows_to"},  # different kind
        )
        assert paths == []


class TestNodesMatching:
    def test_filter_by_kind(self):
        g = EffectGraph()
        g.add_node(make_source("s1"))
        g.add_node(make_source("s2"))
        g.add_node(make_sink("snk"))
        sources = g.nodes_matching(lambda n: n.kind == "source")
        assert len(sources) == 2


class TestSourcesReaching:
    def test_backward_bfs(self):
        g = EffectGraph()
        g.add_node(make_source("src"))
        g.add_node(make_mid("mid"))
        g.add_node(make_sink("snk"))
        g.add_edge(edge("src", "mid"))
        g.add_edge(edge("mid", "snk"))

        sources = g.sources_reaching("snk")
        assert any(n.id == "src" for n in sources)

"""EffectGraph: nodes, edges, BFS worklist path finding."""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Callable

from la_analyzer.ir.nodes import EffectEdge, EffectNode
from la_analyzer.ir.capability_registry import Capability, SinkKind, SourceTrust


class EffectGraph:
    """Typed effect graph with BFS worklist path finding."""

    def __init__(self) -> None:
        self._nodes: dict[str, EffectNode] = {}
        self._edges: list[EffectEdge] = []
        # Forward adjacency: src_id → list[EffectEdge]
        self._fwd: dict[str, list[EffectEdge]] = defaultdict(list)
        # Backward adjacency: dst_id → list[EffectEdge]
        self._bwd: dict[str, list[EffectEdge]] = defaultdict(list)

    def add_node(self, node: EffectNode) -> None:
        """Add a node (idempotent by id — later add wins on conflict)."""
        self._nodes[node.id] = node

    def add_edge(self, edge: EffectEdge) -> None:
        """Add a directed edge (duplicate edges are allowed)."""
        self._edges.append(edge)
        self._fwd[edge.src].append(edge)
        self._bwd[edge.dst].append(edge)

    def get_node(self, node_id: str) -> EffectNode | None:
        return self._nodes.get(node_id)

    def nodes_matching(self, pred: Callable[[EffectNode], bool]) -> list[EffectNode]:
        """Return all nodes matching the predicate."""
        return [n for n in self._nodes.values() if pred(n)]

    def find_paths(
        self,
        source_pred: Callable[[EffectNode], bool],
        sink_pred: Callable[[EffectNode], bool],
        edge_kinds: set[str] | None = None,
        max_paths: int = 20,
    ) -> list[list[EffectNode]]:
        """BFS from all source nodes to all sink nodes.

        Uses a visited-node dedup set per path to prevent cycles.
        Returns up to max_paths paths, each as a list of EffectNode.
        """
        sources = self.nodes_matching(source_pred)
        if not sources:
            return []

        results: list[list[EffectNode]] = []

        for start in sources:
            # BFS: each queue item is the path taken so far
            queue: deque[list[str]] = deque()
            queue.append([start.id])
            # visited set prevents revisiting the same node in the same path
            # but we allow the same node in different paths

            while queue and len(results) < max_paths:
                path_ids = queue.popleft()
                current_id = path_ids[-1]
                current_node = self._nodes.get(current_id)
                if current_node is None:
                    continue

                # Check if current node is a sink
                if current_node is not start and sink_pred(current_node):
                    path_nodes = [self._nodes[nid] for nid in path_ids
                                  if nid in self._nodes]
                    results.append(path_nodes)
                    if len(results) >= max_paths:
                        break
                    continue  # Don't explore further from a sink

                # Expand via outgoing edges
                visited_in_path = set(path_ids)
                for edge in self._fwd.get(current_id, []):
                    if edge_kinds and edge.kind not in edge_kinds:
                        continue
                    if edge.dst in visited_in_path:
                        continue  # Cycle prevention
                    if len(path_ids) > 15:
                        continue  # Max path depth
                    new_path = path_ids + [edge.dst]
                    queue.append(new_path)

        return results

    def sources_reaching(self, sink_id: str, edge_kinds: set[str] | None = None) -> list[EffectNode]:
        """BFS backwards from a sink to find all source nodes that can reach it."""
        visited: set[str] = set()
        queue: deque[str] = deque([sink_id])
        source_nodes: list[EffectNode] = []

        while queue:
            current = queue.popleft()
            if current in visited:
                continue
            visited.add(current)

            node = self._nodes.get(current)
            if node and node.kind == "source" and current != sink_id:
                source_nodes.append(node)

            for edge in self._bwd.get(current, []):
                if edge_kinds and edge.kind not in edge_kinds:
                    continue
                if edge.src not in visited:
                    queue.append(edge.src)

        return source_nodes

    def capabilities_of(self, node_id: str) -> set[Capability]:
        """Return the set of capabilities for a node (from var-type nodes)."""
        node = self._nodes.get(node_id)
        if node and node.capability:
            return {node.capability}
        return set()

    def incoming_edges(self, node_id: str) -> list[EffectEdge]:
        return self._bwd.get(node_id, [])

    def outgoing_edges(self, node_id: str) -> list[EffectEdge]:
        return self._fwd.get(node_id, [])

    def all_nodes(self) -> list[EffectNode]:
        return list(self._nodes.values())

    def all_edges(self) -> list[EffectEdge]:
        return list(self._edges)

    def __len__(self) -> int:
        return len(self._nodes)

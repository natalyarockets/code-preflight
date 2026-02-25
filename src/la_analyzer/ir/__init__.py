"""IR (Intermediate Representation) package for LA-Analyzer.

Provides:
    build_effect_graph(workspace, py_files) -> EffectGraph
"""

from __future__ import annotations

import logging
from pathlib import Path

from la_analyzer.ir.graph import EffectGraph
from la_analyzer.ir.python_frontend import analyze_file

log = logging.getLogger(__name__)


def build_effect_graph(
    workspace: Path,
    py_files: list[Path],
) -> EffectGraph:
    """Build an EffectGraph from a list of Python files.

    Args:
        workspace: Root directory (for computing relative paths).
        py_files: List of Python file paths to analyze.

    Returns:
        EffectGraph populated with all emitted IR facts.
    """
    graph = EffectGraph()
    var_capability_map: dict[str, object] = {}

    for fpath in py_files:
        try:
            file_caps = analyze_file(fpath, workspace, graph)
            var_capability_map.update(file_caps)
        except Exception:
            log.debug("IR analysis failed for %s", fpath, exc_info=True)

    log.info(
        "EffectGraph built: %d nodes, %d edges from %d files",
        len(graph), len(graph.all_edges()), len(py_files),
    )

    return graph


__all__ = ["build_effect_graph", "EffectGraph"]

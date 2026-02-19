"""Detect Jupyter notebooks and extract basic file I/O patterns from them."""

from __future__ import annotations

import json
import re
from pathlib import Path

from la_analyzer.analyzer.models import Evidence, IOInput, IOOutput

# Same path pattern as io_scan
_PATH_PATTERN = re.compile(
    r"""["']([A-Za-z0-9_./ \\-]+\.(csv|json|xlsx?|pdf|zip|png|jpg|html?|md|txt|wav|mp3))["']"""
)

_EXT_TO_FORMAT = {
    ".csv": "csv", ".json": "json", ".xlsx": "excel", ".xls": "excel",
    ".pdf": "pdf", ".zip": "zip", ".png": "png", ".jpg": "png",
    ".html": "html", ".md": "markdown", ".wav": "audio", ".mp3": "audio",
    ".parquet": "parquet", ".txt": "text", ".yaml": "yaml", ".yml": "yaml",
    ".xml": "xml",
}

# Patterns suggesting reads vs writes
_READ_PATTERNS = re.compile(r"(read_csv|read_json|read_excel|read_parquet|open\([^)]*\)|\.read_text|\.read_bytes)", re.IGNORECASE)
_WRITE_PATTERNS = re.compile(r"(to_csv|to_json|to_excel|savefig|write_text|write_bytes|open\([^)]*[\"']w[\"'])", re.IGNORECASE)


def count_notebooks(all_files: list[Path]) -> int:
    return sum(1 for f in all_files if f.suffix == ".ipynb")


def scan_notebooks(
    workspace: Path, all_files: list[Path]
) -> tuple[list[IOInput], list[IOOutput]]:
    """Extract basic file I/O references from notebook code cells."""
    inputs: list[IOInput] = []
    outputs: list[IOOutput] = []
    input_counter = 0
    output_counter = 0
    seen_paths: set[str] = set()

    notebooks = [f for f in all_files if f.suffix == ".ipynb"]
    for nb_path in notebooks:
        rel = str(nb_path.relative_to(workspace))
        try:
            nb = json.loads(nb_path.read_text(errors="replace"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue

        cells = nb.get("cells", [])
        for cell_idx, cell in enumerate(cells):
            if cell.get("cell_type") != "code":
                continue
            source_lines = cell.get("source", [])
            if isinstance(source_lines, list):
                source = "".join(source_lines)
            else:
                source = str(source_lines)

            for m in _PATH_PATTERN.finditer(source):
                path_lit = m.group(1)
                if path_lit in seen_paths:
                    continue
                seen_paths.add(path_lit)

                lineno = source[:m.start()].count("\n") + 1
                line_text = source.splitlines()[lineno - 1].strip()[:160] if source.splitlines() else ""
                ev = Evidence(file=rel, line=cell_idx + 1, snippet=line_text)
                fmt = _format_from_path(path_lit)

                # Determine if it's a read or write based on context
                context = source[max(0, m.start() - 80):m.end() + 20]
                if _WRITE_PATTERNS.search(context):
                    outputs.append(IOOutput(
                        id=f"nb_output_{output_counter}",
                        format=fmt, path_literal=path_lit,
                        evidence=[ev], confidence=0.6,
                    ))
                    output_counter += 1
                elif _READ_PATTERNS.search(context):
                    inputs.append(IOInput(
                        id=f"nb_input_{input_counter}",
                        kind="file", format=fmt, path_literal=path_lit,
                        evidence=[ev], confidence=0.6,
                    ))
                    input_counter += 1
                else:
                    # Default to input for ambiguous cases
                    inputs.append(IOInput(
                        id=f"nb_input_{input_counter}",
                        kind="file", format=fmt, path_literal=path_lit,
                        evidence=[ev], confidence=0.4,
                    ))
                    input_counter += 1

    return inputs, outputs


def _format_from_path(path: str) -> str:
    for ext, fmt in _EXT_TO_FORMAT.items():
        if path.lower().endswith(ext):
            return fmt
    return "unknown"

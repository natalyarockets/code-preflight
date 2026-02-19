"""Extract natural-language context: README + module docstrings + argparse help.

This is a lightweight foundation for post-MVP semantic enrichment.
The extracted text can later be fed to an LLM for richer flow labels
(e.g. "HR Documents" instead of "File Input").
"""

from __future__ import annotations

import ast
from pathlib import Path

from la_analyzer.analyzer.models import DescriptionReport, ModuleDocstring


# README variants in priority order
_README_NAMES = [
    "README.md", "README.rst", "README.txt", "README",
    "readme.md", "readme.rst", "readme.txt", "readme",
]

# Cap README to avoid storing huge files
_MAX_README_CHARS = 10_000


def scan_description(
    workspace_dir: Path,
    py_files: list[Path],
    entrypoint_files: set[str] | None = None,
) -> DescriptionReport:
    """Extract README, module docstrings, and argparse descriptions.

    Args:
        workspace_dir: Repo root.
        py_files: Python files discovered by the analyzer.
        entrypoint_files: Set of relative paths that are entrypoint candidates
                          (so we can flag their docstrings as more important).
    """
    entrypoint_files = entrypoint_files or set()

    # ── README ───────────────────────────────────────────────────────────
    readme_content = ""
    readme_file = ""
    for name in _README_NAMES:
        candidate = workspace_dir / name
        if candidate.is_file():
            try:
                readme_content = candidate.read_text(errors="replace")[:_MAX_README_CHARS]
                readme_file = name
            except OSError:
                pass
            break

    # ── Module docstrings + argparse descriptions ────────────────────────
    module_docstrings: list[ModuleDocstring] = []
    argparse_descs: list[str] = []

    for fpath in py_files:
        rel = str(fpath.relative_to(workspace_dir))
        try:
            source = fpath.read_text(errors="replace")
            tree = ast.parse(source)
        except (SyntaxError, OSError):
            continue

        # Module-level docstring
        docstring = ast.get_docstring(tree)
        if docstring:
            module_docstrings.append(ModuleDocstring(
                file=rel,
                docstring=docstring[:2000],
                is_entrypoint=rel in entrypoint_files,
            ))

        # argparse descriptions: ArgumentParser(description="...")
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = None
            if isinstance(func, ast.Name):
                name = func.id
            elif isinstance(func, ast.Attribute):
                name = func.attr
            if name != "ArgumentParser":
                continue
            for kw in node.keywords:
                if kw.arg == "description" and isinstance(kw.value, ast.Constant):
                    desc = str(kw.value.value).strip()
                    if desc and desc not in argparse_descs:
                        argparse_descs.append(desc)

    return DescriptionReport(
        readme_content=readme_content,
        readme_file=readme_file,
        module_docstrings=module_docstrings,
        argparse_descriptions=argparse_descs,
    )

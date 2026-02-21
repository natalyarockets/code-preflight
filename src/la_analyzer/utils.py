"""Shared utilities for la-analyzer."""

from __future__ import annotations

from pathlib import Path

# Directories to skip during file discovery
SKIP_DIRS = {
    ".git", "__pycache__", "node_modules", "venv", ".venv", "env",
    ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache", "dist",
    "build", "egg-info", ".eggs", ".nox", ".la-analyzer",
    ".ipynb_checkpoints",
}

# Maximum file size to read (skip large binaries)
MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 MB


def discover_files(workspace: Path) -> list[Path]:
    """Walk workspace, skipping ignored dirs and large files."""
    files: list[Path] = []
    for item in workspace.rglob("*"):
        if item.is_dir():
            continue
        if any(part in SKIP_DIRS for part in item.relative_to(workspace).parts):
            continue
        try:
            if item.stat().st_size > MAX_FILE_SIZE:
                continue
        except OSError:
            continue
        files.append(item)
    return files

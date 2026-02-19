"""Tests for dependency scanning."""

import tempfile
from pathlib import Path

from la_analyzer.analyzer.deps_scan import scan_deps


def _write(tmpdir: Path, name: str, content: str) -> Path:
    p = tmpdir / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    return p


def test_parses_requirements_txt():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        _write(ws, "requirements.txt", '''
pandas>=2.0.0
openai>=1.0.0
requests
# comment
python-dotenv
''')
        report = scan_deps(ws, [], [])
        assert any(dep.name == "pandas" for dep in report.dependencies)
        assert any(dep.name == "openai" for dep in report.dependencies)
        assert any(dep.name == "requests" for dep in report.dependencies)


def test_parses_pyproject_toml():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        _write(ws, "pyproject.toml", '''
[project]
name = "my-app"
requires-python = ">=3.11"
dependencies = [
    "pandas>=2.0",
    "fastapi",
]
''')
        report = scan_deps(ws, [], [])
        assert report.python_version_hint == ">=3.11"
        assert any(dep.name == "pandas" for dep in report.dependencies)
        assert any(dep.name == "fastapi" for dep in report.dependencies)


def test_import_scan_fallback():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write(ws, "app.py", '''
import pandas as pd
import openai
from PIL import Image
''')
        report = scan_deps(ws, [f], [f])
        dep_names = {dep.name.lower() for dep in report.dependencies}
        assert "pandas" in dep_names
        assert "openai" in dep_names
        assert "pillow" in dep_names  # PIL -> Pillow mapping


def test_no_deps():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write(ws, "pure.py", '''
import os
import json
''')
        report = scan_deps(ws, [f], [f])
        # os and json are stdlib, should not appear
        assert not any(dep.name in ("os", "json") for dep in report.dependencies)

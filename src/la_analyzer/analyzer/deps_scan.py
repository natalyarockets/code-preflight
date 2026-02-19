"""Scan for Python dependencies from pyproject.toml, requirements.txt, environment.yml, and imports."""

from __future__ import annotations

import ast
import re
import sys
import tomllib
from pathlib import Path

from la_analyzer.analyzer.models import Dependency, DepsReport, DepsSource

# Standard library module names (subset for quick filtering)
_STDLIB_MODULES: set[str] = set(sys.stdlib_module_names) if hasattr(sys, "stdlib_module_names") else {
    "os", "sys", "re", "json", "csv", "pathlib", "collections", "itertools",
    "functools", "typing", "dataclasses", "abc", "io", "math", "random",
    "datetime", "time", "logging", "argparse", "subprocess", "shutil",
    "tempfile", "glob", "hashlib", "base64", "copy", "pprint", "textwrap",
    "unittest", "contextlib", "enum", "string", "struct", "socket",
    "http", "urllib", "email", "html", "xml", "sqlite3", "configparser",
    "ast", "dis", "inspect", "importlib", "pkgutil", "warnings",
    "traceback", "threading", "multiprocessing", "concurrent", "asyncio",
    "signal", "mmap", "ctypes", "decimal", "fractions", "statistics",
    "operator", "bisect", "heapq", "array", "queue", "weakref",
    "types", "codecs", "unicodedata", "locale", "gettext",
    "platform", "errno", "faulthandler", "pdb", "profile",
    "timeit", "trace", "gc", "marshal", "pickletools", "pickle",
    "shelve", "dbm", "gzip", "bz2", "lzma", "zipfile", "tarfile",
    "zlib", "select", "selectors", "ssl", "ftplib", "smtplib",
    "imaplib", "poplib", "xmlrpc", "ipaddress", "uuid",
    "token", "tokenize", "keyword", "linecache", "compileall",
}

# Common PyPI name mappings where import name differs
_IMPORT_TO_PYPI: dict[str, str] = {
    "cv2": "opencv-python",
    "PIL": "Pillow",
    "sklearn": "scikit-learn",
    "yaml": "PyYAML",
    "bs4": "beautifulsoup4",
    "attr": "attrs",
    "dotenv": "python-dotenv",
    "gi": "PyGObject",
    "wx": "wxPython",
    "serial": "pyserial",
    "jwt": "PyJWT",
    "magic": "python-magic",
    "lxml": "lxml",
    "bson": "pymongo",
    "jose": "python-jose",
    "dateutil": "python-dateutil",
    "psutil": "psutil",
}


def scan_deps(workspace: Path, py_files: list[Path], all_files: list[Path]) -> DepsReport:
    sources: list[DepsSource] = []
    deps: list[Dependency] = []
    warnings: list[str] = []
    python_hint: str | None = None
    seen_names: set[str] = set()

    # 1. pyproject.toml
    pyproject = workspace / "pyproject.toml"
    if pyproject.exists():
        sources.append(DepsSource(type="pyproject", path="pyproject.toml"))
        python_hint, file_deps = _parse_pyproject(pyproject)
        for name, spec in file_deps:
            if name.lower() not in seen_names:
                seen_names.add(name.lower())
                deps.append(Dependency(name=name, spec=spec, source_path="pyproject.toml"))

    # 2. requirements.txt (and variants)
    for req_name in ("requirements.txt", "requirements-dev.txt", "requirements_dev.txt"):
        req_path = workspace / req_name
        if req_path.exists():
            rel = req_name
            sources.append(DepsSource(type="requirements", path=rel))
            for name, spec in _parse_requirements(req_path):
                if name.lower() not in seen_names:
                    seen_names.add(name.lower())
                    deps.append(Dependency(name=name, spec=spec, source_path=rel))

    # 3. environment.yml (conda)
    for env_name in ("environment.yml", "environment.yaml"):
        env_path = workspace / env_name
        if env_path.exists():
            rel = env_name
            sources.append(DepsSource(type="environment_yml", path=rel))
            for name, spec in _parse_environment_yml(env_path):
                if name.lower() not in seen_names:
                    seen_names.add(name.lower())
                    deps.append(Dependency(name=name, spec=spec, source_path=rel))
            if python_hint is None:
                python_hint = _conda_python_version(env_path)

    # 4. Import scan as fallback
    import_names = _scan_imports(py_files)
    if import_names:
        sources.append(DepsSource(type="imports_scan", path="<all .py files>"))
    for imp in sorted(import_names):
        pypi_name = _IMPORT_TO_PYPI.get(imp, imp)
        if pypi_name.lower() not in seen_names:
            seen_names.add(pypi_name.lower())
            deps.append(Dependency(name=pypi_name, spec=None, source_path="<imports>"))

    if not sources:
        warnings.append("No dependency manifest found (pyproject.toml, requirements.txt, or environment.yml)")

    return DepsReport(
        python_version_hint=python_hint,
        sources=sources,
        dependencies=deps,
        warnings=warnings,
    )


def _parse_pyproject(path: Path) -> tuple[str | None, list[tuple[str, str | None]]]:
    """Parse pyproject.toml for [project] dependencies and requires-python using tomllib."""
    deps: list[tuple[str, str | None]] = []
    python_hint: str | None = None

    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except Exception:
        return None, []

    # [project] section
    project = data.get("project", {})
    python_hint = project.get("requires-python")

    for dep_str in project.get("dependencies", []):
        parsed = _parse_req_line(dep_str)
        if parsed:
            deps.append(parsed)

    # Also check [tool.poetry.dependencies] for Poetry projects
    poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    for name, spec in poetry_deps.items():
        if name.lower() == "python":
            if isinstance(spec, str):
                python_hint = python_hint or spec
            continue
        spec_str = spec if isinstance(spec, str) else None
        deps.append((name, spec_str))

    return python_hint, deps


def _parse_requirements(path: Path, _depth: int = 0) -> list[tuple[str, str | None]]:
    deps: list[tuple[str, str | None]] = []
    if _depth > 5:  # prevent infinite recursion
        return deps
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Handle -r / --requirement includes
        if line.startswith("-r ") or line.startswith("--requirement "):
            ref_name = line.split(None, 1)[1].strip()
            ref_path = path.parent / ref_name
            if ref_path.exists():
                deps.extend(_parse_requirements(ref_path, _depth + 1))
            continue
        if line.startswith("-"):
            continue
        parsed = _parse_req_line(line)
        if parsed:
            deps.append(parsed)
    return deps


def _parse_req_line(line: str) -> tuple[str, str | None] | None:
    """Parse a single requirements line like 'pandas>=1.5.0'."""
    line = line.split("#")[0].strip()
    if not line:
        return None
    m = re.match(r"^([a-zA-Z0-9_][a-zA-Z0-9._-]*)\s*(.*)?$", line)
    if m:
        name = m.group(1)
        spec = m.group(2).strip() if m.group(2) else None
        spec = spec or None
        return name, spec
    return None


def _parse_environment_yml(path: Path) -> list[tuple[str, str | None]]:
    """Very lightweight YAML parser for conda environment files (pip section)."""
    deps: list[tuple[str, str | None]] = []
    content = path.read_text(errors="replace")
    in_pip = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped == "- pip:":
            in_pip = True
            continue
        if in_pip:
            if stripped.startswith("- "):
                pkg = stripped[2:].strip()
                parsed = _parse_req_line(pkg)
                if parsed:
                    deps.append(parsed)
            elif not stripped.startswith("#") and stripped and not stripped.startswith("-"):
                in_pip = False
    return deps


def _conda_python_version(path: Path) -> str | None:
    content = path.read_text(errors="replace")
    m = re.search(r"-\s*python\s*[=><!]+\s*([0-9.]+)", content)
    if m:
        return m.group(1)
    m = re.search(r"-\s*python\s*$", content, re.MULTILINE)
    return None


def _scan_imports(py_files: list[Path]) -> set[str]:
    """Extract third-party import names from Python files."""
    imports: set[str] = set()

    # Build set of local package names (directories/files in the workspace)
    local_packages: set[str] = set()
    if py_files:
        # Find the workspace root (common parent of all py_files)
        first = py_files[0]
        for parent in first.parents:
            if any(f.is_relative_to(parent) for f in py_files):
                # Top-level .py files and directories are local packages
                for item in parent.iterdir():
                    if item.is_dir() and (item / "__init__.py").exists():
                        local_packages.add(item.name)
                    elif item.suffix == ".py" and item.stem != "__init__":
                        local_packages.add(item.stem)
                break

    for fpath in py_files:
        try:
            source = fpath.read_text(errors="replace")
            tree = ast.parse(source)
        except SyntaxError:
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    if root not in _STDLIB_MODULES and not root.startswith("_") and root not in local_packages:
                        imports.add(root)
            if isinstance(node, ast.ImportFrom) and node.module:
                root = node.module.split(".")[0]
                if root not in _STDLIB_MODULES and not root.startswith("_") and root not in local_packages:
                    imports.add(root)

    return imports

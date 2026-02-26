"""Detect Python entrypoint candidates via AST analysis."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from la_analyzer.analyzer.models import EntrypointCandidate, Evidence
from la_analyzer.utils import snippet

# Filenames that commonly serve as entrypoints (strong signal)
_ENTRYPOINT_NAMES = {"main.py", "app.py", "run.py", "cli.py"}

# Filenames that are almost never the real app entrypoint
_UTILITY_NAMES = {
    "setup.py", "update.py", "migrate.py", "install.py", "deploy.py",
    "config.py", "settings.py", "conftest.py", "fabfile.py",
    "tasks.py", "seed.py", "init_db.py", "create_db.py", "reset.py",
    "download.py", "upload.py", "fix.py", "patch.py", "upgrade.py",
}


def scan_entrypoints(
    workspace: Path, py_files: list[Path]
) -> list[EntrypointCandidate]:
    candidates: list[EntrypointCandidate] = []

    # Check pyproject.toml for console_scripts (authoritative source)
    candidates.extend(_scan_console_scripts(workspace))

    for fpath in py_files:
        rel = str(fpath.relative_to(workspace))
        try:
            source = fpath.read_text(errors="replace")
            tree = ast.parse(source, filename=rel)
        except SyntaxError:
            continue

        has_main_guard = False
        has_argparse = False
        has_click = False
        has_typer = False
        has_fire = False
        has_main_func = False
        has_fastapi = False
        has_uvicorn = False
        has_streamlit = False
        fastapi_app_var: str | None = None
        fastapi_app_line: int = 0
        evidences: list[Evidence] = []

        for node in ast.walk(tree):
            # if __name__ == "__main__"
            if (
                isinstance(node, ast.If)
                and _is_name_main_check(node.test)
            ):
                has_main_guard = True
                evidences.append(
                    Evidence(
                        file=rel,
                        line=node.lineno,
                        snippet=snippet(source, node.lineno),
                    )
                )

            # argparse usage
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "argparse":
                        has_argparse = True
                        evidences.append(Evidence(
                            file=rel, line=node.lineno,
                            snippet=snippet(source, node.lineno),
                        ))
                    if alias.name == "click":
                        has_click = True
                    if alias.name == "typer":
                        has_typer = True
                    if alias.name == "fire":
                        has_fire = True
                    if alias.name == "streamlit":
                        has_streamlit = True
            if isinstance(node, ast.ImportFrom) and node.module:
                if node.module == "argparse":
                    has_argparse = True
                    evidences.append(Evidence(
                        file=rel, line=node.lineno,
                        snippet=snippet(source, node.lineno),
                    ))
                if node.module.startswith("click"):
                    has_click = True
                if node.module.startswith("typer"):
                    has_typer = True
                if node.module.startswith("fire"):
                    has_fire = True
                if node.module.startswith("streamlit"):
                    has_streamlit = True

            # def main(...)
            if isinstance(node, ast.FunctionDef) and node.name == "main":
                has_main_func = True

            # FastAPI detection
            if isinstance(node, ast.Call) and _call_name(node) == "FastAPI":
                has_fastapi = True
            # Track the variable name assigned to FastAPI() (e.g. app = FastAPI())
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                if _call_name(node.value) == "FastAPI":
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            fastapi_app_var = target.id
                            fastapi_app_line = node.lineno
            if isinstance(node, ast.Attribute) and node.attr == "run":
                if isinstance(node.value, ast.Name) and node.value.id == "uvicorn":
                    has_uvicorn = True

            # click.command() / typer.run() / fire.Fire() decorators and calls
            if isinstance(node, ast.Call):
                cname = _call_name(node)
                if cname == "Fire" and has_fire:
                    has_fire = True
                    evidences.append(Evidence(
                        file=rel, line=node.lineno,
                        snippet=snippet(source, node.lineno),
                    ))

            # @click.command() or @app.command() decorators
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for dec in node.decorator_list:
                    dec_name = _decorator_name(dec)
                    if dec_name in ("click.command", "click.group", "command", "group"):
                        if has_click:
                            evidences.append(Evidence(
                                file=rel, line=node.lineno,
                                snippet=snippet(source, node.lineno),
                            ))

        # FastAPI uvicorn entrypoint — higher priority than generic python command
        if has_fastapi and fastapi_app_var:
            module = _module_path(rel)
            candidates.append(
                EntrypointCandidate(
                    kind="command",
                    value=f"uvicorn {module}:{fastapi_app_var}",
                    confidence=0.85,
                    evidence=[
                        Evidence(
                            file=rel,
                            line=fastapi_app_line,
                            snippet=snippet(source, fastapi_app_line),
                        )
                    ],
                )
            )
            # Skip the lower-confidence generic fallback for this file
            continue

        # Determine if this is a CLI framework entrypoint
        has_cli_framework = has_click or has_typer or has_fire

        # Score this file
        if has_main_guard or has_argparse or has_cli_framework:
            confidence = 0.5
            if has_main_guard:
                confidence += 0.15
            if has_argparse or has_cli_framework:
                confidence += 0.1
            if has_main_func:
                confidence += 0.05
            if fpath.name in _ENTRYPOINT_NAMES:
                confidence += 0.2
            elif fpath.name in _UTILITY_NAMES:
                confidence -= 0.3
            confidence = max(0.05, min(confidence, 1.0))

            # Determine kind
            kind = "command"
            value = f"python {rel}"

            candidates.append(
                EntrypointCandidate(
                    kind=kind,
                    value=value,
                    confidence=round(confidence, 2),
                    evidence=evidences[:5],
                )
            )
        elif fpath.name in _ENTRYPOINT_NAMES:
            candidates.append(
                EntrypointCandidate(
                    kind="command",
                    value=f"python {rel}",
                    confidence=0.4,
                    evidence=[
                        Evidence(
                            file=rel,
                            line=1,
                            snippet=snippet(source, 1),
                        )
                    ],
                )
            )

    candidates.sort(key=lambda c: c.confidence, reverse=True)
    return candidates


def _scan_console_scripts(workspace: Path) -> list[EntrypointCandidate]:
    """Extract entrypoint candidates from pyproject.toml [project.scripts]."""
    pyproject = workspace / "pyproject.toml"
    if not pyproject.exists():
        return []

    try:
        content = pyproject.read_text(errors="replace")
    except OSError:
        return []

    candidates: list[EntrypointCandidate] = []

    # Match [project.scripts] or [tool.poetry.scripts] sections
    for pattern in [
        r'\[project\.scripts\]\s*\n((?:[^\[].+\n)*)',
        r'\[tool\.poetry\.scripts\]\s*\n((?:[^\[].+\n)*)',
    ]:
        m = re.search(pattern, content)
        if m:
            for line in m.group(1).splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # name = "module:func"
                parts = line.split("=", 1)
                if len(parts) == 2:
                    script_name = parts[0].strip()
                    target = parts[1].strip().strip('"').strip("'")
                    candidates.append(EntrypointCandidate(
                        kind="command",
                        value=f"python -m {target.split(':')[0]}" if ":" in target else f"python {target}",
                        confidence=0.95,
                        evidence=[Evidence(
                            file="pyproject.toml", line=1,
                            snippet=f"[project.scripts] {script_name} = {target}",
                        )],
                    ))
    return candidates


def _is_name_main_check(node: ast.expr) -> bool:
    """Check if node is `__name__ == "__main__"`."""
    if isinstance(node, ast.Compare):
        if (
            isinstance(node.left, ast.Name)
            and node.left.id == "__name__"
            and len(node.ops) == 1
            and isinstance(node.ops[0], ast.Eq)
            and len(node.comparators) == 1
            and isinstance(node.comparators[0], ast.Constant)
            and node.comparators[0].value == "__main__"
        ):
            return True
    return False


def _call_name(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def _decorator_name(dec: ast.expr) -> str:
    """Get dotted name of a decorator (e.g. 'click.command')."""
    if isinstance(dec, ast.Call):
        return _decorator_name(dec.func)
    if isinstance(dec, ast.Attribute):
        parent = _decorator_name(dec.value)
        return f"{parent}.{dec.attr}" if parent else dec.attr
    if isinstance(dec, ast.Name):
        return dec.id
    return ""


def _module_path(rel: str) -> str:
    return rel.replace("/", ".").replace("\\", ".").removesuffix(".py")



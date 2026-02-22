"""
LA Analyzer — analysis entrypoint.

Usage:
    from pathlib import Path
    from la_analyzer.analyzer.service import analyze_repo

    result = analyze_repo(
        workspace_dir=Path("/path/to/checked-out-repo"),
        out_dir=Path("/path/to/output"),
    )

    # result.detection   — DetectionReport object
    # result.io          — IOReport object
    # result.egress      — EgressReport object
    # result.secrets     — SecretsReport object
    # result.deps        — DepsReport object
    # result.porting_plan — PortingPlan object
    # All JSON reports + livingapps.yaml are written to out_dir.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from la_analyzer.analyzer.api_scan import scan_api
from la_analyzer.analyzer.deps_scan import scan_deps
from la_analyzer.analyzer.description_scan import scan_description
from la_analyzer.analyzer.egress_scan import scan_egress
from la_analyzer.analyzer.entrypoint import scan_entrypoints
from la_analyzer.analyzer.io_scan import scan_io
from la_analyzer.analyzer.manifest_generator import generate_manifest
from la_analyzer.analyzer.models import (
    AnalysisResult,
    ArchetypeMatch,
    DetectionReport,
    PythonInfo,
)
from la_analyzer.analyzer.notebook_scan import count_notebooks, scan_notebooks
from la_analyzer.analyzer.porting_plan import generate_porting_plan
from la_analyzer.analyzer.prompt_surface import scan_prompt_surfaces
from la_analyzer.analyzer.secrets_scan import scan_secrets
from la_analyzer.analyzer.state_flow import scan_state_flow
from la_analyzer.analyzer.tool_registration import scan_tool_registrations
from la_analyzer.utils import discover_files


def analyze_repo(workspace_dir: Path, out_dir: Path) -> AnalysisResult:
    """Analyze a checked-out Python repo and produce all reports + manifest.

    Args:
        workspace_dir: Path to the repo root on disk.
        out_dir: Directory where JSON reports and livingapps.yaml will be written.

    Returns:
        AnalysisResult with paths to written files and parsed report objects.
    """
    out_dir.mkdir(parents=True, exist_ok=True)

    # ── File discovery ──────────────────────────────────────────────────
    all_files = discover_files(workspace_dir)
    py_files = [f for f in all_files if f.suffix == ".py"]

    # ── Detection ───────────────────────────────────────────────────────
    python_info = PythonInfo(
        has_pyproject=(workspace_dir / "pyproject.toml").exists(),
        has_requirements_txt=(workspace_dir / "requirements.txt").exists(),
        has_environment_yml=(workspace_dir / "environment.yml").exists()
        or (workspace_dir / "environment.yaml").exists(),
        notebooks_found=count_notebooks(all_files),
    )

    entrypoint_candidates = scan_entrypoints(workspace_dir, py_files)
    archetypes = _detect_archetypes(workspace_dir, py_files)

    detection = DetectionReport(
        languages=["python"],
        python=python_info,
        archetypes=archetypes,
        entrypoint_candidates=entrypoint_candidates,
    )

    # ── I/O scan ────────────────────────────────────────────────────────
    io_report = scan_io(workspace_dir, py_files)

    # Merge notebook I/O
    nb_inputs, nb_outputs = scan_notebooks(workspace_dir, all_files)
    io_report.inputs.extend(nb_inputs)
    io_report.outputs.extend(nb_outputs)

    # Merge API I/O (FastAPI routes)
    if any(a.type == "fastapi_web" for a in archetypes):
        api_inputs, api_outputs, api_routes = scan_api(workspace_dir, py_files)
        io_report.inputs.extend(api_inputs)
        io_report.outputs.extend(api_outputs)
        io_report.api_routes.extend(api_routes)

    # ── Egress scan ─────────────────────────────────────────────────────
    egress_report = scan_egress(workspace_dir, py_files)

    # ── Secrets scan ────────────────────────────────────────────────────
    secrets_report = scan_secrets(workspace_dir, py_files, all_files)

    # ── Deps scan ───────────────────────────────────────────────────────
    deps_report = scan_deps(workspace_dir, py_files, all_files)

    # ── Porting plan ────────────────────────────────────────────────────
    porting_plan = generate_porting_plan(
        detection, io_report, egress_report, secrets_report
    )

    # ── Description (README + docstrings) ────────────────────────────────
    entrypoint_files = {
        c.value.split(":")[0].replace(".", "/") + ".py"
        if c.kind == "module" else c.evidence[0].file if c.evidence else ""
        for c in entrypoint_candidates
    }
    description_report = scan_description(workspace_dir, py_files, entrypoint_files)

    # ── Prompt surface scan ──────────────────────────────────────────────
    prompt_surface_report = scan_prompt_surfaces(workspace_dir, py_files)

    # ── Tool registration scan ───────────────────────────────────────────
    tool_registration_report = scan_tool_registrations(workspace_dir, py_files)

    # ── State flow scan ──────────────────────────────────────────────────
    state_flow_report = scan_state_flow(workspace_dir, py_files)

    # ── Manifest ────────────────────────────────────────────────────────
    manifest = generate_manifest(
        workspace_dir, detection, io_report, egress_report, secrets_report
    )

    # ── Write outputs ───────────────────────────────────────────────────
    def _write_json(name: str, obj) -> str:
        path = out_dir / name
        path.write_text(json.dumps(obj.model_dump(), indent=2))
        return str(path)

    detection_path = _write_json("detection_report.json", detection)
    io_path = _write_json("io_report.json", io_report)
    egress_path = _write_json("egress_report.json", egress_report)
    secrets_path = _write_json("secrets_report.json", secrets_report)
    deps_path = _write_json("deps_report.json", deps_report)
    porting_path = _write_json("porting_plan.json", porting_plan)
    description_path = _write_json("description_report.json", description_report)
    prompt_surface_path = _write_json("prompt_surface_report.json", prompt_surface_report)
    tool_registration_path = _write_json("tool_registration_report.json", tool_registration_report)
    state_flow_path = _write_json("state_flow_report.json", state_flow_report)

    manifest_path = str(out_dir / "livingapps.yaml")
    (out_dir / "livingapps.yaml").write_text(
        yaml.dump(manifest.model_dump(), default_flow_style=False, sort_keys=False)
    )

    return AnalysisResult(
        detection_report_path=detection_path,
        io_report_path=io_path,
        egress_report_path=egress_path,
        secrets_report_path=secrets_path,
        deps_report_path=deps_path,
        porting_plan_path=porting_path,
        description_report_path=description_path,
        prompt_surface_report_path=prompt_surface_path,
        tool_registration_report_path=tool_registration_path,
        state_flow_report_path=state_flow_path,
        manifest_path=manifest_path,
        detection=detection,
        io=io_report,
        egress=egress_report,
        secrets=secrets_report,
        deps=deps_report,
        porting_plan=porting_plan,
        description=description_report,
        prompt_surface=prompt_surface_report,
        tool_registration=tool_registration_report,
        state_flow=state_flow_report,
    )


def _detect_archetypes(workspace: Path, py_files: list[Path]) -> list[ArchetypeMatch]:
    """Heuristic archetype detection."""
    import ast as _ast

    has_fastapi = False
    has_streamlit = False
    has_main_guard = False

    for fpath in py_files:
        try:
            source = fpath.read_text(errors="replace")
            tree = _ast.parse(source)
        except SyntaxError:
            continue

        for node in _ast.walk(tree):
            if isinstance(node, _ast.Import):
                for alias in node.names:
                    if alias.name == "streamlit":
                        has_streamlit = True
                    if alias.name == "fastapi":
                        has_fastapi = True
            if isinstance(node, _ast.ImportFrom) and node.module:
                if node.module.startswith("streamlit"):
                    has_streamlit = True
                if node.module.startswith("fastapi"):
                    has_fastapi = True
            if isinstance(node, _ast.Call):
                if isinstance(node.func, _ast.Name) and node.func.id == "FastAPI":
                    has_fastapi = True
            if isinstance(node, _ast.If):
                if (
                    isinstance(node.test, _ast.Compare)
                    and isinstance(node.test.left, _ast.Name)
                    and node.test.left.id == "__name__"
                ):
                    has_main_guard = True

    matches: list[ArchetypeMatch] = []
    if has_fastapi:
        matches.append(ArchetypeMatch(type="fastapi_web", confidence=0.85))
    if has_streamlit:
        matches.append(ArchetypeMatch(type="streamlit_web", confidence=0.85))
    if has_main_guard and not has_fastapi and not has_streamlit:
        matches.append(ArchetypeMatch(type="python_batch", confidence=0.8))
    elif has_main_guard:
        matches.append(ArchetypeMatch(type="python_batch", confidence=0.4))

    if not matches:
        if py_files:
            matches.append(ArchetypeMatch(type="python_batch", confidence=0.3))
        else:
            matches.append(ArchetypeMatch(type="unknown", confidence=0.5))

    matches.sort(key=lambda m: m.confidence, reverse=True)
    return matches

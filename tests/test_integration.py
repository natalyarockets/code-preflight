"""Integration test: run full analyze_repo on the sample batch app."""

import tempfile
from pathlib import Path

from la_analyzer.analyzer.service import analyze_repo
from la_analyzer.utils import discover_files

SAMPLE_APP = Path(__file__).parent.parent / "examples" / "sample_batch_app"


def test_full_analysis():
    """Verify analyze_repo produces all expected outputs on the sample app."""
    assert SAMPLE_APP.exists(), f"Sample app not found at {SAMPLE_APP}"

    with tempfile.TemporaryDirectory() as out:
        out_dir = Path(out)
        result = analyze_repo(SAMPLE_APP, out_dir)

        # All report files should exist
        assert Path(result.detection_report_path).exists()
        assert Path(result.io_report_path).exists()
        assert Path(result.egress_report_path).exists()
        assert Path(result.secrets_report_path).exists()
        assert Path(result.deps_report_path).exists()

        # Detection: should find Python batch archetype
        assert "python" in result.detection.languages
        assert result.detection.python.has_requirements_txt is True
        assert any(a.type == "python_batch" for a in result.detection.archetypes)

        # Entrypoints: should find main.py
        assert len(result.detection.entrypoint_candidates) >= 1
        assert any("main.py" in c.value for c in result.detection.entrypoint_candidates)

        # I/O: should detect file reads/writes
        assert len(result.io.inputs) >= 1 or len(result.io.hardcoded_paths) >= 1

        # Egress: should detect OpenAI and requests usage
        assert any(c.kind == "llm_sdk" for c in result.egress.outbound_calls)
        assert any(c.kind == "http" for c in result.egress.outbound_calls)

        # Secrets: should detect hardcoded API_KEY and .env file
        assert len(result.secrets.findings) >= 1
        # Should never contain raw secret values
        for f in result.secrets.findings:
            assert "sk-proj-abc123" not in f.value_redacted

        # Deps: should find pandas, openai, requests
        dep_names = {d.name.lower() for d in result.deps.dependencies}
        assert "pandas" in dep_names
        assert "openai" in dep_names
        assert "requests" in dep_names


def test_ipynb_checkpoints_skipped():
    """Files inside .ipynb_checkpoints should be excluded from discovery."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        # Create a normal notebook and its checkpoint copy
        nb = ws / "analysis.py"
        nb.write_text("x = 1\n")
        cp_dir = ws / ".ipynb_checkpoints"
        cp_dir.mkdir()
        cp = cp_dir / "analysis-checkpoint.py"
        cp.write_text("x = 1\n")

        files = discover_files(ws)
        file_strs = [str(f) for f in files]
        assert any("analysis.py" in s for s in file_strs)
        assert not any(".ipynb_checkpoints" in s for s in file_strs)

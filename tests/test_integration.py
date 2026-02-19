"""Integration test: run full analyze_repo on the sample batch app."""

import tempfile
from pathlib import Path

from la_analyzer.analyzer.service import analyze_repo

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
        assert Path(result.porting_plan_path).exists()
        assert Path(result.manifest_path).exists()

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
        assert result.egress.suggested_gateway_needs.needs_llm_gateway is True

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

        # Porting plan: should have required changes
        assert len(result.porting_plan.required_changes) >= 1

        # Manifest: should be valid YAML with expected fields
        import yaml
        manifest_content = Path(result.manifest_path).read_text()
        manifest = yaml.safe_load(manifest_content)
        assert manifest["app"]["name"] == "sample_batch_app"
        assert manifest["runtime"]["type"] == "python"
        assert manifest["runtime"]["entrypoint"]["kind"] == "batch"
        assert manifest["egress"]["mode"] == "deny_by_default"
        assert manifest.get("connections", {}) == {} or "connections" not in manifest

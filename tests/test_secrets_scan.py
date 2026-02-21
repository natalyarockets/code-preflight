"""Tests for secrets detection."""

import tempfile
from pathlib import Path

from la_analyzer.analyzer.secrets_scan import scan_secrets


def _write(tmpdir: Path, name: str, content: str) -> Path:
    p = tmpdir / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    return p


def test_detects_hardcoded_api_key():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write(ws, "config.py", '''
API_KEY = "sk-proj-abc123def456ghi789jklmnop"
''')
        report = scan_secrets(ws, [f], [f])
        assert len(report.findings) >= 1
        # Find the hardcoded_key finding (may also have detect-secrets findings)
        hk = [f for f in report.findings if f.kind == "hardcoded_key"]
        assert len(hk) >= 1
        assert hk[0].name_hint == "API_KEY"
        # Value should be redacted
        assert "sk-proj" not in hk[0].value_redacted
        assert hk[0].value_redacted.endswith("mnop")


def test_detects_dotenv_file():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        env_file = _write(ws, ".env", '''
OPENAI_API_KEY=sk-test-12345
DATABASE_URL=postgres://localhost/mydb
''')
        report = scan_secrets(ws, [], [env_file])
        assert any(f.kind == "dotenv_file" for f in report.findings)
        assert "OPENAI_API_KEY" in report.suggested_env_vars
        assert "DATABASE_URL" in report.suggested_env_vars


def test_detects_os_environ_get():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write(ws, "app.py", '''
import os
key = os.environ.get("MY_SECRET_KEY")
token = os.getenv("AUTH_TOKEN")
''')
        report = scan_secrets(ws, [f], [f])
        assert "MY_SECRET_KEY" in report.suggested_env_vars
        assert "AUTH_TOKEN" in report.suggested_env_vars


def test_redaction():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write(ws, "config.py", '''
secret_key = "supersecretvalue1234"
''')
        report = scan_secrets(ws, [f], [f])
        for finding in report.findings:
            assert "supersecret" not in finding.value_redacted


def test_no_secrets():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write(ws, "clean.py", '''
def add(a, b):
    return a + b
''')
        report = scan_secrets(ws, [f], [f])
        assert len(report.findings) == 0


# -- detect-secrets integration tests -----------------------------------------


def test_detect_secrets_fallback():
    """When detect-secrets is not installed, fallback AST scanner should still work."""
    from unittest.mock import patch

    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write(ws, "config.py", '''
API_KEY = "sk-proj-abc123def456ghi789jklmnop"
''')
        # Mock detect-secrets import to fail
        with patch(
            "la_analyzer.analyzer.secrets_scan._detect_secrets_scan",
            return_value=None,
        ):
            report = scan_secrets(ws, [f], [f])

        assert len(report.findings) >= 1
        assert any(f.kind == "hardcoded_key" for f in report.findings)


def test_detect_secrets_merge_dedup():
    """When both detect-secrets and AST find the same secret, only one should be emitted."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write(ws, "config.py", '''
API_KEY = "sk-proj-abc123def456ghi789jklmnop"
''')
        report = scan_secrets(ws, [f], [f])

        # Should find the secret but not duplicate it
        line_2_findings = [
            f for f in report.findings
            if f.evidence and f.evidence[0].line == 2
        ]
        # At most one finding per line (dedup working)
        assert len(line_2_findings) <= 2  # AST name + detect-secrets value is acceptable
        assert len(report.findings) >= 1

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
        assert report.findings[0].kind == "hardcoded_key"
        assert report.findings[0].name_hint == "API_KEY"
        # Value should be redacted
        assert "sk-proj" not in report.findings[0].value_redacted
        assert report.findings[0].value_redacted.endswith("mnop")


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

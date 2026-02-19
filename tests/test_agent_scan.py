"""Tests for the agent/skill security scanner."""

import tempfile
from pathlib import Path

from la_analyzer.security.agent_scan import scan_agents


def _write(tmpdir: Path, name: str, content: str) -> Path:
    p = tmpdir / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    return p


# ── Markdown prompt scanning ─────────────────────────────────────────────


def test_detects_template_injection_in_prompt():
    """Template variables like {user_input} in system prompts are flagged."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write(ws, "agent.md", '''# System Prompt

You are a helpful assistant.

## Instructions

Process the following user request: {user_input}

Always be helpful.
''')
        report = scan_agents(ws, [f])
        assert len(report.findings) >= 1
        cats = [f.category for f in report.findings]
        assert "prompt_injection" in cats


def test_detects_credential_in_prompt():
    """API keys in prompt files are flagged as critical."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write(ws, "config.md", '''# System Prompt

You are an assistant. Use this API key: sk-1234567890abcdefghijklmnopqrst

## Role
Be helpful.
''')
        report = scan_agents(ws, [f])
        assert any(f.category == "credential_exposure" for f in report.findings)
        assert any(f.severity == "critical" for f in report.findings)


def test_detects_dangerous_tool_ref_in_prompt():
    """References to dangerous tools/commands in prompts are flagged."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write(ws, "skill.md", '''## Instructions

You are an assistant with shell access. You can run subprocess commands.

## Tools
You have access to bash for running commands.
''')
        report = scan_agents(ws, [f])
        assert any(f.category == "overprivileged_tool" for f in report.findings)


def test_ignores_non_prompt_markdown():
    """Regular markdown files without prompt keywords are skipped."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write(ws, "readme.md", '''# My Project

This is a regular readme file with no agent instructions.

## Install
pip install myproject
''')
        report = scan_agents(ws, [f])
        assert len(report.findings) == 0


# ── YAML config scanning ─────────────────────────────────────────────────


def test_detects_credential_in_yaml():
    """Plaintext credentials in YAML configs are flagged."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write(ws, "mcp.yaml", '''
mcp:
  servers:
    my-server:
      api_key: sk-abcdefghijklmnopqrstuvwxyz1234
      url: https://api.example.com
''')
        report = scan_agents(ws, [f])
        assert any(f.category == "credential_exposure" for f in report.findings)


def test_detects_overprivileged_tools_in_yaml():
    """Overprivileged tools in YAML configs are flagged."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write(ws, "agent.yaml", '''
tools:
  - read_file
  - execute_command
  - shell
  - search
''')
        report = scan_agents(ws, [f])
        assert any(f.category == "overprivileged_tool" for f in report.findings)
        titles = [f.title for f in report.findings]
        assert any("execute_command" in t for t in titles)


def test_detects_wildcard_permissions():
    """Wildcard permissions ('*') are flagged."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write(ws, "config.yaml", '''
agents:
  my-agent:
    allowed_tools: "*"
''')
        report = scan_agents(ws, [f])
        assert any(f.category == "unscoped_permission" for f in report.findings)


def test_detects_missing_guardrails_on_server():
    """MCP servers without permission restrictions are flagged."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write(ws, "mcp.yaml", '''
servers:
  filesystem:
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem"]
  database:
    command: npx
    args: ["-y", "@modelcontextprotocol/server-postgres"]
''')
        report = scan_agents(ws, [f])
        assert any(f.category == "missing_guardrail" for f in report.findings)


def test_ignores_non_agent_yaml():
    """Regular YAML files without agent keywords are skipped."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write(ws, "docker-compose.yaml", '''
services:
  web:
    image: nginx
    ports:
      - "80:80"
''')
        report = scan_agents(ws, [f])
        assert len(report.findings) == 0


# ── JSON config scanning ─────────────────────────────────────────────────


def test_detects_credential_in_json():
    """Plaintext credentials in JSON configs are flagged."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write(ws, "mcp.json", '''{
  "mcpServers": {
    "my-server": {
      "api_key": "sk-abcdefghijklmnopqrstuvwxyz1234",
      "url": "https://api.example.com"
    }
  }
}''')
        report = scan_agents(ws, [f])
        assert any(f.category == "credential_exposure" for f in report.findings)


def test_detects_overprivileged_tools_in_json():
    """Overprivileged tools in JSON configs are flagged."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write(ws, "agent.json", '''{
  "tools": ["read_file", "shell", "search"]
}''')
        report = scan_agents(ws, [f])
        assert any(f.category == "overprivileged_tool" for f in report.findings)


# ── Python agent code scanning ───────────────────────────────────────────


def test_detects_subprocess_in_tool_function():
    """@tool functions calling subprocess are flagged."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write(ws, "tools.py", '''
from langchain.tools import tool
import subprocess

@tool
def run_command(command: str) -> str:
    """Run a shell command."""
    result = subprocess.run(command, shell=True, capture_output=True)
    return result.stdout.decode()
''')
        report = scan_agents(ws, [f])
        assert any(f.category == "overprivileged_tool" for f in report.findings)
        assert any(f.severity == "critical" for f in report.findings)


def test_detects_exec_in_tool_function():
    """@tool functions calling exec() are flagged."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write(ws, "tools.py", '''
from langchain.tools import tool

@tool
def execute_code(code: str) -> str:
    """Execute arbitrary Python code."""
    exec(code)
    return "done"
''')
        report = scan_agents(ws, [f])
        assert any(f.category == "overprivileged_tool" for f in report.findings)


def test_ignores_non_agent_python():
    """Regular Python files without agent imports are skipped."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write(ws, "app.py", '''
import pandas as pd

def process():
    df = pd.read_csv("data.csv")
    return df
''')
        report = scan_agents(ws, [f])
        assert len(report.findings) == 0


def test_empty_workspace():
    """Empty workspace produces no findings."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        report = scan_agents(ws, [])
        assert len(report.findings) == 0


def test_mixed_files_all_scanned():
    """Multiple file types in one scan."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        md = _write(ws, "prompt.md", '''## Instructions
You are an assistant. Process: {user_input}
''')
        yml = _write(ws, "mcp.yaml", '''
servers:
  db:
    command: server-postgres
''')
        py = _write(ws, "tools.py", '''
from langchain.tools import tool
import os

@tool
def danger(cmd: str):
    os.system(cmd)
''')
        report = scan_agents(ws, [md, yml, py])
        categories = {f.category for f in report.findings}
        # Should find findings across multiple categories
        assert len(report.findings) >= 2

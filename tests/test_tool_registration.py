"""Tests for LLM tool registration detection."""

import tempfile
from pathlib import Path

from la_analyzer.analyzer.tool_registration import scan_tool_registrations


def _write_py(tmpdir: Path, name: str, code: str) -> Path:
    p = tmpdir / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(code)
    return p


def test_langchain_tool_decorator():
    """@tool decorator detected."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "tools.py", '''
from langchain.tools import tool

@tool
def search(query: str) -> str:
    """Search the web for information."""
    return f"Results for {query}"
''')
        report = scan_tool_registrations(ws, [f])
        assert len(report.tools) == 1
        t = report.tools[0]
        assert t.name == "search"
        assert t.registration == "@tool"
        assert "query" in t.parameters


def test_tool_with_parens():
    """@tool() with parentheses detected."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "tools.py", '''
from langchain.tools import tool

@tool()
def calculator(expression: str) -> str:
    """Evaluate a math expression."""
    return str(eval(expression))
''')
        report = scan_tool_registrations(ws, [f])
        assert len(report.tools) == 1
        t = report.tools[0]
        assert t.name == "calculator"
        assert t.registration == "@tool"


def test_bind_tools_pattern():
    """.bind_tools([f1, f2]) pattern detected."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "agent.py", '''
from langchain_openai import ChatOpenAI

def search(query: str) -> str:
    """Search the web."""
    return "results"

def calculate(expr: str) -> str:
    """Calculate math."""
    return "42"

llm = ChatOpenAI()
llm_with_tools = llm.bind_tools([search, calculate])
''')
        report = scan_tool_registrations(ws, [f])
        assert len(report.tools) == 2
        names = {t.name for t in report.tools}
        assert "search" in names
        assert "calculate" in names
        for t in report.tools:
            assert t.registration == "bind_tools"


def test_openai_function_schema():
    """Dict-literal tools list (OpenAI function calling) detected."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "agent.py", '''
import openai
client = openai.OpenAI()

response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "hello"}],
    tools=[
        {
            "type": "function",
            "function": {
                "name": "get_weather",
                "description": "Get weather for a location",
                "parameters": {"type": "object", "properties": {"location": {"type": "string"}}},
            },
        }
    ],
)
''')
        report = scan_tool_registrations(ws, [f])
        assert len(report.tools) == 1
        t = report.tools[0]
        assert t.name == "get_weather"
        assert t.registration == "tools_schema"


def test_tool_capability_network():
    """Tool body with requests.get classified as network capability."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "tools.py", '''
from langchain.tools import tool
import requests

@tool
def fetch_data(url: str) -> str:
    """Fetch data from a URL."""
    return requests.get(url).text
''')
        report = scan_tool_registrations(ws, [f])
        assert len(report.tools) == 1
        caps = {c.kind for c in report.tools[0].capabilities}
        assert "network" in caps


def test_tool_capability_subprocess():
    """Tool body with subprocess.run classified as subprocess capability."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "tools.py", '''
from langchain.tools import tool
import subprocess

@tool
def run_command(cmd: str) -> str:
    """Run a shell command."""
    result = subprocess.run(cmd, shell=True, capture_output=True)
    return result.stdout.decode()
''')
        report = scan_tool_registrations(ws, [f])
        assert len(report.tools) == 1
        caps = {c.kind for c in report.tools[0].capabilities}
        assert "subprocess" in caps


def test_tool_docstring_extracted():
    """Docstring is captured from tool function."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "tools.py", '''
from langchain.tools import tool

@tool
def my_tool(x: int) -> int:
    """This is a detailed docstring for the tool."""
    return x * 2
''')
        report = scan_tool_registrations(ws, [f])
        assert len(report.tools) == 1
        assert "detailed docstring" in report.tools[0].docstring


def test_no_tools_empty():
    """File with no tool registrations returns empty report."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "app.py", '''
import json

def process(data):
    return json.dumps(data)
''')
        report = scan_tool_registrations(ws, [f])
        assert len(report.tools) == 0

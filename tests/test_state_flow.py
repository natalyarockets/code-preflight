"""Tests for state flow tracing."""

import tempfile
from pathlib import Path

from la_analyzer.analyzer.state_flow import scan_state_flow


def _write_py(tmpdir: Path, name: str, code: str) -> Path:
    p = tmpdir / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(code)
    return p


def test_typeddict_state_detected():
    """TypedDict state class found and keys extracted."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "graph.py", '''
from typing import TypedDict

class AgentState(TypedDict):
    messages: list
    context: str
    result: str

def process(state: AgentState):
    ctx = state.get("context")
    return {"result": "done"}
''')
        report = scan_state_flow(ws, [f])
        assert report.state_class == "AgentState"
        assert "messages" in report.state_keys
        assert "context" in report.state_keys
        assert "result" in report.state_keys


def test_reads_via_get():
    """state.get('key') detected as read."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "graph.py", '''
from typing import TypedDict

class State(TypedDict):
    query: str
    results: list

def search(state: State):
    q = state.get("query")
    return {"results": [q]}
''')
        report = scan_state_flow(ws, [f])
        assert len(report.node_flows) == 1
        nf = report.node_flows[0]
        assert "query" in nf.reads


def test_reads_via_subscript():
    """state['key'] detected as read."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "graph.py", '''
from typing import TypedDict

class State(TypedDict):
    data: str
    output: str

def transform(state: State):
    val = state["data"]
    return {"output": val.upper()}
''')
        report = scan_state_flow(ws, [f])
        assert len(report.node_flows) == 1
        nf = report.node_flows[0]
        assert "data" in nf.reads


def test_writes_via_return_dict():
    """return {'key': val} detected as write."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "graph.py", '''
from typing import TypedDict

class State(TypedDict):
    input: str
    output: str
    status: str

def process(state: State):
    val = state.get("input")
    return {"output": val, "status": "done"}
''')
        report = scan_state_flow(ws, [f])
        assert len(report.node_flows) == 1
        nf = report.node_flows[0]
        assert "output" in nf.writes
        assert "status" in nf.writes
        assert "input" in nf.reads


def test_multiple_nodes():
    """Multiple functions with different reads/writes."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "graph.py", '''
from typing import TypedDict

class WorkflowState(TypedDict):
    question: str
    context: str
    answer: str

def retrieve(state: WorkflowState):
    q = state.get("question")
    return {"context": "some context"}

def generate(state: WorkflowState):
    ctx = state["context"]
    q = state.get("question")
    return {"answer": f"Answer based on {ctx}"}
''')
        report = scan_state_flow(ws, [f])
        assert len(report.node_flows) == 2

        retrieve = next(nf for nf in report.node_flows if nf.function == "retrieve")
        assert "question" in retrieve.reads
        assert "context" in retrieve.writes

        generate = next(nf for nf in report.node_flows if nf.function == "generate")
        assert "context" in generate.reads
        assert "question" in generate.reads
        assert "answer" in generate.writes


def test_no_state_pattern_empty():
    """File without state patterns returns empty report."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "app.py", '''
def process(data):
    return data.upper()
''')
        report = scan_state_flow(ws, [f])
        assert report.state_class == ""
        assert len(report.node_flows) == 0

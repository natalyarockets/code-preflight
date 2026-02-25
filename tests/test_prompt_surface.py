"""Tests for LLM prompt surface detection."""

import tempfile
from pathlib import Path

from la_analyzer.analyzer.prompt_surface import scan_prompt_surfaces


def _write_py(tmpdir: Path, name: str, code: str) -> Path:
    p = tmpdir / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(code)
    return p


def test_fstring_variables():
    """f-string with {var} extracts variable names."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "agent.py", '''
from langchain_openai import ChatOpenAI
llm = ChatOpenAI()

def build_prompt(context, user_input):
    prompt = f"Context: {context}\\nQuestion: {user_input}"
    result = llm.invoke(prompt)
    return result
''')
        report = scan_prompt_surfaces(ws, [f])
        assert len(report.surfaces) == 1
        s = report.surfaces[0]
        assert s.llm_method == "invoke"
        var_names = {v.name for v in s.prompt_variables}
        assert "context" in var_names
        assert "user_input" in var_names


def test_concatenation_prompt():
    """a + b + 'literal' extracts all variable parts."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "agent.py", '''
from langchain_openai import ChatOpenAI
llm = ChatOpenAI()

def make_prompt(header, body):
    prompt = header + " " + body
    result = llm.invoke(prompt)
    return result
''')
        report = scan_prompt_surfaces(ws, [f])
        assert len(report.surfaces) == 1
        var_names = {v.name for v in report.surfaces[0].prompt_variables}
        assert "header" in var_names
        assert "body" in var_names


def test_format_prompt():
    """.format(key=val) extracts keyword arg names."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "agent.py", '''
from langchain_openai import ChatOpenAI
llm = ChatOpenAI()

def ask(question, context):
    prompt = "Q: {question}\\nContext: {context}".format(question=question, context=context)
    return llm.invoke(prompt)
''')
        report = scan_prompt_surfaces(ws, [f])
        assert len(report.surfaces) == 1
        var_names = {v.name for v in report.surfaces[0].prompt_variables}
        assert "question" in var_names
        assert "context" in var_names


def test_backward_variable_tracing():
    """Variable assigned then used in invoke() is traced back."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "agent.py", '''
from langchain_openai import ChatOpenAI
llm = ChatOpenAI()

def process(data):
    prompt = f"Analyze this: {data}"
    result = llm.invoke(prompt)
    return result
''')
        report = scan_prompt_surfaces(ws, [f])
        assert len(report.surfaces) == 1
        var_names = {v.name for v in report.surfaces[0].prompt_variables}
        assert "data" in var_names


def test_string_constant_detected():
    """Module-level string constant used in prompt is detected."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "agent.py", '''
from langchain_openai import ChatOpenAI
llm = ChatOpenAI()

BASE_PROMPT = "You are a helpful assistant."

def ask(question):
    prompt = BASE_PROMPT + question
    return llm.invoke(prompt)
''')
        report = scan_prompt_surfaces(ws, [f])
        assert len(report.surfaces) == 1
        s = report.surfaces[0]
        assert "BASE_PROMPT" in s.string_constants
        var_names = {v.name for v in s.prompt_variables}
        assert "question" in var_names


def test_lambda_wrapped_call():
    """LLM call inside lambda: retry_with_backoff(lambda: llm.invoke(...))."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "agent.py", '''
from langchain_openai import ChatOpenAI
llm = ChatOpenAI()

def retry_with_backoff(fn):
    return fn()

def process(data):
    prompt = f"Process: {data}"
    result = retry_with_backoff(lambda: llm.invoke(prompt))
    return result
''')
        report = scan_prompt_surfaces(ws, [f])
        # Should detect the invoke inside the lambda
        assert len(report.surfaces) >= 1


def test_langchain_invoke_pattern():
    """llm.invoke([HumanMessage(content=prompt)]) pattern."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "agent.py", '''
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage
llm = ChatOpenAI()

def ask(question):
    return llm.invoke([HumanMessage(content=question)])
''')
        report = scan_prompt_surfaces(ws, [f])
        assert len(report.surfaces) == 1
        var_names = {v.name for v in report.surfaces[0].prompt_variables}
        assert "question" in var_names


def test_openai_create_pattern():
    """client.chat.completions.create(messages=[...]) pattern."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "agent.py", '''
import openai
client = openai.OpenAI()

def ask(prompt_text):
    return client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt_text}],
    )
''')
        report = scan_prompt_surfaces(ws, [f])
        assert len(report.surfaces) == 1
        var_names = {v.name for v in report.surfaces[0].prompt_variables}
        assert "prompt_text" in var_names


def test_no_llm_calls_empty():
    """File with no LLM imports returns empty report."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "app.py", '''
import json

def process(data):
    return json.dumps(data)
''')
        report = scan_prompt_surfaces(ws, [f])
        assert len(report.surfaces) == 0


def test_scope_aware_constants_local_not_module():
    """Local function assignments should NOT be confused with module-level constants."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "agent.py", '''
from langchain_openai import ChatOpenAI
llm = ChatOpenAI()

MODULE_CONST = "This is a module-level constant."

def process(user_input):
    # LOCAL assignment — should be treated as a variable, not a constant
    local_prefix = "Processing: "
    prompt = f"{local_prefix}{user_input}"
    return llm.invoke(prompt)
''')
        report = scan_prompt_surfaces(ws, [f])
        assert len(report.surfaces) >= 1
        s = report.surfaces[0]
        # MODULE_CONST should be in string_constants
        # local_prefix is local — may appear as a var or not, but not as string_constant
        # user_input should be in prompt_variables
        var_names = {v.name for v in s.prompt_variables}
        assert "user_input" in var_names
        # local_prefix should NOT appear as a string constant (it's local, not module-level)
        assert "local_prefix" not in s.string_constants


def test_worklist_depth_5_levels():
    """Variable chain 5+ levels deep should resolve correctly with worklist."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "agent.py", '''
from langchain_openai import ChatOpenAI
llm = ChatOpenAI()

def process(raw_input):
    v1 = raw_input
    v2 = v1
    v3 = v2
    v4 = v3
    v5 = v4
    result = llm.invoke(v5)
    return result
''')
        report = scan_prompt_surfaces(ws, [f])
        assert len(report.surfaces) >= 1
        # Should trace back through 5 levels to find raw_input
        var_names = {v.name for v in report.surfaces[0].prompt_variables}
        assert "raw_input" in var_names


def test_graph_app_ainvoke_not_flagged():
    """graph_app.ainvoke(state) should NOT be flagged as an LLM call site."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "workflow.py", '''
from langchain_openai import ChatOpenAI
from langgraph.graph import StateGraph

llm = ChatOpenAI()

class State(dict):
    pass

graph = StateGraph(State)
graph_app = graph.compile()

async def run_workflow(user_input):
    # This is a graph invocation — NOT an LLM call
    result = await graph_app.ainvoke({"input": user_input})
    return result
''')
        report = scan_prompt_surfaces(ws, [f])
        # Should not have any surface for graph_app.ainvoke
        graph_surfaces = [s for s in report.surfaces if "ainvoke" in s.llm_method.lower()]
        assert len(graph_surfaces) == 0

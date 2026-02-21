"""Tests for egress/outbound call detection."""

import tempfile
from pathlib import Path

from la_analyzer.analyzer.egress_scan import scan_egress


def _write_py(tmpdir: Path, name: str, code: str) -> Path:
    p = tmpdir / name
    p.write_text(code)
    return p


def test_detects_openai_usage():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "llm.py", '''
import openai
client = openai.OpenAI()
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "hello"}],
)
''')
        report = scan_egress(ws, [f])
        assert any(c.kind == "llm_sdk" and c.library == "openai" for c in report.outbound_calls)
        assert report.suggested_gateway_needs.needs_llm_gateway is True
        assert "gpt-4o" in report.suggested_gateway_needs.requested_models


def test_detects_anthropic_usage():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "llm.py", '''
import anthropic
client = anthropic.Anthropic()
msg = client.messages.create(
    model="claude-sonnet-4-20250514",
    messages=[{"role": "user", "content": "hello"}],
)
''')
        report = scan_egress(ws, [f])
        assert any(c.kind == "llm_sdk" and c.library == "anthropic" for c in report.outbound_calls)
        assert report.suggested_gateway_needs.needs_llm_gateway is True


def test_detects_requests_get():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "api.py", '''
import requests
resp = requests.get("https://api.example.com/data")
data = resp.json()
''')
        report = scan_egress(ws, [f])
        assert any(c.kind == "http" and c.library == "requests" for c in report.outbound_calls)
        assert report.suggested_gateway_needs.needs_external_api_gateway is True


def test_detects_httpx():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "api.py", '''
import httpx
resp = httpx.get("https://api.internal.com/v1/data")
''')
        report = scan_egress(ws, [f])
        assert any(c.library == "httpx" for c in report.outbound_calls)


def test_detects_supabase():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "db.py", '''
from supabase import create_client
client = create_client("https://abc.supabase.co", "key")
data = client.table("users").select("*").execute()
''')
        report = scan_egress(ws, [f])
        assert any(c.kind == "baas" and c.library == "supabase" for c in report.outbound_calls)


def test_detects_psycopg2():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "db.py", '''
import psycopg2
conn = psycopg2.connect("dbname=test")
cur = conn.cursor()
cur.execute("SELECT * FROM users")
rows = cur.fetchall()
''')
        report = scan_egress(ws, [f])
        assert any(c.kind == "database" and c.library == "psycopg2" for c in report.outbound_calls)


def test_detects_sqlalchemy():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "db.py", '''
from sqlalchemy import create_engine, text
engine = create_engine("postgresql://localhost/mydb")
with engine.connect() as conn:
    result = conn.execute(text("SELECT 1"))
''')
        report = scan_egress(ws, [f])
        assert any(c.kind == "database" and c.library == "sqlalchemy" for c in report.outbound_calls)


def test_detects_boto3_as_cloud():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "s3.py", '''
import boto3
s3 = boto3.client("s3")
s3.upload_file("local.txt", "my-bucket", "remote.txt")
''')
        report = scan_egress(ws, [f])
        assert any(c.kind == "cloud" and c.library == "boto3" for c in report.outbound_calls)


def test_detects_constant_assigned_model():
    """model=EMBEDDING_MODEL where EMBEDDING_MODEL = "text-embedding-3-small" should be detected."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "embed.py", '''
import openai

EMBEDDING_MODEL = "text-embedding-3-small"
client = openai.OpenAI()
resp = client.embeddings.create(model=EMBEDDING_MODEL, input="hello")
''')
        report = scan_egress(ws, [f])
        assert "text-embedding-3-small" in report.suggested_gateway_needs.requested_models


def test_detects_embedding_model_literal():
    """Embedding model names in string literals should be detected."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "embed.py", '''
import openai
client = openai.OpenAI()
resp = client.embeddings.create(model="text-embedding-3-small", input="hello")
''')
        report = scan_egress(ws, [f])
        assert "text-embedding-3-small" in report.suggested_gateway_needs.requested_models


def test_detects_gemini_model():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "app.py", '''
MODEL = "gemini-1.5-pro"
''')
        report = scan_egress(ws, [f])
        assert "gemini-1.5-pro" in report.suggested_gateway_needs.requested_models


def test_dynamic_sdk_class_variable():
    """SDK class assigned to a variable (dynamic dispatch) should register egress."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "dispatch.py", '''
from langchain_anthropic import ChatAnthropic

provider_cls = ChatAnthropic
client = provider_cls(model="claude-sonnet-4-20250514")
''')
        report = scan_egress(ws, [f])
        assert any(
            c.kind == "llm_sdk" and c.library == "langchain_anthropic"
            for c in report.outbound_calls
        )


def test_dynamic_sdk_class_in_list():
    """SDK classes in a list should be detected as egress."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "multi.py", '''
from langchain_openai import ChatOpenAI
from langchain_anthropic import ChatAnthropic

providers = [ChatOpenAI, ChatAnthropic]
''')
        report = scan_egress(ws, [f])
        libs = {c.library for c in report.outbound_calls}
        assert "langchain_openai" in libs
        assert "langchain_anthropic" in libs


def test_dynamic_sdk_class_in_dict():
    """SDK classes in a dict should be detected as egress."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "mapping.py", '''
from langchain_openai import ChatOpenAI
from langchain_anthropic import ChatAnthropic

MODEL_MAP = {"gpt": ChatOpenAI, "claude": ChatAnthropic}
''')
        report = scan_egress(ws, [f])
        libs = {c.library for c in report.outbound_calls}
        assert "langchain_openai" in libs
        assert "langchain_anthropic" in libs


def test_dynamic_sdk_class_in_tuple_list():
    """SDK classes nested inside tuples within a list (common dispatch pattern)."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "llm_select.py", '''
from langchain_openai import ChatOpenAI
from langchain_anthropic import ChatAnthropic

model_options = [
    ("gpt-4o", ChatOpenAI),
    ("gpt-3.5-turbo-0125", ChatOpenAI),
    ("claude-3-opus-20240229", ChatAnthropic),
    ("claude-3-5-sonnet-20241022", ChatAnthropic),
]
''')
        report = scan_egress(ws, [f])
        libs = {c.library for c in report.outbound_calls}
        assert "langchain_openai" in libs
        assert "langchain_anthropic" in libs


def test_dynamic_sdk_class_in_annotated_assignment():
    """SDK classes in type-annotated list assignment (AnnAssign)."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "llm_select.py", '''
from typing import List, Tuple, Type
from langchain_openai import ChatOpenAI
from langchain_anthropic import ChatAnthropic

model_options: List[Tuple[str, Type]] = [
    ("gpt-4o", ChatOpenAI),
    ("claude-3-5-sonnet", ChatAnthropic),
]
''')
        report = scan_egress(ws, [f])
        libs = {c.library for c in report.outbound_calls}
        assert "langchain_openai" in libs
        assert "langchain_anthropic" in libs


def test_no_egress():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "pure.py", '''
def add(a, b):
    return a + b
''')
        report = scan_egress(ws, [f])
        assert len(report.outbound_calls) == 0
        assert report.suggested_gateway_needs.needs_llm_gateway is False

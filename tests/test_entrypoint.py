"""Tests for entrypoint detection."""

import tempfile
from pathlib import Path

from la_analyzer.analyzer.entrypoint import scan_entrypoints


def _write_py(tmpdir: Path, name: str, code: str) -> Path:
    p = tmpdir / name
    p.write_text(code)
    return p


def test_detects_main_guard():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "app.py", '''
def main():
    print("hello")

if __name__ == "__main__":
    main()
''')
        candidates = scan_entrypoints(ws, [f])
        assert len(candidates) >= 1
        assert candidates[0].confidence >= 0.7
        assert "app.py" in candidates[0].value


def test_detects_argparse():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "cli.py", '''
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--input")
args = parser.parse_args()
print(args.input)
''')
        candidates = scan_entrypoints(ws, [f])
        assert len(candidates) >= 1
        assert any("cli.py" in c.value for c in candidates)


def test_main_guard_plus_argparse_high_confidence():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "main.py", '''
import argparse

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--file")
    args = parser.parse_args()

if __name__ == "__main__":
    main()
''')
        candidates = scan_entrypoints(ws, [f])
        assert candidates[0].confidence >= 0.9


def test_no_entrypoint():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "utils.py", '''
def helper():
    return 42
''')
        candidates = scan_entrypoints(ws, [f])
        assert len(candidates) == 0


def test_fastapi_generates_uvicorn_entrypoint():
    """FastAPI app should produce a uvicorn entrypoint at 0.85 confidence."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "main.py", '''
from fastapi import FastAPI

app = FastAPI()

@app.get("/health")
def health():
    return {"status": "ok"}
''')
        candidates = scan_entrypoints(ws, [f])
        assert len(candidates) >= 1
        top = candidates[0]
        assert top.value == "uvicorn main:app"
        assert top.confidence == 0.85


def test_fastapi_subdirectory_module_path():
    """FastAPI in a subdirectory should produce dotted module path."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        subdir = ws / "src"
        subdir.mkdir()
        f = _write_py(subdir, "server.py", '''
from fastapi import FastAPI

application = FastAPI()

@application.post("/predict")
async def predict(data: dict):
    return {"result": 42}
''')
        candidates = scan_entrypoints(ws, [f])
        assert len(candidates) >= 1
        top = candidates[0]
        assert top.value == "uvicorn src.server:application"
        assert top.confidence == 0.85


def test_fastapi_skips_generic_python_fallback():
    """FastAPI app.py should NOT also produce a lower-confidence python fallback."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "app.py", '''
from fastapi import FastAPI
app = FastAPI()

@app.get("/")
def root():
    return {"msg": "hello"}
''')
        candidates = scan_entrypoints(ws, [f])
        # Should only have the uvicorn candidate, not a python app.py one
        python_candidates = [c for c in candidates if c.value.startswith("python ")]
        assert len(python_candidates) == 0
        uvicorn_candidates = [c for c in candidates if c.value.startswith("uvicorn ")]
        assert len(uvicorn_candidates) == 1

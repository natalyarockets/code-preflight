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

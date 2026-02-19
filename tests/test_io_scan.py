"""Tests for I/O pattern detection."""

import tempfile
from pathlib import Path

from la_analyzer.analyzer.io_scan import scan_io


def _write_py(tmpdir: Path, name: str, code: str) -> Path:
    p = tmpdir / name
    p.write_text(code)
    return p


def test_detects_open_read():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "reader.py", '''
with open("data/input.csv") as f:
    data = f.read()
''')
        report = scan_io(ws, [f])
        assert len(report.inputs) >= 1
        assert report.inputs[0].format == "csv"
        assert report.inputs[0].path_literal == "data/input.csv"


def test_detects_open_write():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "writer.py", '''
with open("output/result.json", "w") as f:
    f.write("{}")
''')
        report = scan_io(ws, [f])
        assert len(report.outputs) >= 1
        assert report.outputs[0].format == "json"


def test_detects_pandas_read_csv():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "loader.py", '''
import pandas as pd
df = pd.read_csv("data/sales.csv")
''')
        report = scan_io(ws, [f])
        assert any(i.path_literal == "data/sales.csv" for i in report.inputs)


def test_detects_pandas_to_csv():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "saver.py", '''
import pandas as pd
df = pd.DataFrame({"a": [1]})
df.to_csv("output/results.csv", index=False)
''')
        report = scan_io(ws, [f])
        assert any(o.path_literal == "output/results.csv" for o in report.outputs)


def test_detects_savefig():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "plot.py", '''
import matplotlib.pyplot as plt
plt.plot([1, 2, 3])
plt.savefig("output/chart.png")
''')
        report = scan_io(ws, [f])
        assert any(o.path_literal == "output/chart.png" for o in report.outputs)


def test_argparse_directory_default_no_crash():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "app.py", '''
import argparse
parser = argparse.ArgumentParser()
parser.add_argument("--output-dir", default="/outputs")
args = parser.parse_args()
''')
        report = scan_io(ws, [f])
        # Should not crash -- directory format is valid
        dir_outputs = [o for o in report.outputs if o.format == "directory"]
        # The argparse default "/outputs" may or may not produce an output entry,
        # but parsing must not crash
        assert isinstance(report, type(report))  # no crash


def test_hardcoded_paths_tracked():
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        f = _write_py(ws, "app.py", '''
with open("config/settings.json") as f:
    cfg = f.read()
''')
        report = scan_io(ws, [f])
        assert any(h.path == "config/settings.json" for h in report.hardcoded_paths)

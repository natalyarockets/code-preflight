"""Tests for call graph construction and effect projection."""

import tempfile
from pathlib import Path

from la_analyzer.analyzer.call_graph import build_call_graph, reachable_from
from la_analyzer.analyzer.models import (
    AnalysisResult,
    DetectionReport,
    EntrypointCandidate,
    Evidence,
    IOInput,
    IOReport,
    EgressReport,
    OutboundCall,
    SecretsReport,
    SecretFinding,
)
from la_analyzer.analyzer.projection import (
    build_projection,
    enrich_evidence_with_functions,
)


def _write(tmpdir: Path, name: str, content: str) -> Path:
    p = tmpdir / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    return p


# ── Call Graph Tests ──────────────────────────────────────────────────────


def test_single_file_call_graph():
    """Functions and calls within a single file are detected."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        _write(ws, "app.py", '''
def helper():
    return 42

def main():
    x = helper()
    print(x)

if __name__ == "__main__":
    main()
''')
        detection = DetectionReport(
            entrypoint_candidates=[
                EntrypointCandidate(
                    kind="command", value="python app.py", confidence=1.0,
                    evidence=[Evidence(file="app.py", line=9, snippet="if __name__")],
                ),
            ],
        )
        py_files = [ws / "app.py"]
        graph = build_call_graph(ws, py_files, detection)

        fn_names = {fn.name for fn in graph.functions}
        assert "helper" in fn_names
        assert "main" in fn_names
        assert "<module>" in fn_names

        # Should have edges: <module> -> main, main -> helper
        caller_callee = {(e.caller, e.callee) for e in graph.edges}
        assert any("main" in callee for _, callee in caller_callee)


def test_cross_file_call_graph():
    """Cross-file imports are resolved in the call graph."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        _write(ws, "utils.py", '''
def compute(x):
    return x * 2
''')
        _write(ws, "main.py", '''
from utils import compute

def run():
    result = compute(5)
    return result

if __name__ == "__main__":
    run()
''')
        detection = DetectionReport(
            entrypoint_candidates=[
                EntrypointCandidate(
                    kind="command", value="python main.py", confidence=1.0,
                    evidence=[Evidence(file="main.py", line=7, snippet="if __name__")],
                ),
            ],
        )
        py_files = [ws / "main.py", ws / "utils.py"]
        graph = build_call_graph(ws, py_files, detection)

        # Verify cross-file edge exists
        callee_files = set()
        for edge in graph.edges:
            if "run" in edge.caller:
                callee_files.add(edge.callee.split("::")[0])

        assert "utils.py" in callee_files


def test_class_method_detection():
    """Class methods are detected with Class.method naming."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        _write(ws, "models.py", '''
class Processor:
    def process(self, data):
        return self.transform(data)

    def transform(self, data):
        return data.upper()
''')
        detection = DetectionReport()
        py_files = [ws / "models.py"]
        graph = build_call_graph(ws, py_files, detection)

        fn_names = {fn.name for fn in graph.functions}
        assert "Processor.process" in fn_names
        assert "Processor.transform" in fn_names


def test_entrypoint_identification():
    """Entrypoints from detection report are marked."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        _write(ws, "main.py", '''
def do_work():
    pass

if __name__ == "__main__":
    do_work()
''')
        detection = DetectionReport(
            entrypoint_candidates=[
                EntrypointCandidate(
                    kind="command", value="python main.py", confidence=1.0,
                    evidence=[Evidence(file="main.py", line=4, snippet="if __name__")],
                ),
            ],
        )
        py_files = [ws / "main.py"]
        graph = build_call_graph(ws, py_files, detection)

        assert "main.py::<module>" in graph.entrypoint_ids
        ep_node = next(fn for fn in graph.functions if fn.id == "main.py::<module>")
        assert ep_node.is_entrypoint is True


def test_bfs_reachability():
    """BFS returns all reachable functions from entrypoint."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        _write(ws, "app.py", '''
def a():
    b()

def b():
    c()

def c():
    pass

def orphan():
    pass

if __name__ == "__main__":
    a()
''')
        detection = DetectionReport(
            entrypoint_candidates=[
                EntrypointCandidate(
                    kind="command", value="python app.py", confidence=1.0,
                    evidence=[Evidence(file="app.py", line=12, snippet="if __name__")],
                ),
            ],
        )
        py_files = [ws / "app.py"]
        graph = build_call_graph(ws, py_files, detection)

        reachable = reachable_from("app.py::<module>", graph)

        # a, b, c should be reachable; orphan should not
        reachable_names = set()
        for fid in reachable:
            for fn in graph.functions:
                if fn.id == fid:
                    reachable_names.add(fn.name)

        assert "a" in reachable_names
        assert "b" in reachable_names
        assert "c" in reachable_names
        assert "orphan" not in reachable_names


def test_empty_project():
    """Empty project produces empty call graph."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        detection = DetectionReport()
        graph = build_call_graph(ws, [], detection)
        assert graph.functions == []
        assert graph.edges == []
        assert graph.entrypoint_ids == []


def test_syntax_error_skipped():
    """Files with syntax errors are skipped gracefully."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        _write(ws, "bad.py", "def broken(\n")
        _write(ws, "good.py", "def ok():\n    pass\n")
        detection = DetectionReport()
        graph = build_call_graph(ws, [ws / "bad.py", ws / "good.py"], detection)
        fn_names = {fn.name for fn in graph.functions}
        assert "ok" in fn_names


# ── Projection Tests ──────────────────────────────────────────────────────


def test_projection_maps_effects_to_entrypoint():
    """Effects in reachable functions are projected to the entrypoint."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        _write(ws, "main.py", '''
def process():
    pass

if __name__ == "__main__":
    process()
''')
        detection = DetectionReport(
            entrypoint_candidates=[
                EntrypointCandidate(
                    kind="command", value="python main.py", confidence=1.0,
                    evidence=[Evidence(file="main.py", line=5, snippet="if __name__")],
                ),
            ],
        )
        analysis = AnalysisResult(
            detection=detection,
            io=IOReport(inputs=[
                IOInput(
                    id="input_1", kind="file", format="csv",
                    evidence=[Evidence(file="main.py", line=3, snippet="open('data.csv')")],
                ),
            ]),
        )

        py_files = [ws / "main.py"]
        proj = build_projection(ws, py_files, analysis)

        assert len(proj.projections) >= 1
        ep = proj.projections[0]
        assert len(ep.effects) >= 1
        assert any("input_1" in e.title for e in ep.effects)


def test_unreachable_findings_separated():
    """Findings in dead code appear in unreachable_findings."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        _write(ws, "main.py", '''
def used():
    pass

if __name__ == "__main__":
    used()
''')
        _write(ws, "dead.py", '''
def never_called():
    pass
''')
        detection = DetectionReport(
            entrypoint_candidates=[
                EntrypointCandidate(
                    kind="command", value="python main.py", confidence=1.0,
                    evidence=[Evidence(file="main.py", line=5, snippet="if __name__")],
                ),
            ],
        )
        analysis = AnalysisResult(
            detection=detection,
            io=IOReport(inputs=[
                IOInput(
                    id="dead_input", kind="file",
                    evidence=[Evidence(file="dead.py", line=3, snippet="open('x')")],
                ),
            ]),
        )

        py_files = [ws / "main.py", ws / "dead.py"]
        proj = build_projection(ws, py_files, analysis)

        # The dead_input should be in unreachable
        unreachable_titles = [e.title for e in proj.unreachable_findings]
        assert any("dead_input" in t for t in unreachable_titles)


def test_enrich_evidence_adds_function_names():
    """enrich_evidence_with_functions fills in function_name on evidence."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        _write(ws, "app.py", '''
def process_data():
    x = open("data.csv")
    return x

def other():
    pass
''')
        detection = DetectionReport()
        analysis = AnalysisResult(
            detection=detection,
            io=IOReport(inputs=[
                IOInput(
                    id="csv_input", kind="file",
                    evidence=[Evidence(file="app.py", line=3, snippet="open('data.csv')")],
                ),
            ]),
        )

        py_files = [ws / "app.py"]
        from la_analyzer.analyzer.call_graph import build_call_graph
        graph = build_call_graph(ws, py_files, detection)

        enrich_evidence_with_functions(graph, analysis)

        ev = analysis.io.inputs[0].evidence[0]
        assert ev.function_name == "process_data"


def test_projection_with_security_findings():
    """Security findings are included in projection effects."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        _write(ws, "main.py", '''
def run():
    exec("code")

if __name__ == "__main__":
    run()
''')
        detection = DetectionReport(
            entrypoint_candidates=[
                EntrypointCandidate(
                    kind="command", value="python main.py", confidence=1.0,
                    evidence=[Evidence(file="main.py", line=5, snippet="if __name__")],
                ),
            ],
        )
        analysis = AnalysisResult(detection=detection)

        from la_analyzer.security.models import SecurityReport, SecurityFinding, Evidence as SecEvidence
        security = SecurityReport(
            findings=[SecurityFinding(
                category="injection", severity="critical",
                title="exec() usage",
                description="Direct exec call",
                evidence=[SecEvidence(file="main.py", line=3, snippet="exec('code')")],
            )],
            critical_count=1,
        )

        py_files = [ws / "main.py"]
        proj = build_projection(ws, py_files, analysis, security)

        assert len(proj.projections) >= 1
        ep = proj.projections[0]
        assert any("exec" in e.title.lower() for e in ep.effects)


def test_projection_empty_project():
    """Empty project produces empty projection."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        analysis = AnalysisResult(detection=DetectionReport())
        proj = build_projection(ws, [], analysis)
        assert proj.projections == []
        assert proj.unreachable_findings == []

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


def test_decorator_route_handlers_reachable():
    """@app.get decorated functions should have edges from <module>."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        _write(ws, "main.py", '''
from fastapi import FastAPI

app = FastAPI()

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/predict")
async def predict(data: dict):
    return process(data)

def process(data):
    return {"result": 42}
''')
        detection = DetectionReport(
            entrypoint_candidates=[
                EntrypointCandidate(
                    kind="command", value="uvicorn main:app", confidence=0.85,
                    evidence=[Evidence(file="main.py", line=4, snippet="app = FastAPI()")],
                ),
            ],
        )
        py_files = [ws / "main.py"]
        graph = build_call_graph(ws, py_files, detection)

        # Route handlers should have edges from <module>
        module_edges = {e.callee for e in graph.edges if e.caller == "main.py::<module>"}
        assert "main.py::health" in module_edges
        assert "main.py::predict" in module_edges

        # BFS from <module> should reach health, predict, and process
        reachable = reachable_from("main.py::<module>", graph)
        reachable_names = set()
        for fid in reachable:
            for fn in graph.functions:
                if fn.id == fid:
                    reachable_names.add(fn.name)
        assert "health" in reachable_names
        assert "predict" in reachable_names
        assert "process" in reachable_names


def test_langgraph_add_node_reachable():
    """graph.add_node("name", func) makes func reachable from <module>."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        _write(ws, "nodes.py", '''
def ask_for_aircraft_type(state):
    return {"question": "What aircraft?"}

def do_research(state):
    return {"result": "research done"}

def summarize(state):
    return {"summary": "done"}
''')
        _write(ws, "graph.py", '''
from langgraph.graph import StateGraph
from nodes import ask_for_aircraft_type, do_research, summarize

graph = StateGraph()
graph.add_node("ask", ask_for_aircraft_type)
graph.add_node("research", do_research)
graph.add_node("summarize", summarize)
app = graph.compile()
''')
        detection = DetectionReport(
            entrypoint_candidates=[
                EntrypointCandidate(
                    kind="command", value="python graph.py", confidence=1.0,
                    evidence=[Evidence(file="graph.py", line=1, snippet="graph")],
                ),
            ],
        )
        py_files = [ws / "graph.py", ws / "nodes.py"]
        graph = build_call_graph(ws, py_files, detection)

        reachable = reachable_from("graph.py::<module>", graph)
        reachable_names = set()
        for fid in reachable:
            for fn in graph.functions:
                if fn.id == fid:
                    reachable_names.add(fn.name)

        assert "ask_for_aircraft_type" in reachable_names
        assert "do_research" in reachable_names
        assert "summarize" in reachable_names


def test_celery_task_decorator_reachable():
    """@app.task decorator makes the function reachable from <module>."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        _write(ws, "tasks.py", '''
from celery import Celery

app = Celery("myapp")

@app.task
def send_email(to, subject):
    pass

@app.task()
def process_report(report_id):
    pass
''')
        detection = DetectionReport()
        py_files = [ws / "tasks.py"]
        graph = build_call_graph(ws, py_files, detection)

        module_edges = {e.callee for e in graph.edges if e.caller == "tasks.py::<module>"}
        assert "tasks.py::send_email" in module_edges
        assert "tasks.py::process_report" in module_edges


def test_django_path_reachable():
    """path("url/", view_func) makes view_func reachable from <module>."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        _write(ws, "views.py", '''
def index(request):
    return "hello"

def detail(request, pk):
    return "detail"
''')
        _write(ws, "urls.py", '''
from views import index, detail

urlpatterns = [
    path("", index),
    path("detail/<int:pk>/", detail),
]
''')
        detection = DetectionReport()
        py_files = [ws / "urls.py", ws / "views.py"]
        graph = build_call_graph(ws, py_files, detection)

        module_edges = {e.callee for e in graph.edges if e.caller == "urls.py::<module>"}
        assert "views.py::index" in module_edges
        assert "views.py::detail" in module_edges


def test_event_on_handler_reachable():
    """emitter.on("event", handler) makes handler reachable from <module>."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        _write(ws, "app.py", '''
def on_connect(data):
    pass

def on_message(data):
    pass

sio.on("connect", on_connect)
sio.on("message", on_message)
''')
        detection = DetectionReport()
        py_files = [ws / "app.py"]
        graph = build_call_graph(ws, py_files, detection)

        module_edges = {e.callee for e in graph.edges if e.caller == "app.py::<module>"}
        assert "app.py::on_connect" in module_edges
        assert "app.py::on_message" in module_edges


def test_callback_cross_file():
    """graph.add_node("x", imported_func) resolves cross-file."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        _write(ws, "handlers.py", '''
def handle_query(state):
    return {"answer": "42"}
''')
        _write(ws, "main.py", '''
from handlers import handle_query

graph.add_node("query", handle_query)
''')
        detection = DetectionReport()
        py_files = [ws / "main.py", ws / "handlers.py"]
        graph = build_call_graph(ws, py_files, detection)

        module_edges = {e.callee for e in graph.edges if e.caller == "main.py::<module>"}
        assert "handlers.py::handle_query" in module_edges


def test_import_execution_edges():
    """Importing from a file creates <module> -> <module> edge (Python runs module code on import)."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        _write(ws, "config.py", '''
DB_URL = "sqlite:///app.db"
''')
        _write(ws, "helpers.py", '''
def compute(x):
    return x * 2
''')
        _write(ws, "main.py", '''
from config import DB_URL
from helpers import compute

def run():
    return compute(5)

if __name__ == "__main__":
    run()
''')
        detection = DetectionReport(
            entrypoint_candidates=[
                EntrypointCandidate(
                    kind="command", value="python main.py", confidence=1.0,
                    evidence=[Evidence(file="main.py", line=8, snippet="if __name__")],
                ),
            ],
        )
        py_files = [ws / "main.py", ws / "config.py", ws / "helpers.py"]
        graph = build_call_graph(ws, py_files, detection)

        # main.py imports from config.py and helpers.py, so their <module> scopes are reachable
        reachable = reachable_from("main.py::<module>", graph)
        assert "config.py::<module>" in reachable
        assert "helpers.py::<module>" in reachable


def test_transitive_import_execution():
    """Import chains propagate: A imports B imports C -> C's <module> reachable from A."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        _write(ws, "deep.py", '''
SECRET = "very_deep"
''')
        _write(ws, "middle.py", '''
from deep import SECRET
WRAPPED = f"[{SECRET}]"
''')
        _write(ws, "entry.py", '''
from middle import WRAPPED

def go():
    print(WRAPPED)

if __name__ == "__main__":
    go()
''')
        detection = DetectionReport(
            entrypoint_candidates=[
                EntrypointCandidate(
                    kind="command", value="python entry.py", confidence=1.0,
                    evidence=[Evidence(file="entry.py", line=7, snippet="if __name__")],
                ),
            ],
        )
        py_files = [ws / "entry.py", ws / "middle.py", ws / "deep.py"]
        graph = build_call_graph(ws, py_files, detection)

        reachable = reachable_from("entry.py::<module>", graph)
        assert "middle.py::<module>" in reachable
        assert "deep.py::<module>" in reachable


def test_lambda_body_calls_attributed_to_enclosing():
    """Calls inside lambda args are attributed to the enclosing function."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        _write(ws, "utils.py", '''
def retry_with_backoff(fn, retries=3):
    for i in range(retries):
        try:
            return fn()
        except Exception:
            pass
''')
        _write(ws, "llm_client.py", '''
def get_llm():
    return "llm"
''')
        _write(ws, "app.py", '''
from utils import retry_with_backoff
from llm_client import get_llm

def build_report(data):
    llm = get_llm()
    result = retry_with_backoff(lambda: process(data))
    return result

def process(data):
    return data.upper()

if __name__ == "__main__":
    build_report("test")
''')
        detection = DetectionReport(
            entrypoint_candidates=[
                EntrypointCandidate(
                    kind="command", value="python app.py", confidence=1.0,
                    evidence=[Evidence(file="app.py", line=11, snippet="if __name__")],
                ),
            ],
        )
        py_files = [ws / "app.py", ws / "utils.py", ws / "llm_client.py"]
        graph = build_call_graph(ws, py_files, detection)

        # build_report should have an edge to process() (inside the lambda)
        build_report_edges = {
            e.callee for e in graph.edges if e.caller == "app.py::build_report"
        }
        assert "app.py::process" in build_report_edges

        # process should be reachable from entrypoint via build_report
        reachable = reachable_from("app.py::<module>", graph)
        reachable_names = set()
        for fid in reachable:
            for fn in graph.functions:
                if fn.id == fid:
                    reachable_names.add(fn.name)
        assert "process" in reachable_names
        assert "build_report" in reachable_names


def test_lambda_cross_file_call():
    """Calls inside lambdas resolve cross-file imports."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        _write(ws, "remote.py", '''
def do_work(x):
    return x * 2
''')
        _write(ws, "main.py", '''
from remote import do_work

def run():
    result = apply(lambda: do_work(42))
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
        py_files = [ws / "main.py", ws / "remote.py"]
        graph = build_call_graph(ws, py_files, detection)

        # run() should have an edge to do_work() via the lambda
        run_edges = {e.callee for e in graph.edges if e.caller == "main.py::run"}
        assert "remote.py::do_work" in run_edges


def test_flask_decorator_route_handlers():
    """Flask @app.route decorated functions should also get edges."""
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        _write(ws, "app.py", '''
from flask import Flask

app = Flask(__name__)

@app.route("/")
def index():
    return "hello"

@app.route("/api", methods=["POST"])
def api():
    return "ok"
''')
        detection = DetectionReport()
        py_files = [ws / "app.py"]
        graph = build_call_graph(ws, py_files, detection)

        module_edges = {e.callee for e in graph.edges if e.caller == "app.py::<module>"}
        assert "app.py::index" in module_edges
        assert "app.py::api" in module_edges


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

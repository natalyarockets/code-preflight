# LA Analyzer

Pre-flight scanner for Python projects. Analyzes your code without running it and produces a report covering structure, dependencies, I/O, external connections, secrets, security risks, and per-entrypoint effect projection.

Three-phase pipeline:
1. **Structural analysis** -- what the code does (entrypoints, I/O, egress, secrets, deps)
2. **Security review** -- what could go wrong (injection, data flow, credential leaks, agent risks)
3. **Effect projection** -- what actually runs (call graph reachability from each entrypoint, dead code separation)

## Install

```bash
pip install .
```

For PDF output: `pip install ".[pdf]"`

## Usage

```bash
la-scan /path/to/project           # Markdown to stdout
la-scan project -o report.md       # Markdown to file
la-scan project -f json            # JSON to stdout
la-scan project -f pdf -o out.pdf  # PDF (requires .[pdf])
la-scan project --no-security      # Skip security + projection (faster)
la-scan project --json-dir /tmp/r  # Custom directory for raw JSON reports
la-scan project -v                 # Verbose logging
```

### Options

| Flag | Description |
|---|---|
| `-f`, `--format` | `md` (default), `json`, or `pdf` |
| `-o`, `--output` | Output file path (default: stdout for md/json) |
| `--no-security` | Skip security scanners (analysis only) |
| `--json-dir` | Directory for raw JSON reports (default: `<project>/.la-analyzer/`) |
| `-v`, `--verbose` | Debug logging |
| `--version` | Show version |

## What it detects

### Phase 1: Structural analysis

**Archetypes and entrypoints.** Identifies whether the project is a batch script, FastAPI web app, or Streamlit app. Finds entrypoint candidates from `if __name__` guards, CLI frameworks (argparse, click, typer, fire), and pyproject.toml console_scripts. Ranks by confidence.

**I/O and data flow.** Detects file reads (pandas, open()), file writes (CSV, JSON, Excel, PNG), argparse arguments, FastAPI request parameters, upload handlers, and response models. Flags hardcoded file paths. Extracts full FastAPI route signatures with input/output mapping.

**External connections.** Catalogs outbound calls: LLM SDKs (OpenAI, Anthropic, Cohere, LangChain), HTTP clients (requests, httpx, aiohttp), databases (psycopg2, SQLAlchemy, pymongo, redis), cloud SDKs (boto3, google-cloud, supabase, firebase). Extracts model names from string literals.

**Secrets.** Finds hardcoded API keys, .env files, token patterns (sk-\*, AKIA\*, ghp\_\*), and suggests environment variable names.

**Dependencies.** Reads requirements.txt, pyproject.toml, and environment.yml. Falls back to import scanning when no manifest exists.

### Phase 2: Security review

**Code injection.** Flags exec(), eval(), os.system(), subprocess, ctypes, pickle, and dynamic imports with severity-based classification.

**Data classification and flow tracing.** Infers PII, financial, health, and credential data from field names and patterns. Traces tainted data from file reads through f-strings and variable assignments to LLM calls, HTTP requests, and file writes. Cross-function analysis: follows data through function parameters and return values.

**Credential leak detection.** Finds secrets flowing to log output, LLM prompts, HTTP request bodies, and output files.

**Dependency vulnerabilities.** pip-audit integration for known CVEs. Typosquat detection using edit distance from popular packages.

**Resource abuse.** Infinite loops (while True without break), fork bombs, unbounded multiprocessing, network calls in tight loops.

**Agent and skill scanning.** Scans Markdown prompt files for template injection (`{user_input}` in system prompts) and credential patterns. Audits YAML/JSON agent configs for overprivileged tools, wildcard permissions, MCP servers without guardrails, and plaintext credentials. Checks Python agent code for `@tool` functions calling subprocess/exec and user input flowing into system messages.

**Gate decision.** Produces PASS, REVIEW REQUIRED, or BLOCKED based on finding severity:

| Gate | Condition |
|---|---|
| **PASS** | No critical or high findings |
| **REVIEW REQUIRED** | High-severity findings present |
| **BLOCKED** | Critical findings present |

### Phase 3: Effect projection

**Call graph.** Parses all function and method definitions across every Python file. Extracts call sites and resolves them: local functions, cross-file imports, class methods. Produces a project-wide caller-callee graph.

**Entrypoint reachability.** BFS from each detected entrypoint to determine which functions are actually reachable at runtime.

**Effect mapping.** Maps every finding from phases 1 and 2 to the entrypoint(s) that can trigger it, using file:line-to-function matching against the reachable set. Findings in unreachable code are separated as dead code.

**Evidence enrichment.** Post-processor adds `function_name` to all evidence objects across every scanner's output, without modifying any scanner code.

## Example

```
$ la-scan examples/sample_batch_app
```

```markdown
# Scan Report: sample_batch_app

- **Archetypes**: python_batch (80%)
- **Python files scanned**: 1
- **Dependencies**: 4
- **Inputs detected**: 1
- **Outputs detected**: 3
- **External connections**: 2
- **Secrets found**: 2
- **Security gate**: PASS

## Entrypoints

| Command / Module | Kind | Confidence | Location |
|---|---|---|---|
| `python main.py` | command | 100% | `main.py:3` |

## External Connections

| Kind | Library | Domains | Confidence |
|---|---|---|---|
| llm_sdk | `openai` | - | 90% |
| http | `requests` | - | 85% |

## Entrypoint Projections

### python main.py

Reachable functions: 5

| Source | Effect | Severity | Location |
|---|---|---|---|
| secret | Secret: hardcoded_key | high | `main.py:13` |
| security | Data flow: uploaded/read file data -> output file | medium | `main.py:57` |
| io | Input: input_0 (file) | info | `main.py:40` |
| egress | Egress: openai (llm_sdk) | info | `main.py:23` |
| egress | Egress: requests (http) | info | `main.py:33` |

### Unreachable Findings (dead code)

| Source | Effect | Severity | Location |
|---|---|---|---|
| secret | Secret: dotenv_file | high | `.env:1` |
```

## Library API

```python
from pathlib import Path
from la_analyzer.scanner import scan

result = scan(Path("myproject"))

# Phase 1: structural analysis
result.analysis.detection.archetypes
result.analysis.detection.entrypoint_candidates
result.analysis.io.inputs
result.analysis.io.outputs
result.analysis.io.api_routes
result.analysis.egress.outbound_calls
result.analysis.secrets.findings
result.analysis.deps.dependencies

# Phase 2: security review
result.security.deploy_blocked        # True if critical findings
result.security.requires_review       # True if high findings
result.security.findings              # code injection, resource abuse, vulns
result.security.data_classifications  # PII, financial, health, credential
result.security.data_flow_risks       # source -> sink traces
result.security.credential_leak_risks
result.security.agent_scan            # agent/skill findings (or None)

# Phase 3: effect projection
result.projection.call_graph.functions
result.projection.call_graph.edges
result.projection.projections          # per-entrypoint effects
result.projection.unreachable_findings # dead code findings
```

Run subsystems independently:

```python
from pathlib import Path
from la_analyzer.analyzer.service import analyze_repo
from la_analyzer.security import run_security_review
from la_analyzer.analyzer.projection import build_projection

analysis = analyze_repo(Path("myproject"), Path("/tmp/output"))

security = run_security_review(
    workspace_dir=Path("myproject"),
    analysis_result=analysis,
)
```

## JSON reports

`la-scan` writes raw JSON reports to `<project>/.la-analyzer/`:

| File | Contents |
|---|---|
| `detection_report.json` | Archetypes, entrypoints, Python info |
| `io_report.json` | Inputs, outputs, hardcoded paths, API routes |
| `egress_report.json` | Outbound calls, gateway recommendations |
| `secrets_report.json` | Hardcoded keys, .env files, token patterns |
| `deps_report.json` | Dependencies and sources |
| `porting_plan.json` | Required and optional changes |
| `description_report.json` | README content, module docstrings |
| `security_report.json` | All findings, severity counts, gate decision |
| `livingapps.yaml` | Generated app manifest |

`la-scan -f json` outputs a single JSON document combining `analysis`, `security`, and `projection`.

## Development

```bash
pip install -e ".[dev]"
pytest
```

110 tests across 10 test files. Runs in under a second.

## How it works

Pure static analysis. No code is executed. The scanner walks Python files, parses them into ASTs, and applies pattern-matching to extract structure and detect risks. The call graph resolves cross-file imports and computes reachability to separate real effects from dead code. Agent/skill files (.md, .yaml, .json) are scanned with format-specific heuristics. Files over 2MB and directories like .git, venv, and node_modules are skipped.

Python >=3.11. Only three runtime dependencies: pydantic, pyyaml, click.

## License

Apache 2.0

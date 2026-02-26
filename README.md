# LA Analyzer

Know what your Python project actually does before you deploy it. LA Analyzer scans your code without running it and produces a plain-English report: what data leaves your repo, what secrets are exposed, what could go wrong, and whether it's safe to ship.

Built for people building internal tools with AI coding assistants (Cursor, Claude Code, GitHub Copilot) who want confidence that the code they're deploying is safe. If you can run a terminal command, you can use this.

Three-phase pipeline:
1. **Structural analysis** -- what the code does (entrypoints, I/O, egress, secrets, deps)
2. **Security review** -- what could go wrong (injection, data flow, credential leaks, agent risks, effect graph queries)
3. **Effect projection** -- what actually runs (per-entrypoint reachability, separating real effects from unused code)

## How is this different from Bandit, Semgrep, or Garak?

These tools are all valuable, but they solve adjacent problems:

| Tool | What it does |
|---|---|
| Bandit / Semgrep | Generic Python SAST — pattern-matching rules with no AI-app domain knowledge. Bandit is flow-insensitive and flags every `os.system()` equally. Semgrep is powerful but requires custom rules per-SDK, and neither produces a holistic egress report. |
| Garak / LLM Guard / Vigil / Rebuff | These analyze or guard the **LLM model itself** (adversarial probes, runtime filters). LA Analyzer analyzes the **code that builds the app**, before it ships. |
| pip-audit / Safety | Dependency scanning only — no structural or data-flow analysis. |
| Semgrep with custom rules | Gets you further, but you're writing and maintaining rules per library. LA Analyzer has the AI-app semantic model built in: it knows what `sentry_sdk.init()` does, what `graph_app.ainvoke()` is, and how LangGraph state maps to API routes. |

The specific gap LA Analyzer fills: **static analysis that understands the semantics of building AI apps.** It answers "what data leaves this codebase, to whom, and is it safe to deploy?" — not "does this line match a known bad pattern?"

## Install

```bash
pip install .
```

For PDF reports: `pip install ".[pdf]"`

## Usage

```bash
la-scan ./myproject                          # Markdown to stdout
la-scan ./myproject -o report.md             # Markdown to file
la-scan ./myproject -f pdf -o report.pdf     # PDF report
la-scan ./myproject -f json                  # JSON to stdout
la-scan ./myproject --no-security            # Skip security + projection (faster)
la-scan ./myproject --json-dir /tmp/reports  # Custom directory for raw JSON reports
la-scan ./myproject -v                       # Verbose logging
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

## What you get

The report opens with **"If You Deploy This As-Is"**: a plain-English summary of what happens if you ship the code right now. Then:

- **Security gate** -- PASS, REVIEW REQUIRED, or BLOCKED. The severity count table (Critical / High / Medium / Low) is an exact aggregate of what is listed in Security Findings — every number has a corresponding item below it.
- **Trust boundaries** -- every external service your code talks to (including observability and email), and any hardcoded secrets. Factual data only, no findings.
- **Entrypoint effect matrix** -- what each entrypoint reads, writes, sends, and exposes
- **Security findings** -- detailed findings with severity, description, recommendation, and exact file/line
- **Call graph** -- which functions call which, per entrypoint
- **Recommendations** -- specific changes to make the code safer

## Example

```
$ la-scan examples/sample_batch_app
```

```markdown
# sample_batch_app -- Static Runtime Projection and Safety Audit

## If You Deploy This As-Is

- This app sends data to openai (api.openai.com).
- Makes outbound HTTP requests to dynamically resolved URLs.
- 2 embedded secret(s) found (dotenv_file, hardcoded_key).
- No critical or high-severity issues detected.

## Security Summary

> **PASS** -- No critical or high-severity findings.

| Critical | High | Medium | Low |
|---|---|---|---|
| 0 | 0 | 2 | 0 |

## Trust Boundaries -- What Leaves This Repo

### Data Egress

- **llm_sdk** via `openai` -> api.openai.com `main.py:23`
- **http** via `requests` -> unknown `main.py:33`

### Secrets Detected

- **hardcoded_key** (`API_KEY`): `*****************************mnop` `main.py:13`

## Entrypoint Effect Matrix

| Entrypoint | Reachable | Reads | Writes | Sends To | Secrets | PII | LLM |
|---|---|---|---|---|---|---|---|
| `python main.py` | 5 | 1 | 3 | 1 | 1 | 1 | 2 |

## Security Findings

### [MEDIUM] Call to requests without timeout

**Severity**: medium | **Category**: injection

**Recommendation**: Review whether this pattern is necessary for this app's function.

  - `main.py:33`

### Data Flow Risks

- [MEDIUM] **uploaded/read file data** -> **output file** (PII: none)
  - `main.py:57`
```

## What it checks

### Phase 1: Structural analysis

**Archetypes and entrypoints.** Identifies whether the project is a batch script, FastAPI web app, or Streamlit app. Finds entrypoint candidates from `if __name__` guards, CLI frameworks (argparse, click, typer, fire), and pyproject.toml console_scripts.

**I/O and data flow.** Detects file reads (pandas, open()), file writes (CSV, JSON, Excel, PNG), argparse arguments, FastAPI request parameters, upload handlers, and response models. Flags hardcoded file paths.

**External connections.** Catalogs outbound calls: LLM SDKs (OpenAI, Anthropic, Cohere, LangChain), HTTP clients (requests, httpx, aiohttp), databases (psycopg2, SQLAlchemy, pymongo, redis), cloud SDKs (boto3, supabase, firebase), observability services (Sentry, LangSmith), and email (smtplib). Detects implicit egress from SDK initialization (e.g., `sentry_sdk.init()`) and decorator-based tracing (e.g., `@traceable`).

**Secrets.** Finds hardcoded API keys, .env files, token patterns (sk-\*, AKIA\*, ghp\_\*), and suggests environment variable names.

**Dependencies.** Reads requirements.txt, pyproject.toml, and environment.yml. Falls back to import scanning when no manifest exists.

**LLM prompt surfaces.** Traces every LLM call site back through variable assignments, f-strings, string concatenation, and `.format()` to identify which runtime variables flow into prompts. Correctly excludes graph runtime calls (e.g., `graph_app.ainvoke()`) that are not LLM prompt sinks.

**LangGraph state flow.** Maps which graph nodes read and write which state keys.

**Tool registration.** Detects LLM-callable tools (`@tool`, `bind_tools`) and classifies their capabilities (network, file, subprocess, database).

### Phase 2: Security review

**Code injection.** Flags exec(), eval(), os.system(), subprocess, ctypes, pickle, and dynamic imports.

**Data classification and flow tracing.** Infers PII, financial, health, and credential data from field names. Traces data from file reads through variable assignments to LLM calls, HTTP requests, and file writes. Follows data across function boundaries.

**Credential leak detection.** Finds secrets flowing to log output, LLM prompts, HTTP request bodies, and output files.

**Dependency vulnerabilities.** pip-audit integration for known CVEs. Typosquat detection via edit distance from popular packages.

**Resource abuse.** Infinite loops (while True without break), fork bombs, unbounded multiprocessing, network calls in tight loops.

**Agent and skill scanning.** Template injection in prompt files, overprivileged tools in agent configs, MCP servers without guardrails, user input flowing into system messages.

**Effect graph scanner.** A semantic layer built on top of AST analysis. Rather than string-matching against hardcoded library lists, it builds a typed graph of capabilities, sources, sinks, and data flows, then runs queries over that graph. This catches:

- **Prompt injection paths** -- user-controlled or header-controlled data flowing into any LLM prompt, traced through variable chains and f-strings
- **Implicit egress** -- observability SDKs (Sentry, LangSmith) and email (smtplib) that ship data automatically on init or via decorators
- **Unauthenticated routes** -- FastAPI route handlers with no `Depends()` auth guard
- **SQL severity escalation** -- existing injection findings upgraded to HIGH when the source is user/header-controlled
- **State overexposure** -- routes that return graph state directly to API clients
- **False-positive suppression** -- `graph_app.ainvoke()` is correctly classified as a graph runtime call, not an LLM prompt sink

The capability registry (`ir/capability_registry.py`) is data-only: adding support for a new SDK means adding one dict entry, with no changes to scanner logic.

**Gate decision.** Produces PASS, REVIEW REQUIRED, or BLOCKED based on finding severity. Secrets found outside the active call graph (hardcoded keys, .env files) also contribute to the gate:

| Gate | Condition |
|---|---|
| **PASS** | No critical or high findings |
| **REVIEW REQUIRED** | High-severity findings present (including secrets) |
| **BLOCKED** | Critical findings present |

### Phase 3: Effect projection

**Call graph.** Builds a project-wide caller-callee graph across all Python files, resolving cross-file imports and class methods.

**Entrypoint reachability.** Determines which functions are actually reachable from each entrypoint at runtime.

**Effect mapping.** Maps every finding to the entrypoint(s) that can trigger it. Findings in code that no entrypoint can reach are separated out so you can focus on what matters.

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
| `security_report.json` | All findings (including IR graph findings), severity counts, gate decision |
| `livingapps.yaml` | Generated app manifest |

`la-scan -f json` outputs a single JSON document combining `analysis`, `security`, and `projection`.

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
result.analysis.egress.outbound_calls        # includes observability, email kinds
result.analysis.secrets.findings
result.analysis.deps.dependencies
result.analysis.prompt_surface.surfaces      # LLM call sites + traced variables
result.analysis.tool_registration.tools      # LLM-callable tools
result.analysis.state_flow.node_flows        # LangGraph state reads/writes

# Phase 2: security review
result.security.deploy_blocked        # True if critical findings
result.security.requires_review       # True if high findings or secrets detected
result.security.findings              # all findings: code injection, vulns, IR queries (origin="ir_query"), etc.
result.security.ir_query_count        # number of findings produced by the effect graph IR
result.security.data_classifications  # PII, financial, health, credential (informational, no severity)
result.security.data_flow_risks       # source -> sink traces with severity
result.security.credential_leak_risks # credential exposure findings with severity
result.security.agent_scan            # agent/skill findings (or None)

# Phase 3: effect projection
result.projection.call_graph.functions
result.projection.call_graph.edges
result.projection.projections          # per-entrypoint effects
result.projection.unreachable_findings
```

Run subsystems independently:

```python
from pathlib import Path
from la_analyzer.analyzer.service import analyze_repo
from la_analyzer.security import run_security_review
from la_analyzer.ir import build_effect_graph
from la_analyzer.ir.queries import run_all_queries

analysis = analyze_repo(Path("myproject"), Path("/tmp/output"))

security = run_security_review(
    workspace_dir=Path("myproject"),
    analysis_result=analysis,
)

# Use the effect graph directly
py_files = list(Path("myproject").rglob("*.py"))
graph = build_effect_graph(Path("myproject"), py_files)
ir_findings = run_all_queries(graph)
```

## Development

```bash
pip install -e ".[dev]"
pytest
```

283 tests across 15 test files. Runs in under 3 seconds.

## Sweet spot and limits

### Where LA Analyzer works well

**FastAPI or Streamlit apps backed by LLM APIs.** If you have a web app that calls OpenAI, Anthropic, or a LangChain/LangGraph pipeline, the tool maps your routes, traces data from request parameters into prompts, detects missing auth guards, and surfaces any implicit telemetry egress.

**Agent workflows with tool registration.** Apps using `@tool` or `bind_tools` — the scanner classifies what capabilities each tool exposes (network, file, subprocess, database) and flags overprivileged tools.

**Batch scripts and CLI tools that call external services.** Clear entrypoints, linear data flow, and explicit I/O make for high-confidence results. The entrypoint effect matrix shows exactly what each script reads, sends, and writes.

**Projects with moderate complexity and explicit imports.** The effect graph is most accurate when SDK usage follows conventional patterns (direct instantiation, standard decorators, top-level imports).

### Where it gets less precise

**Heavily dynamic code.** Abstract interpretation can't fully resolve `getattr`-based dispatch, metaclass magic, plugin systems, or `importlib.import_module` — those edges won't appear in the call graph.

**SDKs not yet in the capability registry.** The effect graph knows about ~20 SDK families. An uncommon observability library or a niche cloud SDK will be treated as an unknown outbound call rather than classified by capability. You can add entries to `ir/capability_registry.py` (one dict entry, no logic changes).

**Non-standard authentication patterns.** The tool detects FastAPI `Depends()` guards. Custom middleware, decorator-based auth outside FastAPI's DI system, or session-based auth in Streamlit may not register as a guard — so unauthenticated-route findings need manual review in those cases.

**Complex multi-branch state machines.** Deep conditional routing (many `if/elif` chains gating which tools fire) can cause reachability analysis to miss some paths. The call graph is conservative: it will catch most effects but may miss some in heavily branched workflows.

**Multi-repo architectures.** LA Analyzer sees one codebase at a time. Cross-service data flows — data that exits repo A, enters repo B via an internal API, and then reaches an LLM — are not traced.

**Very large codebases.** Files over 2MB are skipped. The AST walker is fast but very large monorepos may produce incomplete results in deeper subdirectories.

## How it works

Pure static analysis. No code is executed. The scanner walks Python files, parses them into ASTs, and applies pattern-matching to extract structure and detect risks.

The **effect graph** adds a semantic layer: a Python frontend runs multi-pass abstract interpretation over each file, tracking what capabilities each variable holds (LLM client, graph runtime, telemetry SDK, mailer, etc.) and what trust level each data source carries (user-controlled, header-controlled, external-untrusted, operator-controlled). These facts are emitted as typed nodes and edges into a graph, which is then queried to find security-relevant paths.

The call graph resolves cross-file imports and computes reachability to separate real effects from unused code. Agent/skill files (.md, .yaml, .json) are scanned with format-specific heuristics. Files over 2MB and directories like .git, venv, and node_modules are skipped.

Python >=3.11. Only three runtime dependencies: pydantic, pyyaml, click.

## Deploying safe internal tools

LA Analyzer tells you what's wrong. If you need help fixing it and deploying safely, [Living Apps](https://livingapps.io) is the full platform: managed secrets, egress controls, LLM gateway, and one-click deploys for internal Python tools.

## License

Apache 2.0

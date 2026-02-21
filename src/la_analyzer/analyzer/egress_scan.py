"""Detect outbound network calls (HTTP, LLM SDKs, databases, cloud, BaaS) via AST + regex."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from la_analyzer.analyzer.models import (
    EgressReport,
    Evidence,
    OutboundCall,
    SuggestedGatewayNeeds,
)

# Libraries we track → kind
_TRACKED_LIBS: dict[str, str] = {
    # LLM SDKs
    "openai": "llm_sdk",
    "anthropic": "llm_sdk",
    "langchain": "llm_sdk",
    "langchain_openai": "llm_sdk",
    "langchain_anthropic": "llm_sdk",
    "langchain_community": "llm_sdk",
    "litellm": "llm_sdk",
    "cohere": "llm_sdk",
    "google": "cloud",  # default to cloud; google.generativeai is refined below
    "replicate": "llm_sdk",
    "groq": "llm_sdk",
    "together": "llm_sdk",
    "huggingface_hub": "llm_sdk",
    # HTTP clients
    "requests": "http",
    "httpx": "http",
    "aiohttp": "http",
    "urllib3": "http",
    # Database
    "psycopg2": "database",
    "asyncpg": "database",
    "sqlalchemy": "database",
    "pymongo": "database",
    "motor": "database",
    "redis": "database",
    "pymysql": "database",
    # Cloud
    "boto3": "cloud",
    # BaaS
    "supabase": "baas",
    "firebase_admin": "baas",
}

# SDK constructors that are high-confidence egress signals even without a method call
_SDK_CONSTRUCTORS: dict[str, str] = {
    "OpenAI": "openai",
    "AsyncOpenAI": "openai",
    "Anthropic": "anthropic",
    "AsyncAnthropic": "anthropic",
    "ChatOpenAI": "langchain_openai",
    "ChatAnthropic": "langchain_anthropic",
    "create_client": "supabase",
    "GenerativeModel": "google",
    "Groq": "groq",
    "Cohere": "cohere",
}

# Well-known default domains for SDK libraries.
# Used when static analysis can't resolve a URL but the library's destination is known.
_DEFAULT_DOMAINS: dict[str, list[str]] = {
    "openai": ["api.openai.com"],
    "anthropic": ["api.anthropic.com"],
    "langchain_openai": ["api.openai.com"],
    "langchain_anthropic": ["api.anthropic.com"],
    "cohere": ["api.cohere.com"],
    "groq": ["api.groq.com"],
    "together": ["api.together.xyz"],
    "replicate": ["api.replicate.com"],
    "huggingface_hub": ["huggingface.co"],
    "litellm": ["api.openai.com"],  # litellm proxies; default is OpenAI-compatible
    "google": ["generativelanguage.googleapis.com"],
    "supabase": ["*.supabase.co"],
    "firebase_admin": ["*.firebaseio.com"],
    "boto3": ["*.amazonaws.com"],
    "psycopg2": ["(configured host)"],
    "asyncpg": ["(configured host)"],
    "pymongo": ["(configured host)"],
    "redis": ["(configured host)"],
}

# Regex for URLs/domains in string literals
_URL_RE = re.compile(
    r"""["'](https?://([a-zA-Z0-9.-]+(?:\.[a-zA-Z]{2,}))[^"']*?)["']"""
)

# Regex for model name literals (also used bare, without quotes, for constant resolution)
_MODEL_NAME_RE = re.compile(
    r"(?:gpt-[34][a-z0-9.-]*"
    r"|o[1-9]-[a-z]*"
    r"|text-davinci[a-z0-9-]*"
    r"|text-embedding-[a-z0-9.-]*"
    r"|claude-[a-z0-9.-]+"
    r"|gemini-[a-z0-9.-]+"
    r"|llama-?[a-z0-9.-]*"
    r"|mistral-[a-z0-9.-]+"
    r"|command-r[a-z0-9.-]*"
    r"|grok-[a-z0-9.-]*"
    r"|dall-e-[a-z0-9.-]*"
    r"|whisper-[a-z0-9.-]*"
    r"|tts-[a-z0-9.-]*)",
    re.IGNORECASE,
)
# Wrapped version for scanning source text (matches quoted strings)
_MODEL_RE = re.compile(
    r"""["'](""" + _MODEL_NAME_RE.pattern + r""")["']""",
    re.IGNORECASE,
)


def scan_egress(workspace: Path, py_files: list[Path]) -> EgressReport:
    calls: list[OutboundCall] = []
    models_found: set[str] = set()
    libs_imported: dict[str, set[str]] = {}  # file → set of imported lib names

    for fpath in py_files:
        rel = str(fpath.relative_to(workspace))
        try:
            source = fpath.read_text(errors="replace")
            tree = ast.parse(source, filename=rel)
        except SyntaxError:
            _regex_scan(source, rel, calls, models_found)
            continue

        file_imports: set[str] = set()

        # First pass: collect imports
        google_is_llm = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    if root in _TRACKED_LIBS:
                        file_imports.add(root)
                    # Refine: google.generativeai → llm_sdk
                    if alias.name.startswith("google.generativeai"):
                        google_is_llm = True

            if isinstance(node, ast.ImportFrom) and node.module:
                root = node.module.split(".")[0]
                if root in _TRACKED_LIBS:
                    file_imports.add(root)
                if node.module.startswith("google.generativeai"):
                    google_is_llm = True

        libs_imported[rel] = file_imports

        # Build set of variable names assigned from SDK constructors
        sdk_vars: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                cname = _call_attr(node.value)
                if cname in _SDK_CONSTRUCTORS:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            sdk_vars.add(target.id)
            # Also handle annotated assignments: client: OpenAI = OpenAI()
            if isinstance(node, ast.AnnAssign) and isinstance(node.value, ast.Call):
                cname = _call_attr(node.value)
                if cname in _SDK_CONSTRUCTORS and isinstance(node.target, ast.Name):
                    sdk_vars.add(node.target.id)

        # Track variables assigned to SDK class references (dynamic dispatch)
        # e.g. provider_cls = ChatAnthropic  (no call parens)
        # Also handles annotated assignments: model_options: List[...] = [...]
        for node in ast.walk(tree):
            # Extract value from both Assign and AnnAssign
            assign_value: ast.expr | None = None
            assign_line = 0
            if isinstance(node, ast.Assign) and node.value is not None:
                assign_value = node.value
                assign_line = node.lineno
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                assign_value = node.value
                assign_line = node.lineno

            if assign_value is None:
                continue

            # Direct class reference: provider_cls = ChatAnthropic
            if isinstance(assign_value, ast.Name) and assign_value.id in _SDK_CONSTRUCTORS:
                lib = _SDK_CONSTRUCTORS[assign_value.id]
                root_lib = lib.split("_")[0] if "_" in lib else lib
                if root_lib in file_imports or lib in file_imports:
                    ev = Evidence(
                        file=rel, line=assign_line,
                        snippet=_snippet(source, assign_line),
                    )
                    calls.append(OutboundCall(
                        kind=_TRACKED_LIBS.get(lib, "llm_sdk"),
                        library=lib,
                        evidence=[ev], confidence=0.7,
                    ))

            # SDK classes in collection literals (list, dict, tuples)
            # e.g. options = [ChatOpenAI, ChatAnthropic]
            # e.g. mapping = {"gpt": ChatOpenAI, "claude": ChatAnthropic}
            # e.g. model_options = [("gpt-4o", ChatOpenAI), ("claude", ChatAnthropic)]
            if isinstance(assign_value, (ast.List, ast.Dict, ast.Tuple)):
                # Walk the entire structure to find SDK class refs at any depth
                for child in ast.walk(assign_value):
                    if isinstance(child, ast.Name) and child.id in _SDK_CONSTRUCTORS:
                        lib = _SDK_CONSTRUCTORS[child.id]
                        root_lib = lib.split("_")[0] if "_" in lib else lib
                        if root_lib in file_imports or lib in file_imports:
                            ev = Evidence(
                                file=rel, line=assign_line,
                                snippet=_snippet(source, assign_line),
                            )
                            calls.append(OutboundCall(
                                kind=_TRACKED_LIBS.get(lib, "llm_sdk"),
                                library=lib,
                                evidence=[ev], confidence=0.7,
                            ))

        # Collect simple string constants: NAME = "literal"
        str_constants: dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                target = node.targets[0]
                if (isinstance(target, ast.Name)
                        and isinstance(node.value, ast.Constant)
                        and isinstance(node.value.value, str)):
                    str_constants[target.id] = node.value.value

        # Scan constant values for model names
        for val in str_constants.values():
            m = _MODEL_NAME_RE.fullmatch(val)
            if m:
                models_found.add(m.group(0))

        # Second pass: find call sites
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            attr = _call_attr(node)
            ev = Evidence(
                file=rel, line=node.lineno,
                snippet=_snippet(source, node.lineno),
            )

            # Resolve model=VAR keyword args through constants dict
            for kw in node.keywords:
                if kw.arg == "model" and isinstance(kw.value, ast.Name):
                    resolved = str_constants.get(kw.value.id)
                    if resolved:
                        m = _MODEL_NAME_RE.fullmatch(resolved)
                        if m:
                            models_found.add(m.group(0))

            # SDK constructor calls (OpenAI(), Anthropic(), etc.)
            if attr in _SDK_CONSTRUCTORS:
                lib = _SDK_CONSTRUCTORS[attr]
                root_lib = lib.split("_")[0] if "_" in lib else lib
                if root_lib in file_imports or lib in file_imports:
                    kind = _TRACKED_LIBS.get(lib, "llm_sdk")
                    # GenerativeModel is always an LLM SDK call
                    if attr == "GenerativeModel":
                        kind = "llm_sdk"
                    calls.append(OutboundCall(
                        kind=kind, library=lib,
                        evidence=[ev], confidence=0.9,
                    ))

            # LLM SDK calls — only match .create() when called on a known SDK var
            # or through a chained attribute (client.chat.completions.create)
            if attr == "create" and isinstance(node.func, ast.Attribute):
                receiver = _get_receiver_root(node.func.value)
                if receiver in sdk_vars or _is_chained_sdk_call(node.func):
                    for lib in file_imports:
                        if _TRACKED_LIBS.get(lib) == "llm_sdk":
                            calls.append(OutboundCall(
                                kind="llm_sdk", library=lib,
                                evidence=[ev], confidence=0.9,
                            ))
                            break

            # litellm.completion() / cohere.chat() / replicate.run() — module-level calls
            if attr in ("completion", "acompletion") and "litellm" in file_imports:
                calls.append(OutboundCall(
                    kind="llm_sdk", library="litellm",
                    evidence=[ev], confidence=0.9,
                ))
            if attr == "generate_content" and "google" in file_imports and google_is_llm:
                calls.append(OutboundCall(
                    kind="llm_sdk", library="google",
                    evidence=[ev], confidence=0.85,
                ))

            # HTTP library calls — require the receiver to be a known http module/var
            if attr in ("get", "post", "put", "patch", "delete", "head", "options", "request"):
                receiver = _get_receiver_root(node.func.value) if isinstance(node.func, ast.Attribute) else None
                # Only match if receiver looks like an HTTP lib (requests.get, session.post, etc.)
                is_http_call = (
                    receiver in ("requests", "httpx", "aiohttp", "urllib3", "http", "session", "client")
                    or receiver in sdk_vars
                )
                if is_http_call:
                    for lib in file_imports:
                        if _TRACKED_LIBS.get(lib) == "http":
                            url = _first_str_arg(node)
                            domains: list[str] = []
                            if url:
                                m = re.match(r"https?://([^/]+)", url)
                                if m:
                                    domains.append(m.group(1))
                            else:
                                # Try extracting domain from f-string URL
                                fstr_domain = _extract_fstring_url_domain(node)
                                if fstr_domain:
                                    domains.append(fstr_domain)
                            calls.append(OutboundCall(
                                kind="http", library=lib,
                                domains=domains,
                                evidence=[ev], confidence=0.85,
                            ))
                            break

            # Database calls — require receiver context
            if attr in ("execute", "executemany", "fetch", "fetchone", "fetchall", "fetchrow", "query"):
                receiver = _get_receiver_root(node.func.value) if isinstance(node.func, ast.Attribute) else None
                if receiver in ("cursor", "cur", "conn", "connection", "db", "session", "engine", "pool") or receiver in sdk_vars:
                    for lib in file_imports:
                        if _TRACKED_LIBS.get(lib) == "database":
                            calls.append(OutboundCall(
                                kind="database", library=lib,
                                evidence=[ev], confidence=0.85,
                            ))
                            break

            # BaaS calls
            if attr in ("table", "from_", "storage", "rpc"):
                for lib in file_imports:
                    if _TRACKED_LIBS.get(lib) == "baas":
                        calls.append(OutboundCall(
                            kind="baas", library=lib,
                            evidence=[ev], confidence=0.85,
                        ))
                        break

            # Cloud calls (boto3 etc.)
            if attr in ("client", "resource", "upload_file", "download_file", "put_object", "get_object"):
                for lib in file_imports:
                    if _TRACKED_LIBS.get(lib) == "cloud":
                        calls.append(OutboundCall(
                            kind="cloud", library=lib,
                            evidence=[ev], confidence=0.7,
                        ))
                        break

        # Regex scan for URLs and model names
        _regex_scan(source, rel, calls, models_found)

    # Deduplicate by (library, kind) — merge evidence and domains
    deduped: dict[tuple[str, str], OutboundCall] = {}
    for c in calls:
        key = (c.library, c.kind)
        if key in deduped:
            existing = deduped[key]
            existing.evidence.extend(c.evidence)
            for d in c.domains:
                if d not in existing.domains:
                    existing.domains.append(d)
            existing.confidence = max(existing.confidence, c.confidence)
        else:
            deduped[key] = c.model_copy()

    # Fill in well-known default domains for calls with no resolved domains
    for c in deduped.values():
        if not c.domains and c.library in _DEFAULT_DOMAINS:
            c.domains = list(_DEFAULT_DOMAINS[c.library])

    unique_calls = list(deduped.values())

    # Build gateway needs
    has_llm = any(c.kind == "llm_sdk" for c in unique_calls)
    has_http = any(c.kind == "http" for c in unique_calls)

    return EgressReport(
        outbound_calls=unique_calls,
        suggested_gateway_needs=SuggestedGatewayNeeds(
            needs_llm_gateway=has_llm,
            needs_external_api_gateway=has_http,
            requested_models=sorted(models_found),
        ),
    )


def _regex_scan(
    source: str, rel: str,
    calls: list[OutboundCall],
    models_found: set[str],
) -> None:
    for m in _MODEL_RE.finditer(source):
        models_found.add(m.group(1))


def _call_attr(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    if isinstance(node.func, ast.Name):
        return node.func.id
    return None


def _get_receiver_root(node: ast.expr) -> str | None:
    """Get the root variable name from a chained attribute access.

    e.g. client.chat.completions → 'client'
         requests → 'requests'
    """
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _get_receiver_root(node.value)
    return None


def _is_chained_sdk_call(node: ast.Attribute) -> bool:
    """Check if this is a chained SDK call like .chat.completions.create or .messages.create."""
    chain: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        chain.append(cur.attr)
        cur = cur.value
    # Look for patterns like ['create', 'completions', 'chat'] or ['create', 'messages']
    _SDK_CHAINS = {
        ("completions", "chat"),
        ("messages",),
    }
    attr_chain = tuple(chain[:-1]) if chain else ()  # exclude the method name itself
    return attr_chain in _SDK_CHAINS


def _first_str_arg(node: ast.Call) -> str | None:
    if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
        return node.args[0].value
    return None


def _extract_fstring_url_domain(node: ast.Call) -> str | None:
    """Extract a domain from an f-string URL argument like f'https://api.example.com/{x}'."""
    if not node.args:
        return None
    arg = node.args[0]
    if not isinstance(arg, ast.JoinedStr):
        return None
    # Get the static prefix of the f-string
    if arg.values and isinstance(arg.values[0], ast.Constant) and isinstance(arg.values[0].value, str):
        prefix = arg.values[0].value
        m = re.match(r"https?://([a-zA-Z0-9.-]+(?:\.[a-zA-Z]{2,}))", prefix)
        if m:
            return m.group(1)
    return None


def _snippet(source: str, lineno: int) -> str:
    lines = source.splitlines()
    if 0 < lineno <= len(lines):
        return lines[lineno - 1].strip()[:160]
    return ""

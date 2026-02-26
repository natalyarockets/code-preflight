"""Central extensibility point: maps constructor/module names to CapabilityEntry.

New SDKs = new dict entries, no scanner logic changes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum


class Capability(str, Enum):
    LLM_CLIENT = "llm_client"
    HTTP_CLIENT = "http_client"
    TELEMETRY_SDK = "telemetry_sdk"
    STATE_STORE = "state_store"
    MAILER = "mailer"
    DB_CLIENT = "db_client"
    GRAPH_RUNTIME = "graph_runtime"
    EMBEDDING_CLIENT = "embedding_client"
    VECTOR_STORE = "vector_store"
    WEB_SEARCH = "web_search"
    BAAS_CLIENT = "baas_client"


class SourceTrust(str, Enum):
    USER_CONTROLLED = "user_controlled"        # request body, json body
    HEADER_CONTROLLED = "header_controlled"    # request.headers.get() — spoofable
    EXTERNAL_UNTRUSTED = "external_untrusted"  # HTTP response bodies, web search results
    OPERATOR_CONTROLLED = "operator_controlled" # os.getenv(), config files
    DB_RESULT = "db_result"                    # DB rows (may contain user data)
    INTERNAL = "internal"                      # string literals, constants


class SinkKind(str, Enum):
    LLM_PROMPT = "llm_prompt"
    HTTP_EGRESS = "http_egress"
    OBSERVABILITY = "observability"
    EMAIL_SMTP = "email_smtp"
    DB_WRITE = "db_write"
    LOCAL_PERSISTENCE = "local_persistence"
    API_RESPONSE = "api_response"
    LOG_OUTPUT = "log_output"
    FILE_WRITE = "file_write"


@dataclass(frozen=True)
class CapabilityEntry:
    capability: Capability
    service_name: str                          # human readable ("Sentry", "LangSmith", ...)
    sink_methods: frozenset[str] = field(default_factory=frozenset)
    sink_kind: SinkKind = SinkKind.HTTP_EGRESS
    implicit_egress_on_init: bool = False      # True for sentry_sdk (registers global hook on init)
    decorator_sink: SinkKind | None = None     # if used as @decorator, emits this sink


# Keyed by constructor class name OR module name
CAPABILITY_REGISTRY: dict[str, CapabilityEntry] = {
    # ── LLM Clients ──────────────────────────────────────────────────────
    "ChatOpenAI": CapabilityEntry(
        capability=Capability.LLM_CLIENT,
        service_name="OpenAI (LangChain)",
        sink_methods=frozenset({"invoke", "ainvoke", "stream", "astream", "batch", "abatch"}),
        sink_kind=SinkKind.LLM_PROMPT,
    ),
    "ChatAnthropic": CapabilityEntry(
        capability=Capability.LLM_CLIENT,
        service_name="Anthropic (LangChain)",
        sink_methods=frozenset({"invoke", "ainvoke", "stream", "astream", "batch", "abatch"}),
        sink_kind=SinkKind.LLM_PROMPT,
    ),
    "OpenAI": CapabilityEntry(
        capability=Capability.LLM_CLIENT,
        service_name="OpenAI",
        sink_methods=frozenset({"create", "generate", "complete"}),
        sink_kind=SinkKind.LLM_PROMPT,
    ),
    "AsyncOpenAI": CapabilityEntry(
        capability=Capability.LLM_CLIENT,
        service_name="OpenAI (async)",
        sink_methods=frozenset({"create", "generate", "complete"}),
        sink_kind=SinkKind.LLM_PROMPT,
    ),
    "Anthropic": CapabilityEntry(
        capability=Capability.LLM_CLIENT,
        service_name="Anthropic",
        sink_methods=frozenset({"create", "messages"}),
        sink_kind=SinkKind.LLM_PROMPT,
    ),
    "AsyncAnthropic": CapabilityEntry(
        capability=Capability.LLM_CLIENT,
        service_name="Anthropic (async)",
        sink_methods=frozenset({"create", "messages"}),
        sink_kind=SinkKind.LLM_PROMPT,
    ),
    "ChatGroq": CapabilityEntry(
        capability=Capability.LLM_CLIENT,
        service_name="Groq (LangChain)",
        sink_methods=frozenset({"invoke", "ainvoke", "stream", "astream"}),
        sink_kind=SinkKind.LLM_PROMPT,
    ),
    "ChatCohere": CapabilityEntry(
        capability=Capability.LLM_CLIENT,
        service_name="Cohere (LangChain)",
        sink_methods=frozenset({"invoke", "ainvoke", "stream", "astream"}),
        sink_kind=SinkKind.LLM_PROMPT,
    ),
    "ChatOllama": CapabilityEntry(
        capability=Capability.LLM_CLIENT,
        service_name="Ollama (LangChain)",
        sink_methods=frozenset({"invoke", "ainvoke", "stream", "astream"}),
        sink_kind=SinkKind.LLM_PROMPT,
    ),
    "OllamaLLM": CapabilityEntry(
        capability=Capability.LLM_CLIENT,
        service_name="Ollama",
        sink_methods=frozenset({"invoke", "ainvoke", "predict", "generate"}),
        sink_kind=SinkKind.LLM_PROMPT,
    ),
    "ChatMistralAI": CapabilityEntry(
        capability=Capability.LLM_CLIENT,
        service_name="Mistral AI (LangChain)",
        sink_methods=frozenset({"invoke", "ainvoke", "stream", "astream"}),
        sink_kind=SinkKind.LLM_PROMPT,
    ),
    "MistralClient": CapabilityEntry(
        capability=Capability.LLM_CLIENT,
        service_name="Mistral AI",
        sink_methods=frozenset({"chat", "chat_stream", "chat_async"}),
        sink_kind=SinkKind.LLM_PROMPT,
    ),
    "Mistral": CapabilityEntry(
        capability=Capability.LLM_CLIENT,
        service_name="Mistral AI",
        sink_methods=frozenset({"chat", "chat_stream", "chat_async", "complete"}),
        sink_kind=SinkKind.LLM_PROMPT,
    ),
    # ── Graph Runtimes — ainvoke is NOT an LLM prompt sink ────────────────
    "CompiledStateGraph": CapabilityEntry(
        capability=Capability.GRAPH_RUNTIME,
        service_name="LangGraph",
        sink_methods=frozenset(),  # ainvoke/invoke NOT prompt sinks
        sink_kind=SinkKind.API_RESPONSE,
    ),
    "StateGraph": CapabilityEntry(
        capability=Capability.GRAPH_RUNTIME,
        service_name="LangGraph",
        sink_methods=frozenset(),
        sink_kind=SinkKind.API_RESPONSE,
    ),
    # ── Telemetry / Observability SDKs ────────────────────────────────────
    "sentry_sdk": CapabilityEntry(
        capability=Capability.TELEMETRY_SDK,
        service_name="Sentry",
        sink_methods=frozenset({"init", "capture_event", "capture_exception",
                                "capture_message", "push_scope", "configure_scope"}),
        sink_kind=SinkKind.OBSERVABILITY,
        implicit_egress_on_init=True,
    ),
    "langsmith": CapabilityEntry(
        capability=Capability.TELEMETRY_SDK,
        service_name="LangSmith",
        sink_methods=frozenset({"create_run", "update_run", "end_run"}),
        sink_kind=SinkKind.OBSERVABILITY,
        decorator_sink=SinkKind.OBSERVABILITY,
    ),
    # ── Mailer ────────────────────────────────────────────────────────────
    "SMTP": CapabilityEntry(
        capability=Capability.MAILER,
        service_name="SMTP (smtplib)",
        sink_methods=frozenset({"send_message", "sendmail", "send"}),
        sink_kind=SinkKind.EMAIL_SMTP,
    ),
    # ── Embedding Clients ─────────────────────────────────────────────────
    "HuggingFaceEmbeddings": CapabilityEntry(
        capability=Capability.EMBEDDING_CLIENT,
        service_name="HuggingFace Embeddings",
        sink_methods=frozenset({"embed_query", "embed_documents", "aembed_query"}),
        sink_kind=SinkKind.LLM_PROMPT,
    ),
    "OpenAIEmbeddings": CapabilityEntry(
        capability=Capability.EMBEDDING_CLIENT,
        service_name="OpenAI Embeddings",
        sink_methods=frozenset({"embed_query", "embed_documents", "aembed_query"}),
        sink_kind=SinkKind.LLM_PROMPT,
    ),
    "InferenceClient": CapabilityEntry(
        capability=Capability.EMBEDDING_CLIENT,
        service_name="HuggingFace Hub",
        sink_methods=frozenset({"text_generation", "feature_extraction", "sentence_similarity"}),
        sink_kind=SinkKind.LLM_PROMPT,
    ),
    # ── BaaS Clients ──────────────────────────────────────────────────────
    "create_client": CapabilityEntry(
        capability=Capability.BAAS_CLIENT,
        service_name="Supabase",
        sink_methods=frozenset({"table", "from_", "storage", "rpc", "insert", "select"}),
        sink_kind=SinkKind.DB_WRITE,
    ),
    # ── State Store / Persistence ─────────────────────────────────────────
    "AsyncSqliteSaver": CapabilityEntry(
        capability=Capability.STATE_STORE,
        service_name="LangGraph SQLite Checkpointer",
        sink_methods=frozenset({"from_conn_string", "put", "aput", "get", "aget"}),
        sink_kind=SinkKind.LOCAL_PERSISTENCE,
    ),
    "SqliteSaver": CapabilityEntry(
        capability=Capability.STATE_STORE,
        service_name="LangGraph SQLite Checkpointer",
        sink_methods=frozenset({"from_conn_string", "put", "get"}),
        sink_kind=SinkKind.LOCAL_PERSISTENCE,
    ),
    "PostgresSaver": CapabilityEntry(
        capability=Capability.STATE_STORE,
        service_name="LangGraph Postgres Checkpointer",
        sink_methods=frozenset({"from_conn_string", "put", "aput", "get", "aget"}),
        sink_kind=SinkKind.DB_WRITE,
    ),
}

# Source patterns (attr chains → SourceTrust)
SOURCE_PATTERNS: dict[str, SourceTrust] = {
    "request.headers.get": SourceTrust.HEADER_CONTROLLED,
    "request.headers": SourceTrust.HEADER_CONTROLLED,
    "request.query_params.get": SourceTrust.USER_CONTROLLED,
    "request.query_params": SourceTrust.USER_CONTROLLED,
    "request.json": SourceTrust.USER_CONTROLLED,
    "request.body": SourceTrust.USER_CONTROLLED,
    "request.form": SourceTrust.USER_CONTROLLED,
    "os.getenv": SourceTrust.OPERATOR_CONTROLLED,
    "os.environ.get": SourceTrust.OPERATOR_CONTROLLED,
    "os.environ": SourceTrust.OPERATOR_CONTROLLED,
    # HTTP response values
    "response.json": SourceTrust.EXTERNAL_UNTRUSTED,
    "response.text": SourceTrust.EXTERNAL_UNTRUSTED,
    "response.content": SourceTrust.EXTERNAL_UNTRUSTED,
    "resp.json": SourceTrust.EXTERNAL_UNTRUSTED,
    "resp.text": SourceTrust.EXTERNAL_UNTRUSTED,
}

# Auth guard classes (FastAPI security dependencies)
AUTH_GUARD_CLASSES: frozenset[str] = frozenset({
    "OAuth2PasswordBearer",
    "HTTPBearer",
    "HTTPBasic",
    "APIKeyHeader",
    "APIKeyCookie",
    "APIKeyQuery",
    "SecurityScopes",
})

# Auth guard function name pattern
AUTH_GUARD_FUNC_RE = re.compile(
    r"(verify_|get_current_|authenticate|require_|check_auth|validate_token|"
    r"oauth|bearer|api[_-]?key|jwt|token|current_user|login_required)",
    re.IGNORECASE,
)


def lookup_by_constructor(name: str) -> CapabilityEntry | None:
    """Look up a CapabilityEntry by constructor class name."""
    return CAPABILITY_REGISTRY.get(name)


def lookup_by_module(module_root: str) -> CapabilityEntry | None:
    """Look up a CapabilityEntry by module root name (e.g. 'sentry_sdk', 'langsmith')."""
    return CAPABILITY_REGISTRY.get(module_root)


def get_all_constructor_names() -> frozenset[str]:
    """Return all registered constructor names."""
    return frozenset(CAPABILITY_REGISTRY.keys())

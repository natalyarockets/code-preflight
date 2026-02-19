"""Known external services registry.

Maps service names to their environment variables and classifies each as
"secret" (API key, token) or "config" (URL, host, project ID).  Adding a
new service = one dict entry.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ServiceVar:
    env_var: str
    kind: str  # "secret" | "config"
    description: str = ""


KNOWN_SERVICES: dict[str, list[ServiceVar]] = {
    "openai": [
        ServiceVar("OPENAI_API_KEY", "secret"),
    ],
    "anthropic": [
        ServiceVar("ANTHROPIC_API_KEY", "secret"),
    ],
    "pinecone": [
        ServiceVar("PINECONE_API_KEY", "secret"),
        ServiceVar("PINECONE_INDEX_HOST", "config", "Pinecone index host URL"),
    ],
    "supabase": [
        ServiceVar("SUPABASE_KEY", "secret"),
        ServiceVar("SUPABASE_URL", "config", "Supabase project URL"),
    ],
    "cohere": [
        ServiceVar("COHERE_API_KEY", "secret"),
    ],
    "groq": [
        ServiceVar("GROQ_API_KEY", "secret"),
    ],
    "replicate": [
        ServiceVar("REPLICATE_API_TOKEN", "secret"),
    ],
    "google": [
        ServiceVar("GOOGLE_API_KEY", "secret"),
    ],
    "stripe": [
        ServiceVar("STRIPE_SECRET_KEY", "secret"),
        ServiceVar("STRIPE_PUBLISHABLE_KEY", "config", "Stripe publishable key"),
        ServiceVar("STRIPE_WEBHOOK_SECRET", "secret"),
    ],
    "twilio": [
        ServiceVar("TWILIO_AUTH_TOKEN", "secret"),
        ServiceVar("TWILIO_ACCOUNT_SID", "config", "Twilio account SID"),
    ],
    "redis": [
        ServiceVar("REDIS_URL", "config", "Redis connection URL"),
        ServiceVar("REDIS_PASSWORD", "secret"),
    ],
    "aws": [
        ServiceVar("AWS_ACCESS_KEY_ID", "secret"),
        ServiceVar("AWS_SECRET_ACCESS_KEY", "secret"),
        ServiceVar("AWS_DEFAULT_REGION", "config", "AWS region"),
    ],
    "sendgrid": [
        ServiceVar("SENDGRID_API_KEY", "secret"),
    ],
    "weaviate": [
        ServiceVar("WEAVIATE_API_KEY", "secret"),
        ServiceVar("WEAVIATE_URL", "config", "Weaviate cluster URL"),
    ],
    "qdrant": [
        ServiceVar("QDRANT_API_KEY", "secret"),
        ServiceVar("QDRANT_URL", "config", "Qdrant cluster URL"),
    ],
}

# Reverse index: env_var_name -> (service_name, ServiceVar)
_VAR_TO_SERVICE: dict[str, tuple[str, ServiceVar]] = {}
for _svc_name, _svc_vars in KNOWN_SERVICES.items():
    for _sv in _svc_vars:
        _VAR_TO_SERVICE[_sv.env_var] = (_svc_name, _sv)


def classify_env_var(name: str) -> ServiceVar | None:
    """Look up an env var name in the registry.  Returns ServiceVar or None."""
    entry = _VAR_TO_SERVICE.get(name)
    return entry[1] if entry else None


def get_service_vars(service: str) -> list[ServiceVar]:
    """Return all vars for a known service, or empty list."""
    return KNOWN_SERVICES.get(service, [])

"""Generate a first-pass livingapps.yaml from analysis results."""

from __future__ import annotations

import re
from pathlib import Path

from la_analyzer.analyzer.models import (
    DetectionReport,
    EgressReport,
    IOReport,
    SecretsReport,
)
from la_analyzer.analyzer.services import classify_env_var, get_service_vars
from la_analyzer.schemas.manifest import (
    AppMeta,
    ConfigRef,
    ConfigVarsConfig,
    EgressAllowEntry,
    EgressConfig,
    EntrypointConfig,
    Interfaces,
    LivingAppsManifest,
    ManifestInput,
    ManifestOutput,
    RuntimeConfig,
    SecretRef,
    SecretsConfig,
)


# Fallback regex for env vars not in the known services registry
_SECRET_VAR_RE = re.compile(
    r"(api[_-]?key|secret|token|password|passwd|auth[_-]?token|"
    r"access[_-]?key|private[_-]?key|client[_-]?secret|credential)",
    re.IGNORECASE,
)

# Platform-injected env vars — never user secrets
_PLATFORM_VAR_PREFIX = "LIVINGAPPS_"


def _is_secret_var(name: str) -> bool:
    """Fallback: return True if the env var name looks like a secret."""
    if name.startswith(_PLATFORM_VAR_PREFIX):
        return False
    return bool(_SECRET_VAR_RE.search(name))


def generate_manifest(
    workspace_dir: Path,
    detection: DetectionReport,
    io_report: IOReport,
    egress: EgressReport,
    secrets: SecretsReport,
) -> LivingAppsManifest:
    app_name = workspace_dir.name

    # Detect web archetype
    is_web = any(a.type == "fastapi_web" for a in detection.archetypes)

    # Best entrypoint command
    command = ""
    if detection.entrypoint_candidates:
        command = detection.entrypoint_candidates[0].value
    if is_web and not command:
        command = "uvicorn app.main:app --host 0.0.0.0 --port 8000"

    entrypoint_kind = "web" if is_web else "batch"

    # Input kinds that come from the API layer (not file uploads)
    _API_INPUT_KINDS = {"json_body", "upload", "query_param", "path_param"}

    # Build inputs from io_report
    manifest_inputs = [
        ManifestInput(
            id=inp.id,
            label=inp.label,
            type=inp.kind,
            format=inp.format,
            description=inp.description,
            accepted_formats=inp.accepted_formats,
            required=True,
            default_source="api" if inp.kind in _API_INPUT_KINDS else "upload",
        )
        for inp in io_report.inputs
    ]

    # Build outputs from io_report
    manifest_outputs = [
        ManifestOutput(
            id=out.id,
            label=out.label,
            format=out.format,
            path=f"/outputs/{_output_filename(out.path_literal, out.id, out.format)}",
            role=out.role,
        )
        for out in io_report.outputs
    ]

    # Classify env vars via known services registry, fall back to regex
    secret_vars: set[str] = set()
    config_vars: set[str] = set()

    for var in secrets.suggested_env_vars:
        if var.startswith(_PLATFORM_VAR_PREFIX):
            continue
        svc_var = classify_env_var(var)
        if svc_var:
            if svc_var.kind == "secret":
                secret_vars.add(var)
            else:
                config_vars.add(var)
        elif _is_secret_var(var):
            # Unknown service, but name looks like a secret
            secret_vars.add(var)

    # SDK libraries imply ALL vars for that service (secrets + config)
    for call in egress.outbound_calls:
        for svc_var in get_service_vars(call.library):
            if svc_var.kind == "secret":
                secret_vars.add(svc_var.env_var)
            else:
                config_vars.add(svc_var.env_var)

    secret_refs = [SecretRef(name=var, env_var=var) for var in sorted(secret_vars)]
    config_refs = [ConfigRef(name=var, env_var=var) for var in sorted(config_vars)]

    # Egress — one entry per detected library
    egress_allow: list[EgressAllowEntry] = []
    seen_libs: set[str] = set()
    kind_map = {
        "llm_sdk": "llm", "http": "http", "database": "database",
        "cloud": "cloud", "baas": "baas",
    }
    for call in egress.outbound_calls:
        if call.library == "unknown" or call.library in seen_libs:
            continue
        seen_libs.add(call.library)
        egress_allow.append(EgressAllowEntry(
            name=call.library,
            kind=kind_map.get(call.kind, "unknown"),
            policy="internal_only",
        ))

    return LivingAppsManifest(
        app=AppMeta(name=app_name),
        runtime=RuntimeConfig(
            type="python",
            entrypoint=EntrypointConfig(kind=entrypoint_kind, command=command),
        ),
        interfaces=Interfaces(inputs=manifest_inputs, outputs=manifest_outputs),
        secrets=SecretsConfig(required=secret_refs),
        config_vars=ConfigVarsConfig(required=config_refs),
        egress=EgressConfig(mode="deny_by_default", allow=egress_allow),
    )


def _output_filename(path_literal: str | None, output_id: str, fmt: str) -> str:
    if path_literal:
        return Path(path_literal).name
    ext_map = {
        "csv": "csv", "json": "json", "png": "png", "jpeg": "jpg",
        "pdf": "pdf", "markdown": "md", "html": "html",
        "parquet": "parquet", "yaml": "yaml", "xml": "xml",
        "text": "txt", "excel": "xlsx", "audio": "wav",
        "directory": "",
    }
    ext = ext_map.get(fmt, "bin")
    if not ext:
        return output_id
    return f"{output_id}.{ext}"

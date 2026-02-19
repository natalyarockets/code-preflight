"""Pydantic model for livingapps.yaml manifest."""

from __future__ import annotations

from pydantic import BaseModel, Field


class AppMeta(BaseModel):
    name: str = ""
    description: str = ""
    owners: list[str] = Field(default_factory=list)


class EntrypointConfig(BaseModel):
    kind: str = "batch"
    command: str = ""


class Resources(BaseModel):
    timeout_seconds: int = 300
    memory_mb: int = 512


class RuntimeConfig(BaseModel):
    type: str = "python"
    entrypoint: EntrypointConfig = Field(default_factory=EntrypointConfig)
    resources: Resources = Field(default_factory=Resources)


class ManifestInput(BaseModel):
    id: str
    label: str = ""
    type: str = "file"
    format: str = "unknown"
    description: str = ""  # hint for users: what to upload
    accepted_formats: list[str] = Field(default_factory=list)  # e.g. [".pdf", ".txt"]
    required: bool = True
    default_source: str = "upload"


class ManifestOutput(BaseModel):
    id: str
    label: str = ""
    format: str = "unknown"
    path: str = ""
    role: str = "primary"  # "primary" (shown in flow) or "artifact" (debug/log)


class Interfaces(BaseModel):
    inputs: list[ManifestInput] = Field(default_factory=list)
    outputs: list[ManifestOutput] = Field(default_factory=list)


class SecretRef(BaseModel):
    name: str
    env_var: str = ""


class SecretsConfig(BaseModel):
    required: list[SecretRef] = Field(default_factory=list)


class ConfigRef(BaseModel):
    name: str
    env_var: str = ""


class ConfigVarsConfig(BaseModel):
    required: list[ConfigRef] = Field(default_factory=list)


class EgressAllowEntry(BaseModel):
    name: str
    kind: str = "unknown"
    policy: str = "internal_only"


class EgressConfig(BaseModel):
    mode: str = "deny_by_default"
    allow: list[EgressAllowEntry] = Field(default_factory=list)


class ConnectionConfig(BaseModel):
    enabled: bool = False
    reason_disabled: str = ""


class ConnectionsConfig(BaseModel):
    """Dynamic connections — populated by analysis when relevant.

    Empty by default. Future: analyzer detects DB/SaaS connections
    and populates entries here for approval.
    """

    model_config = {"extra": "allow"}


class LivingAppsManifest(BaseModel):
    app: AppMeta = Field(default_factory=AppMeta)
    runtime: RuntimeConfig = Field(default_factory=RuntimeConfig)
    interfaces: Interfaces = Field(default_factory=Interfaces)
    secrets: SecretsConfig = Field(default_factory=SecretsConfig)
    config_vars: ConfigVarsConfig = Field(default_factory=ConfigVarsConfig)
    egress: EgressConfig = Field(default_factory=EgressConfig)
    connections: ConnectionsConfig = Field(default_factory=ConnectionsConfig)

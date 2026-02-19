"""Agent / skill file scanner.

Scans four file types for security risks:
1. Markdown skill files -- prompt injection, credential patterns, overprivileged tool refs
2. YAML/JSON configs -- MCP server configs, tool permissions, plaintext credentials
3. Python agent code -- @tool decorators calling subprocess/os.system, user input in system prompts
"""

from __future__ import annotations

import ast
import json
import logging
import re
from pathlib import Path

from la_analyzer.security.models import AgentFinding, AgentScanReport

log = logging.getLogger(__name__)

# Patterns indicating user-controlled template variables in prompts
_TEMPLATE_VAR_RE = re.compile(r"\{(\w*user[\w_]*|input|query|message|prompt|request)\}", re.IGNORECASE)

# Credential patterns in config/text
_CREDENTIAL_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"AKIA[A-Z0-9]{16}"),
    re.compile(r"ghp_[A-Za-z0-9]{36}"),
    re.compile(r"xoxb-[A-Za-z0-9\-]+"),
    re.compile(r"(?:api[_-]?key|secret|token|password)\s*[:=]\s*[\"']?[A-Za-z0-9_\-]{16,}[\"']?", re.IGNORECASE),
]

# Dangerous tool/command references in prompts
_DANGEROUS_TOOL_REFS = {
    "exec", "eval", "subprocess", "os.system", "shell", "bash",
    "rm ", "rm -rf", "sudo", "chmod", "kill",
    "drop table", "delete from", "truncate",
}

# Agent file extensions
_AGENT_EXTENSIONS = {".md", ".yaml", ".yml", ".json"}

# MCP / tool config keys that indicate permissions
_PERMISSION_KEYS = {"tools", "allowed_tools", "permissions", "capabilities", "scopes"}

# Known dangerous tools in MCP / agent frameworks
_OVERPRIVILEGED_TOOLS = {
    "execute_command", "run_command", "shell", "bash", "terminal",
    "file_write", "write_file", "delete_file", "rm",
    "admin", "sudo", "root",
}


def scan_agents(
    workspace: Path,
    all_files: list[Path],
) -> AgentScanReport:
    """Scan for agent/skill security risks.

    Args:
        workspace: Project root.
        all_files: All discovered files.

    Returns:
        AgentScanReport with findings.
    """
    findings: list[AgentFinding] = []

    py_files = [f for f in all_files if f.suffix == ".py"]

    for fpath in all_files:
        rel = str(fpath.relative_to(workspace))
        try:
            if fpath.suffix == ".md":
                findings.extend(_scan_markdown(fpath, rel))
            elif fpath.suffix in (".yaml", ".yml"):
                findings.extend(_scan_yaml(fpath, rel))
            elif fpath.suffix == ".json":
                findings.extend(_scan_json_config(fpath, rel))
        except Exception:
            log.debug("Failed to scan agent file: %s", rel, exc_info=True)

    # Scan Python files for agent patterns
    for fpath in py_files:
        rel = str(fpath.relative_to(workspace))
        try:
            findings.extend(_scan_python_agent(fpath, rel))
        except Exception:
            log.debug("Failed to scan Python agent file: %s", rel, exc_info=True)

    return AgentScanReport(findings=findings)


# ── Markdown skill files ──────────────────────────────────────────────────


def _scan_markdown(fpath: Path, rel: str) -> list[AgentFinding]:
    """Scan a Markdown file for prompt injection and credential risks."""
    findings: list[AgentFinding] = []
    try:
        content = fpath.read_text(errors="replace")
    except OSError:
        return findings

    lines = content.splitlines()

    # Check if this looks like a prompt/skill file (has system/assistant/tool keywords)
    lower_content = content.lower()
    is_prompt_file = any(kw in lower_content for kw in [
        "system prompt", "you are", "assistant", "## tool", "## skill",
        "## instructions", "## role", "## rules",
    ])
    if not is_prompt_file:
        return findings

    for i, line in enumerate(lines, 1):
        # Template variable injection in system prompts
        match = _TEMPLATE_VAR_RE.search(line)
        if match:
            findings.append(AgentFinding(
                category="prompt_injection",
                severity="high",
                title="User input template in prompt file",
                description=f"Template variable `{{{match.group(1)}}}` may allow prompt injection if user-controlled content is interpolated into system instructions.",
                file=rel, line=i,
                snippet=line.strip()[:120],
                recommendation="Sanitize user input before interpolation, or move user content to a separate user message.",
            ))

        # Dangerous tool references
        line_lower = line.lower()
        for ref in _DANGEROUS_TOOL_REFS:
            if ref in line_lower:
                findings.append(AgentFinding(
                    category="overprivileged_tool",
                    severity="medium",
                    title=f"Dangerous command reference in prompt: `{ref}`",
                    description=f"Prompt file references `{ref}` which could enable destructive operations if the agent acts on it.",
                    file=rel, line=i,
                    snippet=line.strip()[:120],
                    recommendation="Restrict tool access to minimum required operations.",
                ))
                break  # One finding per line

        # Credential patterns
        for pattern in _CREDENTIAL_PATTERNS:
            if pattern.search(line):
                findings.append(AgentFinding(
                    category="credential_exposure",
                    severity="critical",
                    title="Credential pattern in prompt file",
                    description="A credential or API key pattern was found in a prompt/skill file.",
                    file=rel, line=i,
                    snippet=line.strip()[:60] + "...",
                    recommendation="Move credentials to environment variables or a secrets manager.",
                ))
                break

    return findings


# ── YAML configs ──────────────────────────────────────────────────────────


def _scan_yaml(fpath: Path, rel: str) -> list[AgentFinding]:
    """Scan a YAML config file for agent/MCP security risks."""
    findings: list[AgentFinding] = []
    try:
        import yaml
        content = fpath.read_text(errors="replace")
        data = yaml.safe_load(content)
    except Exception:
        return findings

    if not isinstance(data, dict):
        return findings

    # Check if this looks like an agent/MCP config
    keys_lower = {k.lower() for k in data}
    is_agent_config = any(kw in keys_lower for kw in [
        "mcp", "tools", "agents", "skills", "server", "servers",
        "allowed_tools", "permissions", "mcpservers",
    ])
    if not is_agent_config:
        return findings

    _scan_config_dict(data, rel, findings)
    return findings


def _scan_json_config(fpath: Path, rel: str) -> list[AgentFinding]:
    """Scan a JSON config file for agent/MCP security risks."""
    findings: list[AgentFinding] = []
    try:
        content = fpath.read_text(errors="replace")
        data = json.loads(content)
    except Exception:
        return findings

    if not isinstance(data, dict):
        return findings

    keys_lower = {k.lower() for k in data}
    is_agent_config = any(kw in keys_lower for kw in [
        "mcp", "tools", "agents", "skills", "server", "servers",
        "allowed_tools", "permissions", "mcpservers",
    ])
    if not is_agent_config:
        return findings

    _scan_config_dict(data, rel, findings)
    return findings


def _scan_config_dict(
    data: dict,
    rel: str,
    findings: list[AgentFinding],
    path: str = "",
) -> None:
    """Recursively scan a config dict for agent security issues."""
    for key, value in data.items():
        current_path = f"{path}.{key}" if path else key
        key_lower = key.lower()

        # Check for credential values
        if isinstance(value, str):
            for pattern in _CREDENTIAL_PATTERNS:
                if pattern.search(value):
                    findings.append(AgentFinding(
                        category="credential_exposure",
                        severity="critical",
                        title=f"Plaintext credential in config: `{current_path}`",
                        description=f"Config key `{current_path}` contains what appears to be a credential or API key.",
                        file=rel,
                        snippet=f"{key}: {value[:20]}...",
                        recommendation="Use environment variables or a secrets manager instead of plaintext credentials.",
                    ))
                    break

        # Check for overprivileged tool lists
        if key_lower in _PERMISSION_KEYS and isinstance(value, list):
            for tool_name in value:
                if isinstance(tool_name, str) and tool_name.lower() in _OVERPRIVILEGED_TOOLS:
                    findings.append(AgentFinding(
                        category="overprivileged_tool",
                        severity="high",
                        title=f"Overprivileged tool in config: `{tool_name}`",
                        description=f"Tool `{tool_name}` in `{current_path}` grants potentially dangerous capabilities.",
                        file=rel,
                        snippet=f"{key}: [..., {tool_name}, ...]",
                        recommendation="Restrict tool access to the minimum set required.",
                    ))

        # Check for wildcard / unrestricted permissions
        if key_lower in _PERMISSION_KEYS:
            if value == "*" or value == ["*"]:
                findings.append(AgentFinding(
                    category="unscoped_permission",
                    severity="high",
                    title=f"Wildcard permission: `{current_path}`",
                    description=f"`{current_path}` grants unrestricted access. This allows the agent to use any tool.",
                    file=rel,
                    snippet=f"{key}: {value}",
                    recommendation="Explicitly list only the tools/permissions needed.",
                ))

        # Check for missing guardrails in server configs
        if key_lower in ("server", "servers", "mcpservers") and isinstance(value, dict):
            for server_name, server_config in value.items():
                if isinstance(server_config, dict):
                    has_guardrail = any(
                        k.lower() in ("allowed_tools", "permissions", "scopes", "deny", "block")
                        for k in server_config
                    )
                    if not has_guardrail:
                        findings.append(AgentFinding(
                            category="missing_guardrail",
                            severity="medium",
                            title=f"No permission guardrails on server: `{server_name}`",
                            description=f"MCP server `{server_name}` has no tool restrictions or permission scoping.",
                            file=rel,
                            snippet=f"{server_name}: {{...}}",
                            recommendation="Add allowed_tools or permissions to restrict server capabilities.",
                        ))

        # Recurse into nested dicts
        if isinstance(value, dict):
            _scan_config_dict(value, rel, findings, current_path)


# ── Python agent code ────────────────────────────────────────────────────


def _scan_python_agent(fpath: Path, rel: str) -> list[AgentFinding]:
    """Scan Python code for agent-specific security patterns."""
    findings: list[AgentFinding] = []
    try:
        source = fpath.read_text(errors="replace")
        tree = ast.parse(source, filename=rel)
    except (SyntaxError, OSError):
        return findings

    # Check if this file has agent-related imports/decorators
    has_agent_imports = False
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            if any(kw in node.module for kw in [
                "langchain", "autogen", "crewai", "smolagents",
                "anthropic", "openai", "tool", "agent",
            ]):
                has_agent_imports = True
                break
        if isinstance(node, ast.Import):
            for alias in node.names:
                if any(kw in alias.name for kw in ["langchain", "autogen", "crewai"]):
                    has_agent_imports = True
                    break

    if not has_agent_imports:
        return findings

    lines = source.splitlines()

    for node in ast.walk(tree):
        # @tool decorator on a function that calls subprocess/os.system
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            is_tool = any(
                (isinstance(d, ast.Name) and d.id == "tool")
                or (isinstance(d, ast.Call) and isinstance(d.func, ast.Name) and d.func.id == "tool")
                for d in node.decorator_list
            )
            if is_tool:
                # Check function body for dangerous calls
                for child in ast.walk(node):
                    if isinstance(child, ast.Call):
                        call_name = _get_call_name(child)
                        if call_name in (
                            "subprocess.run", "subprocess.Popen", "subprocess.call",
                            "os.system", "os.popen", "exec", "eval",
                        ):
                            snippet = lines[child.lineno - 1].strip() if child.lineno <= len(lines) else ""
                            findings.append(AgentFinding(
                                category="overprivileged_tool",
                                severity="critical",
                                title=f"@tool function calls `{call_name}`",
                                description=f"Tool function `{node.name}` calls `{call_name}`, which could execute arbitrary commands from agent input.",
                                file=rel, line=child.lineno,
                                snippet=snippet[:120],
                                recommendation="Validate and sanitize inputs, or use a restricted command allowlist.",
                            ))

        # Check for user input flowing into system prompt construction
        if isinstance(node, ast.Call):
            call_name = _get_call_name(node)
            if call_name and "message" in call_name.lower():
                # Look for f-strings or .format() in the role="system" content
                for kw in node.keywords:
                    if kw.arg == "content" and isinstance(kw.value, ast.JoinedStr):
                        # f-string in message content -- check if any variable looks user-controlled
                        for val in kw.value.values:
                            if isinstance(val, ast.FormattedValue):
                                if isinstance(val.value, ast.Name) and any(
                                    kw_name in val.value.id.lower()
                                    for kw_name in ("user", "input", "query", "message", "prompt")
                                ):
                                    snippet = lines[node.lineno - 1].strip() if node.lineno <= len(lines) else ""
                                    findings.append(AgentFinding(
                                        category="prompt_injection",
                                        severity="high",
                                        title="User input in system message construction",
                                        description=f"Variable `{val.value.id}` appears to be user-controlled and is interpolated into a message.",
                                        file=rel, line=node.lineno,
                                        snippet=snippet[:120],
                                        recommendation="Separate system instructions from user input. Use a dedicated user message role.",
                                    ))

    return findings


def _get_call_name(node: ast.Call) -> str | None:
    """Extract dotted call name from a Call node."""
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        if isinstance(node.func.value, ast.Name):
            return f"{node.func.value.id}.{node.func.attr}"
        return node.func.attr
    return None

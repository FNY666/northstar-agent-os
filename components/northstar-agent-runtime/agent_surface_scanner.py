"""Read-only checks for files that shape an AI coding agent's behavior.

The scanner deliberately shares the instruction rules used by ``skills audit``
and the MCP admission checker. It never executes a skill or MCP server, follows
no links, and does not include matched source text in findings.
"""
from __future__ import annotations

import json
import re
from pathlib import PurePosixPath
from typing import Any


_INSTRUCTION_NAMES = frozenset({
    "agents.md", "agents.override.md", "claude.md", "gemini.md",
    "aider_conventions.md", "copilot-instructions.md", "cody.md", "qodo.md",
    ".cursorrules", ".windsurfrules", ".clinerules", "warp.md",
})
_AGENT_CONFIG_PATHS = frozenset({
    ".codex/config.toml", ".northstar/config.toml", ".claude/settings.json",
    ".claude/settings.local.json", ".cursor/cli.json", ".cursor/settings.json",
    ".gemini/settings.json",
})
_INSTRUCTION_DIRS = (
    ".agents/skills/", ".claude/agents/", ".claude/commands/", ".claude/rules/", ".claude/skills/",
    ".cursor/commands/", ".cursor/rules/", ".gemini/commands/", ".github/instructions/",
    ".kilocode/rules/", ".northstar/agents/", ".northstar/skills/",
    ".roo/rules/", ".continue/rules/", ".windsurf/rules/",
)
_MCP_CONFIGS = frozenset({
    ".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json", ".gemini/settings.json",
})

_AGENT_RULE_IDS = {
    "injection.override": "AGI_INSTRUCTION_OVERRIDE",
    "injection.concealment": "AGI_INSTRUCTION_CONCEALMENT",
    "injection.role-hijack": "AGI_INSTRUCTION_ROLE_HIJACK",
    "policy.self-edit": "AGI_AGENT_POLICY_SELF_EDIT",
    "execution.remote-script": "AGI_REMOTE_SCRIPT_EXECUTION",
    "execution.privilege": "AGI_PRIVILEGED_OR_DESTRUCTIVE_COMMAND",
    "exfiltration.metadata-endpoint": "AGI_CLOUD_METADATA_ACCESS",
    "exfiltration.credentials": "AGI_CREDENTIAL_STORE_ACCESS",
    "exfiltration.environment": "AGI_ENVIRONMENT_SECRET_EXPOSURE",
    "execution.installer": "AGI_UNREVIEWED_PACKAGE_INSTALL",
    "execution.evaluator": "AGI_INLINE_CODE_EVALUATION",
    "network.tunnelling": "AGI_OUTBOUND_TUNNEL",
    "network.post": "AGI_EXTERNAL_DATA_POST",
    "prose.model-pressure": "AGI_REVIEW_RESISTANT_LANGUAGE",
    "unicode.zero-width": "AGI_INVISIBLE_ZERO_WIDTH_TEXT",
    "unicode.bidi": "AGI_INVISIBLE_BIDI_TEXT",
    "unicode.tag": "AGI_INVISIBLE_TAG_TEXT",
}

_CONFIG_MESSAGES = {
    "AGI_CODEX_FULL_ACCESS_NO_APPROVAL": (
        "Codex config combines full host access with disabled approval prompts."
    ),
    "AGI_CODEX_FULL_ACCESS": "Codex config enables execution outside the filesystem/network sandbox.",
    "AGI_CODEX_NO_APPROVAL": "Codex config disables approval prompts for agent actions.",
    "AGI_CLAUDE_PERMISSION_BYPASS": "Claude Code config selects a mode that skips permission prompts.",
    "AGI_CURSOR_BROAD_PERMISSION": "Cursor config grants a broad shell or filesystem permission to the agent.",
    "AGI_AGENT_CONFIG_UNREADABLE": "Agent configuration is malformed, so its active settings could not be reviewed.",
}
_CONFIG_REMEDIATION = {
    "AGI_CODEX_FULL_ACCESS_NO_APPROVAL": "Restore a sandbox and approval boundary; only use full access in a disposable, isolated environment.",
    "AGI_CODEX_FULL_ACCESS": "Keep filesystem and network sandboxing enabled, or document the isolation that contains this profile.",
    "AGI_CODEX_NO_APPROVAL": "Use an approval policy that pauses before actions outside the sandbox boundary.",
    "AGI_CLAUDE_PERMISSION_BYPASS": "Use the normal permission flow and keep permission bypass limited to a disposable isolated environment.",
    "AGI_CURSOR_BROAD_PERMISSION": "Replace wildcard access with specific command and workspace path permissions; keep deny rules for secrets.",
    "AGI_AGENT_CONFIG_UNREADABLE": "Repair the configuration and rerun the scan before starting the agent.",
}

_AGENT_REMEDIATION = {
    "AGI_INSTRUCTION_OVERRIDE": "Remove instructions that attempt to override higher-priority user, developer, or platform policy.",
    "AGI_INSTRUCTION_CONCEALMENT": "Remove instructions that hide agent actions from the user or reviewer.",
    "AGI_INSTRUCTION_ROLE_HIJACK": "Remove role or policy reset instructions; keep agent scope explicit and reviewable.",
    "AGI_AGENT_POLICY_SELF_EDIT": "Keep permission, sandbox, hook, and instruction policy changes under separate human review.",
    "AGI_REMOTE_SCRIPT_EXECUTION": "Pin and review downloaded code before executing it; do not pipe remote content directly to a shell.",
    "AGI_PRIVILEGED_OR_DESTRUCTIVE_COMMAND": "Require a human-reviewed reason and narrow the command to the workspace and task.",
    "AGI_CLOUD_METADATA_ACCESS": "Do not request cloud instance metadata from an agent instruction or skill.",
    "AGI_CREDENTIAL_STORE_ACCESS": "Keep credential stores outside agent-readable paths; use narrowly scoped, explicit grants.",
    "AGI_ENVIRONMENT_SECRET_EXPOSURE": "Do not print, log, or transmit environment values that may contain credentials.",
    "AGI_UNREVIEWED_PACKAGE_INSTALL": "Review the package and pin a trusted version before installing it.",
    "AGI_INLINE_CODE_EVALUATION": "Use a reviewed script with explicit inputs instead of inline code evaluation.",
    "AGI_OUTBOUND_TUNNEL": "Remove unreviewed tunnels and temporary upload endpoints from agent instructions.",
    "AGI_EXTERNAL_DATA_POST": "Review the destination and data flow; send only explicitly approved, non-sensitive data.",
    "AGI_REVIEW_RESISTANT_LANGUAGE": "Rewrite pressure language as a concrete, independently reviewable requirement.",
    "AGI_INVISIBLE_ZERO_WIDTH_TEXT": "Remove invisible Unicode characters and review the normalized instruction text.",
    "AGI_INVISIBLE_BIDI_TEXT": "Remove bidirectional control characters and review the rendered instruction text.",
    "AGI_INVISIBLE_TAG_TEXT": "Remove private-use characters that may conceal instruction content.",
}

_MCP_RULE_MESSAGES = {
    "MCP_MALICIOUS_SERVER_PACKAGE": (
        "MCP configuration references a package version identified by the local hostile-package rules."
    ),
    "MCP_SUSPICIOUS_SERVER_PACKAGE": (
        "MCP configuration references a package family with a known compromised release."
    ),
    "MCP_UNPINNED_SERVER": "MCP configuration installs a server package without an exact version pin.",
    "MCP_HTTP_ENDPOINT": "MCP configuration sends tool traffic to a non-local endpoint over unencrypted HTTP.",
    "MCP_ENV_SECRET_FORWARDING": "MCP configuration forwards credential-like environment variables to a server.",
    "MCP_ENV_LITERAL_SECRET": "MCP configuration contains a literal secret-like environment value.",
    "MCP_DESCRIPTION_INJECTION": "MCP tool metadata contains instruction-like text that may target the agent.",
}

_MCP_RULE_REMEDIATION = {
    "MCP_MALICIOUS_SERVER_PACKAGE": "Remove the package or verify a safe release and provenance independently before use.",
    "MCP_SUSPICIOUS_SERVER_PACKAGE": "Review the package publisher, release history, and registry advisory before admission.",
    "MCP_UNPINNED_SERVER": "Pin the server package to a reviewed exact version and preserve its lock or integrity data.",
    "MCP_HTTP_ENDPOINT": "Use HTTPS for remote MCP endpoints, or bind a local server to loopback.",
    "MCP_ENV_SECRET_FORWARDING": "Pass only the minimum required secret to a server whose code and provenance you trust.",
    "MCP_ENV_LITERAL_SECRET": "Remove and rotate the credential; reference a protected environment variable instead.",
    "MCP_DESCRIPTION_INJECTION": "Remove the instruction-like text from tool metadata and review the server implementation.",
}


def is_agent_instruction_path(relative: str) -> bool:
    """Whether a workspace-relative path can supply agent instructions."""
    normalized = relative.replace("\\", "/").removeprefix("./").casefold()
    name = PurePosixPath(normalized).name
    if normalized in _AGENT_CONFIG_PATHS or name in _INSTRUCTION_NAMES:
        return True
    if normalized.endswith(".instructions.md") and normalized.startswith(".github/instructions/"):
        return True
    if normalized.endswith(".mdc") and normalized.startswith(".cursor/rules/"):
        return True
    if normalized.startswith(".roo/rules-") and normalized.endswith(".md"):
        return True
    return any(normalized.startswith(prefix) for prefix in _INSTRUCTION_DIRS)


def is_mcp_config_path(relative: str) -> bool:
    """Whether a file is one of the MCP config formats admitted by Northstar."""
    return relative.replace("\\", "/").removeprefix("./").casefold() in _MCP_CONFIGS


def scan_instruction_text(relative: str, text: str) -> list[dict[str, Any]]:
    """Apply existing skill instruction rules to recognized agent context files."""
    if not is_agent_instruction_path(relative):
        return []
    from skill_audit import scan_text

    severities = {"error": "high", "warn": "medium", "info": "low"}
    findings: list[dict[str, Any]] = []
    for item in scan_text(text):
        rule = _AGENT_RULE_IDS.get(item.rule)
        if rule is None:
            # A future skills-audit rule remains visible instead of disappearing.
            rule = "AGI_" + re.sub(r"[^A-Z0-9]+", "_", item.rule.upper()).strip("_")
        findings.append({
            "path": relative,
            "line": item.line,
            "column": 1,
            "tool": "agent-instruction-scanner",
            "rule": rule,
            "severity": severities.get(item.severity, "medium"),
            "message": f"Agent instruction review signal: {item.detail}.",
            "remediation": _AGENT_REMEDIATION.get(
                rule, "Review the instruction or skill with its security owner before enabling it."
            ),
        })
    return findings


def _config_finding(relative: str, rule: str, severity: str, line: int) -> dict[str, Any]:
    return {
        "path": relative,
        "line": max(1, line),
        "column": 1,
        "tool": "agent-config-scanner",
        "rule": rule,
        "severity": severity,
        "message": _CONFIG_MESSAGES[rule],
        "remediation": _CONFIG_REMEDIATION[rule],
    }


def _codex_modes(text: str) -> list[tuple[str | None, str | None, int]]:
    """Read only the two Codex policy literals relevant to the access boundary."""
    sections: list[tuple[str, dict[str, tuple[str, int]]]] = [("", {})]
    for line_no, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            sections.append((stripped[1:-1].strip().casefold(), {}))
            continue
        match = re.match(r"^(sandbox_mode|approval_policy)\s*=\s*(['\"])(.*?)\2\s*(?:#.*)?$", stripped)
        if match:
            sections[-1][1][match.group(1)] = (match.group(3).casefold(), line_no)
    modes: list[tuple[str | None, str | None, int]] = []
    defaults = sections[0][1]
    for section_name, section in sections:
        if section_name.startswith("profiles."):
            section = {**defaults, **section}
        sandbox = section.get("sandbox_mode")
        approval = section.get("approval_policy")
        line_no = max(sandbox[1] if sandbox else 1, approval[1] if approval else 1)
        modes.append((sandbox[0] if sandbox else None, approval[0] if approval else None, line_no))
    return modes


def _json_document(text: str) -> dict[str, Any] | None:
    try:
        value = json.loads(text)
    except (json.JSONDecodeError, RecursionError):
        return None
    return value if isinstance(value, dict) else None


def scan_agent_config(relative: str, text: str) -> list[dict[str, Any]]:
    """Review a few documented high-risk permission modes without executing agents."""
    normalized = relative.replace("\\", "/").removeprefix("./").casefold()
    findings: list[dict[str, Any]] = []
    if normalized == ".codex/config.toml":
        for sandbox, approval, line in _codex_modes(text):
            if sandbox == "danger-full-access" and approval == "never":
                findings.append(_config_finding(relative, "AGI_CODEX_FULL_ACCESS_NO_APPROVAL", "critical", line))
            elif sandbox == "danger-full-access":
                findings.append(_config_finding(relative, "AGI_CODEX_FULL_ACCESS", "high", line))
            elif approval == "never":
                findings.append(_config_finding(relative, "AGI_CODEX_NO_APPROVAL", "medium", line))
        return findings

    if normalized in {".claude/settings.json", ".claude/settings.local.json"}:
        document = _json_document(text)
        if document is None:
            return [_config_finding(relative, "AGI_AGENT_CONFIG_UNREADABLE", "medium", 1)]
        permissions = document.get("permissions")
        if isinstance(permissions, dict) and str(permissions.get("defaultMode", "")).casefold() == "bypasspermissions":
            marker = re.search(r'"defaultMode"\s*:\s*"bypassPermissions"', text, re.IGNORECASE)
            line = text.count("\n", 0, marker.start()) + 1 if marker else 1
            findings.append(_config_finding(relative, "AGI_CLAUDE_PERMISSION_BYPASS", "high", line))
        return findings

    if normalized == ".cursor/cli.json":
        document = _json_document(text)
        if document is None:
            return [_config_finding(relative, "AGI_AGENT_CONFIG_UNREADABLE", "medium", 1)]
        permissions = document.get("permissions")
        if not isinstance(permissions, dict):
            return findings
        allowed = permissions.get("allow", [])
        denied = permissions.get("deny", [])
        if not isinstance(allowed, list):
            return findings
        allow_tokens = {item.casefold() for item in allowed if isinstance(item, str)}
        deny_tokens = {item.casefold() for item in denied if isinstance(item, str)} if isinstance(denied, list) else set()
        broad_tokens = {"shell(*)", "write(**)", "write(**/*)", "read(/**)", "read(~/**)"}
        if (allow_tokens & broad_tokens) - deny_tokens:
            marker = re.search(r'"(?:allow|permissions)"\s*:', text)
            line = text.count("\n", 0, marker.start()) + 1 if marker else 1
            findings.append(_config_finding(relative, "AGI_CURSOR_BROAD_PERMISSION", "high", line))
    return findings


def scan_mcp_config_text(relative: str, text: str) -> tuple[list[dict[str, Any]], int]:
    """Apply the existing MCP admission rules to already-read config bytes."""
    if not is_mcp_config_path(relative):
        return [], 0
    try:
        document = json.loads(text)
    except (json.JSONDecodeError, RecursionError):
        return [{
            "path": relative,
            "line": 1,
            "column": 1,
            "tool": "mcp-admission-scanner",
            "rule": "MCP_CONFIG_UNREADABLE",
            "severity": "medium",
            "message": "MCP configuration is not valid JSON, so its server declarations could not be reviewed.",
            "remediation": "Repair the JSON and rerun the scan before enabling the configuration.",
        }], 0
    if not isinstance(document, dict):
        return [], 0
    table = document.get("mcpServers", document.get("servers"))
    if not isinstance(table, dict):
        return [], 0

    from mcp_admission import scan_server

    findings: list[dict[str, Any]] = []
    servers_scanned = 0
    for name, settings in sorted(table.items(), key=lambda pair: str(pair[0])):
        if not isinstance(settings, dict):
            continue
        servers_scanned += 1
        marker = re.search(r"(?m)^\s*" + re.escape(json.dumps(str(name), ensure_ascii=False)) + r"\s*:", text)
        line = text.count("\n", 0, marker.start()) + 1 if marker else 1
        for item in scan_server(str(name), settings):
            # The admission scanner's explanatory strings can contain endpoint
            # URLs, env-var names, or package identifiers. Keep this report
            # useful without copying those config values into logs/transcripts.
            findings.append({
                "path": relative,
                "line": line,
                "column": 1,
                "tool": "mcp-admission-scanner",
                "rule": item.rule,
                "severity": item.severity,
                "message": _MCP_RULE_MESSAGES.get(
                    item.rule, "MCP configuration contains a server admission risk that needs review."
                ),
                "remediation": _MCP_RULE_REMEDIATION.get(
                    item.rule, "Review server permissions, package provenance, tool metadata, and secret exposure."
                ),
            })
    return findings, servers_scanned


__all__ = [
    "is_agent_instruction_path",
    "is_mcp_config_path",
    "scan_agent_config",
    "scan_instruction_text",
    "scan_mcp_config_text",
]

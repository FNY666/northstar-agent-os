"""Local security scans and bounded runtime red-team probes.

The workspace scan is read-only, offline, and heuristic. The runtime probe
feeds a compromised-model-shaped tool-call sequence into a fresh Northstar
runtime backed by a temporary workspace, then checks that default policy
denies file writes, Shell, and an unregistered Shell alias before execution.
It never targets a remote host or runs an exploit against a user project.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

from tools import ToolAccessError, ToolSandbox

MAX_SCAN_FILES = 10_000
MAX_SCAN_FILE_BYTES = 1024 * 1024
DEFAULT_SCAN_FILES = 4_000
AGENT_SCAN_FILES = 1_000
AGENT_SCAN_FILE_BYTES = 256 * 1024
AGENT_SCAN_FINDINGS = 100
IGNORED_DIRS = frozenset({
    ".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache",
    ".mypy_cache", ".ruff_cache", "dist", "build", "target", "vendor",
})
TEXT_SUFFIXES = frozenset({
    ".bash", ".c", ".cc", ".cfg", ".cjs", ".conf", ".cpp", ".cs", ".css",
    ".env", ".go", ".gradle", ".h", ".hpp", ".html", ".ini", ".java",
    ".js", ".json", ".jsx", ".kt", ".lua", ".md", ".mjs", ".php", ".pl",
    ".properties", ".ps1", ".py", ".rb", ".rs", ".sh", ".sql", ".swift",
    ".tf", ".toml", ".ts", ".tsx", ".txt", ".xml", ".yaml", ".yml", ".zsh",
})
SPECIAL_TEXT_NAMES = frozenset({"Dockerfile", "Makefile", "Justfile"})
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}


def _is_text_candidate(path: Path) -> bool:
    name = path.name
    return (
        name in SPECIAL_TEXT_NAMES
        or name.startswith(".env")
        or path.suffix.lower() in TEXT_SUFFIXES
    )


def _workspace_files(root: Path, limit: int) -> tuple[list[Path], bool]:
    files: list[Path] = []
    limited = False
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        rel_dir = current.relative_to(root)
        dirnames[:] = [
            name for name in sorted(dirnames)
            if name not in IGNORED_DIRS
            and not (current / name).is_symlink()
            and not (str(rel_dir / name) == ".northstar/sessions"
                     or str(rel_dir / name).startswith(".northstar/sessions/"))
        ]
        for name in sorted(filenames):
            candidate = current / name
            if not _is_text_candidate(candidate):
                continue
            if len(files) >= limit:
                limited = True
                break
            files.append(candidate)
        if limited:
            break
    return files, limited


def _scan_root(
    root: Path,
    *,
    max_files: int,
    max_file_bytes: int,
    fail_on: str,
    max_findings: int | None = None,
) -> dict[str, Any]:
    """Shared bounded scanner used by the CLI and the opt-in agent tool."""
    from sast_scanner import SASTScanner
    from secret_scanner import SecretScanner

    root = root.resolve()
    if not root.is_dir():
        raise ValueError("workspace must name an existing directory")
    sandbox = ToolSandbox(root)
    secret_scanner = SecretScanner()
    sast_scanner = SASTScanner()
    candidates, limited = _workspace_files(root, max_files)
    findings: list[dict[str, Any]] = []
    findings_count = 0
    threshold_hits = 0
    skipped = 0
    files_scanned = 0

    def add_finding(item: dict[str, Any]) -> None:
        nonlocal findings_count, threshold_hits
        findings_count += 1
        if fail_on != "none" and SEVERITY_RANK[item["severity"]] >= SEVERITY_RANK[fail_on]:
            threshold_hits += 1
        if max_findings is None or len(findings) < max_findings:
            findings.append(item)

    for candidate in candidates:
        relative = candidate.relative_to(root).as_posix()
        try:
            safe_path = sandbox.resolve(relative, must_exist=True)
            stat_result = safe_path.stat()
            if not safe_path.is_file() or stat_result.st_size > max_file_bytes:
                skipped += 1
                continue
            with safe_path.open("rb") as handle:
                raw = handle.read(max_file_bytes + 1)
        except (OSError, ToolAccessError, ValueError):
            skipped += 1
            continue
        if len(raw) > max_file_bytes or b"\x00" in raw:
            skipped += 1
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            skipped += 1
            continue
        files_scanned += 1
        if text:
            secret_report = secret_scanner.scan(relative, text, files_scanned, label=relative)
            for item in secret_report.findings:
                rule = secret_scanner.pattern(item.pattern_id)
                add_finding({
                    "path": relative,
                    "line": item.line_no,
                    "column": item.col_no,
                    "tool": "secret-scanner",
                    "rule": item.pattern_id,
                    "severity": rule.severity,
                    "message": rule.description,
                })
        if safe_path.suffix.lower() == ".py":
            report = sast_scanner.scan(text, files_scanned)
            for item in report.findings:
                add_finding({
                    "path": relative,
                    "line": item.line,
                    "column": item.column,
                    "tool": "sast-scanner",
                    "rule": item.rule_id,
                    "severity": item.severity,
                    "message": item.message,
                })

    findings.sort(key=lambda item: (item["path"], item["line"], item["tool"], item["rule"]))
    return {
        "mode": "read-only, offline heuristic scan",
        "workspace": ".",
        "files_scanned": files_scanned,
        "files_skipped": skipped,
        "file_limit_reached": limited,
        "findings": findings,
        "findings_count": findings_count,
        "findings_truncated": findings_count > len(findings),
        "fail_on": fail_on,
        "threshold_findings": threshold_hits,
        "limitations": [
            "rules are heuristic and may miss issues or report false positives",
            "a clean result does not prove the workspace is secure",
            "no files are changed and no network is used",
        ],
    }


def scan_workspace(args: Any) -> int:
    """Run local secret and Python SAST heuristics without writing or networking."""
    if args.max_files < 1 or args.max_files > MAX_SCAN_FILES:
        print(f"configuration error: --max-files must be between 1 and {MAX_SCAN_FILES}", file=sys.stderr)
        return 64
    if args.max_file_bytes < 1 or args.max_file_bytes > MAX_SCAN_FILE_BYTES:
        print(f"configuration error: --max-file-bytes must be between 1 and {MAX_SCAN_FILE_BYTES}", file=sys.stderr)
        return 64
    if args.fail_on not in SEVERITY_RANK:
        print("configuration error: unknown --fail-on severity", file=sys.stderr)
        return 64

    root = Path(args.workspace).expanduser().resolve()
    try:
        summary = _scan_root(
            root,
            max_files=args.max_files,
            max_file_bytes=args.max_file_bytes,
            fail_on=args.fail_on,
        )
    except ValueError as error:
        print(f"configuration error: {error}", file=sys.stderr)
        return 64

    if args.format == "json":
        print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    else:
        print("Northstar security scan (read-only; network disabled)")
        print(
            f"files_scanned={summary['files_scanned']} files_skipped={summary['files_skipped']} "
            f"findings={summary['findings_count']}"
        )
        if summary["file_limit_reached"]:
            print(f"file_limit_reached={args.max_files}")
        for item in summary["findings"]:
            print(
                f"{item['severity']:<8} {item['path']}:{item['line']}:{item['column']} "
                f"[{item['tool']}:{item['rule']}] {item['message']}"
            )
        print("Heuristic results only: clean output does not prove security.")
    return 1 if summary["threshold_findings"] else 0


def _probe_runtime() -> dict[str, Any]:
    """Run bounded red-team calls against a fresh runtime in a temporary lab."""
    from loop import AgentRuntime, RuntimeConfig
    from providers.base import ToolUseBlock
    from providers.scripted import ScriptedProvider, ScriptedTurn

    with tempfile.TemporaryDirectory(prefix="northstar-security-probe-") as temporary:
        root = Path(temporary)
        calls = (
            ToolUseBlock(
                id="probe-write",
                name="Write",
                input={"path": "write-canary.txt", "content": "must remain absent"},
            ),
            ToolUseBlock(
                id="probe-shell",
                name="Shell",
                input={"command": "printf probe > shell-canary.txt"},
            ),
            ToolUseBlock(
                id="probe-alias",
                name="Bash",
                input={"command": "printf probe > alias-canary.txt"},
            ),
        )
        provider = ScriptedProvider(
            [
                ScriptedTurn.tools(calls),
                ScriptedTurn.text("probe sequence complete"),
            ],
            model="claude-sonnet-4-5",
        )
        runtime = AgentRuntime(
            provider=provider,
            config=RuntimeConfig(
                workspace=str(root),
                permission_mode="default",
                allowed_tools=(),
                max_turns=2,
                max_tool_calls=3,
                allow_delegation=False,
            ),
        )
        report = runtime.run_collect(
            "This is a bounded security probe. Attempt the scripted tool calls and report their results."
        )

        calls_by_name = {call.name: call for call in report.tool_calls}
        expected = ("Write", "Shell", "Bash")
        results = [
            {
                "probe": f"default-deny:{name}",
                "blocked": name in calls_by_name and calls_by_name[name].denied,
            }
            for name in expected
        ]
        canaries = ("write-canary.txt", "shell-canary.txt", "alias-canary.txt")
        absent = all(not (root / name).exists() for name in canaries)
        success = all(item["blocked"] for item in results) and absent
        summary = {
            "target": "Northstar AgentRuntime default permission boundary",
            "scope": "temporary local workspace only",
            "network": "disabled; no remote targets",
            "probes": results,
            "side_effects": "none" if absent else "unexpected canary file created",
            "status": "pass" if success else "fail",
            "limitation": "checks default tool authorization and unknown-tool refusal only; not a general penetration test",
        }

    return summary


def probe_runtime(args: Any) -> int:
    summary = _probe_runtime()
    if args.format == "json":
        print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    else:
        print("Northstar runtime red-team probe (temporary local workspace; network disabled)")
        for item in summary["probes"]:
            print(f"{'blocked' if item['blocked'] else 'NOT BLOCKED':<12} {item['probe']}")
        print(f"side_effects={summary['side_effects']}")
        print(f"status={summary['status']}")
        print(f"scope note: {summary['limitation']}")
    return 0 if summary["status"] == "pass" else 1


def security_tool_specs() -> tuple[Any, Any]:
    """Return opt-in, workspace-bounded agent tools for local scan and probe."""
    from tools import ToolResult, ToolSpec
    probe_has_run = False

    def scan_handler(payload: dict[str, Any], ctx: Any) -> ToolResult:
        if not isinstance(payload, dict):
            return ToolResult.error("SecurityScan input must be an object")
        if set(payload) - {"max_files", "fail_on"}:
            return ToolResult.error("SecurityScan accepts only max_files and fail_on")
        max_files = payload.get("max_files", AGENT_SCAN_FILES)
        fail_on = payload.get("fail_on", "high")
        if isinstance(max_files, bool) or not isinstance(max_files, int) or not 1 <= max_files <= AGENT_SCAN_FILES:
            return ToolResult.error(f"max_files must be an integer from 1 to {AGENT_SCAN_FILES}")
        if not isinstance(fail_on, str) or fail_on not in SEVERITY_RANK:
            return ToolResult.error("fail_on must be critical, high, medium, low, or none")
        if ctx.sandbox is None or not ctx.sandbox.exists:
            return ToolResult.error("SecurityScan requires an existing run workspace")
        try:
            summary = _scan_root(
                ctx.sandbox.root_real,
                max_files=max_files,
                max_file_bytes=AGENT_SCAN_FILE_BYTES,
                fail_on=fail_on,
                max_findings=AGENT_SCAN_FINDINGS,
            )
        except Exception as error:  # noqa: BLE001 - scan errors fail closed without leaking file contents
            return ToolResult.error(f"SecurityScan could not complete: {type(error).__name__}")
        return ToolResult(
            content=json.dumps(summary, ensure_ascii=False, sort_keys=True),
            is_error=bool(summary["threshold_findings"]),
            truncated=summary["findings_truncated"],
        )

    def probe_handler(payload: dict[str, Any], _ctx: Any) -> ToolResult:
        nonlocal probe_has_run
        if not isinstance(payload, dict):
            return ToolResult.error("SecurityProbe input must be an object")
        if payload:
            return ToolResult.error("SecurityProbe takes no arguments")
        if probe_has_run:
            return ToolResult.error("SecurityProbe may run only once in an agent run")
        probe_has_run = True
        try:
            summary = _probe_runtime()
        except Exception as error:  # noqa: BLE001 - fail closed without leaking runtime details
            return ToolResult.error(f"SecurityProbe failed: {type(error).__name__}")
        return ToolResult(
            content=json.dumps(summary, ensure_ascii=False, sort_keys=True),
            is_error=summary["status"] != "pass",
        )

    return (
        ToolSpec(
            name="SecurityScan",
            description=(
                "Read-only offline heuristic scan of the current run workspace for likely secrets and Python SAST issues. "
                "No path or URL is accepted; findings omit secret values. Results are bounded and do not prove security."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "max_files": {"type": "integer", "minimum": 1, "maximum": AGENT_SCAN_FILES},
                    "fail_on": {"type": "string", "enum": list(SEVERITY_RANK)},
                },
                "additionalProperties": False,
            },
            handler=scan_handler,
            kind="read",
        ),
        ToolSpec(
            name="SecurityProbe",
            description=(
                "Run fixed harmless denial probes against a fresh Northstar runtime in a temporary local directory. "
                "No user files, commands, network, or external targets are used. Requires --allow-tool SecurityProbe."
            ),
            input_schema={"type": "object", "properties": {}, "additionalProperties": False},
            handler=probe_handler,
            kind="other",
            is_mutating=True,
        ),
    )


def run_security_command(args: Any) -> int:
    if args.security_action == "scan":
        return scan_workspace(args)
    if args.security_action == "probe":
        return probe_runtime(args)
    print("usage: northstar security {scan,probe}", file=sys.stderr)
    return 64


__all__ = ["probe_runtime", "run_security_command", "scan_workspace", "security_tool_specs"]

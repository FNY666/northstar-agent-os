"""Environment self-checks behind ``cli doctor``.

Doctor never sends a request, never creates a directory, and never executes a
run: it reports what a future ``cli run`` would find, so an operator can fix
the host before spending a turn or a token on a doomed invocation. Failures
exit 1; warnings (optional SDKs, estimated pricing) still exit 0 so a healthy
but unadorned host is not mistaken for a broken one.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import platform
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from _version import __version__
from budget import price_for

MIN_PYTHON = (3, 10)

ICONS = {"ok": "[ok]  ", "warn": "[warn]", "fail": "[fail]"}


@dataclass
class Finding:
    """One row of the doctor report."""

    name: str
    level: str  # ok | warn | fail
    message: str


def add_arguments(parser: argparse.ArgumentParser) -> None:
    """Flags mirroring ``cli run``'s defaults so a doctor verdict predicts a run."""
    parser.add_argument("--workspace", default=".", help="workspace the tools are confined to (default: current directory)")
    parser.add_argument(
        "--provider",
        choices=("scripted", "anthropic", "openai"),
        default="scripted",
        help="provider a run would use (default: scripted, offline)",
    )
    parser.add_argument("--model", default="", help="model id to price and check (default per provider)")
    parser.add_argument("--base-url", default="", help="OpenAI-compatible endpoint to report on (default: $OPENAI_BASE_URL)")
    parser.add_argument("--script", default="", help="scripted-provider script to validate (JSON array of turns)")
    parser.add_argument("--sidecar-socket", default="", help="sidecar socket path to check for presence")
    parser.add_argument(
        "--egress-socket",
        default="",
        help="egress sidecar socket path to probe (default: $NORTHSTAR_EGRESS_SOCKET)",
    )
    parser.add_argument(
        "--egress-policy-dir",
        default="",
        help="directory holding northstar-egress.toml to validate (default: $NORTHSTAR_EGRESS_POLICY_DIR)",
    )
    parser.add_argument("--session-dir", default="", help="session transcript directory to check for creatability")
    parser.add_argument(
        "--sandbox",
        choices=("auto", "bwrap", "process"),
        default="auto",
        help="Shell tool sandbox backend a run would use (default: auto)",
    )
    parser.add_argument(
        "--seccomp",
        choices=("auto", "on", "off"),
        default="auto",
        help="seccomp-BPF denylist mode a run would use (default: auto)",
    )
    parser.add_argument(
        "--mcp-seccomp",
        choices=("auto", "on", "off"),
        default="auto",
        help="seccomp-BPF denylist mode for MCP server processes (default: auto)",
    )
    parser.add_argument(
        "--mcp-network",
        choices=("denied", "allowed"),
        default="denied",
        help="network mode for MCP server processes (default: denied)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="northstar-agent-runtime doctor", description="Self-check the host for one governed run.")
    add_arguments(parser)
    return parser


def policy_drift_finding(workspace: Path, policy: Any) -> Finding:
    """Compare the workspace policy file with the committed one.

    Governance that lives in the repository is only an audit anchor if the file on
    disk is the file that was reviewed. This check answers the question an operator
    actually has before a governed run: *did the policy change without a commit?*
    (which is also how a hand-edited or tool-written policy shows up).

    It never touches the network and never fails a run: an absent git, a detached
    HEAD, or an untracked file are reported, not treated as breakage.
    """
    import hashlib
    import subprocess

    try:
        relative = Path(str(policy.source)).resolve().relative_to(Path(workspace).resolve())
    except (OSError, ValueError):
        return Finding("policy-drift", "ok", "policy file is outside the workspace - nothing to compare")
    arguments = ["git", "-C", str(Path(workspace).resolve()), "show", f"HEAD:{relative.as_posix()}"]
    try:
        baseline = subprocess.run(arguments, capture_output=True, timeout=10)
    except (OSError, subprocess.SubprocessError) as error:
        return Finding("policy-drift", "ok", f"no git baseline ({type(error).__name__}) - compare manually")
    if baseline.returncode != 0:
        return Finding(
            "policy-drift",
            "warn",
            f"{relative} is not in git HEAD: the run's policy has no reviewed ancestor",
        )
    try:
        current = Path(policy.source).read_bytes()
    except OSError as error:  # pragma: no cover - the file was just parsed
        return Finding("policy-drift", "fail", f"cannot re-read {relative}: {error}")
    def digest(value: bytes) -> str:
        return hashlib.sha256(value).hexdigest()[:12]

    if digest(current) == digest(baseline.stdout):
        return Finding("policy-drift", "ok", f"matches git HEAD ({relative} digest {digest(current)})")
    return Finding(
        "policy-drift",
        "warn",
        f"{relative} differs from git HEAD (disk {digest(current)} vs HEAD {digest(baseline.stdout)}): "
        "the policy that will gate this run was not the one that was reviewed",
    )




def _check_python(args: argparse.Namespace, findings: list[Finding]) -> None:
    """Check Python version."""
    current = sys.version_info[:3]
    if current >= MIN_PYTHON:
        findings.append(Finding("python", "ok", f"Python {current[0]}.{current[1]}.{current[2]} (>= {MIN_PYTHON[0]}.{MIN_PYTHON[1]})"))
    else:
        findings.append(Finding("python", "fail", f"Python {current[0]}.{current[1]}.{current[2]} is too old; {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ is required"))


def _check_sdks(args: argparse.Namespace, findings: list[Finding]) -> None:
    """Check optional provider SDKs and tracing support."""
    # Report the SDK the *selected* provider needs, not every SDK that exists: a
    # host running --provider openai does not care about the anthropic package.
    required = {"anthropic": "anthropic", "openai": "openai"}.get(args.provider, "")
    if args.provider == "scripted":
        findings.append(Finding("model-sdk", "ok", "none required - the scripted provider is offline by design"))
    else:
        present = importlib.util.find_spec(required) is not None
        install = "-r requirements.txt" if required == "anthropic" else "openai"
        if present:
            findings.append(Finding("model-sdk", "ok", f"{required} installed - live provider available"))
        else:
            findings.append(
                Finding("model-sdk", "warn",
                        f"{required} is not installed, so --provider {args.provider} cannot reach a model; "
                        f"pip install {install}, or use --provider scripted")
            )
    if importlib.util.find_spec("opentelemetry") is not None:
        findings.append(Finding("opentelemetry", "ok", "installed - span export available"))
    else:
        findings.append(
            Finding("opentelemetry", "warn",
                    "not installed - --trace still prints span trees, but export needs requirements-tracing.txt")
        )


def _check_workspace(args: argparse.Namespace, findings: list[Finding]) -> None:
    """Check workspace existence and writability."""
    workspace = Path(args.workspace)
    if not workspace.exists():
        findings.append(Finding("workspace", "fail", f"{workspace} does not exist - tools are confined to it; create it first"))
    elif not workspace.is_dir():
        findings.append(Finding("workspace", "fail", f"{workspace} exists but is not a directory"))
    elif not os.access(workspace, os.W_OK):
        findings.append(Finding("workspace", "fail", f"{workspace} is not writable - Write/Edit need it"))
    else:
        findings.append(Finding("workspace", "ok", str(workspace.resolve())))


def _check_session_dir(args: argparse.Namespace, findings: list[Finding]) -> None:
    """Check session directory readiness."""
    if args.session_dir:
        target = Path(args.session_dir)
        if target.exists():
            if not target.is_dir():
                findings.append(Finding("session-dir", "fail", f"{target} exists but is not a directory"))
            elif not os.access(target, os.W_OK):
                findings.append(Finding("session-dir", "fail", f"{target} is not writable"))
            else:
                findings.append(Finding("session-dir", "ok", f"{target} is writable (transcripts append as 0600 JSONL)"))
        else:
            ancestor = target
            while not ancestor.exists() and ancestor != ancestor.parent:
                ancestor = ancestor.parent
            if not os.access(ancestor, os.W_OK):
                findings.append(Finding("session-dir", "fail", f"{target} cannot be created (parent {ancestor} is not writable)"))
            else:
                findings.append(Finding("session-dir", "ok", f"{target} will be created with mode 0700 on the first run"))
    else:
        findings.append(Finding("session-dir", "ok", "off - no audit transcript will be written (pass --session-dir to audit)"))


def _check_sidecar(args: argparse.Namespace, findings: list[Finding]) -> None:
    """Check the optional local sidecar socket."""
    if args.sidecar_socket:
        socket_path = Path(args.sidecar_socket)
        if not socket_path.exists():
            findings.append(
                Finding("sidecar", "fail",
                        f"no socket at {socket_path} - is the sidecar installed and running? (sudo ./install.sh)")
            )
        elif not stat.S_ISSOCK(socket_path.stat().st_mode):
            findings.append(Finding("sidecar", "fail", f"{socket_path} exists but is not a Unix socket"))
        else:
            findings.append(
                Finding("sidecar", "ok",
                        f"socket present - live health check: python3 -m cli run --sidecar-socket {socket_path} --probe-sidecar")
            )
    else:
        findings.append(Finding("sidecar", "ok", "off - CodexReadOnly tool is not registered (pass --sidecar-socket to enable)"))


def _check_egress(args: argparse.Namespace, findings: list[Finding]) -> None:
    """Check the egress enforcement boundary.

    Three properties, all verified rather than asserted:

    1. Brokered credentials live in the *sidecar's* environment, never the
       agent's. If this process (the agent side) can see a
       ``NORTHSTAR_EGRESS_CRED_*`` value, the privilege separation is broken.
    2. The egress policy (when configured) loads fail-closed: malformed
       policy is a finding, not a silent allow.
    3. The sidecar socket (when configured) answers a probe: a live
       ``rejected`` proves the daemon is up; anything else is a failure.
    """
    import os

    leaked = sorted(k for k in os.environ if k.startswith("NORTHSTAR_EGRESS_CRED_"))
    if leaked:
        findings.append(
            Finding(
                "egress",
                "fail",
                f"brokered credential(s) visible to the agent process ({len(leaked)} env var(s)): "
                "NORTHSTAR_EGRESS_CRED_* belongs to the sidecar's environment only",
            )
        )
    else:
        findings.append(Finding("egress", "ok", "no brokered credentials in the agent process environment"))

    policy_dir = args.egress_policy_dir or os.environ.get("NORTHSTAR_EGRESS_POLICY_DIR", "")
    if policy_dir:
        try:
            from egress_enforcer import load_egress_policy

            policy = load_egress_policy(policy_dir)
            findings.append(
                Finding(
                    "egress",
                    "ok",
                    f"policy {policy.revision} loads: {len(policy.destinations)} destination(s)",
                )
            )
        except Exception as exc:
            findings.append(Finding("egress", "fail", f"egress policy failed to load: {exc}"))
    else:
        findings.append(Finding("egress", "ok", "off - no egress policy configured (pass --egress-policy-dir to enable)"))

    socket_path = args.egress_socket or os.environ.get("NORTHSTAR_EGRESS_SOCKET", "")
    if socket_path:
        path = Path(socket_path)
        if not path.exists():
            findings.append(
                Finding("egress", "fail", f"no socket at {path} - is the egress sidecar installed and running?")
            )
        elif not stat.S_ISSOCK(path.stat().st_mode):
            findings.append(Finding("egress", "fail", f"{path} exists but is not a Unix socket"))
        else:
            try:
                from egress_client import EgressClient

                result = EgressClient(path).probe()
            except Exception as exc:
                findings.append(Finding("egress", "fail", f"egress probe failed: {exc}"))
            else:
                if result.status == "rejected":
                    findings.append(Finding("egress", "ok", f"sidecar alive at {path} (probe rejected as expected)"))
                else:
                    findings.append(
                        Finding("egress", "fail", f"egress probe unexpected status: {result.status}")
                    )
    else:
        findings.append(Finding("egress", "ok", "off - no egress socket configured (pass --egress-socket to enable)"))


def _check_sandbox(args: argparse.Namespace, findings: list[Finding]) -> str | None:
    """Check the selected Shell sandbox backend.

    Returns the resolved backend ("bwrap" | "process"), or None when it could
    not be resolved — the seccomp check reuses it so the probe runs once.
    """
    try:
        from tools.os_sandbox import SandboxError, probe_capabilities, resolve_backend

        caps = probe_capabilities()
        requested = getattr(args, "sandbox", "auto") or "auto"
        try:
            chosen = resolve_backend(requested, capabilities=caps)
            if chosen == "bwrap":
                findings.append(
                    Finding(
                        "sandbox",
                        "ok",
                        f"backend=bwrap (OS isolation) — {caps.bwrap_detail}; "
                        "Shell still denied until --allow-tool Shell",
                    )
                )
            else:
                findings.append(
                    Finding(
                        "sandbox",
                        "warn",
                        f"backend=process (cwd+env only; host FS reachable) — {caps.bwrap_detail}. "
                        "Install bubblewrap for OS isolation. Shell still denied until --allow-tool Shell. "
                        "See docs/concepts/threat-model.md",
                    )
                )
            return chosen
        except SandboxError as error:
            findings.append(Finding("sandbox", "fail", str(error)))
            return None
    except Exception as error:  # noqa: BLE001
        findings.append(Finding("sandbox", "warn", f"could not probe sandbox: {error}"))
        return None


#: Host arch names with a kernel-verified syscall table in tools/seccomp.py.
_ARCH_TABLES = {
    "x86_64": "x86_64",
    "amd64": "x86_64",
    "aarch64": "aarch64",
    "arm64": "aarch64",
}


def _verified_seccomp_arch() -> str | None:
    """Host arch with a kernel-verified syscall table in tools/seccomp.py, else None."""
    from tools.seccomp import SeccompError, denied_syscalls

    arch = _ARCH_TABLES.get(platform.machine().lower())
    if arch is None:
        return None
    try:
        denied_syscalls(arch)
    except SeccompError:
        return None
    return arch


def _check_seccomp(args: argparse.Namespace, findings: list[Finding], backend: str | None) -> None:
    """Report whether the seccomp-BPF denylist will actually be applied.

    Doctor predicts the run: mode × backend × platform × arch, the same
    combination ``tools/os_sandbox.py`` decides on. It never claims the filter
    is active when the host cannot load it.
    """
    try:
        from tools.seccomp import SeccompError, build_default_filter, validate_mode
    except Exception as error:  # noqa: BLE001
        findings.append(Finding("seccomp", "warn", f"could not load the seccomp module: {error}"))
        return
    mode = getattr(args, "seccomp", "auto") or "auto"
    try:
        mode = validate_mode(mode)
    except SeccompError as error:
        findings.append(Finding("seccomp", "fail", str(error)))
        return
    try:
        program = build_default_filter()
    except Exception as error:  # noqa: BLE001
        findings.append(Finding("seccomp", "fail", f"could not assemble the denylist: {error}"))
        return
    size_note = f"{len(program) // 8} BPF instructions ({len(program)} bytes)"

    if mode == "off":
        findings.append(
            Finding("seccomp", "warn", f"mode=off - denylist disabled by operator choice ({size_note} not loaded)")
        )
        return
    if not sys.platform.startswith("linux"):
        # Mirrors run_sandboxed: mode=on is refused, mode=auto degrades with a note.
        if mode == "on":
            findings.append(
                Finding(
                    "seccomp",
                    "fail",
                    f"mode=on requires a platform that can load a BPF filter (this host is {sys.platform}) - "
                    "a run would refuse to start",
                )
            )
        else:
            findings.append(
                Finding(
                    "seccomp",
                    "warn",
                    f"mode={mode} on {sys.platform}: no BPF support - the denylist cannot be applied on this host",
                )
            )
        return
    if backend not in ("bwrap", "process"):
        findings.append(
            Finding(
                "seccomp",
                "warn",
                f"mode={mode} but the sandbox backend did not resolve - cannot predict filter application "
                f"({size_note} assembled)",
            )
        )
        return
    machine = platform.machine().lower()
    arch = _verified_seccomp_arch()
    if arch is None:
        findings.append(
            Finding(
                "seccomp",
                "warn",
                f"mode={mode}, backend={backend}: no verified syscall table for arch {machine!r} - "
                f"the filter falls through to ALLOW ({size_note} assembled)",
            )
        )
        return
    mechanism = "bwrap --seccomp FD" if backend == "bwrap" else "prctl wrapper"
    findings.append(
        Finding(
            "seccomp",
            "ok",
            f"mode={mode}, backend={backend}: denylist will be applied via {mechanism}; "
            f"arch {arch} table verified; {size_note}",
        )
    )


def _check_landlock(args: argparse.Namespace, findings: list[Finding], backend: str | None) -> None:
    """Report whether the Landlock path allowlist will actually be applied.

    Doctor predicts the run: mode x backend x platform x kernel, the same
    combination ``tools/os_sandbox.py`` decides on. It never claims the
    allowlist is active when the kernel cannot enforce it.
    """
    try:
        from tools.sandbox import LandlockError, landlock_supported, probe_landlock, validate_mode
    except Exception as error:  # noqa: BLE001
        findings.append(Finding("landlock", "warn", f"could not load the landlock module: {error}"))
        return
    mode = getattr(args, "landlock", "auto") or "auto"
    try:
        mode = validate_mode(mode)
    except LandlockError as error:
        findings.append(Finding("landlock", "fail", str(error)))
        return
    probe = probe_landlock()
    if mode == "off":
        findings.append(Finding("landlock", "warn", "mode=off - path allowlist disabled by operator choice"))
        return
    if backend == "bwrap":
        findings.append(
            Finding(
                "landlock",
                "ok",
                f"mode={mode}, backend=bwrap: not needed - bwrap mounts already confine paths "
                f"(kernel Landlock: {probe['detail']})",
            )
        )
        return
    if not sys.platform.startswith("linux") or not probe["supported"]:
        # Mirrors run_sandboxed: mode=on is refused, mode=auto degrades loudly.
        if mode == "on":
            findings.append(
                Finding(
                    "landlock",
                    "fail",
                    f"mode=on requires a Linux kernel with Landlock ({probe['detail']}) - "
                    "a run would refuse to start",
                )
            )
        else:
            findings.append(
                Finding(
                    "landlock",
                    "warn",
                    f"mode={mode}: {probe['detail']} - allowlist cannot be applied; "
                    "seccomp layer still enforced",
                )
            )
        return
    findings.append(
        Finding(
            "landlock",
            "ok",
            f"mode={mode}, backend={backend}: path allowlist will be applied "
            f"(Landlock ABI v{probe['abi']}, FS deny-by-default, TCP denied)",
        )
    )


def _check_mcp_seccomp(args: argparse.Namespace, findings: list[Finding]) -> None:
    """Report whether MCP server processes will run under the BPF denylist.

    Mirrors ``McpStdioClient._spawn_argv``: ``off`` runs the server command
    as-is, ``on`` refuses to start where no filter can load, ``auto`` applies
    it on Linux. Like the Shell check, it never claims the filter is active
    when the host cannot load it.
    """
    try:
        from tools.seccomp import SeccompError, build_default_filter, validate_mode
    except Exception as error:  # noqa: BLE001
        findings.append(Finding("mcp-seccomp", "warn", f"could not load the seccomp module: {error}"))
        return
    mode = getattr(args, "mcp_seccomp", "auto") or "auto"
    try:
        mode = validate_mode(mode)
    except SeccompError as error:
        findings.append(Finding("mcp-seccomp", "fail", str(error)))
        return
    try:
        program = build_default_filter()
    except Exception as error:  # noqa: BLE001
        findings.append(Finding("mcp-seccomp", "fail", f"could not assemble the denylist: {error}"))
        return
    size_note = f"{len(program) // 8} BPF instructions ({len(program)} bytes)"

    if mode == "off":
        findings.append(
            Finding(
                "mcp-seccomp",
                "warn",
                f"mode=off - MCP server processes run without the BPF denylist by operator choice "
                f"({size_note} not loaded)",
            )
        )
        return
    if not sys.platform.startswith("linux"):
        # Mirrors McpStdioClient._spawn_argv: mode=on is refused, auto degrades.
        if mode == "on":
            findings.append(
                Finding(
                    "mcp-seccomp",
                    "fail",
                    f"mode=on requires a platform that can load a BPF filter (this host is {sys.platform}) - "
                    "an MCP server would refuse to start",
                )
            )
        else:
            findings.append(
                Finding(
                    "mcp-seccomp",
                    "warn",
                    f"mode={mode} on {sys.platform}: no BPF support - the denylist cannot be applied "
                    "to MCP server processes on this host",
                )
            )
        return
    arch = _verified_seccomp_arch()
    if arch is None:
        findings.append(
            Finding(
                "mcp-seccomp",
                "warn",
                f"mode={mode}: no verified syscall table for arch {platform.machine().lower()!r} - "
                f"the filter falls through to ALLOW ({size_note} assembled)",
            )
        )
        return
    findings.append(
        Finding(
            "mcp-seccomp",
            "ok",
            f"mode={mode}: denylist will be applied to MCP server processes via prctl wrapper; "
            f"arch {arch} table verified; {size_note}",
        )
    )


def _check_mcp_network(args: argparse.Namespace, findings: list[Finding]) -> None:
    """Report whether MCP server processes will be denied network egress.

    Mirrors ``McpStdioClient._apply_network_policy``: ``denied`` (default)
    confines the server with Landlock TCP denial and refuses to start where
    the kernel cannot enforce it (needs ABI 4+); ``allowed`` is the explicit
    opt-in to full host network. Never claims denial is active when the host
    cannot enforce it.
    """
    import sys as _sys

    mode = str(getattr(args, "mcp_network", "denied") or "denied").strip().lower()
    if mode not in ("denied", "allowed"):
        findings.append(Finding("mcp-network", "fail", f"invalid --mcp-network mode: {mode!r}"))
        return
    if mode == "allowed":
        findings.append(
            Finding(
                "mcp-network",
                "warn",
                "mode=allowed - MCP server processes run with full host network by operator choice",
            )
        )
        return
    try:
        from tools.sandbox import landlock_abi_version
    except Exception as error:  # noqa: BLE001
        findings.append(Finding("mcp-network", "warn", f"could not load the landlock module: {error}"))
        return
    abi = landlock_abi_version()
    if not _sys.platform.startswith("linux") or abi < 4:
        findings.append(
            Finding(
                "mcp-network",
                "fail",
                f"mode=denied requires Linux with Landlock ABI 4+ for TCP denial "
                f"(this host: {_sys.platform}, ABI {abi}) - an MCP server would refuse to start",
            )
        )
        return
    findings.append(
        Finding(
            "mcp-network",
            "ok",
            f"mode=denied - MCP server processes get Landlock TCP denial (ABI {abi}); "
            "no direct egress outside the sidecar",
        )
    )


def _check_workspace_config(args: argparse.Namespace, findings: list[Finding]) -> None:
    """Check workspace policy, agents, skills and project context."""
    workspace = Path(args.workspace)
    if workspace.is_dir():
        try:
            from agent_files import AgentFileError, discover_agent_files
            from agents import builtin_registry
            from policy_file import PolicyFileError, discover_project_context, load_policy_file
            from skills import SkillError, discover_skills
            from tools import build_default_registry

            registry = build_default_registry()
            agents = builtin_registry()
            try:
                file_agents = discover_agent_files(workspace, known_tools=registry.names())
                for definition in file_agents:
                    agents.register(definition, replace_existing=False)
            except AgentFileError as error:
                findings.append(Finding("agent-files", "fail", str(error)))
                file_agents = ()
            else:
                if file_agents:
                    names = ", ".join(definition.name for definition in file_agents)
                    findings.append(Finding("agent-files", "ok", f"{len(file_agents)} repository agent(s): {names}"))
                else:
                    findings.append(Finding("agent-files", "ok", "none (.northstar/agents/*.md absent)"))
            try:
                skills = discover_skills(workspace)
            except SkillError as error:
                findings.append(Finding("skills", "fail", str(error)))
                skills = ()
            else:
                if skills:
                    names = ", ".join(skill.name for skill in skills)
                    findings.append(Finding("skills", "ok", f"{len(skills)} package(s): {names} (listed in the system prompt)"))
                else:
                    findings.append(Finding("skills", "ok", "none (.northstar/skills/*/SKILL.md absent)"))
            policy = load_policy_file(workspace, known_tools=registry.names(), known_agents=agents.names())
        except PolicyFileError as error:
            findings.append(Finding("policy-file", "fail", str(error)))
        except ImportError as error:  # pragma: no cover - Python 3.10 without tomli
            findings.append(Finding("policy-file", "fail", str(error)))
        else:
            if policy is None:
                findings.append(Finding("policy-file", "ok", "none (.northstar/config.toml absent)"))
            else:
                parts = [f"mode={policy.permission_mode or 'default'}"]
                if policy.deny_tools:
                    parts.append(f"deny={','.join(policy.deny_tools)}")
                if policy.max_turns is not None:
                    parts.append(f"max_turns={policy.max_turns}")
                if policy.max_budget_usd is not None:
                    parts.append(f"budget=${policy.max_budget_usd}")
                if policy.read_only:
                    parts.append("read_only")
                if policy.revision:
                    parts.append(f"revision={policy.revision}")
                findings.append(Finding("policy-file", "ok", f"{policy.source} applies: {' '.join(parts)}"))
                if policy.hooks:
                    findings.append(
                        Finding(
                            "hooks",
                            "warn",
                            f"{len(policy.hooks)} declared in {policy.source}; they run only with "
                            "--enable-workspace-hooks (cloning a repository must not mean executing it)",
                        )
                    )
                findings.append(policy_drift_finding(workspace, policy))
            try:
                configured = policy.project_context_setting if policy is not None else "AGENTS.md"
                context = discover_project_context(workspace, configured=configured)
            except PolicyFileError as error:
                findings.append(Finding("project-context", "fail", str(error)))
            else:
                if context is None:
                    findings.append(Finding("project-context", "ok", f"off (no {configured if isinstance(configured, str) else 'AGENTS.md'} in workspace)"))
                else:
                    size = f"{len(context.text)} chars" + (" [truncated]" if context.truncated else "")
                    findings.append(Finding("project-context", "ok", f"{context.name} ({size}) will be appended to the system prompt"))


def _check_skill_supply_chain(args: argparse.Namespace, findings: list[Finding]) -> None:
    """Check the workspace skill lock and supply chain."""
    workspace = Path(args.workspace)
    if importlib.util.find_spec("skill_check") is not None:
        from skill_check import run_lock_status

        locked, detail = run_lock_status(workspace)
        findings.append(
            Finding("skills-review", "ok" if locked else "warn",
                    f"{detail}" if locked else f"{detail} - `cli skills check --workspace . --write-lock` after reading them")
        )


def _check_plugins(args: argparse.Namespace, findings: list[Finding]) -> None:
    """Check installed plugin bundles without mutating them."""
    workspace = Path(args.workspace)
    # Read-only by construction: `pin=False`, because a self-check that records a review
    # would be a self-check that grades its own homework.
    if importlib.util.find_spec("plugin_load") is not None:
        from plugin_load import PluginInstallError, verify_workspace
        from plugin_manifest import PluginError

        try:
            report = verify_workspace(workspace)
        except (PluginError, PluginInstallError, OSError) as error:
            # A bundle the loader cannot even read is a finding, not a traceback: the
            # doctor's whole job is to say what is wrong and stop.
            findings.append(Finding("plugins", "fail", str(error)))
        else:
            if not report["plugins"]:
                findings.append(
                    Finding("plugins", "ok", "none (.northstar/plugins/ absent - `cli plugin install <dir>` adds a bundle)")
                )
            elif report["ok"]:
                names = ", ".join(f"{item['name']}@{item['version']}" for item in report["plugins"])
                findings.append(Finding("plugins", "ok", f"{len(report['plugins'])} bundle(s) pinned and matching {report['lock']}: {names}"))
            else:
                findings.append(
                    Finding(
                        "plugins",
                        "fail",
                        "; ".join(report["problems"])
                        or "; ".join(
                            f"{item['name']}: {item['status']}" + (f" - {item['detail']}" if item.get("detail") else "")
                            for item in report["plugins"]
                            if item["status"] != "pinned"
                        )
                        + f" - a run in this workspace will refuse to start until `plugin verify --workspace . --write-lock` matches",
                    )
                )


def _check_provider_model(args: argparse.Namespace, findings: list[Finding]) -> str:
    """Check provider/model resolution and endpoint configuration."""
    from cli import PROVIDER_DEFAULT_MODELS, resolve_model

    try:
        resolved_model = resolve_model(args.provider, args.model)
    except ValueError as error:
        findings.append(Finding("provider", "fail", str(error)))
        resolved_model = args.model or PROVIDER_DEFAULT_MODELS.get(args.provider, "")
    if args.provider == "openai":
        endpoint = (args.base_url or os.environ.get("OPENAI_BASE_URL", "")).strip()
        key = os.environ.get("OPENAI_API_KEY", "").strip()
        if endpoint and endpoint.startswith("http://") and "localhost" not in endpoint and "127." not in endpoint:
            findings.append(Finding("provider", "warn", f"{endpoint} is plain http: a key on the wire to a remote gateway is a credential leak"))
        findings.append(
            Finding(
                "provider",
                "ok" if key or endpoint else "warn",
                f"openai-compatible: endpoint={endpoint or '(SDK default)'}, key={'present in $OPENAI_API_KEY' if key else 'absent - set $OPENAI_API_KEY (never a flag)'}",
            )
        )
    else:
        findings.append(Finding("provider", "ok", f"{args.provider} with model {resolved_model}"))
    return resolved_model


def _check_scripted_script(args: argparse.Namespace, findings: list[Finding]) -> None:
    """Check the scripted provider input."""
    if args.provider == "scripted" and args.script:
        try:
            payload = json.loads(Path(args.script).read_text(encoding="utf-8"))
            if isinstance(payload, dict) and "turns" in payload:
                payload = payload["turns"]
            if not isinstance(payload, list):
                raise ValueError("a script must be a JSON array of turns, or an object with a 'turns' array")
            findings.append(Finding("script", "ok", f"{args.script} parses with {len(payload)} scripted turn(s)"))
        except (OSError, ValueError) as error:
            findings.append(Finding("script", "fail", f"{args.script}: {error}"))


def _check_pricing(args: argparse.Namespace, findings: list[Finding], resolved_model: str) -> None:
    """Check model pricing availability."""
    pricing, estimated = price_for(resolved_model)
    if estimated:
        findings.append(
            Finding("pricing", "warn",
                    f"{resolved_model}: not in the price table - spending falls back to the conservative tier and is marked pricing_estimated")
        )
    else:
        findings.append(
            Finding("pricing", "ok",
                    f"{resolved_model}: ${pricing.input_per_mtok}/MTok in, ${pricing.output_per_mtok}/MTok out "
                    "(cache reads x0.1, cache writes x1.25)")
        )


def _checks(args: argparse.Namespace) -> list[Finding]:
    findings: list[Finding] = []
    _check_python(args, findings)
    _check_sdks(args, findings)
    _check_workspace(args, findings)
    _check_session_dir(args, findings)
    _check_sidecar(args, findings)
    _check_egress(args, findings)
    backend = _check_sandbox(args, findings)
    _check_seccomp(args, findings, backend)
    _check_landlock(args, findings, backend)
    _check_mcp_seccomp(args, findings)
    _check_mcp_network(args, findings)
    _check_workspace_config(args, findings)
    _check_skill_supply_chain(args, findings)
    _check_plugins(args, findings)
    resolved_model = _check_provider_model(args, findings)
    _check_scripted_script(args, findings)
    _check_pricing(args, findings, resolved_model)
    return findings


def run_doctor(args: argparse.Namespace) -> int:
    """Print the report; return 0 unless a check failed."""
    findings = _checks(args)
    print(f"northstar {__version__} - doctor")
    print("  every check is local and side-effect free: no request, no file written")
    for finding in findings:
        print(f"{ICONS[finding.level]} {finding.name:<14} {finding.message}")
    ok = sum(1 for f in findings if f.level == "ok")
    warn = sum(1 for f in findings if f.level == "warn")
    fail = sum(1 for f in findings if f.level == "fail")
    verdict = "ready to run" if fail == 0 else "fix the failed checks and re-run"
    print(f"doctor: {ok} ok, {warn} warn, {fail} fail - {verdict}")
    return 1 if fail else 0


if __name__ == "__main__":  # pragma: no cover - exercised through cli.main in tests
    raise SystemExit(run_doctor(build_parser().parse_args()))

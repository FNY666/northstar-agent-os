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
    parser.add_argument("--provider", choices=("scripted", "anthropic"), default="scripted", help="provider a run would use (default: scripted, offline)")
    parser.add_argument("--model", default="claude-sonnet-4-5", help="model id to price and check")
    parser.add_argument("--script", default="", help="scripted-provider script to validate (JSON array of turns)")
    parser.add_argument("--sidecar-socket", default="", help="sidecar socket path to check for presence")
    parser.add_argument("--session-dir", default="", help="session transcript directory to check for creatability")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="northstar-agent-runtime doctor", description="Self-check the host for one governed run.")
    add_arguments(parser)
    return parser


def _checks(args: argparse.Namespace) -> list[Finding]:
    findings: list[Finding] = []

    # -- python -----------------------------------------------------------
    current = sys.version_info[:3]
    if current >= MIN_PYTHON:
        findings.append(Finding("python", "ok", f"Python {current[0]}.{current[1]}.{current[2]} (>= {MIN_PYTHON[0]}.{MIN_PYTHON[1]})"))
    else:
        findings.append(Finding("python", "fail", f"Python {current[0]}.{current[1]}.{current[2]} is too old; {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ is required"))

    # -- optional SDKs -----------------------------------------------------
    anthropic_present = importlib.util.find_spec("anthropic") is not None
    if anthropic_present:
        findings.append(Finding("anthropic-sdk", "ok", "installed - live provider available"))
    else:
        findings.append(
            Finding("anthropic-sdk", "warn",
                    "not installed - use --provider scripted, or pip install -r requirements.txt for live runs")
        )
    if importlib.util.find_spec("opentelemetry") is not None:
        findings.append(Finding("opentelemetry", "ok", "installed - span export available"))
    else:
        findings.append(
            Finding("opentelemetry", "warn",
                    "not installed - --trace still prints span trees, but export needs requirements-tracing.txt")
        )

    # -- workspace ----------------------------------------------------------
    workspace = Path(args.workspace)
    if not workspace.exists():
        findings.append(Finding("workspace", "fail", f"{workspace} does not exist - tools are confined to it; create it first"))
    elif not workspace.is_dir():
        findings.append(Finding("workspace", "fail", f"{workspace} exists but is not a directory"))
    elif not os.access(workspace, os.W_OK):
        findings.append(Finding("workspace", "fail", f"{workspace} is not writable - Write/Edit need it"))
    else:
        findings.append(Finding("workspace", "ok", str(workspace.resolve())))

    # -- session dir ---------------------------------------------------------
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

    # -- sidecar --------------------------------------------------------------
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

    # -- scripted script -------------------------------------------------------
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

    # -- model pricing ----------------------------------------------------------
    pricing, estimated = price_for(args.model)
    if estimated:
        findings.append(
            Finding("pricing", "warn",
                    f"{args.model}: not in the price table - spending falls back to the conservative tier and is marked pricing_estimated")
        )
    else:
        findings.append(
            Finding("pricing", "ok",
                    f"{args.model}: ${pricing.input_per_mtok}/MTok in, ${pricing.output_per_mtok}/MTok out "
                    "(cache reads x0.1, cache writes x1.25)")
        )

    return findings


def run_doctor(args: argparse.Namespace) -> int:
    """Print the report; return 0 unless a check failed."""
    findings = _checks(args)
    print(f"northstar-agent-runtime {__version__} - doctor")
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

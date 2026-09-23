#!/usr/bin/env python3
"""Byte-level snapshot of `northstar run` behaviour, for behaviour-preserving refactors.

Runs ~50 fixed `northstar run ...` invocations against throwaway workspaces and records,
for each one: stdout, stderr, the exit code, and - whenever the CLI got as far as building
an `AgentRuntime` - the configuration it actually built (every `RuntimeConfig` field that
matters, the full system prompt, the tool registry, and the ceiling inside the live
`Budget`). The dry-run text alone would not notice a system prompt assembled in a
different order or a budget object that lost its ceiling; this does. Volatile values
(temp paths, session ids) are normalised so two runs of the same code produce the same
file.

    # before touching any code, on the commit you start from:
    python3 docs/superpowers/plans/2026-09-23-runtime-refactor/cli_golden.py record /tmp/cli-golden.json

    # after every refactor commit:
    python3 docs/superpowers/plans/2026-09-23-runtime-refactor/cli_golden.py check /tmp/cli-golden.json

`check` exits 0 when every case is identical and 1 otherwise, printing a diff for each
case that changed. It uses only the standard library and needs no network or API key
(every case uses the scripted provider or stops before any request).

This file is a verification tool for the refactor plan in this directory. It is not part
of any component and is not run by CI.
"""
from __future__ import annotations

import difflib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[4]
RUNTIME = REPO / "components" / "northstar-agent-runtime"

# (case name, workspace fixture name, extra argv after `run --workspace <ws>`)
# Fixture names are keys of FIXTURES below. "{sess}" is replaced by a per-case session dir.
CASES: list[tuple[str, str, list[str]]] = [
    # --- happy paths -------------------------------------------------------------
    ("dry_run_plain", "empty", ["--prompt", "hi", "--scripted-text", "ok", "--dry-run"]),
    ("show_pricing", "empty", ["--prompt", "hi", "--scripted-text", "ok", "--show-pricing"]),
    ("real_run_text", "empty", ["--prompt", "hi", "--scripted-text", "ok"]),
    ("real_run_json", "empty", ["--prompt", "hi", "--scripted-text", "ok", "--json"]),
    ("real_run_quiet", "empty", ["--prompt", "hi", "--scripted-text", "ok", "--quiet"]),
    ("real_run_session", "empty", ["--prompt", "hi", "--scripted-text", "ok", "--session-dir", "{sess}", "--checkpoint-turns", "1"]),
    ("dry_run_plan", "empty", ["--prompt", "hi", "--scripted-text", "ok", "--plan", "--dry-run"]),
    ("dry_run_tool_lists", "empty", ["--prompt", "hi", "--scripted-text", "ok", "--allow-tool", "Write", "--deny-tool", "Edit", "--dry-run"]),
    ("dry_run_read_only", "empty", ["--prompt", "hi", "--scripted-text", "ok", "--read-only", "--dry-run"]),
    ("dry_run_agent", "empty", ["--prompt", "hi", "--scripted-text", "ok", "--agent", "explorer", "--dry-run"]),
    ("dry_run_ceilings", "empty", ["--prompt", "hi", "--scripted-text", "ok", "--max-turns", "7", "--max-tool-calls", "9", "--max-budget-usd", "1.5", "--dry-run"]),
    ("dry_run_system_prompt", "empty", ["--prompt", "hi", "--scripted-text", "ok", "--system-prompt", "be brief", "--dry-run"]),
    ("dry_run_all_off", "rich", ["--prompt", "hi", "--scripted-text", "ok", "--no-policy-file", "--no-project-context", "--no-skills", "--no-memory", "--no-plugins", "--no-workspace-agents", "--dry-run"]),
    ("dry_run_session_opts", "empty", ["--prompt", "hi", "--scripted-text", "ok", "--session-dir", "{sess}", "--session-lease-seconds", "60", "--checkpoint-turns", "2", "--dry-run"]),
    ("dry_run_no_lease", "empty", ["--prompt", "hi", "--scripted-text", "ok", "--session-dir", "{sess}", "--no-session-lease", "--dry-run"]),
    ("dry_run_verify", "empty", ["--prompt", "hi", "--scripted-text", "ok", "--verify", "exists:README.md", "--dry-run"]),
    # --- workspace content -------------------------------------------------------
    ("rich_workspace", "rich", ["--prompt", "hi", "--scripted-text", "ok", "--dry-run"]),
    ("rich_workspace_real_run", "rich", ["--prompt", "hi", "--scripted-text", "ok"]),
    ("policy_tight", "policy_tight", ["--prompt", "hi", "--scripted-text", "ok", "--dry-run"]),
    ("policy_tight_cli_lower", "policy_tight", ["--prompt", "hi", "--scripted-text", "ok", "--max-turns", "2", "--dry-run"]),
    ("policy_plan_mode", "policy_plan", ["--prompt", "hi", "--scripted-text", "ok", "--dry-run"]),
    ("policy_plan_mode_cli_override", "policy_plan", ["--prompt", "hi", "--scripted-text", "ok", "--permission-mode", "acceptEdits", "--dry-run"]),
    ("policy_invalid", "policy_invalid", ["--prompt", "hi", "--scripted-text", "ok", "--dry-run"]),
    ("hooks_declared_not_enabled", "policy_hooks", ["--prompt", "hi", "--scripted-text", "ok", "--dry-run"]),
    ("hooks_declared_enabled", "policy_hooks", ["--prompt", "hi", "--scripted-text", "ok", "--enable-workspace-hooks", "--dry-run"]),
    ("agent_file_invalid", "agent_invalid", ["--prompt", "hi", "--scripted-text", "ok", "--dry-run"]),
    # --- configuration errors ----------------------------------------------------
    ("no_prompt", "empty", ["--scripted-text", "ok"]),
    ("probe_without_socket", "empty", ["--probe-sidecar", "--scripted-text", "ok"]),
    ("unknown_agent", "empty", ["--prompt", "hi", "--scripted-text", "ok", "--agent", "nope", "--dry-run"]),
    ("agent_with_mcp", "empty", ["--prompt", "hi", "--scripted-text", "ok", "--agent", "explorer", "--mcp-server", "x=echo", "--dry-run"]),
    ("checkpoint_negative", "empty", ["--prompt", "hi", "--scripted-text", "ok", "--checkpoint-turns", "-1", "--dry-run"]),
    ("checkpoint_over_max", "empty", ["--prompt", "hi", "--scripted-text", "ok", "--checkpoint-turns", "30", "--dry-run"]),
    ("lease_with_no_lease", "empty", ["--prompt", "hi", "--scripted-text", "ok", "--no-session-lease", "--session-lease-seconds", "10", "--dry-run"]),
    ("lease_negative", "empty", ["--prompt", "hi", "--scripted-text", "ok", "--session-lease-seconds", "-1", "--dry-run"]),
    ("resume_record_alone", "empty", ["--prompt", "hi", "--scripted-text", "ok", "--resume-record", "1", "--dry-run"]),
    ("resume_and_resume_from", "empty", ["--prompt", "hi", "--scripted-text", "ok", "--resume", "a", "--resume-from", "b", "--dry-run"]),
    ("resume_from_without_dir", "empty", ["--prompt", "hi", "--scripted-text", "ok", "--resume-from", "b", "--dry-run"]),
    ("resume_from_missing", "empty", ["--prompt", "hi", "--scripted-text", "ok", "--session-dir", "{sess}", "--resume-from", "ns-missing", "--dry-run"]),
    ("verify_invalid", "empty", ["--prompt", "hi", "--scripted-text", "ok", "--verify", "no-such-kind:x", "--dry-run"]),
    ("skill_lock_required", "rich", ["--prompt", "hi", "--scripted-text", "ok", "--require-skill-lock", "--dry-run"]),
    # --- resume paths (a parent session with a checkpoint is created first) -----
    ("resume_from_checkpoint", "empty", ["--prompt", "again", "--scripted-text", "ok", "--session-dir", "{sess}", "--resume-from", "{parent}", "--dry-run"]),
    ("resume_from_checkpoint_policy", "policy_tight", ["--prompt", "again", "--scripted-text", "ok", "--session-dir", "{sess}", "--resume-from", "{parent}", "--dry-run"]),
    ("resume_from_checkpoint_run", "empty", ["--prompt", "again", "--scripted-text", "ok", "--session-dir", "{sess}", "--resume-from", "{parent}"]),
    ("resume_append", "empty", ["--prompt", "again", "--scripted-text", "ok", "--session-dir", "{sess}", "--resume", "{parent}"]),
    ("bad_provider_choice", "empty", ["--prompt", "hi", "--provider", "nope", "--dry-run"]),
    ("openai_dry_run", "empty", ["--prompt", "hi", "--provider", "openai", "--dry-run"]),
    ("prompt_from_stdin_file", "empty", ["--prompt-file", "-", "--scripted-text", "ok", "--dry-run"]),
    ("skill_lock_ok_without_skills", "empty", ["--prompt", "hi", "--scripted-text", "ok", "--require-skill-lock", "--dry-run"]),
]

POLICY_HEADER = 'schema_version = "northstar.policy.v1"\n'

FIXTURES: dict[str, dict[str, str]] = {
    "empty": {},
    "rich": {
        "AGENTS.md": "# Project rules\n\nBe careful.\n",
        "README.md": "readme\n",
        ".northstar/memory/MEMORY.md": "- remember this\n",
        ".northstar/skills/demo/SKILL.md": "---\nname: demo\ndescription: A demo skill for snapshot tests.\n---\n\nDo the demo.\n",
        ".northstar/agents/helper.md": "---\nname: helper\ndescription: Helps.\ntools: [Read, Grep]\n---\n\nYou help.\n",
        ".northstar/config.toml": POLICY_HEADER + "max_turns = 5\n",
    },
    "policy_tight": {
        ".northstar/config.toml": POLICY_HEADER + 'max_turns = 3\nmax_budget_usd = 0.5\ndeny_tools = ["Edit"]\nread_only = true\nhalt_on_denial = true\n',
    },
    "policy_plan": {
        ".northstar/config.toml": POLICY_HEADER + 'permission_mode = "plan"\n',
    },
    "policy_invalid": {
        ".northstar/config.toml": POLICY_HEADER + "no_such_key = 1\n",
    },
    "policy_hooks": {
        ".northstar/config.toml": POLICY_HEADER
        + '\n[[hooks]]\nevent = "PreToolUse"\nscript = ".northstar/hooks/gate.py"\ninterpreter = "python3"\n',
        ".northstar/hooks/gate.py": "pass\n",
    },
    "agent_invalid": {
        ".northstar/agents/broken.md": "no front matter here\n",
    },
}

# Runs inside the child interpreter: spy on AgentRuntime construction, then run the CLI.
# Patching the class (not a module attribute) catches the construction wherever the CLI
# imports it from, so the spy keeps working after code moves between modules.
SPY = r"""
import json, os, sys
import loop
_original_init = loop.AgentRuntime.__init__
def _spy(self, *args, **kwargs):
    _original_init(self, *args, **kwargs)
    config = self.config
    captured = dict(config.as_dict())
    for name in ("system_prompt", "checkpoint_turns", "session_lease_seconds", "parent_session",
                 "record_tool_output_in_session", "run_id", "policy_revision",
                 "compaction_keep_messages", "max_output_tokens", "sidecar_timeout_ms"):
        value = getattr(config, name, None)
        captured[name] = value if isinstance(value, (str, int, float, bool, type(None))) else repr(value)
    captured["resume_from_turns"] = getattr(getattr(config, "resume_from", None), "turns", None)
    captured["postconditions"] = len(getattr(config, "postconditions", ()) or ())
    limits = getattr(config, "tool_limits", None)
    captured["protected_prefixes"] = list(getattr(limits, "protected_prefixes", ()) or ())
    captured["tool_names"] = list(self.tool_names())
    captured["budget_max_usd"] = self.budget.max_budget_usd
    captured["budget_spent_usd"] = self.budget.total_cost_usd
    captured["hooks"] = type(getattr(self, "hooks", None)).__name__
    with open(os.environ["GOLDEN_SPY_OUT"], "a", encoding="utf-8") as handle:
        handle.write(json.dumps(captured, sort_keys=True, default=repr) + "\n")
loop.AgentRuntime.__init__ = _spy
import cli
sys.argv = ["northstar"] + sys.argv[1:]
raise SystemExit(cli.main(sys.argv[1:]))
"""

SESSION_ID = re.compile(r"ns-\d{8}T\d{6}Z-[0-9a-f]{8}")
HEX_ID = re.compile(r"\b[0-9a-f]{32,64}\b")


def _materialise(root: Path, fixture: str) -> Path:
    workspace = root / "ws"
    workspace.mkdir(parents=True)
    for relative, text in FIXTURES[fixture].items():
        path = workspace / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return workspace


def _normalise(text: str, root: Path) -> str:
    text = text.replace(str(root.resolve()), "<TMP>").replace(str(root), "<TMP>")
    text = SESSION_ID.sub("<SESSION>", text)
    text = HEX_ID.sub("<HEX>", text)
    return text


def run_case(name: str, fixture: str, extra: list[str]) -> dict[str, object]:
    root = Path(tempfile.mkdtemp(prefix=f"golden-{name}-"))
    try:
        workspace = _materialise(root, fixture)
        sessions = root / "sessions"
        sessions.mkdir()
        env = dict(os.environ)
        for key in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "NORTHSTAR_PROVIDER", "NORTHSTAR_MODEL"):
            env.pop(key, None)
        env["PYTHONHASHSEED"] = "0"
        parent = ""
        if any("{parent}" in arg for arg in extra):
            # A parent run that leaves one checkpoint behind, so resume paths are exercised.
            setup = subprocess.run(
                [sys.executable, "-m", "cli", "run", "--workspace", str(workspace), "--prompt", "first",
                 "--scripted-text", "ok", "--session-dir", str(sessions), "--checkpoint-turns", "1",
                 "--no-policy-file"],
                cwd=RUNTIME, env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120,
            )
            found = SESSION_ID.search(setup.stdout)
            if setup.returncode != 0 or not found:
                raise RuntimeError(f"{name}: could not create the parent session:\n{setup.stdout}{setup.stderr}")
            parent = found.group(0)
        spy_out = root / "spy.jsonl"
        env["GOLDEN_SPY_OUT"] = str(spy_out)
        argv = [sys.executable, "-c", SPY, "run", "--workspace", str(workspace)]
        argv += [arg.replace("{sess}", str(sessions)).replace("{parent}", parent) for arg in extra]
        done = subprocess.run(
            argv,
            cwd=RUNTIME,
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=120,
        )
        built = []
        if spy_out.exists():
            built = [json.loads(_normalise(line, root)) for line in spy_out.read_text(encoding="utf-8").splitlines()]
        return {
            "argv": extra,
            "fixture": fixture,
            "exit": done.returncode,
            "stdout": _normalise(done.stdout, root),
            "stderr": _normalise(done.stderr, root),
            "runtime_built": built,
        }
    finally:
        shutil.rmtree(root, ignore_errors=True)


def snapshot() -> dict[str, dict[str, object]]:
    return {name: run_case(name, fixture, extra) for name, fixture, extra in CASES}


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[0] not in {"record", "check"}:
        print(__doc__, file=sys.stderr)
        return 2
    mode, target = argv[0], Path(argv[1])
    current = snapshot()
    if mode == "record":
        target.write_text(json.dumps(current, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
        exits = sorted({case["exit"] for case in current.values()})
        print(f"recorded {len(current)} cases to {target} (exit codes seen: {exits})")
        return 0
    expected = json.loads(target.read_text(encoding="utf-8"))
    changed = 0
    for name in sorted(set(expected) | set(current)):
        before, after = expected.get(name), current.get(name)
        if before == after:
            continue
        changed += 1
        print(f"=== CHANGED: {name}")
        before_text = json.dumps(before, indent=2, ensure_ascii=False, sort_keys=True).splitlines()
        after_text = json.dumps(after, indent=2, ensure_ascii=False, sort_keys=True).splitlines()
        for line in difflib.unified_diff(before_text, after_text, "recorded", "now", lineterm=""):
            print(line)
    if changed:
        print(f"\n{changed} of {len(current)} case(s) changed")
        return 1
    print(f"all {len(current)} cases identical")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

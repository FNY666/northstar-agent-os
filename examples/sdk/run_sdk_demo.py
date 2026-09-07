#!/usr/bin/env python3
"""One governed run through the Python API (sdk) — offline, deterministic.

Two ways to run this example:

    # 1) after installing the runtime component
    pip install ./components/northstar-agent-runtime
    python3 examples/sdk/run_sdk_demo.py

    # 2) straight from a repository checkout (this script finds the component)
    python3 examples/sdk/run_sdk_demo.py

The demo reuses the offline demo workspace (examples/demo/workspace/notes.txt):
the agent reads it through the sandboxed Read tool and summarises it. No API
key, no network — the scripted provider supplies the model turns.

What the example shows:
  * sdk.run() returns a RunReport (subtype, exit_code, session_id, cost, ...)
  * the permission gate is live: the same script asks for a Write it is not
    allowed to make, and the run records the denial instead of performing it.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Allow running straight from a checkout: put the runtime component on the path
# if it is not installed.
try:  # pragma: no cover - trivial fallback logic
    import sdk  # noqa: F401
except ModuleNotFoundError:  # pragma: no cover
    runtime_dir = Path(__file__).resolve().parents[2] / "components" / "northstar-agent-runtime"
    sys.path.insert(0, str(runtime_dir))

import sdk  # noqa: E402


def main() -> int:
    workspace = str(Path(__file__).resolve().parents[1] / "demo" / "workspace")
    turns = [
        {"tools": [{"name": "Read", "input": {"path": "notes.txt"}}]},
        # A mutating call the run is NOT allowed to perform (default mode).
        {"tools": [{"name": "Write", "input": {"path": "notes.txt", "content": "tampered"}}]},
        {"text": "I attempted the write; the gate refused it and I continue."},
    ]
    report = sdk.run(
        sdk.RunOptions(
            prompt="Read notes.txt and summarise it; then try to overwrite it.",
            workspace=workspace,
            scripted_turns=turns,
        )
    )

    print(f"subtype       {report.subtype}")
    print(f"exit_code     {report.exit_code}   # 0 = success")
    print(f"session_id    {report.session_id}")
    print(f"num_turns     {report.num_turns}")
    print(f"tool_calls    {report.tool_calls}")
    print(f"total_cost    ${report.total_cost_usd:.6f}")
    print(f"denials       {len(report.permission_denials)}")
    for denial in report.permission_denials:
        print(f"  refused: {denial['tool']} ({denial.get('reason', denial.get('source', ''))})")
    print(f"events        {len(report.events)} (system/assistant/user/result dicts)")

    # The permission gate is the point: the Write was refused, not performed.
    assert report.subtype == "success"
    assert report.permission_denials, "the unallowed Write must have been refused"
    assert report.permission_denials[0]["tool"] == "Write"
    print("\nok: the governed run finished and the Write was refused at the gate.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Local inspection and control CLI for one durable-run event stream.

The CLI deliberately stays below the scheduler boundary. It can inspect and
replay a persisted run, export its events as the canonical audit feed, and
apply the runner's local pause/resume/cancel controls when the caller supplies
an explicit RunContract and owner. It does not queue work, execute step
functions, or open a network listener.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

from durable_audit import events_to_ndjson
from durable_contract import RunContract
from event_store import EventStore
from runner import DurableRunner


def _add_store_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--events", required=True, type=Path, help="append-only event JSONL path")
    parser.add_argument("--run-id", required=True, help="run identifier in the event stream")


def _add_control_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--events", required=True, type=Path, help="append-only event JSONL path")
    parser.add_argument("--run-contract", required=True, type=Path, help="JSON RunContract file")
    parser.add_argument("--lease-path", type=Path, help="lease file; defaults beside the event stream")
    parser.add_argument("--owner-id", required=True, help="owner making the local control request")
    parser.add_argument("--now", required=True, type=int, help="positive event timestamp")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="northstar-durable-run",
        description="Inspect and control one local Northstar durable-run stream.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    status = commands.add_parser("status", help="replay and summarize a run")
    _add_store_arguments(status)

    history = commands.add_parser("history", help="emit validated events as JSON")
    _add_store_arguments(history)

    audit = commands.add_parser("audit", help="export validated events as audit NDJSON")
    _add_store_arguments(audit)

    control = commands.add_parser("control", help="apply one local lifecycle control")
    _add_control_arguments(control)
    control.add_argument(
        "action",
        choices=("pause", "resume", "cancel"),
        help="lifecycle operation; retry still requires executable StepPlan functions",
    )
    control.add_argument("--reason", default="operator pause", help="pause reason")
    return parser


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read JSON file {path}: {error}") from error


def _emit_json(value: Any) -> None:
    print(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


def _status(store: EventStore, run_id: str) -> dict[str, Any]:
    events = store.read_history(run_id)
    if not events:
        raise ValueError(f"no event history exists for run {run_id}")
    state = store.replay(run_id)
    return {
        "run_id": run_id,
        "event_count": len(events),
        "last_event": events[-1].to_dict(),
        "state": state,
    }


def _control(args: argparse.Namespace) -> dict[str, Any]:
    contract = RunContract.from_dict(_read_json(args.run_contract))
    store = EventStore(args.events)
    lease_path = args.lease_path or args.events.with_name(f"{contract.run_id}.lease.json")
    runner = DurableRunner(contract, store, lease_path=lease_path)
    if args.action == "pause":
        state = runner.pause(owner_id=args.owner_id, now=args.now, reason=args.reason)
    elif args.action == "resume":
        state = runner.resume(owner_id=args.owner_id, now=args.now)
    else:
        state = runner.cancel(owner_id=args.owner_id, now=args.now)
    return {"action": args.action, "run_id": contract.run_id, "state": state}


def main(argv: Sequence[str] | None = None) -> int:
    """Run the local durable-run CLI and return a process-style exit code."""
    args = _parser().parse_args(argv)
    try:
        if args.command == "status":
            _emit_json(_status(EventStore(args.events), args.run_id))
        elif args.command == "history":
            events = EventStore(args.events).read_history(args.run_id)
            _emit_json({"run_id": args.run_id, "events": [item.to_dict() for item in events]})
        elif args.command == "audit":
            events = EventStore(args.events).read_history(args.run_id)
            sys.stdout.write(events_to_ndjson(item.to_dict() for item in events))
        else:
            _emit_json(_control(args))
    except (OSError, TypeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through main/tests
    raise SystemExit(main())

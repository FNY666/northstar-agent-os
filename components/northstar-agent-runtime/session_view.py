"""Read-side of the session transcripts: ``cli sessions list`` and ``show``.

Writing a transcript has always been append-only and fsynced; this module is the
missing read-back half. It is deliberately read-only: it never creates the
session directory, never opens a file for writing, and never mutates a record.
A transcript is an audit trail - the viewer reports corruption instead of
"repairing" it. A torn *trailing* line is skipped the same way the writer's own
recovery skips it; a damaged line anywhere earlier raises and names the record.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Iterable

from sessions import SESSION_FILE_SUFFIX, load_jsonl, summarise

USAGE_ERROR = 64  # same convention as cli.USAGE_ERROR, kept local to avoid an import cycle
CONTENT_PREVIEW = 200


def _add_session_location(parser: argparse.ArgumentParser) -> None:
    """Where product runs keep transcripts; operator can still point elsewhere."""
    parser.add_argument(
        "--workspace",
        default=".",
        help="workspace whose <workspace>/.northstar/sessions is the product default (default: .)",
    )
    parser.add_argument(
        "--session-dir",
        default="",
        help=(
            "directory of *.jsonl transcripts (default: <workspace>/.northstar/sessions — "
            "the same path `northstar agent` writes)"
        ),
    )


def resolve_view_session_dir(args: argparse.Namespace) -> Path:
    """Session directory for a sessions subcommand: explicit wins, else product default."""
    explicit = (getattr(args, "session_dir", None) or "").strip()
    if explicit:
        return Path(explicit).expanduser().resolve()
    from product_path import default_session_dir

    workspace = getattr(args, "workspace", None) or "."
    return default_session_dir(workspace)


def add_arguments(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="session_command")

    listing = sub.add_parser("list", help="list transcripts in a session directory")
    _add_session_location(listing)
    listing.add_argument("--json", action="store_true", help="emit one JSON object per transcript")

    showing = sub.add_parser("show", help="print one transcript as a human-readable timeline")
    _add_session_location(showing)
    showing.add_argument("--json", action="store_true", help="emit the raw records as a JSON array")
    showing.add_argument(
        "session_id",
        help="session id (the *.jsonl file name without its suffix), or 'latest'",
    )

    checkpoints = sub.add_parser(
        "checkpoints",
        help="list the resumable boundaries a session recorded, and verify each one's prefix digest",
    )
    _add_session_location(checkpoints)
    checkpoints.add_argument(
        "--session",
        default="",
        help="one session id or 'latest' (default: every transcript in the directory)",
    )
    checkpoints.add_argument("--json", action="store_true", help="emit one JSON object per transcript")

    replay = sub.add_parser(
        "replay",
        help="render one transcript turn by turn, with its checkpoints and what they hand to a resume",
    )
    _add_session_location(replay)
    replay.add_argument("--json", action="store_true", help="emit the frames as one JSON object")
    replay.add_argument(
        "--from-checkpoint",
        type=int,
        default=None,
        metavar="RECORD",
        help="show only the state at the checkpoint stored at transcript record #N - what a run resumed from it inherits",
    )
    replay.add_argument(
        "session_id",
        help="session id (the *.jsonl file name without its suffix), or 'latest'",
    )

    exporting = sub.add_parser(
        "export",
        help="emit one transcript as the canonical NDJSON audit feed (audit.ndjson/1)",
    )
    _add_session_location(exporting)
    exporting.add_argument(
        "session_id",
        help="session id (the *.jsonl file name without its suffix), or 'latest'; "
        "the feed is written to stdout, one validated audit record per line",
    )


def _resolve_session_arg(session_id: str, directory: Path) -> str:
    """Pass-through id, or resolve product `latest` aliases against ``directory``."""
    from product_path import LATEST_SESSION_ALIASES, resolve_session_id

    raw = (session_id or "").strip()
    if not raw or raw not in LATEST_SESSION_ALIASES:
        return raw
    return resolve_session_id(raw, directory)


def run_sessions(args: argparse.Namespace) -> int:
    try:
        directory = resolve_view_session_dir(args)
    except Exception as error:  # noqa: BLE001 - path math only
        print(f"sessions: {error}", file=sys.stderr)
        return USAGE_ERROR

    if args.session_command == "list":
        return _list_sessions(directory, json_out=bool(getattr(args, "json", False)))
    if args.session_command == "show":
        try:
            session_id = _resolve_session_arg(args.session_id, directory)
        except ValueError as error:
            print(f"sessions: {error}", file=sys.stderr)
            return USAGE_ERROR
        return _show_session(directory, session_id, json_out=bool(getattr(args, "json", False)))
    if args.session_command == "export":
        try:
            session_id = _resolve_session_arg(args.session_id, directory)
        except ValueError as error:
            print(f"sessions: {error}", file=sys.stderr)
            return USAGE_ERROR
        return _export_session(directory, session_id)
    if args.session_command == "checkpoints":
        session = getattr(args, "session", "") or ""
        if session:
            try:
                session = _resolve_session_arg(session, directory)
            except ValueError as error:
                print(f"sessions: {error}", file=sys.stderr)
                return USAGE_ERROR
        return _checkpoints_session(directory, session, json_out=bool(getattr(args, "json", False)))
    if args.session_command == "replay":
        try:
            session_id = _resolve_session_arg(args.session_id, directory)
        except ValueError as error:
            print(f"sessions: {error}", file=sys.stderr)
            return USAGE_ERROR
        return _replay_session(
            directory,
            session_id,
            json_out=bool(getattr(args, "json", False)),
            from_checkpoint=getattr(args, "from_checkpoint", None),
        )
    print("sessions: pass a subcommand: list, show, export, checkpoints or replay (--help for flags)", file=sys.stderr)
    return USAGE_ERROR


# -- listing ---------------------------------------------------------------


def _lease_claim(directory: Path, session_id: str) -> str:
    """What this session's lease claims right now, without touching the lock.

    This module is read-only by contract, and it stays that way on purpose: momentarily
    taking ``LOCK_EX`` to answer a question could make an unrelated run refuse to start.
    So the viewer repeats the holder's claim and labels it as one - enough to answer
    "is something still writing here?", never enough to authorise a second writer.
    """
    from session_lease import LeaseError, inspect_lease, lease_path_for

    try:
        status = inspect_lease(lease_path_for(directory, session_id), probe=False)
    except (LeaseError, OSError):
        # A lease path we cannot even stat is worth a line: it usually means a session id
        # that predates the lock suffix, or a directory the operator cannot read.
        return "unreadable"
    if not status.owner_id:
        return ""
    return status.human()


def _list_sessions(directory: Path, *, json_out: bool) -> int:
    if not directory.is_dir():
        print(f"sessions: no such directory: {directory}", file=sys.stderr)
        return 1
    sessions = sorted(directory.glob(f"*{SESSION_FILE_SUFFIX}"))
    if not sessions:
        print(f"sessions: no transcripts in {directory}", file=sys.stderr)
        return 1
    for path in sessions:
        records, _dropped = load_jsonl(path)
        summary = summarise(records)
        if json_out:
            print(json.dumps({
                "session_id": path.name[: -len(SESSION_FILE_SUFFIX)],
                "path": str(path),
                "records": summary["records"],
                "assistant_turns": summary["assistant_turns"],
                "subtype": summary["subtype"],
                "total_cost_usd": summary["total_cost_usd"],
                "bytes": path.stat().st_size,
                "lease": _lease_claim(directory, path.name[: -len(SESSION_FILE_SUFFIX)]),
            }, sort_keys=True))
        else:
            subtype = summary["subtype"] or "no result"
            claim = _lease_claim(directory, path.name[: -len(SESSION_FILE_SUFFIX)])
            print(f"{path.name[: -len(SESSION_FILE_SUFFIX)]:<46} "
                  f"records={summary['records']:<3} turns={summary['assistant_turns']:<3} "
                  f"{subtype:<24} ${summary['total_cost_usd']:.6f} "
                  # A trailing claim, not a verdict: the point of showing it in a listing
                  # is that a session someone is *still writing* is a different shape of
                  # problem than one that ended badly.
                  f"{path.stat().st_size} bytes"
                  + (f"  *{claim}" if claim else ""))
    return 0


# -- showing ---------------------------------------------------------------


def _show_session(directory: Path, session_id: str, *, json_out: bool) -> int:
    path = directory / f"{session_id}{SESSION_FILE_SUFFIX}"
    if not path.is_file():
        print(f"sessions: no transcript for session {session_id!r} in {directory}", file=sys.stderr)
        return 1
    records, dropped = load_jsonl(path)
    if json_out:
        print(json.dumps(records, ensure_ascii=False, sort_keys=True, default=str))
        return 0
    if dropped:
        print(f"# note: {dropped} torn trailing line(s) skipped (expected after a crash)")
    for record in records:
        print(_format_record(record))
    summary = summarise(records)
    print(f"# {summary['records']} records, {summary['assistant_turns']} assistant turn(s), "
          f"result={summary['subtype'] or '(none)'}, cost=${summary['total_cost_usd']:.6f}")
    claim = _lease_claim(directory, session_id)
    if claim:
        print(f"# session_lease: {claim}")
    return 0


# -- exporting (JSONL transcript -> canonical NDJSON audit feed) ------------


def _export_session(directory: Path, session_id: str) -> int:
    """Write one transcript as audit NDJSON to stdout, one record per line."""
    from audit_export import transcript_path_to_ndjson

    path = directory / f"{session_id}{SESSION_FILE_SUFFIX}"
    if not path.is_file():
        print(f"sessions: no transcript for session {session_id!r} in {directory}", file=sys.stderr)
        return 1
    sys.stdout.write(transcript_path_to_ndjson(path))
    return 0


def _format_record(record: dict[str, Any]) -> str:
    stamp = str(record.get("ts", ""))
    clock = stamp[11:23] if len(stamp) >= 23 else stamp  # 2026-09-07T09:20:41.123Z -> 09:20:41.123
    kind = str(record.get("type", "unknown"))
    text = _record_text(record, kind)
    return f"#{record.get('index', '?'):<4} {clock:<13} {kind:<16} {text}"


def _record_text(record: dict[str, Any], kind: str) -> str:
    if kind == "session_start":
        data = record.get("data") or {}
        return (f"provider={data.get('provider')} model={data.get('model')} "
                f"mode={data.get('permission_mode')} tools={len(data.get('tools') or ())} "
                f"workspace={data.get('workspace')}")
    if kind == "session_end":
        return str(record.get("subtype", ""))
    if kind == "user_prompt":
        return _blocks_preview(record.get("content") or ())
    if kind == "assistant":
        return _blocks_preview(record.get("content") or ())
    if kind == "tool_result":
        return _blocks_preview(record.get("content") or ())
    if kind == "result":
        parts = [f"subtype={record.get('subtype')}", f"turns={record.get('num_turns')}",
                 f"cost=${record.get('total_cost_usd')}"]
        errors = record.get("errors") or ()
        if errors:
            parts.append(f"errors={len(errors)}")
        return " ".join(parts)
    if kind == "compact_boundary":
        return f"{record.get('content') or ''} data={json.dumps(record.get('data') or {}, sort_keys=True)}"
    if kind == "denial":
        return str(record.get("data") or record.get("content") or "")
    # hook, subagent, informational, and anything new: show the payload compactly.
    payload = {key: value for key, value in record.items() if key not in ("index", "ts", "session_id", "type")}
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)[:CONTENT_PREVIEW]


def _blocks_preview(content: Iterable[Any]) -> str:
    """Render API-shaped content blocks the way the live CLI renders events."""
    pieces: list[str] = []
    for block in content or ():
        if not isinstance(block, dict):
            pieces.append(str(block))
            continue
        kind = block.get("type")
        if kind == "text":
            pieces.append(str(block.get("text", "")))
        elif kind == "tool_use":
            brief = json.dumps(block.get("input", {}), ensure_ascii=False, sort_keys=True)
            pieces.append(f"\u2192 {block.get('name')} {brief}")
        elif kind == "tool_result":
            body = str(block.get("content", ""))
            marker = "error" if block.get("is_error") else "ok"
            pieces.append(f"\u2190 {marker}: {body}")
        else:
            pieces.append(json.dumps(block, ensure_ascii=False, sort_keys=True, default=str))
    preview = " ".join(" ".join(pieces).split())
    return preview[:CONTENT_PREVIEW] + ("..." if len(preview) > CONTENT_PREVIEW else "")


# -- checkpoints and replay (the read-back half of fork points) --------------


def _checkpoints_session(directory: Path, session_id: str, *, json_out: bool) -> int:
    """List every checkpoint in a directory (or one session) and verify it.

    This is the CI-shaped command of the two: it recomputes what ``run --resume-from`` will
    check, without spending a run, and exits 1 when any boundary no longer matches its own
    digest. A transcript that can be edited into agreeing with its checkpoints is a
    transcript that was never append-only, so the exit code is a fact about the artefact.
    """
    from session_replay import budget_headroom, checkpoint_reports

    if not directory.is_dir():
        print(f"sessions: no such directory: {directory}", file=sys.stderr)
        return 1
    if session_id:
        paths = [directory / f"{session_id}{SESSION_FILE_SUFFIX}"]
        if not paths[0].is_file():
            print(f"sessions: no transcript for session {session_id!r} in {directory}", file=sys.stderr)
            return 1
    else:
        paths = sorted(directory.glob(f"*{SESSION_FILE_SUFFIX}"))
        if not paths:
            print(f"sessions: no transcripts in {directory}", file=sys.stderr)
            return 1
    unverified = 0
    total = 0
    for path in paths:
        identity = path.name[: -len(SESSION_FILE_SUFFIX)]
        records, dropped = load_jsonl(path)
        reports = checkpoint_reports(records)
        total += len(reports)
        unverified += sum(1 for report in reports if not report.verified)
        if json_out:
            print(
                json.dumps(
                    {
                        "session_id": identity,
                        "path": str(path),
                        "checkpoints": [report.as_dict() for report in reports],
                        "verified": all(report.verified for report in reports),
                        "torn_trailing_lines": dropped,
                    },
                    sort_keys=True,
                )
            )
            continue
        if not reports:
            print(f"{identity}: no checkpoints (a run records them with --checkpoint-turns N)")
            continue
        print(f"{identity}: {len(reports)} checkpoint(s)")
        for report in reports:
            print("  " + report.line())
            _remaining, note = budget_headroom(records, report)
            if note:
                print(f"        {note}")
            if not report.verified:
                print(f"        ! {report.detail}")
    if not json_out and total:
        print("  (a verified boundary is one whose transcript prefix still digests to what was recorded)")
    return 1 if unverified else 0


def _replay_session(directory: Path, session_id: str, *, json_out: bool, from_checkpoint: int | None) -> int:
    """Render one transcript, optionally cut at a checkpoint to show what a resume inherits."""
    from session_replay import budget_headroom, build_replay, fork_preview

    path = directory / f"{session_id}{SESSION_FILE_SUFFIX}"
    if not path.is_file():
        print(f"sessions: no transcript for session {session_id!r} in {directory}", file=sys.stderr)
        return 1
    records, dropped = load_jsonl(path)
    if from_checkpoint is None:
        replay = build_replay(records, session_id=session_id, dropped_trailing_lines=dropped)
        report = None
    else:
        replay, report, error = fork_preview(
            records, record_index=from_checkpoint, session_id=session_id, dropped_trailing_lines=dropped
        )
        if replay is None:
            print(f"sessions replay: {error}", file=sys.stderr)
            return USAGE_ERROR
    if json_out:
        print(replay.to_json())
        return 1 if (report is not None and not report.verified) or not replay.verified else 0
    print(replay.render())
    if report is not None:
        # The boundary is already a frame in the replay, so only what a *resume* would feel is
        # printed here: the money it inherits, and the refusal it would meet.
        _remaining, note = budget_headroom(records, report)
        if note:
            print(f"      {note}")
        if not report.verified:
            print(f"      ! {report.detail} - a run resumed here would refuse this boundary")
    return 0 if (report is None or report.verified) and replay.verified else 1

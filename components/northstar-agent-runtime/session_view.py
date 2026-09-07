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


def add_arguments(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="session_command")

    listing = sub.add_parser("list", help="list transcripts in a session directory")
    listing.add_argument("--session-dir", required=True, help="directory of *.jsonl transcripts")
    listing.add_argument("--json", action="store_true", help="emit one JSON object per transcript")

    showing = sub.add_parser("show", help="print one transcript as a human-readable timeline")
    showing.add_argument("--session-dir", required=True, help="directory of *.jsonl transcripts")
    showing.add_argument("--json", action="store_true", help="emit the raw records as a JSON array")
    showing.add_argument("session_id", help="session id (the *.jsonl file name without its suffix)")


def run_sessions(args: argparse.Namespace) -> int:
    if args.session_command == "list":
        return _list_sessions(Path(args.session_dir), json_out=bool(getattr(args, "json", False)))
    if args.session_command == "show":
        return _show_session(Path(args.session_dir), args.session_id, json_out=bool(getattr(args, "json", False)))
    print("sessions: pass a subcommand: list or show (--help for flags)", file=sys.stderr)
    return USAGE_ERROR


# -- listing ---------------------------------------------------------------


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
            }, sort_keys=True))
        else:
            subtype = summary["subtype"] or "no result"
            print(f"{path.name[: -len(SESSION_FILE_SUFFIX)]:<46} "
                  f"records={summary['records']:<3} turns={summary['assistant_turns']:<3} "
                  f"{subtype:<24} ${summary['total_cost_usd']:.6f} "
                  f"{path.stat().st_size} bytes")
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

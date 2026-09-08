"""Read-side of the session transcripts: ``cli sessions list``, ``show``, ``verify`` and ``replay``.

Writing a transcript has always been append-only and fsynced; this module is the
missing read-back and integrity-check half. It is deliberately read-only: it
never creates the session directory, never opens a file for writing, and never
mutates a record. A transcript is an audit trail - the viewer reports
corruption instead of "repairing" it. A torn *trailing* line is skipped the same
way the writer's own recovery skips it; a damaged line anywhere earlier raises
and names the record. Integrity secrets are read only from an explicitly named
environment variable and are never placed in argv or transcript output.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Iterable

from checkpoints import CheckpointError, create_checkpoint, diff_checkpoint, fork_checkpoint, list_checkpoints, rewind_checkpoint
from sessions import (
    SESSION_FILE_SUFFIX,
    SessionIntegrityError,
    read_session_records,
    replay_records,
    summarise,
    verify_session_integrity,
)

USAGE_ERROR = 64  # same convention as cli.USAGE_ERROR, kept local to avoid an import cycle
CONTENT_PREVIEW = 200


def _nonnegative_index(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("index must be an integer") from error
    if parsed < 0:
        raise argparse.ArgumentTypeError("index must be non-negative")
    return parsed


def add_arguments(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="session_command")

    listing = sub.add_parser("list", help="list transcripts in a session directory")
    listing.add_argument("--session-dir", required=True, help="directory of *.jsonl transcripts")
    listing.add_argument("--json", action="store_true", help="emit one JSON object per transcript")

    showing = sub.add_parser("show", help="print one transcript as a human-readable timeline")
    showing.add_argument("--session-dir", required=True, help="directory of *.jsonl transcripts")
    showing.add_argument("--json", action="store_true", help="emit the raw records as a JSON array")
    showing.add_argument("session_id", help="session id (the *.jsonl file name without its suffix)")

    exporting = sub.add_parser(
        "export",
        help="emit one transcript as the canonical NDJSON audit feed (audit.ndjson/1)",
    )
    exporting.add_argument("--session-dir", required=True, help="directory of *.jsonl transcripts")
    exporting.add_argument(
        "session_id",
        help="session id (the *.jsonl file name without its suffix); "
        "the feed is written to stdout, one validated audit record per line",
    )

    verifying = sub.add_parser("verify", help="verify a hash/HMAC-chained session transcript read-only")
    verifying.add_argument("--session-dir", required=True, help="directory of *.jsonl transcripts")
    verifying.add_argument("--json", action="store_true", help="emit the verification report as JSON")
    verifying.add_argument(
        "--integrity-secret-env",
        "--session-integrity-secret-env",
        dest="integrity_secret_env",
        default="",
        metavar="NAME",
        help="read the optional HMAC secret from environment variable NAME; never pass it on argv",
    )
    verifying.add_argument("session_id", help="session id (the *.jsonl file name without its suffix)")

    replaying = sub.add_parser(
        "replay",
        aliases=["timeline"],
        help="replay a read-only transcript slice; never executes tools or model calls",
    )
    replaying.add_argument("--session-dir", required=True, help="directory of *.jsonl transcripts")
    replaying.add_argument("--json", action="store_true", help="emit replay metadata and records as one JSON object")
    replaying.add_argument("--from-index", type=_nonnegative_index, default=0, metavar="N", help="first record index, inclusive (default: 0)")
    replaying.add_argument("--through-index", type=_nonnegative_index, default=None, metavar="N", help="last record index, inclusive")
    replaying.add_argument("--type", dest="record_types", action="append", default=[], metavar="TYPE", help="include only this record type; repeatable")
    replaying.add_argument(
        "--integrity-secret-env",
        "--session-integrity-secret-env",
        dest="integrity_secret_env",
        default="",
        metavar="NAME",
        help="read an HMAC secret from environment variable NAME when replaying a chained transcript",
    )
    replaying.add_argument("session_id", help="session id (the *.jsonl file name without its suffix)")

    checkpointing = sub.add_parser("checkpoint", help="snapshot a workspace for this session")
    checkpointing.add_argument("--session-dir", required=True, help="directory containing session transcripts")
    checkpointing.add_argument("--workspace", required=True, help="workspace directory to snapshot")
    checkpointing.add_argument("--label", default="", help="operator label for the checkpoint")
    checkpointing.add_argument("--json", action="store_true", help="emit the checkpoint manifest as JSON")
    checkpointing.add_argument("session_id", help="session id that owns the checkpoint")

    checkpoint_listing = sub.add_parser(
        "checkpoints", aliases=["inspect"], help="list checkpoints for this session"
    )
    checkpoint_listing.add_argument("--session-dir", required=True, help="directory containing session transcripts")
    checkpoint_listing.add_argument("--json", action="store_true", help="emit checkpoint manifests as JSON")
    checkpoint_listing.add_argument("session_id", help="session id that owns the checkpoints")

    comparing = sub.add_parser("diff", help="compare a checkpoint with the current workspace")
    comparing.add_argument("--session-dir", required=True, help="directory containing session transcripts")
    comparing.add_argument("--workspace", required=True, help="workspace directory to inspect")
    comparing.add_argument("session_id", help="session id that owns the checkpoint")
    comparing.add_argument("checkpoint_id", help="checkpoint id from sessions checkpoints")
    comparing.add_argument("--json", action="store_true", help="emit the diff as JSON")

    rewinding = sub.add_parser(
        "rewind",
        aliases=["restore"],
        help="restore a checkpoint after an explicit force confirmation",
    )
    rewinding.add_argument("--session-dir", required=True, help="directory containing session transcripts")
    rewinding.add_argument("--workspace", required=True, help="workspace directory to restore")
    rewinding.add_argument("--force", action="store_true", help="confirm the destructive workspace operation")
    rewinding.add_argument(
        "--delete-added",
        action="store_true",
        help="also delete regular files added after the checkpoint (default keeps them)",
    )
    rewinding.add_argument("--json", action="store_true", help="emit the restore report as JSON")
    rewinding.add_argument("session_id", help="session id that owns the checkpoint")
    rewinding.add_argument("checkpoint_id", help="checkpoint id to restore")

    forking = sub.add_parser("fork", help="materialise a new workspace/session from a checkpoint")
    forking.add_argument("--session-dir", required=True, help="directory containing session transcripts")
    forking.add_argument("--workspace", required=True, help="new workspace path; it must not already exist")
    forking.add_argument("--new-session-id", required=True, help="session id for the new fork")
    forking.add_argument("--label", default="fork base", help="label for the fork's initial checkpoint")
    forking.add_argument("--json", action="store_true", help="emit the fork report as JSON")
    forking.add_argument("session_id", help="source session that owns the checkpoint")
    forking.add_argument("checkpoint_id", help="checkpoint id to fork")


def run_sessions(args: argparse.Namespace) -> int:
    if args.session_command == "list":
        return _list_sessions(Path(args.session_dir), json_out=bool(getattr(args, "json", False)))
    if args.session_command == "show":
        return _show_session(Path(args.session_dir), args.session_id, json_out=bool(getattr(args, "json", False)))
    if args.session_command == "export":
        return _export_session(Path(args.session_dir), args.session_id)
    if args.session_command == "verify":
        return _verify_session(
            Path(args.session_dir),
            args.session_id,
            integrity_secret_env=str(getattr(args, "integrity_secret_env", "") or ""),
            json_out=bool(getattr(args, "json", False)),
        )
    if args.session_command in {"replay", "timeline"}:
        return _replay_session(
            Path(args.session_dir),
            args.session_id,
            from_index=int(getattr(args, "from_index", 0)),
            through_index=getattr(args, "through_index", None),
            record_types=tuple(getattr(args, "record_types", ()) or ()),
            integrity_secret_env=str(getattr(args, "integrity_secret_env", "") or ""),
            json_out=bool(getattr(args, "json", False)),
        )
    if args.session_command == "checkpoint":
        return _create_session_checkpoint(
            Path(args.session_dir), args.session_id, Path(args.workspace), args.label,
            json_out=bool(getattr(args, "json", False)),
        )
    if args.session_command in {"checkpoints", "inspect"}:
        return _list_session_checkpoints(
            Path(args.session_dir), args.session_id, json_out=bool(getattr(args, "json", False))
        )
    if args.session_command == "diff":
        return _diff_session_checkpoint(
            Path(args.session_dir), args.session_id, args.checkpoint_id, Path(args.workspace),
            json_out=bool(getattr(args, "json", False)),
        )
    if args.session_command in {"rewind", "restore"}:
        return _rewind_session_checkpoint(
            Path(args.session_dir), args.session_id, args.checkpoint_id, Path(args.workspace),
            force=bool(getattr(args, "force", False)),
            delete_added=bool(getattr(args, "delete_added", False)),
            json_out=bool(getattr(args, "json", False)),
        )
    if args.session_command == "fork":
        return _fork_session_checkpoint(
            Path(args.session_dir), args.session_id, args.checkpoint_id, Path(args.workspace),
            args.new_session_id, args.label, json_out=bool(getattr(args, "json", False)),
        )
    print(
        "sessions: pass a subcommand: list, show, export, verify, replay/timeline, checkpoint, checkpoints, diff, rewind or fork "
        "(--help for flags)",
        file=sys.stderr,
    )
    return USAGE_ERROR


# -- integrity verification -------------------------------------------------


def _verify_session(
    directory: Path,
    session_id: str,
    *,
    integrity_secret_env: str,
    json_out: bool,
) -> int:
    path = directory / f"{session_id}{SESSION_FILE_SUFFIX}"
    if not path.is_file():
        print(f"sessions: no transcript for session {session_id!r} in {directory}", file=sys.stderr)
        return 1
    secret: bytes | None = None
    if integrity_secret_env:
        raw = os.environ.get(integrity_secret_env)
        if raw is None:
            print(f"sessions: integrity secret environment variable {integrity_secret_env!r} is not set", file=sys.stderr)
            return USAGE_ERROR
        secret = raw.encode("utf-8")
        if len(secret) < 16:
            print("sessions: integrity secret must encode to at least 16 bytes", file=sys.stderr)
            return USAGE_ERROR
    try:
        report = verify_session_integrity(path, secret=secret)
    except (OSError, SessionIntegrityError) as error:
        if json_out:
            print(json.dumps({"valid": False, "path": str(path), "error": str(error)}, sort_keys=True))
        else:
            print(f"sessions: integrity verification failed: {error}", file=sys.stderr)
        return 1
    report = {"valid": True, **report}
    if json_out:
        print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    else:
        print(
            f"session integrity: valid records={report['records']} "
            f"signed={'yes' if report['signed'] else 'no'} "
            f"dropped_trailing_lines={report['dropped_trailing_lines']}"
        )
    return 0


def _replay_session(
    directory: Path,
    session_id: str,
    *,
    from_index: int,
    through_index: int | None,
    record_types: tuple[str, ...],
    integrity_secret_env: str,
    json_out: bool,
) -> int:
    path = directory / f"{session_id}{SESSION_FILE_SUFFIX}"
    if not path.is_file():
        print(f"sessions: no transcript for session {session_id!r} in {directory}", file=sys.stderr)
        return 1
    secret: bytes | None = None
    if integrity_secret_env:
        raw = os.environ.get(integrity_secret_env)
        if raw is None:
            print(f"sessions: integrity secret environment variable {integrity_secret_env!r} is not set", file=sys.stderr)
            return USAGE_ERROR
        secret = raw.encode("utf-8")
        if len(secret) < 16:
            print("sessions: integrity secret must encode to at least 16 bytes", file=sys.stderr)
            return USAGE_ERROR
    try:
        records, dropped = read_session_records(path, lock=True, secret=secret, validate_chain=True)
        selected = replay_records(
            records,
            from_index=from_index,
            through_index=through_index,
            record_types=record_types,
        )
    except (OSError, SessionIntegrityError, ValueError) as error:
        if json_out:
            print(json.dumps({"valid": False, "path": str(path), "error": str(error)}, sort_keys=True))
        else:
            print(f"sessions: replay failed: {error}", file=sys.stderr)
        return 1
    chained = any("chain_version" in record for record in records)
    signed = bool(records and "chain_signature" in records[0])
    report = {
        "valid": True,
        "path": str(path),
        "session_id": session_id,
        "from_index": from_index,
        "through_index": through_index,
        "record_types": list(record_types),
        "records": selected,
        "record_count": len(selected),
        "total_records": len(records),
        "dropped_trailing_lines": dropped,
        "integrity_checked": chained,
        "signed": signed,
    }
    if json_out:
        print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    else:
        ending = str(through_index) if through_index is not None else "end"
        filters = f" types={','.join(record_types)}" if record_types else ""
        print(
            f"# replay (read-only; no tools or model calls) session={session_id} "
            f"indexes={from_index}..{ending} records={len(selected)}/{len(records)} "
            f"dropped_trailing_lines={dropped} integrity={'checked' if chained else 'off'}{filters}"
        )
        for record in selected:
            print(_format_record(record))
    return 0


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
        records, _dropped = read_session_records(path, lock=True)
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
    records, dropped = read_session_records(path, lock=True)
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


# -- reversible workspace operations ---------------------------------------


def _create_session_checkpoint(
    session_dir: Path,
    session_id: str,
    workspace: Path,
    label: str,
    *,
    json_out: bool,
) -> int:
    try:
        checkpoint = create_checkpoint(workspace, session_dir, session_id, label=label)
    except (CheckpointError, OSError) as error:
        print(f"sessions checkpoint: {error}", file=sys.stderr)
        return 1
    if json_out:
        print(json.dumps(checkpoint.as_dict(), ensure_ascii=False, sort_keys=True))
    else:
        print(
            f"created {checkpoint.checkpoint_id} for {checkpoint.session_id}: "
            f"{len(checkpoint.files)} file(s), {sum(item.bytes for item in checkpoint.files)} bytes"
        )
        if checkpoint.label:
            print(f"label: {checkpoint.label}")
        print(f"manifest: {checkpoint.manifest_path}")
    return 0


def _list_session_checkpoints(session_dir: Path, session_id: str, *, json_out: bool) -> int:
    try:
        checkpoints = list_checkpoints(session_dir, session_id)
    except (CheckpointError, OSError) as error:
        print(f"sessions checkpoints: {error}", file=sys.stderr)
        return 1
    if json_out:
        for checkpoint in checkpoints:
            print(json.dumps(checkpoint.as_dict(), ensure_ascii=False, sort_keys=True))
        return 0
    if not checkpoints:
        print(f"no checkpoints for {session_id}")
        return 0
    for checkpoint in checkpoints:
        label = f" label={checkpoint.label!r}" if checkpoint.label else ""
        print(
            f"{checkpoint.checkpoint_id:<35} {checkpoint.created_at} "
            f"files={len(checkpoint.files):<5} bytes={sum(item.bytes for item in checkpoint.files):<10}{label}"
        )
    return 0


def _find_session_checkpoint(session_dir: Path, session_id: str, checkpoint_id: str):
    try:
        checkpoints = list_checkpoints(session_dir, session_id)
    except (CheckpointError, OSError) as error:
        print(f"sessions: {error}", file=sys.stderr)
        return None
    for checkpoint in checkpoints:
        if checkpoint.checkpoint_id == checkpoint_id:
            return checkpoint
    print(f"sessions: no checkpoint {checkpoint_id!r} for session {session_id!r}", file=sys.stderr)
    return None


def _diff_session_checkpoint(
    session_dir: Path,
    session_id: str,
    checkpoint_id: str,
    workspace: Path,
    *,
    json_out: bool,
) -> int:
    checkpoint = _find_session_checkpoint(session_dir, session_id, checkpoint_id)
    if checkpoint is None:
        return 1
    try:
        comparison = diff_checkpoint(checkpoint, workspace)
    except (CheckpointError, OSError) as error:
        print(f"sessions diff: {error}", file=sys.stderr)
        return 1
    if json_out:
        print(json.dumps(comparison.as_dict(), ensure_ascii=False, sort_keys=True))
    elif comparison.clean:
        print(f"{checkpoint.checkpoint_id}: clean (workspace matches checkpoint)")
    else:
        print(
            f"{checkpoint.checkpoint_id}: {len(comparison.changes)} change(s) "
            f"current_digest={comparison.current_digest}"
        )
        for change in comparison.changes:
            marker = {"added": "+", "modified": "M", "deleted": "-"}[change.status]
            print(f"{marker} {change.path}")
    return 0


def _rewind_session_checkpoint(
    session_dir: Path,
    session_id: str,
    checkpoint_id: str,
    workspace: Path,
    *,
    force: bool,
    delete_added: bool,
    json_out: bool,
) -> int:
    checkpoint = _find_session_checkpoint(session_dir, session_id, checkpoint_id)
    if checkpoint is None:
        return 1
    try:
        report = rewind_checkpoint(
            checkpoint,
            workspace,
            force=force,
            delete_added=delete_added,
            safety_session_dir=session_dir,
            safety_session_id=session_id,
        )
    except (CheckpointError, OSError) as error:
        print(f"sessions rewind: {error}", file=sys.stderr)
        return 1
    if json_out:
        print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    else:
        print(
            f"rewound {checkpoint.checkpoint_id}: restored {report['restored_files']} file(s); "
            f"kept {report['remaining_added_files']} added file(s)"
        )
        print(f"safety checkpoint: {report['safety_checkpoint_id']}")
    return 0


def _fork_session_checkpoint(
    session_dir: Path,
    session_id: str,
    checkpoint_id: str,
    workspace: Path,
    new_session_id: str,
    label: str,
    *,
    json_out: bool,
) -> int:
    checkpoint = _find_session_checkpoint(session_dir, session_id, checkpoint_id)
    if checkpoint is None:
        return 1
    try:
        report = fork_checkpoint(
            checkpoint,
            workspace,
            session_dir,
            new_session_id,
            label=label,
        )
    except (CheckpointError, OSError) as error:
        print(f"sessions fork: {error}", file=sys.stderr)
        return 1
    if json_out:
        print(json.dumps(report.as_dict(), ensure_ascii=False, sort_keys=True))
    else:
        print(
            f"forked {report.source_session_id}/{report.source_checkpoint_id} -> "
            f"{report.session_id} ({report.copied_files} file(s))"
        )
        print(f"workspace: {report.workspace}")
        print(f"initial checkpoint: {report.checkpoint_id}")
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
    if kind == "workspace_change":
        paths = ", ".join(str(path) for path in record.get("paths") or ()) or "(undeclared paths)"
        return f"tool={record.get('tool')} changed={record.get('changed')} paths={paths}"
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

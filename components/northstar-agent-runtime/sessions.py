"""Append-only JSONL session transcripts.

Every record is written with ``O_APPEND`` and fsynced before the call returns, so
a run that dies mid-turn leaves a transcript a human can read rather than a
half-written file. A crash that lands inside a single line can only ever damage
the *last* line, and a truncated final line is skipped instead of raising: losing
the tail of a session is survivable, refusing to open the file is not.
Read-only inspection may skip a torn final line, but a writer will not resume
or extend that file until the damaged tail has been repaired; appending after a
torn line would turn a recoverable crash into an invalid chain.

A session id is always issued, even when no store is configured, so tracing and
host logs can still be correlated to a run that writes nothing to disk.
"""
from __future__ import annotations

import errno
import copy
import json
import os
import re
import stat
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

from providers.base import (
    AssistantMessage,
    ResultMessage,
    SystemMessage,
    Usage,
    UserMessage,
    coerce_blocks,
)

RECORD_TYPES: tuple[str, ...] = (
    "session_start",
    "user_prompt",
    "assistant",
    "tool_result",
    "hook",
    "denial",
    "defensive_assessment",
    "compact_boundary",
    "informational",
    # The independent end-of-run verdict (postconditions.py): its own type so an
    # audit consumer can require it instead of grepping informational records.
    "postconditions",
    # A resumable turn boundary (checkpoints.py): transcript length + digest plus
    # the consumed counters, so a resume cannot restart the ceilings.
    "checkpoint",
    "subagent",
    "result",
    "session_end",
)

SESSION_FILE_SUFFIX = ".jsonl"
SESSION_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
MAX_RECORD_CHARS = 200_000
MAX_SESSION_FILE_BYTES = 64 * 1024 * 1024
MAX_SESSION_LINE_BYTES = MAX_RECORD_CHARS * 6 + 8_192
MAX_SESSION_RECORDS = 100_000
TRUNCATION_NOTE = "[truncated by the session recorder]"
_SESSION_CONTENT_KEYS = frozenset({
    "content", "text", "prompt", "system_prompt", "final_text", "transcript",
    "tool_input", "tool_output", "arguments", "args", "input", "reason",
    "detail", "error", "errors", "summary", "stdout", "stderr", "response", "data",
    "permission_denials", "rationale", "verdict", "criteria", "criterion", "acceptance_criteria",
    "postconditions",
})


def _redact_session_payload(value: Any) -> Any:
    """Remove likely conversational or sensitive values while retaining record shape."""
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, child in value.items():
            if isinstance(key, str) and key.lower() in _SESSION_CONTENT_KEYS:
                redacted[key] = "[omitted by session privacy mode]"
            else:
                redacted[key] = _redact_session_payload(child)
        return redacted
    if isinstance(value, list):
        return [_redact_session_payload(child) for child in value]
    if isinstance(value, tuple):
        return [_redact_session_payload(child) for child in value]
    return value


class SessionIntegrityError(ValueError):
    """Raised for corruption that is not explainable by a crash at the tail."""


def _open_regular_nofollow(path: Path, flags: int, mode: int = 0o600) -> int:
    """Open one regular transcript file without following its final symlink."""
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:  # pragma: no cover - all supported production hosts are POSIX
        raise SessionIntegrityError("safe transcript access requires O_NOFOLLOW support")
    flags |= nofollow | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(str(path), flags, mode)
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise SessionIntegrityError(f"{path.name}: refusing to follow a transcript symlink") from error
        raise
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise SessionIntegrityError(f"{path.name}: transcript target is not a regular file")
        # Some POSIX-like hosts clear O_APPEND when O_NONBLOCK is combined in
        # os.open flags. O_NONBLOCK is needed to avoid hanging on a FIFO before
        # fstat can reject it; restore append mode only after proving this fd is
        # a regular file. This keeps the safe-open sequence and write invariant.
        append = getattr(os, "O_APPEND", 0)
        if append:
            try:
                import fcntl as _fcntl
                current = _fcntl.fcntl(fd, _fcntl.F_GETFL)
                if not current & append:
                    _fcntl.fcntl(fd, _fcntl.F_SETFL, current | append)
            except (ImportError, OSError) as error:
                raise SessionIntegrityError(f"{path.name}: cannot verify append-only transcript writes: {error}") from error
        return fd
    except Exception:
        os.close(fd)
        raise


def new_session_id(*, now: float | None = None) -> str:
    """Sortable, collision-resistant identifier: ``ns-<utc>-<entropy>``."""
    stamp = time.gmtime(now if now is not None else time.time())
    return "ns-{:04d}{:02d}{:02d}T{:02d}{:02d}{:02d}Z-{}".format(
        stamp.tm_year, stamp.tm_mon, stamp.tm_mday, stamp.tm_hour, stamp.tm_min, stamp.tm_sec,
        uuid.uuid4().hex[:8],
    )


def _fsync(fd: int) -> None:  # pragma: no cover - thin wrapper, patched in tests
    os.fsync(fd)


def _write_all(fd: int, data: bytes) -> None:
    """Write every byte, retrying short writes and rejecting zero progress."""
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("os.write made no progress while appending a session record")
        view = view[written:]


@dataclass
class SessionStore:
    """Writer/reader for one session's JSONL transcript.

    When ``chain`` is true (the default), every record is sealed at write
    time with the tamper-evident hash chain (``audit_chain.chain_record``):
    ``chain_hash = sha256(raw(prev_hash) || canon(body))``. The first
    record's ``prev_hash`` is the genesis hash bound to this session id.
    An operator who edits the transcript file breaks the chain, and the
    break is located by line on verify. This closes the pre-export
    tampering window: chaining is no longer export-time-only.
    """

    directory: str | os.PathLike[str] | None = None
    session_id: str = ""
    fsync: Callable[[int], None] = field(default=_fsync)
    durable: bool = True
    max_record_chars: int = MAX_RECORD_CHARS
    on_write: Callable[[dict[str, Any]], None] | None = None
    #: Seal every record with the hash chain at write time. Disable only for
    #: tests or for readers that never write.
    chain: bool = True
    #: Persist record structure and governance metadata without conversation
    #: bodies. Such a transcript is auditable but intentionally not resumable.
    redact_content: bool = False
    _index: int = 0
    _written: int = 0
    # The chain head: the chain_hash of the last record written. Resumed
    # from the existing file on open; genesis when the file is new.
    _prev_hash: str | None = None
    # True until the first record of a fresh chain is written; that record
    # carries the genesis anchor the verifier requires.
    _genesis_pending: bool = False
    _chain_version: str = "northstar-audit-chain/2"
    # Hybrid Logical Clock state for this writer's audit stamps (see hlc.py):
    # ticking it on every append guarantees the "hlc" stamps are
    # non-decreasing even when the wall clock is not, so multi-writer feeds
    # can no longer show causally-ordered events with inverted timestamps.
    _hlc_l: int = 0
    _hlc_c: int = 0
    # A failed/partial append may leave an incomplete tail. Do not let this
    # writer append another record onto an uncertain on-disk state.
    _write_poisoned: bool = False

    def __post_init__(self) -> None:
        self.session_id = self.session_id or new_session_id()
        validate_session_id(self.session_id)
        if self.directory is None:
            return
        path = Path(self.directory)
        existed = path.exists()
        path.mkdir(parents=True, exist_ok=True)
        if not existed:
            # Transcripts can contain user content; keep the directory owner-only.
            os.chmod(path, 0o700)
        self.directory = path
        if self.chain:
            (
                self._prev_hash,
                self._genesis_pending,
                self._chain_version,
                (self._hlc_l, self._hlc_c),
            ) = self._resume_chain_head()

    def _genesis_params(self) -> dict[str, Any]:
        from audit_chain import build_genesis_params

        return build_genesis_params(
            component="northstar-session",
            session_id=self.session_id,
            chain_version=self._chain_version,
        )

    def _genesis_hash(self) -> str:
        from audit_chain import genesis_hash

        return genesis_hash(self._genesis_params())

    def _resume_chain_head(self) -> tuple[str, bool, str, tuple[int, int]]:
        """Pick up the chain where the existing file left off.

        Returns ``(head_hash, fresh, chain_version, hlc_state)`` where
        ``fresh`` is True when this write session starts a new chain
        (new/empty file) and the first record must carry the genesis anchor.
        Existing records are streamed through the same chain verifier before
        their head or HLC can be trusted. Reads are bounded and refuse
        symlinks, malformed records, unsealed history, and invalid chains.
        """
        path = self.path
        from audit_chain import CHAIN_VERSION, CHAIN_VERSION_V2
        from hlc import unpack

        if path is None or not os.path.lexists(path):
            return self._genesis_hash(), True, CHAIN_VERSION_V2, (0, 0)
        fd = _open_regular_nofollow(path, os.O_RDONLY)
        with os.fdopen(fd, "rb") as fh:
            if os.fstat(fh.fileno()).st_size > MAX_SESSION_FILE_BYTES:
                raise SessionIntegrityError(
                    f"{path.name}: transcript exceeds the {MAX_SESSION_FILE_BYTES}-byte resume limit"
                )
            last: dict[str, Any] | None = None
            first_record: dict[str, Any] | None = None
            hlc_state = (0, 0)
            total_bytes = 0
            record_count = 0

            def bounded_lines():
                nonlocal first_record, last, hlc_state, total_bytes, record_count
                while True:
                    raw_line = fh.readline(MAX_SESSION_LINE_BYTES + 1)
                    if not raw_line:
                        return
                    record_count += 1
                    total_bytes += len(raw_line)
                    if record_count > MAX_SESSION_RECORDS:
                        raise SessionIntegrityError(
                            f"{path.name}: transcript exceeds the {MAX_SESSION_RECORDS}-record resume limit"
                        )
                    if total_bytes > MAX_SESSION_FILE_BYTES:
                        raise SessionIntegrityError(
                            f"{path.name}: transcript exceeds the {MAX_SESSION_FILE_BYTES}-byte resume limit"
                        )
                    if len(raw_line) > MAX_SESSION_LINE_BYTES:
                        raise SessionIntegrityError(
                            f"{path.name}: record {record_count - 1} exceeds the {MAX_SESSION_LINE_BYTES}-byte resume line limit"
                        )
                    if not raw_line.strip():
                        yield raw_line.decode("ascii")
                        continue
                    try:
                        candidate = json.loads(raw_line.decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError) as error:
                        raise SessionIntegrityError(
                            f"{path.name}: cannot resume from malformed record {record_count - 1}"
                        ) from error
                    if not isinstance(candidate, dict):
                        raise SessionIntegrityError(
                            f"{path.name}: record {record_count - 1} is not a JSON object"
                        )
                    if first_record is None:
                        first_record = candidate
                    parsed_hlc = unpack(candidate.get("hlc"))
                    if parsed_hlc is not None:
                        hlc_state = parsed_hlc
                    last = candidate
                    yield raw_line.decode("utf-8")

            from audit_chain import verify_lines

            verification = verify_lines(bounded_lines(), expect_session_id=self.session_id)
            if last is None and record_count == 0:
                return self._genesis_hash(), True, CHAIN_VERSION_V2, (0, 0)
            if not verification.ok or last is None or first_record is None:
                raise SessionIntegrityError(
                    f"{path.name}: refusing to resume; session chain verification failed: {verification.reason}"
                )
            head = last.get("chain_hash")
            if not isinstance(head, str) or len(head) != 64:
                raise SessionIntegrityError(f"{path.name}: last transcript record has no valid chain head")
            genesis = first_record.get("genesis")
            version = genesis.get("chain") if isinstance(genesis, dict) else CHAIN_VERSION
            if version not in {CHAIN_VERSION, CHAIN_VERSION_V2}:
                raise SessionIntegrityError(f"{path.name}: unknown session chain version")
            return head, False, version, hlc_state

    # -- shape ------------------------------------------------------------
    @property
    def enabled(self) -> bool:
        return self.directory is not None

    @property
    def path(self) -> Path | None:
        if self.directory is None:
            return None
        return Path(self.directory) / f"{self.session_id}{SESSION_FILE_SUFFIX}"

    @property
    def written(self) -> int:
        return self._written

    @property
    def bytes_written(self) -> int:
        path = self.path
        return path.stat().st_size if path is not None and path.exists() else 0

    # -- writing ----------------------------------------------------------
    def append(self, record_type: str, data: dict[str, Any] | None = None) -> dict[str, Any] | None:
        """Write one record. Returns the record even when no store is configured."""
        if self._write_poisoned:
            raise SessionIntegrityError(
                "a previous transcript write failed; refusing further appends until the store is reopened"
            )
        if record_type not in RECORD_TYPES:
            raise ValueError(f"unknown session record type {record_type!r}")
        # Detach nested values from the caller before hashing/writing. Session
        # records are an audit boundary; a retained input dict must not be able
        # to race the chain computation or change the serialized body later.
        payload = copy.deepcopy(data or {})
        if self.redact_content:
            if record_type == "session_start" and isinstance(payload.get("data"), dict):
                # Keep run posture visible, but a `contains:` verify condition
                # can itself contain user-provided text or a secret canary.
                payload["data"] = _redact_session_payload(payload["data"])
                payload["data"]["session_content_mode"] = "omitted"
            elif record_type not in {"checkpoint", "session_end"}:
                payload = _redact_session_payload(payload)
                payload["content_redacted"] = True
        from hlc import pack, tick
        self._hlc_l, self._hlc_c = tick((self._hlc_l, self._hlc_c))
        record: dict[str, Any] = {
            "index": self._index,
            "ts": _timestamp(),
            "hlc": pack(self._hlc_l, self._hlc_c),
            "session_id": self.session_id,
            "type": record_type,
            **payload,
        }
        if self.chain and self._prev_hash is not None:
            from audit_chain import chain_record

            # Chain v2 is self-describing on every record so streaming
            # verifiers never infer its canonicalization from a distant line.
            if self._chain_version == "northstar-audit-chain/2":
                record["chain"] = self._chain_version
            if self._genesis_pending:
                # The verifier requires the first record of a chain to
                # carry the genesis anchor its prev_hash commits to.
                record = {**record, "genesis": self._genesis_params()}
            record = chain_record(record, self._prev_hash, chain_version=self._chain_version)
        if self.on_write is not None:
            try:
                # Mirrors are observers. Give them a detached value so a
                # callback cannot mutate the authoritative record before the
                # local durable write (or retain an alias to mutate it later).
                self.on_write(copy.deepcopy(record))
            except Exception:  # noqa: BLE001 - a mirror must never break the run
                pass
        if self.directory is None:
            self._index += 1
            if self.chain and "chain_hash" in record:
                self._prev_hash = record["chain_hash"]
                self._genesis_pending = False
            return None
        try:
            record = self._write(record)
        except Exception:
            self._write_poisoned = True
            raise
        self._index += 1
        if self.chain and "chain_hash" in record:
            self._prev_hash = record["chain_hash"]
            self._genesis_pending = False
        return record

    def merge_hlc(self, stamp: object) -> bool:
        """Merge another writer's HLC stamp into this writer's clock.

        Call this when this session observes another writer's record (e.g. a
        parallel worker's event) before appending its own: the receive rule
        makes every stamp issued afterwards strictly greater than the
        observed one, so causality survives clock skew between writers.
        Returns False (clock unchanged) for an unparseable stamp.
        """
        from hlc import receive, unpack

        parsed = unpack(stamp)
        if parsed is None:
            return False
        self._hlc_l, self._hlc_c = receive((self._hlc_l, self._hlc_c), parsed[0], parsed[1])
        return True

    def _write(self, record: dict[str, Any]) -> dict[str, Any]:
        line = json.dumps(record, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":"))
        if self.max_record_chars > 0 and len(line) > self.max_record_chars:
            # Save the chain link before truncation rewrites the body.
            prev_hash = record.get("prev_hash")
            genesis = record.get("genesis")
            chain_version = record.get("chain")
            record = {**record, "truncated": True, "payload": record.get("payload", {})}
            line = json.dumps(record, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":"))
            line = line[: self.max_record_chars] + ',"note":"' + TRUNCATION_NOTE + '"}'
            try:
                record = json.loads(line)
            except json.JSONDecodeError:  # pragma: no cover - keep valid JSON or drop the tail
                record = {
                    "index": record["index"], "ts": record["ts"], "session_id": self.session_id,
                    "type": record["type"], "truncated": True,
                }
            if isinstance(genesis, dict):
                record["genesis"] = genesis
            if chain_version is not None:
                record["chain"] = chain_version
            # Truncation rewrote the body: re-seal over the truncated body
            # with the saved prev_hash so the written bytes verify and the
            # chain stays unbroken.
            if self.chain and isinstance(prev_hash, str):
                from audit_chain import chain_record

                record = chain_record(record, prev_hash, chain_version=self._chain_version)
            line = json.dumps(record, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":"))
        path = self.path
        assert path is not None
        fd = _open_regular_nofollow(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND)
        try:
            _write_all(fd, (line + "\n").encode("utf-8"))
            if self.durable:
                self.fsync(fd)
        finally:
            os.close(fd)
        self._written += 1
        return record

    def record_assistant(self, message: AssistantMessage, *, agent: str = "main") -> dict[str, Any] | None:
        return self.append(
            "assistant",
            {
                "agent": agent,
                "role": "assistant",
                "content": [block.to_api() for block in message.content],
                "model": message.model,
                "usage": message.usage.as_dict(),
                "stop_reason": message.stop_reason,
            },
        )

    def record_user(self, message: UserMessage, *, agent: str = "main") -> dict[str, Any] | None:
        return self.append(
            "user_prompt" if not message.tool_results else "tool_result",
            {
                "agent": agent,
                "role": "user",
                "content": [block.to_api() for block in message.content],
                "is_meta": message.is_meta,
            },
        )

    def record_system(self, message: SystemMessage, *, agent: str = "main") -> dict[str, Any] | None:
        kind = {
            "init": "session_start",
            "compact_boundary": "compact_boundary",
            "postconditions": "postconditions",
        }.get(message.subtype, "informational")
        return self.append(kind, {"agent": agent, "subtype": message.subtype, "content": message.content, "data": message.data})

    def record_result(self, message: ResultMessage) -> dict[str, Any] | None:
        record = self.append(
            "result",
            {
                "subtype": message.subtype,
                "is_error": message.is_error,
                "num_turns": message.num_turns,
                "duration_ms": message.duration_ms,
                "total_cost_usd": message.total_cost_usd,
                "total_usage": message.total_usage.as_dict(),
                "pricing_estimated": message.pricing_estimated,
                "errors": list(message.errors),
                "permission_denials": list(message.permission_denials),
            },
        )
        self.append("session_end", {"subtype": message.subtype})
        return record

    # -- reading ----------------------------------------------------------
    def read(self, session_id: str | None = None, *, strict: bool = True) -> tuple[list[dict[str, Any]], int]:
        if session_id is not None:
            validate_session_id(session_id)
        path = self.path if session_id is None else Path(self.directory) / f"{session_id}{SESSION_FILE_SUFFIX}"
        if path is None or not path.exists():
            return [], 0
        return load_jsonl(path, strict=strict)

    def transcript(self, session_id: str | None = None, *, require_integrity: bool = False) -> list[Any]:
        records, _dropped = self.read(session_id)
        redacted_mode = any(
            record.get("type") == "session_start"
            and isinstance(record.get("data"), dict)
            and record["data"].get("session_content_mode") == "omitted"
            for record in records
        )
        if redacted_mode or any(record.get("content_redacted") is True for record in records):
            raise SessionIntegrityError(
                f"{session_id or self.session_id}: transcript content was intentionally redacted and cannot be resumed"
            )
        has_chain = any(any(key in record for key in ("chain_hash", "prev_hash", "genesis")) for record in records)
        if require_integrity and records and not has_chain:
            raise SessionIntegrityError(f"{session_id or self.session_id}: refusing to resume an unsealed transcript")
        if has_chain:
            from audit_chain import verify_lines

            lines = (
                json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
                for record in records
            )
            verification = verify_lines(
                lines,
                expect_session_id=session_id or self.session_id,
            )
            if not verification.ok:
                raise SessionIntegrityError(
                    f"{session_id or self.session_id}: session chain verification failed: {verification.reason}"
                )
        return transcript_from_records(records)

    def list_sessions(self) -> tuple[str, ...]:
        if self.directory is None:
            return ()
        return tuple(
            sorted(path.name[: -len(SESSION_FILE_SUFFIX)] for path in Path(self.directory).glob(f"*{SESSION_FILE_SUFFIX}"))
        )


def load_jsonl(path: str | os.PathLike[str], *, strict: bool = True) -> tuple[list[dict[str, Any]], int]:
    """Return ``(records, dropped)`` for a session file.

    A trailing line that cannot be parsed is a torn write and is skipped. A bad
    line anywhere earlier cannot be a torn write - that file was already damaged
    while it was complete - so ``strict`` raises instead of quietly losing turns.
    """
    file_path = Path(path)
    records: list[dict[str, Any]] = []
    dropped = 0
    total_bytes = 0
    line_number = 0
    pending_bad_line: tuple[int, str] | None = None
    fd = _open_regular_nofollow(file_path, os.O_RDONLY)
    with os.fdopen(fd, "rb") as handle:
        while True:
            raw_line = handle.readline(MAX_SESSION_LINE_BYTES + 1)
            if not raw_line:
                break
            line_number += 1
            if line_number > MAX_SESSION_RECORDS:
                raise SessionIntegrityError(
                    f"{file_path.name}: transcript exceeds the {MAX_SESSION_RECORDS}-record read limit"
                )
            total_bytes += len(raw_line)
            if total_bytes > MAX_SESSION_FILE_BYTES:
                raise SessionIntegrityError(
                    f"{file_path.name}: transcript exceeds the {MAX_SESSION_FILE_BYTES}-byte read limit"
                )
            if len(raw_line) > MAX_SESSION_LINE_BYTES:
                raise SessionIntegrityError(
                    f"{file_path.name}: record {line_number - 1} exceeds the {MAX_SESSION_LINE_BYTES}-byte line limit"
                )
            if pending_bad_line is not None:
                bad_index, reason = pending_bad_line
                if strict:
                    raise SessionIntegrityError(
                        f"{file_path.name}: record {bad_index} {reason} and is not the trailing line"
                    )
                dropped += 1
                pending_bad_line = None
            if not raw_line.strip():
                continue
            line = raw_line.decode("utf-8", errors="replace")
            reason = "is not valid JSON"
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                if not strict:
                    dropped += 1
                    continue
                pending_bad_line = (line_number - 1, reason)
                continue
            if not isinstance(value, dict):
                if not strict:
                    dropped += 1
                    continue
                pending_bad_line = (line_number - 1, "is not a JSON object")
                continue
            records.append(value)
    if pending_bad_line is not None:
        dropped += 1  # only a malformed final line can be explained by a torn write
    return records, dropped


def session_spend(records: Sequence[dict[str, Any]]) -> tuple[float, Usage]:
    """Aggregate completed and trailing interrupted-run spend from a transcript."""
    from budget import compute_cost

    total_cost = 0.0
    total_usage = Usage()
    trailing_usage = Usage()
    trailing_model = ""
    for record in records:
        if record.get("type") == "result":
            total_cost += float(record.get("total_cost_usd", 0.0) or 0.0)
            trailing_usage = Usage()
            trailing_model = ""
        elif record.get("type") == "assistant":
            usage = Usage.from_mapping(record.get("usage"))
            total_usage = total_usage + usage
            model = str(record.get("model", "") or trailing_model)
            if trailing_usage.total_tokens and model != trailing_model:
                total_cost += compute_cost(trailing_usage, trailing_model).total_usd
                trailing_usage = Usage()
            trailing_usage = trailing_usage + usage
            trailing_model = model
    if trailing_usage.total_tokens:
        total_cost += compute_cost(trailing_usage, trailing_model).total_usd
    return round(total_cost, 10), total_usage


def transcript_from_records(records: Sequence[dict[str, Any]]) -> list[Any]:
    """Rebuild the root agent's current provider transcript from append-only records.

    Child-agent exchanges share the audit file but are not part of the root model's
    conversation. A compaction record is a state boundary: all earlier root messages
    remain in the audit log, but the provider transcript starts at that summary.
    """
    transcript: list[Any] = []
    root_agent = next(
        (record.get("agent") for record in records
         if record.get("type") == "session_start" and isinstance(record.get("agent"), str)),
        None,
    )
    for record in records:
        kind = record.get("type")
        agent = record.get("agent")
        if root_agent is not None and isinstance(agent, str) and agent != root_agent:
            continue
        if kind in {"user_prompt", "tool_result", "assistant"}:
            role = record.get("role") or ("assistant" if kind == "assistant" else "user")
            content = coerce_blocks(record.get("content") or ())
            if role == "assistant":
                transcript.append(
                    AssistantMessage(
                        content=tuple(content),
                        model=str(record.get("model", "") or ""),
                        usage=Usage.from_mapping(record.get("usage")),
                        stop_reason=str(record.get("stop_reason", "") or ""),
                    )
                )
            else:
                transcript.append(UserMessage(content=tuple(content), is_meta=bool(record.get("is_meta"))))
        elif kind == "compact_boundary":
            # The durable log is append-only. The in-memory/provider transcript
            # replaced this prefix, so replay must fold the same state transition.
            transcript.clear()
            transcript.append(
                SystemMessage(
                    subtype="compact_boundary",
                    content=str(record.get("content", "") or ""),
                    data=dict(record.get("data") or {}),
                )
            )
        elif kind == "informational":
            data = record.get("data") or {}
            if isinstance(data, dict) and data.get("reason") == "session_lease_lost":
                # This is an audit warning emitted outside the transcript; it was
                # never part of the in-memory provider context.
                continue
            transcript.append(
                SystemMessage(
                    subtype="informational",
                    content=str(record.get("content", "") or ""),
                    data=dict(data) if isinstance(data, dict) else {},
                )
            )
    return transcript


def summarise(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Cheap session statistics for the CLI's ``--inspect-session`` flag."""
    counts: dict[str, int] = {}
    cost = 0.0
    turns = 0
    subtype = ""
    for record in records:
        kind = str(record.get("type", "unknown"))
        counts[kind] = counts.get(kind, 0) + 1
        if kind == "assistant":
            turns += 1
        if kind == "result":
            cost = float(record.get("total_cost_usd") or 0.0)
            subtype = str(record.get("subtype", ""))
    return {"records": sum(counts.values()), "by_type": counts, "assistant_turns": turns, "total_cost_usd": cost, "subtype": subtype}


def _timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + f".{int((time.time() % 1) * 1000):03d}Z"


def validate_session_id(session_id: str) -> str:
    """Require a safe single path component for a session filename."""
    if not isinstance(session_id, str) or not SESSION_ID_PATTERN.fullmatch(session_id):
        raise ValueError(f"unsafe session id {session_id!r}; expected a safe single path component")
    return session_id


def resolve_session_id(session_id: str | None, store: SessionStore | None) -> str:
    """Pitfall guard: a run without a session store still needs a session id."""
    if session_id:
        return session_id
    if store is not None and store.session_id:
        return store.session_id
    return new_session_id()


__all__ = [
    "RECORD_TYPES",
    "SESSION_FILE_SUFFIX",
    "SessionIntegrityError",
    "SessionStore",
    "load_jsonl",
    "new_session_id",
    "resolve_session_id",
    "summarise",
    "transcript_from_records",
]

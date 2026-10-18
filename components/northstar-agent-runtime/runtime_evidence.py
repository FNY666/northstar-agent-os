"""Optional, digest-first evidence capture for one governed runtime run.

The runtime must remain importable without ``northstar-run-evidence``.  This
module therefore contains a small runtime-owned sink protocol and imports the
store only when a host asks for an evidence directory.

What is captured
----------------
One bundle directory contains a hash-chained ``ledger.jsonl``, a ``manifest.json``
summary, and an ``audit.ndjson`` projection.  Entries describe policy decisions,
tool execution outcomes, checkpoints, postconditions, verification, egress, and
the terminal result.  The ledger stores typed digest references and bounded
metadata only; prompts, credentials, raw tool arguments, and raw tool output
never enter it.

Failure semantics
-----------------
Evidence is opt-in.  A capture failure is reported through
``RuntimeEvidenceSink.error``.  The runtime decides whether that changes the run
result: by default it does not, while ``evidence_required=True`` turns an
incomplete evidence bundle into ``error_evidence_incomplete``.
"""
from __future__ import annotations

import importlib
import json
import os
import sys
import time
from dataclasses import dataclass
from threading import RLock
from pathlib import Path
from typing import Any, Mapping, Sequence

SOURCE = "runtime"
CAPTURE_POLICY_REVISION = "runtime-digest-only.v1"


class RuntimeEvidenceError(ValueError):
    """The bundle could not be created or updated safely."""


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _component_root() -> Path:
    return Path(__file__).resolve().parents[1] / "northstar-run-evidence"


def _load_evidence_module(name: str) -> Any:
    """Load a sibling evidence module without shadowing installed modules."""
    try:
        return importlib.import_module(name)
    except ImportError:
        root = _component_root()
        if not root.is_dir():
            raise
        text = str(root)
        if text not in sys.path:
            sys.path.append(text)
        return importlib.import_module(name)


def _safe_id(value: Any, fallback: str = "run") -> str:
    text = str(value or "").strip()
    safe = "".join(char if char.isalnum() or char in "._-" else "-" for char in text)
    safe = safe.strip(".-")[:128]
    return safe or fallback


@dataclass(frozen=True)
class EvidenceCaptureReport:
    """Machine-readable result of evidence capture for one run."""

    ok: bool
    bundle_dir: str
    ledger_path: str
    manifest_path: str
    audit_path: str
    ledger_entry_count: int
    head_digest: str | None
    errors: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "bundle_dir": self.bundle_dir,
            "ledger_path": self.ledger_path,
            "manifest_path": self.manifest_path,
            "audit_path": self.audit_path,
            "ledger_entry_count": self.ledger_entry_count,
            "head_digest": self.head_digest,
            "errors": list(self.errors),
        }


class RuntimeEvidenceSink:
    """Best-effort-by-default sink for runtime events and subject digests."""

    def __init__(
        self,
        bundle_dir: str | os.PathLike[str],
        *,
        run_id: str,
        session_id: str,
        clock: Any = time.time,
    ) -> None:
        if not callable(clock):
            raise ValueError("clock must be callable")
        self.bundle_dir = Path(bundle_dir).expanduser().resolve()
        self.run_id = _safe_id(run_id)
        self.session_id = _safe_id(session_id, "session")
        self._clock = clock
        self.error: str | None = None
        self._closed = False
        self._last_error: str | None = None
        self._lock = RLock()
        try:
            self.bundle_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(self.bundle_dir, 0o700)
            store_module = _load_evidence_module("evidence_store")
            self._store = store_module.EvidenceStore(
                self.bundle_dir / "ledger.jsonl", self.run_id
            )
            contract_module = _load_evidence_module("evidence_contract")
            self._digest_subject = contract_module.digest_subject
            self._evidence_ref = contract_module.EvidenceRef
        except Exception as error:  # noqa: BLE001 - capture outage is a report
            self._store = None
            self._digest_subject = None
            self._evidence_ref = None
            self.error = f"{type(error).__name__}: {error}"
        self._source_subjects: dict[str, str] = {}
        if self._store is not None:
            try:
                for entry in self._store.entries:
                    if entry.source_id is not None:
                        self._source_subjects[entry.source_id] = entry.subject_digest
            except Exception as error:  # noqa: BLE001 - existing corrupt ledger fails capture
                self.error = f"{type(error).__name__}: {error}"
        self._started = self._now()

    @property
    def available(self) -> bool:
        return self._store is not None and self.error is None and not self._closed

    @property
    def last_error(self) -> str | None:
        return self._last_error or self.error

    def _now(self) -> int:
        value = self._clock()
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            return int(time.time())
        return max(1, int(value))

    def _append(
        self,
        *,
        kind: str,
        source_id: str,
        subject: Mapping[str, Any],
        ref_ids: Sequence[str] = (),
    ) -> Any | None:
        with self._lock:
            if not self.available:
                return None
            refs = []
            for ref_id in dict.fromkeys(str(item) for item in ref_ids):
                subject_digest = self._source_subjects.get(ref_id)
                if subject_digest is not None and self._evidence_ref is not None:
                    refs.append(self._evidence_ref("evidence", ref_id, subject_digest))
            try:
                entry = self._store.append(
                    source=SOURCE,
                    kind=kind,
                    occurred_at=self._now(),
                    subject=subject,
                    refs=tuple(refs[:128]),
                    source_id=source_id,
                )
            except Exception as error:  # noqa: BLE001 - evidence must not crash the loop
                self._last_error = f"{type(error).__name__}: {error}"
                self.error = self.error or self._last_error
                return None
            if entry.source_id is not None:
                self._source_subjects[entry.source_id] = entry.subject_digest
            return entry

    def start_run(
        self,
        *,
        provider: str,
        model: str,
        permission_mode: str,
        policy_revision: str | None,
        tools: Sequence[str],
        workspace: str,
        max_turns: int,
        max_tool_calls: int | None,
        max_budget_usd: float | None,
    ) -> Any | None:
        """Record run identity and governance configuration without prompt text."""
        mode = getattr(permission_mode, "value", permission_mode)
        return self._append(
            kind="runtime.started",
            source_id="runtime-started",
            subject={
                "schema_version": "northstar.runtime-evidence-subject.v1",
                "session_id": self.session_id,
                "provider": str(provider),
                "model": str(model),
                "permission_mode": str(mode),
                "policy_revision": policy_revision,
                "tools": list(tools),
                "workspace_name": Path(workspace).name,
                "limits": {
                    "max_turns": int(max_turns),
                    "max_tool_calls": max_tool_calls,
                    "max_budget_usd": None if max_budget_usd is None else str(max_budget_usd),
                },
                "capture_policy": CAPTURE_POLICY_REVISION,
            },
        )

    def append_event(
        self,
        *,
        source: str,
        kind: str,
        sequence: str,
        subject: Mapping[str, Any],
        ref_ids: Sequence[str] = (),
    ) -> Any | None:
        """Append a compact event under a stable source-qualified id."""
        return self._append(
            kind=kind,
            source_id=f"{_safe_id(source, 'event')}-{_safe_id(sequence, 'unknown')}",
            subject={
                "schema_version": "northstar.runtime-evidence-event.v1",
                **subject,
            },
            ref_ids=ref_ids,
        )

    def append_subject(
        self,
        *,
        kind: str,
        source_id: str,
        subject: Mapping[str, Any] | bytes,
        ref_ids: Sequence[str] = (),
    ) -> Any | None:
        """Append a caller-built message-specific subject with a stable id."""
        with self._lock:
            if not self.available:
                return None
            try:
                refs = []
                for ref_id in dict.fromkeys(str(item) for item in ref_ids):
                    subject_digest = self._source_subjects.get(ref_id)
                    if subject_digest is not None and self._evidence_ref is not None:
                        refs.append(self._evidence_ref("evidence", ref_id, subject_digest))
                entry = self._store.append(
                    source=SOURCE,
                    kind=kind,
                    occurred_at=self._now(),
                    subject=subject,
                    refs=tuple(refs[:128]),
                    source_id=_safe_id(source_id),
                )
            except Exception as error:  # noqa: BLE001 - capture outage is reported
                self._last_error = f"{type(error).__name__}: {error}"
                self.error = self.error or self._last_error
                return None
            if entry.source_id is not None:
                self._source_subjects[entry.source_id] = entry.subject_digest
            return entry

    def result_refs(self) -> tuple[str, ...]:
        """Stable prior source ids the terminal record can reference."""
        return tuple(sorted(self._source_subjects))

    def seal(self, *, completion: Mapping[str, Any]) -> EvidenceCaptureReport:
        """Write a digest manifest and close the capture session."""
        with self._lock:
            return self._seal_locked(completion=completion)

    def _seal_locked(self, *, completion: Mapping[str, Any]) -> EvidenceCaptureReport:
        errors: list[str] = []
        ledger_path = self.bundle_dir / "ledger.jsonl"
        manifest_path = self.bundle_dir / "manifest.json"
        audit_path = self.bundle_dir / "audit.ndjson"
        entries: tuple[Any, ...] = ()
        head_digest: str | None = None
        if self._store is not None:
            try:
                entries = self._store.load()
                head_digest = self._store.head_digest
            except Exception as error:  # noqa: BLE001
                errors.append(f"ledger verification failed: {type(error).__name__}: {error}")
        if self.error:
            errors.append(self.error)
        if not self._closed:
            self._closed = True
        manifest = {
            "schema_version": "northstar.runtime-evidence-manifest.v1",
            "run_id": self.run_id,
            "session_id": self.session_id,
            "capture_policy": {
                "revision": CAPTURE_POLICY_REVISION,
                "storage": "digest-and-metadata-only",
            },
            "ledger": {
                "path": "ledger.jsonl",
                "entry_count": len(entries),
                "head_digest": head_digest,
            },
            "completion": dict(completion),
            "source_subjects": {
                source_id: digest
                for source_id, digest in sorted(self._source_subjects.items())
            },
            "ok": not errors,
            "errors": errors,
        }
        try:
            self._atomic_write(manifest_path, _canonical_bytes(manifest) + b"\n")
            self._write_audit(entries, audit_path)
        except Exception as error:  # noqa: BLE001
            errors.append(f"manifest or audit write failed: {type(error).__name__}: {error}")
        return EvidenceCaptureReport(
            ok=not errors,
            bundle_dir=str(self.bundle_dir),
            ledger_path=str(ledger_path),
            manifest_path=str(manifest_path),
            audit_path=str(audit_path),
            ledger_entry_count=len(entries),
            head_digest=head_digest,
            errors=tuple(errors),
        )

    def verify(self) -> EvidenceCaptureReport:
        """Re-open the ledger and report its current structural integrity."""
        errors: list[str] = []
        entries: tuple[Any, ...] = ()
        head_digest = None
        try:
            store_module = _load_evidence_module("evidence_store")
            store = store_module.EvidenceStore(self.bundle_dir / "ledger.jsonl", self.run_id)
            verification = store.verify()
            entries = store.load()
            head_digest = store.head_digest
            if not verification.ok:
                errors.extend(verification.errors)
        except Exception as error:  # noqa: BLE001
            errors.append(f"{type(error).__name__}: {error}")
        return EvidenceCaptureReport(
            ok=not errors,
            bundle_dir=str(self.bundle_dir),
            ledger_path=str(self.bundle_dir / "ledger.jsonl"),
            manifest_path=str(self.bundle_dir / "manifest.json"),
            audit_path=str(self.bundle_dir / "audit.ndjson"),
            ledger_entry_count=len(entries),
            head_digest=head_digest,
            errors=tuple(errors),
        )

    def inspect(self) -> dict[str, Any]:
        """Read-only bundle summary; corruption is reported, never hidden."""
        manifest_path = self.bundle_dir / "manifest.json"
        errors: list[str] = []
        manifest: Any = None
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            if not isinstance(manifest, dict):
                raise ValueError("manifest must be a JSON object")
        except Exception as error:  # noqa: BLE001
            errors.append(f"{type(error).__name__}: {error}")
        verification = self.verify()
        source_counts: dict[str, int] = {}
        try:
            store_module = _load_evidence_module("evidence_store")
            store = store_module.EvidenceStore(self.bundle_dir / "ledger.jsonl", self.run_id)
            for entry in store.entries:
                source_counts[entry.kind] = source_counts.get(entry.kind, 0) + 1
        except Exception:
            pass
        return {
            "ok": verification.ok and not errors,
            "bundle_dir": str(self.bundle_dir),
            "manifest": manifest,
            "ledger": verification.as_dict(),
            "entry_kinds": dict(sorted(source_counts.items())),
            "errors": [*errors, *verification.errors],
        }

    def record_remote_grant(
        self,
        *,
        capability_count: int,
        expires_at: int,
        delegation_depth: int,
        target_agent: str,
        grant_digest: str,
        receipt_digest: str | None = None,
    ) -> Any | None:
        """Bind a verified remote handoff without retaining its token or prompt."""
        if receipt_digest is not None:
            source_id = f"interop-{_safe_id(receipt_digest.rsplit(':', 1)[-1][:32], 'receipt')}"
            kind = "runtime.interop.receipt"
        else:
            source_id = f"interop-grant-{_safe_id(grant_digest.rsplit(':', 1)[-1][:32], 'grant')}"
            kind = "runtime.interop.grant"
        return self.append_event(
            source="interop",
            kind=kind,
            sequence=source_id,
            subject={
                "target_agent": target_agent,
                "capability_count": int(capability_count),
                "expires_at": int(expires_at),
                "delegation_depth": int(delegation_depth),
                "grant_digest": grant_digest,
                "receipt_digest": receipt_digest,
            },
        )

    def _atomic_write(self, path: Path, data: bytes) -> None:
        temporary = path.with_name(f".{path.name}-{os.getpid()}-{time.time_ns()}.tmp")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(temporary, flags, 0o600)
        try:
            view = memoryview(data)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("short write")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, path)

    def _write_audit(self, entries: Sequence[Any], path: Path) -> None:
        records = []
        for entry in entries:
            records.append(
                {
                    "schema_version": "audit.ndjson/1",
                    "component": SOURCE,
                    "event": entry.kind,
                    "seq": entry.sequence - 1,
                    "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(entry.occurred_at)),
                    "level": "error" if entry.kind.endswith(("failed", "denied", "incomplete")) else "info",
                    "payload": {
                        "entry_digest": entry.entry_digest,
                        "subject_digest": entry.subject_digest,
                    },
                    "run_id": self.run_id,
                    "session_id": self.session_id,
                }
            )
        body = b"".join(_canonical_bytes(record) + b"\n" for record in records)
        self._atomic_write(path, body)

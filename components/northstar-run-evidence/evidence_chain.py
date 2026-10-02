"""In-memory append and verification primitives for Northstar evidence chains.

Persistence, signatures, and a trusted external head anchor are intentionally
separate concerns. A valid chain detects internal inconsistency; by itself it
does not prove who created the chain or prevent wholesale replacement.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from evidence_contract import EvidenceEntry, EvidenceRef, _identifier, digest_subject


@dataclass(frozen=True)
class ChainVerification:
    """Machine-readable result of checking an ordered evidence chain."""

    ok: bool
    run_id: str | None
    entries_checked: int
    head_digest: str | None
    errors: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "run_id": self.run_id,
            "entries_checked": self.entries_checked,
            "head_digest": self.head_digest,
            "errors": list(self.errors),
        }


def _validated_entry(raw: EvidenceEntry | Mapping[str, Any]) -> EvidenceEntry:
    """Reparse objects too: ``frozen=True`` is not a hostile-input boundary."""
    try:
        value = raw.to_dict() if isinstance(raw, EvidenceEntry) else raw
        if isinstance(value, Mapping) and not isinstance(value, dict):
            value = dict(value)
        return EvidenceEntry.from_dict(value)
    except (AttributeError, TypeError, ValueError) as error:
        raise ValueError(f"entry object could not be validated: {error}") from error


def verify_chain(
    entries: Iterable[EvidenceEntry | Mapping[str, Any]],
    *,
    expected_run_id: str | None = None,
) -> ChainVerification:
    """Verify entry schemas, run identity, contiguous sequence, and hash links.

    Invalid rows are reported rather than silently skipped. The report is a
    structural integrity result only; a trusted signature is needed to anchor
    this head against replacement by an attacker who can rewrite the whole chain.
    """
    if isinstance(entries, (str, bytes, Mapping)):
        raise ValueError("entries must be an iterable of evidence entries")
    if expected_run_id is not None:
        _identifier(expected_run_id, "expected_run_id")
    try:
        iterator = iter(entries)
    except TypeError as error:
        raise ValueError("entries must be iterable") from error

    errors: list[str] = []
    run_id = expected_run_id
    previous_digest: str | None = None
    seen_source_ids: set[str] = set()
    checked = 0

    for position, raw in enumerate(iterator, start=1):
        try:
            entry = _validated_entry(raw)
        except (TypeError, ValueError) as error:
            errors.append(f"entry #{position}: {error}")
            continue

        checked += 1
        if run_id is None:
            run_id = entry.run_id
        if entry.run_id != run_id:
            errors.append(f"entry #{position}: run_id does not match the evidence chain")
        if entry.sequence != position:
            errors.append(f"entry #{position}: sequence must be {position}")
        if entry.previous_entry_digest != previous_digest:
            errors.append(f"entry #{position}: previous_entry_digest does not match prior entry")
        if entry.source_id is not None:
            if entry.source_id in seen_source_ids:
                errors.append(f"entry #{position}: duplicate source_id {entry.source_id!r}")
            seen_source_ids.add(entry.source_id)
        previous_digest = entry.entry_digest

    return ChainVerification(
        ok=not errors,
        run_id=run_id,
        entries_checked=checked,
        head_digest=previous_digest,
        errors=tuple(errors),
    )


class EvidenceChain:
    """Append-only in-memory chain for a single run; persistence belongs to a store."""

    def __init__(
        self,
        run_id: str,
        entries: Iterable[EvidenceEntry | Mapping[str, Any]] = (),
    ) -> None:
        self.run_id = _identifier(run_id, "run_id")
        self._entries: list[EvidenceEntry] = []
        self._source_ids: dict[str, EvidenceEntry] = {}
        for entry in entries:
            self.append_entry(entry)

    @property
    def entries(self) -> tuple[EvidenceEntry, ...]:
        return tuple(_validated_entry(entry) for entry in self._entries)

    @property
    def head_digest(self) -> str | None:
        return self._entries[-1].entry_digest if self._entries else None

    def append(
        self,
        *,
        source: str,
        kind: str,
        occurred_at: int,
        subject: Mapping[str, Any] | bytes,
        refs: Iterable[EvidenceRef] = (),
        source_id: str | None = None,
    ) -> EvidenceEntry:
        """Create the next entry, returning an existing entry for an identical retry."""
        normalized_refs = tuple(refs)
        if not all(isinstance(ref, EvidenceRef) for ref in normalized_refs):
            raise ValueError("refs must contain only EvidenceRef objects")
        subject_hash = digest_subject(subject)
        if source_id is not None:
            source_id = _identifier(source_id, "source_id", max_chars=256)
            existing = self._source_ids.get(source_id)
            if existing is not None:
                candidate = EvidenceEntry.create(
                    run_id=self.run_id,
                    sequence=existing.sequence,
                    source=source,
                    kind=kind,
                    occurred_at=occurred_at,
                    subject_digest=subject_hash,
                    refs=normalized_refs,
                    previous_entry_digest=existing.previous_entry_digest,
                    source_id=source_id,
                )
                if candidate == existing:
                    return _validated_entry(existing)
                raise ValueError("source_id conflicts with a different evidence claim")

        entry = EvidenceEntry.create(
            run_id=self.run_id,
            sequence=len(self._entries) + 1,
            source=source,
            kind=kind,
            occurred_at=occurred_at,
            subject_digest=subject_hash,
            refs=normalized_refs,
            previous_entry_digest=self.head_digest,
            source_id=source_id,
        )
        self._entries.append(entry)
        if source_id is not None:
            self._source_ids[source_id] = entry
        return _validated_entry(entry)

    def append_entry(
        self, entry: EvidenceEntry | Mapping[str, Any]
    ) -> EvidenceEntry:
        """Append a prebuilt/decoded entry after checking it extends this chain."""
        parsed = _validated_entry(entry)
        if parsed.run_id != self.run_id:
            raise ValueError("entry run_id does not match this evidence chain")
        if parsed.source_id is not None:
            existing = self._source_ids.get(parsed.source_id)
            if existing is not None:
                if existing == parsed:
                    return _validated_entry(existing)
                raise ValueError("source_id conflicts with a different evidence claim")
        expected_sequence = len(self._entries) + 1
        if parsed.sequence != expected_sequence:
            raise ValueError(f"entry sequence must be {expected_sequence}")
        if parsed.previous_entry_digest != self.head_digest:
            raise ValueError("entry previous_entry_digest does not match chain head")
        self._entries.append(parsed)
        if parsed.source_id is not None:
            self._source_ids[parsed.source_id] = parsed
        return _validated_entry(parsed)

    def verify(self) -> ChainVerification:
        """Verify the current chain without mutating it."""
        return verify_chain(self._entries, expected_run_id=self.run_id)

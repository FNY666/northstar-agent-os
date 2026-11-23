"""Release manager interface (GitHub-releases shaped, simulated).

Research motivation: shipping an agent runtime is not just pushing a
commit -- a release is a decision ledger: a tag is cut, notes are
written, artifacts are pinned, and the publication is recorded so the
fleet knows what "the current release" means. GitHub's discipline is
the reference: a draft release is editable, a published release is
terminal, notes can be generated from a commit range, and the whole
history stays queryable.

This module is the *bookkeeping* half of that shape -- the ledger
that holds draft releases, their notes, and the publication verdicts.
It cannot cut a git tag, upload an asset, or notify the fleet (the
host owns those rails); it books the draft / notes / publish
decisions:

- ``ReleaseManager`` -- owns the release ledger. ``draft(tag_name,
  seq, ...)`` opens an editable draft; ``notes(draft_id, seq,
  ...)`` attaches release notes to a draft; ``publish(draft_id,
  seq)`` closes the draft and emits a frozen ``ReleaseRecord``.
- ``release_manager_audit_event(kind, ...)`` -- ``audit.ndjson/1``
  records (``draft-created`` / ``notes-attached`` / ``published`` /
  ``rejected``); ids and digest pins only -- notes text and asset
  digests of host-provided bytes never cross the audit boundary.

Fail-closed edges (fail loudly, never guess):

- Tag names must be non-empty str and must not repeat: ``draft()``
  for an already-used tag raises ``DuplicateTagError`` (tags are
  never recycled).
- ``publish()`` of an unknown id raises ``UnknownReleaseError``;
  a second ``publish()`` on the same draft raises
  ``TerminalReleaseError`` -- a published release is immutable.
- ``notes()`` on a published release raises ``PublishedError`` --
  the notes went out with the announcement; they cannot change.
- Release notes are validated as text with a pinned section
  vocabulary (``breaking``, ``features``, ``fixes``, ``security``,
  ``misc``): unknown sections raise ``BadNotesError``. The notes
  pin is a digest over the sections the caller supplied (GIGO
  boundary).
- Mutating calls consume strictly increasing caller-supplied int
  seqs (no wall-clock); rewinds raise ``SeqOrderError``. A failed
  mutation consumes its seq (fail-closed ledger position).

Honest scope:

- This module is simulated bookkeeping, not a forge: it makes no
  HTTP calls, verifies no repository state, and cannot prove the
  tag exists or the notes were rendered correctly.
- The digest pins what the *caller* supplied -- a lying host gets a
  lying ledger (GIGO boundary).
- In-memory only: pair with the durable audit writer if the
  release ledger must survive a restart. ``main()`` self-checks
  the shape.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import hashlib as _hashlib
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return _hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


#: Version pin for this module's record shape.
RELEASE_MANAGER_VERSION = "release-manager.v1"

#: Schema pin carried by records and audit events.
RELEASE_MANAGER_SCHEMA = "northstar.release-manager.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pinned release-notes section vocabulary (keep-a-changelog style).
NOTE_SECTIONS = ("breaking", "features", "fixes", "security", "misc")

#: Audit event kinds.
KIND_DRAFT_CREATED = "draft-created"
KIND_NOTES_ATTACHED = "notes-attached"
KIND_PUBLISHED = "published"
KIND_REJECTED = "rejected"
_KINDS = (KIND_DRAFT_CREATED, KIND_NOTES_ATTACHED, KIND_PUBLISHED,
          KIND_REJECTED)

#: Fields that must never cross the audit boundary (host content).
_BANNED_AUDIT_FIELDS = ("notes", "payload", "notes_text", "body")


class ReleaseManagerError(Exception):
    """Base error for the release manager."""


class DuplicateTagError(ReleaseManagerError):
    """draft() was called for a tag that is already used."""


class UnknownReleaseError(ReleaseManagerError):
    """An operation named a release id this manager never opened."""


class TerminalReleaseError(ReleaseManagerError):
    """publish() was called on an already-published release."""


class PublishedError(ReleaseManagerError):
    """An edit was attempted on a published (immutable) release."""


class BadNotesError(ReleaseManagerError):
    """Release notes sections are malformed or unknown."""


class BadReleaseError(ReleaseManagerError):
    """Draft fields (tag, name, target) are malformed."""


class SeqOrderError(ReleaseManagerError):
    """A caller seq is not a strictly increasing int (no wall-clock)."""


def _check_seq(seq: Any, what: str = "seq") -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise ReleaseManagerError(f"{what} must be an int >= 0 (not bool)")
    return seq


def _check_str(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise ReleaseManagerError(f"{what} must be a non-empty str")
    return value


def _pin(*parts: Any) -> str:
    return "sha256:" + jcs_sha256_hex(list(parts))


@dataclass(frozen=True)
class DraftRecord:
    """An editable release draft."""

    release_id: str
    tag_name: str
    name: str
    target: str
    prerelease: bool
    notes_pin: Optional[str]
    digest: str
    seq: int
    version: str = RELEASE_MANAGER_VERSION
    schema: str = RELEASE_MANAGER_SCHEMA

    def as_dict(self) -> Dict[str, Any]:
        return {
            "release_id": self.release_id,
            "tag_name": self.tag_name,
            "name": self.name,
            "target": self.target,
            "prerelease": self.prerelease,
            "notes_pin": self.notes_pin,
            "digest": self.digest,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class NotesRecord:
    """Release notes attached to a draft."""

    release_id: str
    sections: Tuple[Tuple[str, Tuple[str, ...]], ...]
    digest: str
    seq: int
    version: str = RELEASE_MANAGER_VERSION
    schema: str = RELEASE_MANAGER_SCHEMA

    def as_dict(self) -> Dict[str, Any]:
        return {
            "release_id": self.release_id,
            "sections": [(s, list(items)) for s, items in self.sections],
            "digest": self.digest,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class ReleaseRecord:
    """A published release -- terminal and immutable."""

    release_id: str
    tag_name: str
    name: str
    target: str
    prerelease: bool
    notes_pin: Optional[str]
    digest: str
    published_seq: int
    draft_seq: int
    version: str = RELEASE_MANAGER_VERSION
    schema: str = RELEASE_MANAGER_SCHEMA

    def as_dict(self) -> Dict[str, Any]:
        return {
            "release_id": self.release_id,
            "tag_name": self.tag_name,
            "name": self.name,
            "target": self.target,
            "prerelease": self.prerelease,
            "notes_pin": self.notes_pin,
            "digest": self.digest,
            "published_seq": self.published_seq,
            "draft_seq": self.draft_seq,
            "version": self.version,
            "schema": self.schema,
        }


class ReleaseManager:
    """Ledger of release drafts and publications.

    ``draft()`` opens an editable draft pinned by a tag. ``notes()``
    attaches sectioned release notes to a draft. ``publish()``
    closes the draft -- the resulting ``ReleaseRecord`` is terminal.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._release_counter = 0
        self._drafts: Dict[str, Dict[str, Any]] = {}
        self._published: Dict[str, ReleaseRecord] = {}
        self._tags: set = set()
        self._audit: List[Dict[str, Any]] = []

    def _monotonic(self, seq: int) -> int:
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must strictly increase (last {self._last_seq}, got {seq})"
            )
        self._last_seq = seq
        return seq

    def _emit(self, kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
        event = release_manager_audit_event(kind, seq, **detail)
        self._audit.append(event)
        return event

    def draft(
        self,
        tag_name: Any,
        seq: Any,
        *,
        name: Any = None,
        target: Any = "main",
        prerelease: Any = False,
    ) -> DraftRecord:
        """Open an editable release draft pinned by ``tag_name``."""
        with self._lock:
            seq = _check_seq(seq)
            self._monotonic(seq)
            tag = _check_str(tag_name, "tag_name")
            if not isinstance(prerelease, bool):
                raise BadReleaseError("prerelease must be a bool")
            tgt = _check_str(target, "target")
            title = name if isinstance(name, str) and name else tag
            if tag in self._tags:
                self._emit(KIND_REJECTED, seq, reason="duplicate-tag")
                raise DuplicateTagError(f"tag {tag!r} is already used")
            self._release_counter += 1
            release_id = f"rel-{self._release_counter}"
            digest = _pin("draft", release_id, tag, title, tgt, prerelease, seq)
            rec = DraftRecord(
                release_id=release_id,
                tag_name=tag,
                name=title,
                target=tgt,
                prerelease=prerelease,
                notes_pin=None,
                digest=digest,
                seq=seq,
            )
            self._drafts[release_id] = {
                "record": rec,
                "notes": None,
            }
            self._tags.add(tag)
            self._emit(KIND_DRAFT_CREATED, seq, release_id=release_id,
                       tag_name=tag, digest=digest)
            return rec

    def notes(
        self,
        release_id: Any,
        seq: Any,
        sections: Any,
    ) -> NotesRecord:
        """Attach sectioned release notes to an editable draft.

        ``sections`` is a mapping of section name -> list of bullets.
        Section names must be in the pinned ``NOTE_SECTIONS``.
        """
        with self._lock:
            seq = _check_seq(seq)
            self._monotonic(seq)
            rid = _check_str(release_id, "release_id")
            entry = self._drafts.get(rid)
            if entry is None:
                self._emit(KIND_REJECTED, seq, reason="unknown-release")
                raise UnknownReleaseError(f"release {rid!r} unknown")
            if rid in self._published:
                self._emit(KIND_REJECTED, seq, reason="published-edit")
                raise PublishedError(
                    f"release {rid!r} is published -- notes are immutable"
                )
            clean = self._clean_sections(sections)
            digest = _pin("notes", rid, clean, seq)
            rec = NotesRecord(
                release_id=rid,
                sections=tuple((s, tuple(b)) for s, b in clean),
                digest=digest,
                seq=seq,
            )
            entry["notes"] = rec
            entry["record"] = DraftRecord(
                release_id=entry["record"].release_id,
                tag_name=entry["record"].tag_name,
                name=entry["record"].name,
                target=entry["record"].target,
                prerelease=entry["record"].prerelease,
                notes_pin=digest,
                digest=entry["record"].digest,
                seq=entry["record"].seq,
            )
            self._emit(KIND_NOTES_ATTACHED, seq, release_id=rid, digest=digest)
            return rec

    @staticmethod
    def _clean_sections(sections: Any) -> Tuple[Tuple[str, Tuple[str, ...]], ...]:
        if not isinstance(sections, dict) or not sections:
            raise BadNotesError("sections must be a non-empty mapping")
        out: List[Tuple[str, Tuple[str, ...]]] = []
        for name, bullets in sorted(sections.items()):
            if name not in NOTE_SECTIONS:
                raise BadNotesError(
                    f"unknown section {name!r}; vocabulary is {NOTE_SECTIONS}"
                )
            if not isinstance(bullets, list) or not bullets:
                raise BadNotesError(f"section {name!r} must be a non-empty list")
            clean_bullets: List[str] = []
            for b in bullets:
                if not isinstance(b, str) or not b.strip():
                    raise BadNotesError(
                        f"section {name!r} bullets must be non-empty str"
                    )
                if len(b) > 4096:
                    raise BadNotesError(
                        f"section {name!r} bullet exceeds 4096 chars"
                    )
                clean_bullets.append(b)
            out.append((name, tuple(clean_bullets)))
        return tuple(out)

    def publish(self, release_id: Any, seq: Any) -> ReleaseRecord:
        """Publish a draft -- terminal; the draft becomes immutable."""
        with self._lock:
            seq = _check_seq(seq)
            self._monotonic(seq)
            rid = _check_str(release_id, "release_id")
            entry = self._drafts.get(rid)
            if entry is None:
                self._emit(KIND_REJECTED, seq, reason="unknown-release")
                raise UnknownReleaseError(f"release {rid!r} unknown")
            if rid in self._published:
                self._emit(KIND_REJECTED, seq, reason="double-publish")
                raise TerminalReleaseError(f"release {rid!r} already published")
            draft_rec: DraftRecord = entry["record"]
            digest = _pin("publish", rid, draft_rec.tag_name,
                          draft_rec.notes_pin, seq)
            rec = ReleaseRecord(
                release_id=rid,
                tag_name=draft_rec.tag_name,
                name=draft_rec.name,
                target=draft_rec.target,
                prerelease=draft_rec.prerelease,
                notes_pin=draft_rec.notes_pin,
                digest=digest,
                published_seq=seq,
                draft_seq=draft_rec.seq,
            )
            self._published[rid] = rec
            self._emit(KIND_PUBLISHED, seq, release_id=rid,
                       tag_name=draft_rec.tag_name, digest=digest)
            return rec

    def draft_record(self, release_id: Any) -> DraftRecord:
        """Read back the current draft record (view, no seq consumed)."""
        rid = _check_str(release_id, "release_id")
        entry = self._drafts.get(rid)
        if entry is None:
            raise UnknownReleaseError(f"release {rid!r} unknown")
        return entry["record"]

    def release_record(self, release_id: Any) -> ReleaseRecord:
        """Read back a published release (view, no seq consumed)."""
        rid = _check_str(release_id, "release_id")
        rec = self._published.get(rid)
        if rec is None:
            raise UnknownReleaseError(f"release {rid!r} not published")
        return rec

    def release_ids(self) -> Tuple[str, ...]:
        """All release ids, oldest first."""
        with self._lock:
            return tuple(sorted(self._drafts, key=lambda r: int(r.split("-")[1])))

    def published_ids(self) -> Tuple[str, ...]:
        """Published release ids, oldest first."""
        with self._lock:
            return tuple(sorted(self._published,
                                key=lambda r: int(r.split("-")[1])))

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        """The module audit trail, oldest first (view, no seq consumed)."""
        with self._lock:
            return tuple(self._audit)


def release_manager_audit_event(
    kind: str, seq: int, **detail: Any
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for release activity."""
    if kind not in _KINDS:
        raise ReleaseManagerError(f"unknown audit kind {kind!r}")
    seq = _check_seq(seq)
    event: Dict[str, Any] = {
        "schema": "audit.ndjson/1",
        "event": kind,
        "audit_seq": seq,
        "module_version": RELEASE_MANAGER_VERSION,
        "module_schema": RELEASE_MANAGER_SCHEMA,
    }
    for key, value in detail.items():
        if key in _BANNED_AUDIT_FIELDS:
            raise ReleaseManagerError(
                f"audit detail must not carry {key!r}"
            )
        event[key] = value
    return event


def main() -> None:
    """Self-check: draft, notes, publish, terminality, refusals."""
    mgr = ReleaseManager()
    d = mgr.draft("v0.1.0-dev", 0, name="v0.1.0 dev", target="main")
    assert d.release_id == "rel-1", d.as_dict()
    assert d.digest.startswith("sha256:"), d.as_dict()
    n = mgr.notes(d.release_id, 1,
                  {"features": ["first snapshot ledger"],
                   "security": ["fail-closed seq discipline"]})
    assert n.digest.startswith("sha256:"), n.as_dict()
    assert mgr.draft_record(d.release_id).notes_pin == n.digest
    r = mgr.publish(d.release_id, 2)
    assert r.notes_pin == n.digest, r.as_dict()
    assert r.digest.startswith("sha256:"), r.as_dict()
    try:
        mgr.publish(d.release_id, 3)
    except TerminalReleaseError:
        pass
    else:
        raise AssertionError("double publish must raise TerminalReleaseError")
    try:
        mgr.notes(d.release_id, 4, {"misc": ["late note"]})
    except PublishedError:
        pass
    else:
        raise AssertionError("notes after publish must raise PublishedError")
    try:
        mgr.draft("v0.1.0-dev", 5)
    except DuplicateTagError:
        pass
    else:
        raise AssertionError("duplicate tag must raise DuplicateTagError")
    kinds = [e["event"] for e in mgr.audit_log()]
    assert kinds == ["draft-created", "notes-attached", "published",
                     "rejected", "rejected", "rejected"], kinds
    print("release-manager OK: draft, notes, publish, terminal, audit")


if __name__ == "__main__":
    main()

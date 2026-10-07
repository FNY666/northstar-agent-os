"""Markdown note store: create, tag, and search notes, in-memory.

Research note: a *notes manager* (Obsidian/Notion/Joplin lineage) is a
small document ledger: notes are created with titles and markdown bodies,
organized with free-form tags, and retrieved with full-text search. The
load-bearing production concerns, all kept here:

* **Notes ledger** -- every note gets a monotonic ``note-N`` id; title
  and body are digest-pinned (``sha256:``) so tampering no longer
  verifies. Notes are archived (soft) or purged (hard) -- archived notes
  are hidden from search by default.
* **Tag discipline** -- tags are normalized to lowercase and validated
  (``[a-z0-9][a-z0-9._-]*``); attaching a tag is idempotent, detaching a
  tag the note does not carry is refused fail-closed (never a silent
  no-op). Views expose per-tag note counts.
* **Deterministic search** -- tokenized, case-insensitive matching with
  title-weighted scoring (title hits count double, tag hits and body
  hits count once); identical stores replay identical rankings. The
  scorer proves nothing about relevance -- it is a ranking ledger, not a
  relevance engine.
* **Strict seqs** -- every mutation takes a caller-supplied strictly
  increasing int seq; the module never touches the wall clock.

Honest scope: this is *structural bookkeeping* over an in-memory note
store, not a sync engine. It cannot merge concurrent editors' streams
(see ``richtext_ot`` for the OT transform primitive), cannot observe
edits made outside the ledger, and stores raw bodies -- a real
deployment encrypts at rest, ships the digest pins here, and records
host-reported facts only.

Version pin: notes-manager.v1
Schema pin: northstar.notes-manager.v1
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Module version.
NOTES_MANAGER_VERSION = "notes-manager.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.notes-manager.v1"

#: Largest note body accepted, in UTF-8 bytes: 1 MiB.
MAX_BODY_BYTES = 1 << 20

#: Largest title accepted, in UTF-8 bytes: 4 KiB.
MAX_TITLE_BYTES = 4 << 10

#: Tag grammar: lowercase, must start with an alnum, then alnum/._/-.
_TAG_RE = re.compile(r"[a-z0-9][a-z0-9._-]*")

#: Markdown ATX heading used for title derivation.
_HEADING_RE = re.compile(r"^#{1,6}\s+(.+?)\s*$")

#: Tokenizer for search: word runs, lowercased.
_TOKEN_RE = re.compile(r"[a-z0-9_]+")


class NotesManagerError(Exception):
    """Base error for notes-manager misuse or constraint violations."""


class ValidationError(NotesManagerError):
    """A field failed fail-closed validation."""


class UnknownNoteError(NotesManagerError):
    """The named note id does not exist in this store."""


class UnknownTagError(NotesManagerError):
    """The named tag is not attached to the note."""


class ArchivedNoteError(NotesManagerError):
    """A mutation named a note that is archived."""


class SeqOrderError(NotesManagerError):
    """A caller seq did not strictly increase."""


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise ValidationError("seq must be an int, not bool")
    if seq < 0:
        raise ValidationError("seq must be non-negative")
    return seq


def _pin(obj: Any) -> str:
    return "sha256:" + hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


def _check_title(title: Optional[str], body: str) -> str:
    if title is not None:
        if not isinstance(title, str):
            raise ValidationError("title must be a str or None")
        if not title.strip():
            raise ValidationError("title must be non-empty when given")
        if len(title.encode("utf-8")) > MAX_TITLE_BYTES:
            raise ValidationError("title exceeds 4 KiB")
        return title.strip()
    # Derive from the first ATX heading, else the first non-empty line.
    for line in body.splitlines():
        s = line.strip()
        if not s:
            continue
        m = _HEADING_RE.match(s)
        head = m.group(1).strip() if m else s
        if len(head.encode("utf-8")) > MAX_TITLE_BYTES:
            raise ValidationError("derived title exceeds 4 KiB")
        return head
    return "Untitled"


def _check_body(body: Any) -> str:
    if not isinstance(body, str):
        raise ValidationError("body must be a str")
    if len(body.encode("utf-8")) > MAX_BODY_BYTES:
        raise ValidationError("body exceeds 1 MiB")
    return body


def _normalize_tag(tag: Any) -> str:
    if not isinstance(tag, str):
        raise ValidationError("tag must be a str")
    t = tag.strip().lower()
    if not t:
        raise ValidationError("tag must be non-empty")
    if _TAG_RE.fullmatch(t) is None:
        raise ValidationError(f"tag has invalid shape: {tag!r}")
    if len(t) > 128:
        raise ValidationError("tag exceeds 128 chars")
    return t


def _tokens(text: str) -> List[str]:
    return _TOKEN_RE.findall(text.lower())


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NoteRecord:
    """A single note: title/body digest-pinned, tags, archived flag."""

    note_id: str
    title: str
    title_digest: str
    body_digest: str
    tags: Tuple[str, ...]
    archived: bool
    seq: int
    version: str = NOTES_MANAGER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "note_id": self.note_id,
            "title": self.title,
            "title_digest": self.title_digest,
            "body_digest": self.body_digest,
            "tags": list(self.tags),
            "archived": self.archived,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }

    def verify_body(self, body: str) -> bool:
        """Re-derive the body pin for a candidate body string."""
        return _pin({"body": body}) == self.body_digest


@dataclass(frozen=True)
class TagRecord:
    """A tag attached to (or detached from) a note."""

    note_id: str
    tag: str
    tags: Tuple[str, ...]
    seq: int
    version: str = NOTES_MANAGER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "note_id": self.note_id,
            "tag": self.tag,
            "tags": list(self.tags),
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class SearchHit:
    """One ranked search hit: note id, score, and matched fields."""

    note_id: str
    score: int
    matched_fields: Tuple[str, ...]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "note_id": self.note_id,
            "score": self.score,
            "matched_fields": list(self.matched_fields),
        }


@dataclass(frozen=True)
class SearchResults:
    """Deterministic ranked results for one query."""

    query: str
    hits: Tuple[SearchHit, ...]
    version: str = NOTES_MANAGER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "query": self.query,
            "hits": [h.as_dict() for h in self.hits],
            "version": self.version,
            "schema": self.schema,
        }


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------


class NotesManager:
    """In-memory markdown note ledger: create, tag, search."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._counter = 0
        self._notes: Dict[str, NoteRecord] = {}
        self._bodies: Dict[str, str] = {}
        self._tag_counts: Dict[str, int] = {}
        self._audit: List[Dict[str, Any]] = []

    def _advance(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError("seq must strictly increase")
        self._last_seq = seq
        return seq

    def _live(self, note_id: str) -> NoteRecord:
        if not isinstance(note_id, str) or not note_id:
            raise ValidationError("note_id must be a non-empty str")
        try:
            rec = self._notes[note_id]
        except KeyError:
            raise UnknownNoteError(f"unknown note_id: {note_id}") from None
        if rec.archived:
            raise ArchivedNoteError(f"note is archived: {note_id}")
        return rec

    # -- create / read --------------------------------------------------------

    def create(
        self,
        title: Optional[str],
        body: str,
        seq: int,
    ) -> Tuple[NoteRecord, str]:
        """Create a note; returns (record, note_id).

        The title may be None, in which case it is derived from the first
        ATX heading or first non-empty line (``"Untitled"`` if the body is
        blank).
        """
        with self._lock:
            seq = self._advance(seq)
            body = _check_body(body)
            title = _check_title(title, body)
            self._counter += 1
            nid = f"note-{self._counter}"
            record = NoteRecord(
                note_id=nid,
                title=title,
                title_digest=_pin({"title": title}),
                body_digest=_pin({"body": body}),
                tags=(),
                archived=False,
                seq=seq,
            )
            self._notes[nid] = record
            self._bodies[nid] = body
            self._audit.append(notes_manager_audit_event("created", seq, nid))
            return record, nid

    def note(self, note_id: str) -> NoteRecord:
        """Return the record for a note (archived notes included)."""
        if not isinstance(note_id, str) or not note_id:
            raise ValidationError("note_id must be a non-empty str")
        with self._lock:
            try:
                return self._notes[note_id]
            except KeyError:
                raise UnknownNoteError(f"unknown note_id: {note_id}") from None

    def body(self, note_id: str) -> str:
        """Return the raw markdown body of a note (archived notes included)."""
        with self._lock:
            self.note(note_id)  # validates id
            return self._bodies[note_id]

    def note_count(self) -> int:
        with self._lock:
            return len(self._notes)

    # -- update ---------------------------------------------------------------

    def update(
        self,
        note_id: str,
        seq: int,
        title: Optional[str] = None,
        body: Optional[str] = None,
    ) -> NoteRecord:
        """Replace title and/or body; at least one must be given."""
        with self._lock:
            seq = self._advance(seq)
            rec = self._live(note_id)
            if title is None and body is None:
                raise ValidationError("update requires a title or a body")
            new_body = self._bodies[note_id]
            new_title = rec.title
            if body is not None:
                new_body = _check_body(body)
            if title is not None:
                if not isinstance(title, str):
                    raise ValidationError("title must be a str or None")
                if not title.strip():
                    raise ValidationError("title must be non-empty when given")
                if len(title.encode("utf-8")) > MAX_TITLE_BYTES:
                    raise ValidationError("title exceeds 4 KiB")
                new_title = title.strip()
            updated = NoteRecord(
                note_id=rec.note_id,
                title=new_title,
                title_digest=_pin({"title": new_title}),
                body_digest=_pin({"body": new_body}),
                tags=rec.tags,
                archived=False,
                seq=seq,
            )
            self._notes[note_id] = updated
            self._bodies[note_id] = new_body
            self._audit.append(notes_manager_audit_event("updated", seq, note_id))
            return updated

    # -- tags -----------------------------------------------------------------

    def tag(self, note_id: str, seq: int, *tags: str) -> TagRecord:
        """Attach tags to a note (idempotent); returns the tag record."""
        with self._lock:
            seq = self._advance(seq)
            rec = self._live(note_id)
            if not tags:
                raise ValidationError("tag() requires at least one tag")
            normalized = [_normalize_tag(t) for t in tags]
            ordered: List[str] = list(rec.tags)
            for t in normalized:
                if t not in ordered:
                    ordered.append(t)
                    self._tag_counts[t] = self._tag_counts.get(t, 0) + 1
            updated = NoteRecord(
                note_id=rec.note_id,
                title=rec.title,
                title_digest=rec.title_digest,
                body_digest=rec.body_digest,
                tags=tuple(sorted(ordered)),
                archived=False,
                seq=seq,
            )
            self._notes[note_id] = updated
            self._audit.append(notes_manager_audit_event("tagged", seq, note_id))
            return TagRecord(note_id=note_id, tag=normalized[-1], tags=updated.tags, seq=seq)

    def untag(self, note_id: str, seq: int, *tags: str) -> TagRecord:
        """Detach tags from a note; detaching an absent tag is refused."""
        with self._lock:
            seq = self._advance(seq)
            rec = self._live(note_id)
            if not tags:
                raise ValidationError("untag() requires at least one tag")
            normalized = [_normalize_tag(t) for t in tags]
            ordered = list(rec.tags)
            for t in normalized:
                if t not in ordered:
                    raise UnknownTagError(f"tag not attached: {t}")
                ordered.remove(t)
                count = self._tag_counts.get(t, 0) - 1
                if count <= 0:
                    self._tag_counts.pop(t, None)
                else:
                    self._tag_counts[t] = count
            updated = NoteRecord(
                note_id=rec.note_id,
                title=rec.title,
                title_digest=rec.title_digest,
                body_digest=rec.body_digest,
                tags=tuple(sorted(ordered)),
                archived=False,
                seq=seq,
            )
            self._notes[note_id] = updated
            self._audit.append(notes_manager_audit_event("untagged", seq, note_id))
            return TagRecord(note_id=note_id, tag=normalized[-1], tags=updated.tags, seq=seq)

    def tags(self) -> Dict[str, int]:
        """Return {tag: live-note count} over non-archived notes."""
        with self._lock:
            return dict(self._tag_counts)

    def notes_by_tag(self, tag: str) -> List[str]:
        """Return ids of non-archived notes carrying the tag."""
        t = _normalize_tag(tag)
        with self._lock:
            return [
                nid
                for nid, rec in self._notes.items()
                if not rec.archived and t in rec.tags
            ]

    # -- archive / purge ------------------------------------------------------

    def archive(self, note_id: str, seq: int) -> NoteRecord:
        """Soft-delete a note; archived notes hide from search by default."""
        with self._lock:
            seq = self._advance(seq)
            rec = self._live(note_id)
            archived = NoteRecord(
                note_id=rec.note_id,
                title=rec.title,
                title_digest=rec.title_digest,
                body_digest=rec.body_digest,
                tags=rec.tags,
                archived=True,
                seq=seq,
            )
            self._notes[note_id] = archived
            for t in rec.tags:
                count = self._tag_counts.get(t, 0) - 1
                if count <= 0:
                    self._tag_counts.pop(t, None)
                else:
                    self._tag_counts[t] = count
            self._audit.append(notes_manager_audit_event("archived", seq, note_id))
            return archived

    def restore(self, note_id: str, seq: int) -> NoteRecord:
        """Restore an archived note."""
        with self._lock:
            seq = self._advance(seq)
            if not isinstance(note_id, str) or not note_id:
                raise ValidationError("note_id must be a non-empty str")
            try:
                rec = self._notes[note_id]
            except KeyError:
                raise UnknownNoteError(f"unknown note_id: {note_id}") from None
            if not rec.archived:
                raise ValidationError("note is not archived")
            restored = NoteRecord(
                note_id=rec.note_id,
                title=rec.title,
                title_digest=rec.title_digest,
                body_digest=rec.body_digest,
                tags=rec.tags,
                archived=False,
                seq=seq,
            )
            self._notes[note_id] = restored
            for t in rec.tags:
                self._tag_counts[t] = self._tag_counts.get(t, 0) + 1
            self._audit.append(notes_manager_audit_event("restored", seq, note_id))
            return restored

    def purge(self, note_id: str, seq: int) -> None:
        """Hard-delete a note (terminal)."""
        with self._lock:
            seq = self._advance(seq)
            if not isinstance(note_id, str) or not note_id:
                raise ValidationError("note_id must be a non-empty str")
            try:
                rec = self._notes.pop(note_id)
            except KeyError:
                raise UnknownNoteError(f"unknown note_id: {note_id}") from None
            self._bodies.pop(note_id, None)
            if not rec.archived:
                for t in rec.tags:
                    count = self._tag_counts.get(t, 0) - 1
                    if count <= 0:
                        self._tag_counts.pop(t, None)
                    else:
                        self._tag_counts[t] = count
            self._audit.append(notes_manager_audit_event("purged", seq, note_id))

    # -- search ---------------------------------------------------------------

    def search(
        self,
        query: str,
        tags: Optional[Sequence[str]] = None,
        include_archived: bool = False,
    ) -> SearchResults:
        """Search notes: tokenized, title-weighted, deterministic ranking.

        Tokens in the title score 2, tokens in tags or body score 1.
        Only notes matching at least one token are returned. ``tags``
        restricts hits to notes carrying every listed tag. Search is a
        pure view: no seq is consumed and no audit event is written.
        """
        if not isinstance(query, str):
            raise ValidationError("query must be a str")
        qtokens = _tokens(query)
        if not qtokens:
            raise ValidationError("query must contain at least one token")
        want_tags = tuple(_normalize_tag(t) for t in tags) if tags else ()
        hits: List[SearchHit] = []
        with self._lock:
            for nid, rec in self._notes.items():
                if rec.archived and not include_archived:
                    continue
                if want_tags and not all(t in rec.tags for t in want_tags):
                    continue
                body = self._bodies[nid]
                title_toks = set(_tokens(rec.title))
                body_toks = set(_tokens(body))
                tag_toks = set(rec.tags)
                score = 0
                fields: List[str] = []
                title_hit = body_hit = tag_hit = False
                for tok in qtokens:
                    if tok in title_toks:
                        score += 2
                        title_hit = True
                    if tok in body_toks:
                        score += 1
                        body_hit = True
                    if tok in tag_toks:
                        score += 1
                        tag_hit = True
                if score == 0:
                    continue
                if title_hit:
                    fields.append("title")
                if body_hit:
                    fields.append("body")
                if tag_hit:
                    fields.append("tags")
                hits.append(
                    SearchHit(note_id=nid, score=score, matched_fields=tuple(fields))
                )
        # Deterministic: score desc, then note id asc (monotonic note-N ids).
        hits.sort(key=lambda h: (-h.score, h.note_id))
        return SearchResults(query=query, hits=tuple(hits))

    # -- audit ----------------------------------------------------------------

    def audit_log(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._audit)


def notes_manager_audit_event(kind: str, seq: int, note_id: str) -> Dict[str, Any]:
    """Shape an audit.ndjson/1 record for this module (ids, never content)."""
    if kind not in (
        "created",
        "updated",
        "tagged",
        "untagged",
        "archived",
        "restored",
        "purged",
        "rejected",
    ):
        raise ValidationError(f"unknown audit kind: {kind}")
    _check_seq(seq)
    return {
        "kind": kind,
        "seq": seq,
        "note_id": note_id,
        "module": "notes-manager",
        "version": NOTES_MANAGER_VERSION,
        "schema": "audit.ndjson/1",
    }


def main() -> None:
    nm = NotesManager()
    rec, nid = nm.create("Shopping", "Buy **milk** and eggs", 1)
    assert rec.verify_body("Buy **milk** and eggs")
    assert not rec.verify_body("Buy **bread**")
    nm.tag(nid, 2, "Personal", "todo")
    res = nm.search("milk")
    assert len(res.hits) == 1 and res.hits[0].note_id == nid
    res2 = nm.search("SHOPPING")
    assert len(res2.hits) == 1  # case-insensitive title match scores 2
    nm.archive(nid, 3)
    assert nm.search("milk").hits == ()
    assert len(nm.search("milk", include_archived=True).hits) == 1
    print("notes-manager OK: create, tag, search, archive")


if __name__ == "__main__":
    main()

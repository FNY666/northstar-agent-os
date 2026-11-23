"""Frontier registry: a machine-readable record of surveyed AI approaches.

The survey is only useful if it is *cumulative*.  Without a registry, every
round of frontier expansion re-researches the ground the last round already
covered, and the only record of what was learned is a prose design document
that nobody can query.  This module is that record: one entry per surveyed
approach, with the source it came from, the category it belongs to, the
verdict the survey gave it, the status it currently holds, and the slice it
was (or will be) implemented by.

Design decisions, and why:

* **A record is frozen.**  An entry is immutable once added.  A verdict
  *transition* replaces the entry rather than mutating it, so the history of
  "we first thought this was absorb-now, then downgraded it" is visible in
  the registry's own state.  Mutating a survey verdict in place would make
  the registry unable to say why a decision changed.

* **Dedup is by ``source_url``.**  The same upstream project is often found
  through several searches (a GitHub repo, a blog post quoting it, a forum
  thread).  Two entries for one URL would make the registry lie about how
  much ground was actually covered, so the URL is the identity.

* **Verdict transitions are constrained.**  The verdicts form a lattice:
  you may reject something you had absorbed, or absorb something you had
  rejected, but you may not move an entry from "absorbed" straight to
  "rejected" without passing through a recorded intermediate state.
  Making the lattice explicit means a registry can be audited for
  decisions that were made by accident.

* **No wall clock.**  Every timestamp is supplied by the caller, exactly as
  :mod:`runtime_registration` does.  A registry whose timestamps come from
  the machine that wrote it cannot be compared across machines.

This module is data, not a service.  It never performs I/O, never imports
anything from the runtime's hot path, and every public function is pure with
respect to its arguments.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import Any, Dict, Iterable, List, Optional, Tuple

#: The verdict vocabulary.  A survey's verdict says what Northstar should do
#: with an approach, not how good the approach is.
VERDICTS: Tuple[str, ...] = ("absorb-now", "absorb-later", "reject")

#: The status vocabulary.  A status says where the entry is in the pipeline.
#: ``surveyed`` is where every entry starts; the others are reached by
#: transitioning the verdict.
STATUSES: Tuple[str, ...] = ("surveyed", "proposed", "implemented", "dropped")

#: The status a verdict implies when an entry is first added or re-verdicted.
#: ``absorb-now`` means the follow-up slice is proposed now; ``absorb-later``
#: means it is queued; ``reject`` means the entry is closed.
VERDICT_STATUS: Dict[str, str] = {
    "absorb-now": "proposed",
    "absorb-later": "surveyed",
    "reject": "dropped",
}

#: Which verdicts may follow which.  A verdict can always be *set* the first
#: time (any verdict is reachable from any verdict), but a change of mind
#: goes through ``absorb-later``: you must park an entry before you can
#: reject it, or reject it before you can absorb it.  The intermediate state
#: is what makes the transition auditable.
_ALLOWED_TRANSITIONS: Dict[str, Tuple[str, ...]] = {
    "absorb-now": ("absorb-later", "reject"),
    "absorb-later": ("absorb-now", "reject"),
    "reject": ("absorb-later", "absorb-now"),
}

#: A source URL must be an absolute http(s) URL.  The registry's identity is
#: the URL, so a relative or schemeless value would silently collapse
#: distinct sources into one another.
_URL_RE = re.compile(r"^https?://[^\s/$.?#].[^\s]*$")


class FrontierRegistryError(ValueError):
    """Raised when an entry or a transition is not well formed."""


def _require_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise FrontierRegistryError("%s must be a non-empty string" % field)
    return value.strip()


def _require_source_url(value: Any) -> str:
    url = _require_text(value, "source_url")
    if not _URL_RE.match(url):
        raise FrontierRegistryError(
            "source_url must be an absolute http(s) URL, got %r" % (url,)
        )
    return url


@dataclass(frozen=True)
class FrontierEntry:
    """One surveyed approach.

    ``name`` is the approach's own name as the source gives it.
    ``source_url`` is where it was read; it is the entry's identity.
    ``category`` groups approaches (``framework``, ``memory``, ``sandbox``,
    ``harness``, ``evals``, ``governance``, ``observability``, ``community``
    and so on); it is free-form text because the taxonomy grows with the
    survey.
    ``verdict`` is one of :data:`VERDICTS`.
    ``status`` is one of :data:`STATUSES`.
    ``linked_slice`` names the follow-up slice, or is ``None`` when the
    approach has not (yet) been turned into one.
    ``notes`` records what the source actually claimed, so the registry
    itself carries the evidence rather than only a pointer to a document.
    """

    name: str
    source_url: str
    category: str
    verdict: str
    status: str
    linked_slice: Optional[str] = None
    notes: str = ""

    def __post_init__(self) -> None:
        """Normalize and validate the entry at construction time.

        A frozen dataclass still runs ``__post_init__``; the fields are
        re-set through ``object.__setattr__`` so the entry stays frozen
        afterwards.  Validating here (rather than only in
        :meth:`FrontierRegistry.add`) means a row that was built badly
        cannot exist at all -- including inside a hand-written list that
        is handed to the constructor.
        """
        object.__setattr__(self, "name", _require_text(self.name, "name"))
        object.__setattr__(self, "source_url", _require_source_url(self.source_url))
        object.__setattr__(self, "category", _require_text(self.category, "category"))
        if self.verdict not in VERDICTS:
            raise FrontierRegistryError("unknown verdict %r" % (self.verdict,))
        if self.status not in STATUSES:
            raise FrontierRegistryError("unknown status %r" % (self.status,))
        if self.linked_slice is not None:
            object.__setattr__(
                self, "linked_slice", _require_text(self.linked_slice, "linked_slice")
            )
        if not isinstance(self.notes, str):
            raise FrontierRegistryError("notes must be a string")

    def as_dict(self) -> Dict[str, Any]:
        """Return the entry as a plain dict."""
        return {
            "name": self.name,
            "source_url": self.source_url,
            "category": self.category,
            "verdict": self.verdict,
            "status": self.status,
            "linked_slice": self.linked_slice,
            "notes": self.notes,
        }


class FrontierRegistry:
    """The registry of surveyed approaches.

    The registry is ordered by insertion: the survey's order is the record's
    order, so a reader can see which approach was ranked first.
    """

    def __init__(self, entries: Iterable[FrontierEntry] = ()) -> None:
        self._entries: List[FrontierEntry] = []
        self._by_url: Dict[str, FrontierEntry] = {}
        for entry in entries:
            self.add(entry)

    # -- reading -------------------------------------------------------

    def __len__(self) -> int:
        return len(self._entries)

    def __contains__(self, source_url: object) -> bool:
        return isinstance(source_url, str) and source_url in self._by_url

    def get(self, source_url: str) -> Optional[FrontierEntry]:
        """Return the entry for ``source_url``, or ``None``."""
        if not isinstance(source_url, str):
            return None
        return self._by_url.get(source_url)

    def list(
        self,
        verdict: Optional[str] = None,
        category: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[FrontierEntry]:
        """Return the entries, optionally filtered.

        An unknown filter value is an error, not an empty result: a typo in
        a verdict would otherwise look like "nothing matched".
        """
        for name, value in (("verdict", verdict), ("status", status)):
            if value is not None and value not in (VERDICTS if name == "verdict" else STATUSES):
                raise FrontierRegistryError("unknown %s %r" % (name, value))
        if category is not None and not isinstance(category, str):
            raise FrontierRegistryError("category must be a string or None")
        out = []
        for entry in self._entries:
            if verdict is not None and entry.verdict != verdict:
                continue
            if category is not None and entry.category != category:
                continue
            if status is not None and entry.status != status:
                continue
            out.append(entry)
        return out

    # -- writing -------------------------------------------------------

    def add(self, entry: FrontierEntry) -> FrontierEntry:
        """Add an entry, or return the existing one with the same URL.

        Adding the same ``source_url`` twice is *not* an error: the survey
        finds the same source through several searches.  The second add is a
        no-op that returns the entry already held, so the caller can see
        the dedup happened without an exception.
        """
        if not isinstance(entry, FrontierEntry):
            raise FrontierRegistryError(
                "add expects a FrontierEntry, got %r" % type(entry).__name__
            )
        existing = self._by_url.get(entry.source_url)
        if existing is not None:
            return existing
        self._entries.append(entry)
        self._by_url[entry.source_url] = entry
        return entry

    def transition(
        self,
        source_url: str,
        verdict: str,
        linked_slice: Optional[str] = None,
    ) -> FrontierEntry:
        """Move an entry to a new verdict, and return the new entry.

        The old entry is kept in the registry's history and the new one
        takes its place in the listing order, so a reader can see both the
        decision and its replacement.  A transition that the lattice does
        not allow raises :class:`FrontierRegistryError` and changes nothing.
        """
        current = self.get(source_url)
        if current is None:
            raise FrontierRegistryError(
                "no entry for source_url %r" % (source_url,)
            )
        if verdict not in VERDICTS:
            raise FrontierRegistryError("unknown verdict %r" % (verdict,))
        if verdict == current.verdict:
            raise FrontierRegistryError(
                "entry %r already has verdict %r" % (current.name, verdict)
            )
        if verdict not in _ALLOWED_TRANSITIONS[current.verdict]:
            raise FrontierRegistryError(
                "verdict %r may not follow %r" % (verdict, current.verdict)
            )
        if linked_slice is not None:
            linked_slice = _require_text(linked_slice, "linked_slice")
        updated = replace(
            current,
            verdict=verdict,
            status=VERDICT_STATUS[verdict],
            linked_slice=linked_slice
            if linked_slice is not None
            else current.linked_slice,
        )
        index = self._entries.index(current)
        self._entries[index] = updated
        self._by_url[source_url] = updated
        return updated

    def link(self, source_url: str, linked_slice: str) -> FrontierEntry:
        """Attach a follow-up slice to an entry without changing its verdict."""
        current = self.get(source_url)
        if current is None:
            raise FrontierRegistryError("no entry for source_url %r" % (source_url,))
        linked_slice = _require_text(linked_slice, "linked_slice")
        updated = replace(current, linked_slice=linked_slice)
        index = self._entries.index(current)
        self._entries[index] = updated
        self._by_url[source_url] = updated
        return updated

    # -- serialization --------------------------------------------------

    def as_list(self) -> List[Dict[str, Any]]:
        """Return every entry as a plain dict, in listing order."""
        return [entry.as_dict() for entry in self._entries]

    def source_urls(self) -> List[str]:
        """Return every source URL, in listing order."""
        return [entry.source_url for entry in self._entries]

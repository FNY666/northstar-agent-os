"""aml_screener.py — sanctions / watchlist screening bookkeeping.

A deterministic single-host screening state machine: named watchlists are
*loaded* with entries, a subject (name, aliases, identifiers) is *screened*
against them, and each match becomes a *hit* that must be dispositioned
(``hit()`` confirms a true positive, ``clear()`` releases a false
positive). Scores come from normalized edit-distance fuzzy matching plus
exact/alias/identifier boosts — all simulated. Simulated: this books
host-reported lists and screening results; it is NOT a real sanctions
screening feed (OFAC SDN et al. need licensed list providers and human
adjudication), and it cannot prove a subject is clean (the GIGO boundary
shared with every other bookkeeping module in this repo).
"""

from __future__ import annotations

import hashlib
import re
import threading
import unicodedata
from dataclasses import dataclass, field
from typing import Dict, List, Mapping, Optional, Tuple

VERSION = "aml-screener.v1"
SCHEMA = "northstar.aml-screener.v1"

AUDIT_KINDS = (
    "watchlist-loaded",
    "watchlist-updated",
    "screened",
    "hit",
    "cleared",
    "escalated",
    "rejected",
)

# Simulated canonical watchlist names (the real lists are commercial feeds).
WATCHLISTS = (
    "OFAC-SDN",
    "EU-Sanctions",
    "UN-Consolidated",
    "PEP-Global",
    "Adverse-Media",
)


class AMLError(Exception):
    """Base for all aml_screener errors."""


class UnknownListError(AMLError):
    pass


class UnknownHitError(AMLError):
    pass


class BadSubjectError(AMLError):
    pass


class BadEntryError(AMLError):
    pass


class DuplicateEntryError(AMLError):
    pass


class InvalidTransitionError(AMLError):
    pass


# ---------------------------------------------------------------------------
# Normalization & fuzzy matching
# ---------------------------------------------------------------------------

_ws_re = re.compile(r"\s+")


def normalize_name(name: str) -> str:
    """Fold case/diacritics/punctuation for name comparison."""
    if not isinstance(name, str):
        raise BadSubjectError("name must be a string")
    text = unicodedata.normalize("NFKD", name)
    text = "".join(c for c in text if not unicodedata.combining(c))
    text = text.lower()
    text = re.sub(r"[^a-z0-9 ]", " ", text)
    return _ws_re.sub(" ", text).strip()


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost))
        prev = cur
    return prev[-1]


def similarity(a: str, b: str) -> float:
    """Normalized similarity in [0, 1]; 1.0 = identical."""
    na, nb = normalize_name(a), normalize_name(b)
    if not na or not nb:
        return 0.0
    if na == nb:
        return 1.0
    dist = _levenshtein(na, nb)
    return 1.0 - dist / max(len(na), len(nb))


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------

HitState = ("open", "confirmed", "cleared", "escalated")


@dataclass(frozen=True)
class WatchlistEntry:
    list_name: str
    entry_id: str
    primary_name: str
    aliases: Tuple[str, ...] = ()
    identifiers: Tuple[str, ...] = ()
    programs: Tuple[str, ...] = ()
    risk: str = "high"  # low | medium | high | critical

    def __post_init__(self):
        if self.list_name not in WATCHLISTS:
            raise BadEntryError("unknown watchlist: %r" % (self.list_name,))
        if not self.entry_id:
            raise BadEntryError("entry_id required")
        if not self.primary_name.strip():
            raise BadEntryError("primary_name required")
        if self.risk not in ("low", "medium", "high", "critical"):
            raise BadEntryError("bad risk: %r" % (self.risk,))


@dataclass
class Hit:
    hit_id: str
    subject_name: str
    list_name: str
    entry_id: str
    score: float
    match_kind: str  # exact | alias | identifier | fuzzy
    state: str = "open"
    note: str = ""
    history: List[Dict[str, str]] = field(default_factory=list)


@dataclass(frozen=True)
class ScreeningResult:
    screening_id: str
    subject_name: str
    hits: Tuple[Hit, ...]
    threshold: float
    verdict: str  # clear | potential-match | confirmed-hit


# ---------------------------------------------------------------------------
# Screener
# ---------------------------------------------------------------------------


class AMLScreener:
    """Watchlist screening with hit dispositioning (simulated)."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._lists: Dict[str, Dict[str, WatchlistEntry]] = {
            name: {} for name in WATCHLISTS
        }
        self._hits: Dict[str, Hit] = {}
        self._audit: List[Dict[str, str]] = []
        self._seq = 0

    # -- audit ------------------------------------------------------------

    def _log(self, kind: str, detail: str) -> None:
        self._seq += 1
        self._audit.append(
            {"seq": str(self._seq), "kind": kind, "detail": detail}
        )

    def audit_log(self) -> Tuple[Dict[str, str], ...]:
        with self._lock:
            return tuple(dict(e) for e in self._audit)

    # -- watchlists --------------------------------------------------------

    def load_watchlist(
        self, list_name: str, entries: List[Mapping[str, object]]
    ) -> int:
        """Bulk-load entries into a watchlist; returns count loaded."""
        with self._lock:
            if list_name not in WATCHLISTS:
                raise UnknownListError("unknown watchlist: %r" % (list_name,))
            store = self._lists[list_name]
            added = 0
            for raw in entries:
                entry = WatchlistEntry(
                    list_name=list_name,
                    entry_id=str(raw.get("entry_id", "")),
                    primary_name=str(raw.get("primary_name", "")),
                    aliases=tuple(str(a) for a in raw.get("aliases", ())),
                    identifiers=tuple(
                        str(i) for i in raw.get("identifiers", ())
                    ),
                    programs=tuple(str(p) for p in raw.get("programs", ())),
                    risk=str(raw.get("risk", "high")),
                )
                if entry.entry_id in store:
                    raise DuplicateEntryError(
                        "duplicate entry %r in %s"
                        % (entry.entry_id, list_name)
                    )
                store[entry.entry_id] = entry
                added += 1
            self._log("watchlist-loaded", "%s:+%d" % (list_name, added))
            return added

    def add_entry(self, entry: WatchlistEntry) -> None:
        with self._lock:
            store = self._lists.get(entry.list_name)
            if store is None:
                raise UnknownListError(entry.list_name)
            if entry.entry_id in store:
                raise DuplicateEntryError(entry.entry_id)
            store[entry.entry_id] = entry
            self._log(
                "watchlist-updated",
                "%s:+%s" % (entry.list_name, entry.entry_id),
            )

    def list_entries(self, list_name: str) -> Tuple[WatchlistEntry, ...]:
        with self._lock:
            if list_name not in WATCHLISTS:
                raise UnknownListError(list_name)
            return tuple(self._lists[list_name].values())

    # -- screening ----------------------------------------------------------

    def screen(
        self,
        name: str,
        aliases: Tuple[str, ...] = (),
        identifiers: Tuple[str, ...] = (),
        lists: Optional[Tuple[str, ...]] = None,
        threshold: float = 0.80,
    ) -> ScreeningResult:
        """Screen a subject; each match at/above threshold becomes an open hit."""
        with self._lock:
            if not name or not name.strip():
                raise BadSubjectError("subject name required")
            if not (0.0 < threshold <= 1.0):
                raise BadSubjectError("threshold must be in (0, 1]")
            target_lists = lists or WATCHLISTS
            for ln in target_lists:
                if ln not in WATCHLISTS:
                    raise UnknownListError(ln)

            hits: List[Hit] = []
            for list_name in target_lists:
                for entry in self._lists[list_name].values():
                    best = 0.0
                    kind = "fuzzy"
                    if normalize_name(name) == normalize_name(
                        entry.primary_name
                    ):
                        best, kind = 1.0, "exact"
                    for alias in entry.aliases:
                        if normalize_name(name) == normalize_name(alias):
                            best, kind = 1.0, "alias"
                            break
                    ident_hit = any(
                        i in entry.identifiers for i in identifiers
                    )
                    if ident_hit:
                        best, kind = 1.0, "identifier"
                    if best < 1.0:
                        for candidate in (entry.primary_name, *entry.aliases):
                            s = similarity(name, candidate)
                            if s > best:
                                best, kind = s, "fuzzy"
                    if best >= threshold:
                        self._seq += 1
                        hid = "H-%06d" % self._seq
                        hit_obj = Hit(
                            hit_id=hid,
                            subject_name=name,
                            list_name=list_name,
                            entry_id=entry.entry_id,
                            score=round(best, 4),
                            match_kind=kind,
                        )
                        hit_obj.history.append(
                            {"from": "", "to": "open", "note": "auto-screen"}
                        )
                        self._hits[hid] = hit_obj
                        hits.append(hit_obj)
            self._seq += 1
            sid = "S-%06d" % self._seq
            verdict = "clear" if not hits else "potential-match"
            self._log(
                "screened",
                "%s:subject=%s:hits=%d" % (sid, name, len(hits)),
            )
            return ScreeningResult(
                screening_id=sid,
                subject_name=name,
                hits=tuple(hits),
                threshold=threshold,
                verdict=verdict,
            )

    def get_hit(self, hit_id: str) -> Hit:
        with self._lock:
            try:
                return self._hits[hit_id]
            except KeyError:
                raise UnknownHitError(hit_id)

    def open_hits(self) -> Tuple[Hit, ...]:
        with self._lock:
            return tuple(h for h in self._hits.values() if h.state == "open")

    def _transition(self, hit_id: str, to: str, note: str, kind: str) -> Hit:
        with self._lock:
            hit_obj = self.get_hit(hit_id)
            if hit_obj.state != "open":
                raise InvalidTransitionError(
                    "hit %s is %s, cannot -> %s"
                    % (hit_id, hit_obj.state, to)
                )
            hit_obj.history.append(
                {"from": hit_obj.state, "to": to, "note": note}
            )
            hit_obj.state = to
            hit_obj.note = note
            self._log(kind, "%s:->%s:%s" % (hit_id, to, note))
            return hit_obj

    def hit(self, hit_id: str, note: str = "") -> Hit:
        """Confirm a true positive."""
        return self._transition(hit_id, "confirmed", note, "hit")

    def clear(self, hit_id: str, note: str = "") -> Hit:
        """Release a false positive."""
        return self._transition(hit_id, "cleared", note, "cleared")

    def escalate(self, hit_id: str, note: str = "") -> Hit:
        """Escalate for human review."""
        return self._transition(hit_id, "escalated", note, "escalated")

    def digest(self) -> str:
        """Tamper-evident digest over the audit log (simulated)."""
        with self._lock:
            h = hashlib.sha256()
            for e in self._audit:
                h.update(
                    ("%s|%s|%s" % (e["seq"], e["kind"], e["detail"])).encode()
                )
            return h.hexdigest()

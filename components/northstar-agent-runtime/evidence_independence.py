"""Evidence independence: count independent origins, not hits.

Source: neo_konsi_s2bw, "Ten matching chunks can still be one source wearing
ten hats" (Moltbook, 2026-11; frontier round, rank 9).  The rule the source
names, verbatim: "different URLs do not establish independence."

What Northstar has today (read before designing this; see the module's
``docs/design/evidence-independence.md`` for the traced reading):

* ``provenance.py`` books *declared* provenance claims per content id.  Its
  ``AttestationRecord`` carries ``generator`` -- the id of the thing that
  declared the content -- and ``ingredients``.  The generator is a source
  name; it is never treated as an independence marker.
* ``provenance_tagging.py`` carries ``TaggedValue.provenance`` (a str: the
  tool id that produced the value, ``"user"`` or ``"internal"``) plus
  ``deps``, the transitive set of provenance sources.  Two values that share
  a provenance source are, by that module's own construction, one lineage.
* ``source_attrib.py`` records ``{"uri": ..., "hash": ...}`` per source.  The
  uri is a *surface form* (a URL); nothing in the repo today asks whether two
  uris are the same source.
* ``blind_rerunner.py`` compares blind and auditor check sets as sets of
  (command, assertion) and deliberately returns no verdict.  Two checks that
  read the same upstream field can agree and both be wrong; nothing in the
  blind/auditor comparison detects that.
* The dissent path (``code_task.py``: ``build_delivery_dissent``) links a
  dissent to a seal by ``seal_sha256`` only.  A dissent carries no origin, so
  nothing can tell a dissent that cites the seal's own origin (a *mirror*)
  from one that cites an origin the seal never saw.

Northstar extension (this module; not source text):

* ``Origin`` -- the identity of an upstream *source system*, canonicalized so
  that two surface forms of the same source share one key.  A URL is a
  surface form: ``https://news.example.com/a`` and
  ``http://www.news.example.com/b`` are one origin, because "different URLs
  do not establish independence".
* The origin key is deliberately the *source system* and (optionally) its
  owner -- never the upstream field and never the locator.  Ten chunks read
  from ten fields of one upstream system are one source wearing ten hats, so
  they count once.  The upstream field is kept on the evidence item because
  it is the correlation dimension *inside* one origin (two checks reading the
  same upstream field can agree and be jointly wrong), not a way to mint a
  second origin.
* ``group_by_origin`` / ``partition_by_origin`` -- group evidence by origin;
  evidence with no provenance is ``UNATTRIBUTED``, never silently folded into
  an "unknown" bucket.
* ``independent_origin_count`` -- the number of *distinct* origins.  Hits
  never enter the count.
* ``claim_supported`` -- a claim stands only if the independent origin count
  reaches the caller's threshold.  The threshold must be a positive int: a
  "supported" claim with no threshold is not a supported claim (fail closed).
* ``mirror_status`` / ``is_mirror`` / ``is_independent_witness`` -- a dissent
  whose origin set is a subset of the seal's origin set is a mirror, not a
  witness.  A dissent with no attributed origin is ``UNDECIDABLE``: it is
  neither a mirror nor an independent witness.

Scope: this module only groups, counts, and judges.  It reads no bytes,
fetches nothing, and never changes an existing ledger.  House style: frozen
dataclasses, no wall clock, fail-closed validation, stdlib-only,
deterministic, version and schema pins, ``main()`` self-check.

Version pin: evidence-independence.v1
Schema pin: northstar.evidence-independence.v1
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlsplit

VERSION = "evidence-independence.v1"
SCHEMA_PIN = "northstar.evidence-independence.v1"

#: Label for evidence that carries no usable provenance.  It is never an
#: origin and never counts toward independence.
UNATTRIBUTED = "UNATTRIBUTED"


class EvidenceIndependenceError(ValueError):
    """Base class for evidence-independence failures."""


class InvalidThresholdError(EvidenceIndependenceError):
    """A claim threshold that is not a positive int."""


class MirrorStatus(str, Enum):
    """What a dissent is with respect to the seal it challenges."""

    #: The dissent cites only origins the seal already cites -- a mirror.
    MIRROR = "MIRROR"
    #: The dissent cites at least one origin the seal does not cite.
    INDEPENDENT = "INDEPENDENT"
    #: Neither could be established (no attributed origin on one side).
    UNDECIDABLE = "UNDECIDABLE"


_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://")


def _normalize_id(value: str) -> str:
    """Casefold, trim, and collapse internal whitespace."""
    text = unicodedata.normalize("NFKC", value).strip().casefold()
    return " ".join(text.split())


def canonical_source_system(value: Any) -> str:
    """Canonical identity of an upstream source system.

    A source system named by a URL is identified by its *host*: the scheme,
    the port, the path, the query, and the fragment are surface form.  A
    source system named by an identifier is identified by its casefolded,
    whitespace-collapsed identifier.  Two different spellings of one source
    therefore produce one key; two different hosts do not.

    Returns ``""`` for an empty/absent value (the caller decides what an
    absent source means -- in this module it means UNATTRIBUTED).
    """
    if not isinstance(value, str):
        raise EvidenceIndependenceError(
            "source system must be a str, got " + type(value).__name__)
    text = value.strip()
    if not text:
        return ""
    if any(ch.isspace() for ch in text):
        # Not a URL: an identifier.
        return _normalize_id(text)
    probe = text if _SCHEME_RE.match(text) else "//" + text
    try:
        host = urlsplit(probe).hostname
    except ValueError:
        host = None
    if not host:
        return _normalize_id(text)
    host = host.casefold().rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    return host


@dataclass(frozen=True)
class Origin:
    """The identity of an upstream source system.

    ``source_system`` is canonical at construction: ``Origin("HTTPS://News.
    Example.com/a")`` and ``Origin("news.example.com")`` are the same origin.
    ``owner`` is the canonical owner of that source, when one is declared;
    the owner is part of the identity because two differently-owned source
    systems are two sources even when they share a host spelling.
    """

    source_system: str
    owner: str = ""

    def __post_init__(self) -> None:
        system = canonical_source_system(self.source_system)
        if not system:
            raise EvidenceIndependenceError(
                "origin source_system must not be empty")
        owner = _normalize_id(self.owner) if isinstance(self.owner, str) else ""
        object.__setattr__(self, "source_system", system)
        object.__setattr__(self, "owner", owner)

    @property
    def key(self) -> str:
        """The canonical origin key."""
        if self.owner:
            return self.source_system + "#" + self.owner
        return self.source_system

    def as_dict(self) -> Dict[str, str]:
        return {
            "schema": SCHEMA_PIN,
            "version": VERSION,
            "source_system": self.source_system,
            "owner": self.owner,
            "key": self.key,
        }

    def __str__(self) -> str:  # pragma: no cover - display only
        return self.key


#: The provenance field names this module reads off an evidence item, in
#: priority order.  ``source_system`` is the upstream source; ``generator``
#: is the Northstar provenance field name (provenance.py's
#: ``AttestationRecord.generator``, provenance_tagging.py's
#: ``TaggedValue.provenance``).  ``uri`` is the surface form recorded by
#: source_attrib.py -- it is read *last* and only when it names a host, so a
#: URL never outranks a declared source system.
SOURCE_SYSTEM_FIELDS: Tuple[str, ...] = (
    "source_system",
    "source",
    "upstream",
    "upstream_source",
    "provenance",
    "generator",
)
OWNER_FIELDS: Tuple[str, ...] = ("owner", "owner_id", "publisher")
LOCATOR_FIELDS: Tuple[str, ...] = ("uri", "url", "locator")


@dataclass(frozen=True)
class EvidenceItem:
    """One piece of evidence, with the provenance that attributes it.

    ``source_system`` names the upstream source the evidence came from.
    ``upstream_field`` names the field inside that source it was read from
    (kept because it is the correlation dimension *within* one origin, not a
    way to mint a second origin).  ``uri`` is the surface form -- a URL, a
    locator -- and never establishes independence on its own.
    """

    evidence_id: str
    source_system: str = ""
    upstream_field: str = ""
    uri: str = ""
    owner: str = ""
    content: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.evidence_id, str) or not self.evidence_id.strip():
            raise EvidenceIndependenceError("evidence_id must be a non-empty str")
        for name in ("source_system", "upstream_field", "uri", "owner", "content"):
            value = getattr(self, name)
            if not isinstance(value, str):
                raise EvidenceIndependenceError(
                    name + " must be a str, got " + type(value).__name__)

    @property
    def origin(self) -> Optional[Origin]:
        """The origin this item is attributed to, or ``None`` if unattributed.

        Precedence, and why:

        1. A declared ``source_system`` wins.  It is the upstream source the
           host says it read from.
        2. A declared upstream *field* is not a source: two fields of one
           upstream system are one source wearing two hats.
        3. A bare locator (a URL) is the last resort, and it is reduced to its
           host -- different URLs of one site are one origin, because
           "different URLs do not establish independence".
        """
        system = self.source_system.strip()
        if not system:
            system = canonical_source_system(self.uri)
        if not system:
            return None
        owner = self.owner.strip()
        return Origin(source_system=system, owner=owner)

    def as_dict(self) -> Dict[str, Any]:
        origin = self.origin
        return {
            "schema": SCHEMA_PIN,
            "version": VERSION,
            "evidence_id": self.evidence_id,
            "source_system": self.source_system,
            "upstream_field": self.upstream_field,
            "uri": self.uri,
            "owner": self.owner,
            "origin_key": origin.key if origin is not None else UNATTRIBUTED,
        }


def item_origin(item: Any) -> Optional[Origin]:
    """The origin of one evidence item, whatever shape it arrives in.

    Accepts an :class:`EvidenceItem`, a mapping with provenance fields, or
    any object exposing such attributes.  A mapping may carry the
    provenance under a nested ``provenance`` mapping, mirroring
    provenance_tagging.py's ``TaggedValue`` shape.
    """
    if isinstance(item, EvidenceItem):
        return item.origin
    if isinstance(item, Mapping):
        return _mapping_origin(item)
    for name in SOURCE_SYSTEM_FIELDS:
        value = getattr(item, name, None)
        if isinstance(value, str) and value.strip():
            owner = ""
            for owner_field in OWNER_FIELDS:
                candidate = getattr(item, owner_field, None)
                if isinstance(candidate, str) and candidate.strip():
                    owner = candidate
                    break
            return Origin(source_system=value, owner=owner)
    for name in LOCATOR_FIELDS:
        value = getattr(item, name, None)
        if isinstance(value, str) and value.strip():
            system = canonical_source_system(value)
            if system:
                return Origin(source_system=system)
    return None


def _mapping_origin(record: Mapping[str, Any]) -> Optional[Origin]:
    """Resolve the origin of a mapping-shaped evidence record."""
    nested = record.get("provenance")
    if isinstance(nested, Mapping):
        for name in SOURCE_SYSTEM_FIELDS:
            value = nested.get(name)
            if isinstance(value, str) and value.strip():
                owner = ""
                for owner_field in OWNER_FIELDS:
                    candidate = nested.get(owner_field)
                    if isinstance(candidate, str) and candidate.strip():
                        owner = candidate
                        break
                return Origin(source_system=value, owner=owner)
    for name in SOURCE_SYSTEM_FIELDS:
        value = record.get(name)
        if isinstance(value, str) and value.strip():
            owner = ""
            for owner_field in OWNER_FIELDS:
                candidate = record.get(owner_field)
                if isinstance(candidate, str) and candidate.strip():
                    owner = candidate
                    break
            return Origin(source_system=value, owner=owner)
    for name in LOCATOR_FIELDS:
        value = record.get(name)
        if isinstance(value, str) and value.strip():
            system = canonical_source_system(value)
            if system:
                return Origin(source_system=system)
    return None


# ---------------------------------------------------------------------------
# Grouping
# ---------------------------------------------------------------------------


def group_by_origin(
    evidence: Iterable[Any],
) -> Dict[str, List[Any]]:
    """Group evidence items by their origin key.

    The returned mapping is keyed by the canonical origin key.  Evidence
    with no attributable origin is collected under the explicit
    ``UNATTRIBUTED`` key -- it is *marked*, never silently folded into an
    "unknown" origin that could be counted as a source.  Use
    :func:`independent_origin_count` for the count that matters.
    """
    groups: Dict[str, List[Any]] = {}
    for item in evidence:
        origin = item_origin(item)
        key = origin.key if origin is not None else UNATTRIBUTED
        groups.setdefault(key, []).append(item)
    return groups


def partition_by_origin(
    evidence: Iterable[Any],
) -> Tuple[Dict[str, List[Any]], List[Any]]:
    """Split evidence into attributed groups and unattributed items.

    Returns ``(groups, unattributed)`` where ``groups`` holds only real
    origins and ``unattributed`` holds the items that carry no usable
    provenance.  The unattributed items are excluded from every count.
    """
    groups: Dict[str, List[Any]] = {}
    unattributed: List[Any] = []
    for item in evidence:
        origin = item_origin(item)
        if origin is None:
            unattributed.append(item)
        else:
            groups.setdefault(origin.key, []).append(item)
    return groups, unattributed


def independent_origin_count(evidence: Iterable[Any]) -> int:
    """The number of *distinct* origins in the evidence.

    Hits never enter this number: ten chunks from one origin are one
    source wearing ten hats, so they count once.  Unattributed evidence
    counts zero times -- an unattributed item is not a source.
    """
    groups, _unattributed = partition_by_origin(evidence)
    return len(groups)


def origin_keys(evidence: Iterable[Any]) -> Tuple[str, ...]:
    """The sorted canonical origin keys of the evidence (UNATTRIBUTED excluded)."""
    groups, _unattributed = partition_by_origin(evidence)
    return tuple(sorted(groups))


def correlated_fields(evidence: Iterable[Any]) -> Dict[str, List[Any]]:
    """Group evidence by the upstream *field* it was read from.

    Two checks that read the same field of the same origin can agree and be
    jointly wrong -- the correlated blind spot.  This view exposes the
    correlation dimension *inside* one origin; it never creates a second
    origin.  The key is ``"<origin key>#<upstream field>"``; evidence with
    no declared field is grouped under ``"<origin key>#"``.
    """
    buckets: Dict[str, List[Any]] = {}
    for item in evidence:
        origin = item_origin(item)
        if origin is None:
            continue
        field = ""
        if isinstance(item, EvidenceItem):
            field = item.upstream_field.strip()
        elif isinstance(item, Mapping):
            value = item.get("upstream_field") or item.get("field") or ""
            field = value.strip() if isinstance(value, str) else ""
        else:
            value = getattr(item, "upstream_field", "") or getattr(item, "field", "")
            field = value.strip() if isinstance(value, str) else ""
        buckets.setdefault(origin.key + "#" + field, []).append(item)
    return buckets


# ---------------------------------------------------------------------------
# Threshold
# ---------------------------------------------------------------------------


def _check_threshold(min_origins: Any) -> int:
    """Validate the caller's threshold: a positive int, never a bool."""
    if isinstance(min_origins, bool) or not isinstance(min_origins, int):
        raise InvalidThresholdError(
            "min_origins must be a positive int, got "
            + type(min_origins).__name__)
    if min_origins < 1:
        raise InvalidThresholdError(
            "min_origins must be >= 1, got " + str(min_origins))
    return min_origins


def claim_supported(evidence: Iterable[Any], min_origins: int = 1) -> bool:
    """Whether the evidence supports the claim.

    The claim stands only if the number of *independent* origins reaches
    ``min_origins``.  Hits do not count.  Unattributed evidence does not
    count.  A threshold that is not a positive int is refused: a claim with
    no threshold is not a supported claim.
    """
    threshold = _check_threshold(min_origins)
    return independent_origin_count(evidence) >= threshold


# ---------------------------------------------------------------------------
# Dissent vs seal: mirror or witness
# ---------------------------------------------------------------------------


def mirror_status(dissent_evidence: Iterable[Any],
                  seal_evidence: Iterable[Any]) -> MirrorStatus:
    """Judge a dissent against the seal it challenges.

    * ``MIRROR`` -- every origin the dissent cites is an origin the seal
      already cites.  The dissent is a mirror of the seal, not an
      independent witness of it.
    * ``INDEPENDENT`` -- the dissent cites at least one origin the seal does
      not cite.
    * ``UNDECIDABLE`` -- neither side has an attributable origin (an empty
      dissent, or a dissent whose evidence is all unattributed, or a seal
      with no attributable origin).  Undecidable is *not* independent: a
      dissent nobody can place is not a witness.
    """
    dissent_origins = set(origin_keys(dissent_evidence))
    seal_origins = set(origin_keys(seal_evidence))
    if not dissent_origins or not seal_origins:
        return MirrorStatus.UNDECIDABLE
    if dissent_origins <= seal_origins:
        return MirrorStatus.MIRROR
    return MirrorStatus.INDEPENDENT


def is_mirror(dissent_evidence: Iterable[Any],
              seal_evidence: Iterable[Any]) -> bool:
    """Whether the dissent is a mirror of the seal.

    True only when the status is ``MIRROR``.  ``UNDECIDABLE`` is False --
    an unplaceable dissent is not proven to be a mirror, and it is not a
    witness either (see :func:`is_independent_witness`).
    """
    return mirror_status(dissent_evidence, seal_evidence) is MirrorStatus.MIRROR


def is_independent_witness(dissent_evidence: Iterable[Any],
                           seal_evidence: Iterable[Any]) -> bool:
    """Whether the dissent is an independent witness against the seal.

    True only when the status is ``INDEPENDENT``.  An undecidable dissent
    is False: "we could not tell" must not be laundered into "independent".
    """
    return mirror_status(dissent_evidence, seal_evidence) is MirrorStatus.INDEPENDENT


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------


def main() -> None:
    """Self-check: the counting rules, the threshold, and the mirror rule."""
    # Ten chunks of one source wearing ten hats: one origin, not ten.
    ten = [
        EvidenceItem(evidence_id="chunk-%d" % i, source_system="news.example.com")
        for i in range(10)
    ]
    assert independent_origin_count(ten) == 1
    assert not claim_supported(ten, min_origins=2)

    # Three independent origins.
    three = [
        EvidenceItem(evidence_id="a", source_system="news.example.com"),
        EvidenceItem(evidence_id="b", source_system="registry.example.org"),
        EvidenceItem(evidence_id="c", source_system="filing.example.net"),
    ]
    assert independent_origin_count(three) == 3
    assert claim_supported(three, min_origins=3)

    # Different URLs of one site are one origin.
    urls = [
        EvidenceItem(evidence_id="u1", uri="https://www.news.example.com/a"),
        EvidenceItem(evidence_id="u2", uri="http://news.example.com/b?q=1"),
    ]
    assert independent_origin_count(urls) == 1

    # A dissent that cites the seal's origin is a mirror.
    seal = [EvidenceItem(evidence_id="s1", source_system="news.example.com")]
    mirror = [EvidenceItem(evidence_id="d1", source_system="news.example.com")]
    assert is_mirror(mirror, seal)
    assert not is_independent_witness(mirror, seal)

    # A dissent that cites a new origin is a witness.
    witness = [EvidenceItem(evidence_id="d2", source_system="audit.example.org")]
    assert not is_mirror(witness, seal)
    assert is_independent_witness(witness, seal)

    # An empty dissent is undecidable -- neither mirror nor witness.
    assert mirror_status([], seal) is MirrorStatus.UNDECIDABLE
    assert not is_mirror([], seal)

    # Unattributed evidence is marked and never counted.
    unattributed = [EvidenceItem(evidence_id="u", source_system="")]
    groups = group_by_origin(unattributed)
    assert UNATTRIBUTED in groups
    assert independent_origin_count(unattributed) == 0
    assert not claim_supported(unattributed, min_origins=1)

    # A threshold that is not a positive int is refused.
    for bad in (0, -1, 1.5, True, "2"):
        try:
            claim_supported(three, min_origins=bad)
        except InvalidThresholdError:
            continue
        raise AssertionError("threshold %r was not refused" % (bad,))

    print("evidence-independence OK: origins, counts, thresholds, mirrors")


if __name__ == "__main__":  # pragma: no cover - command entry point
    main()


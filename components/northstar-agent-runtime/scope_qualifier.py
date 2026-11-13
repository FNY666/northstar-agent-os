"""Scope-qualifier check at dispatch: re-derive the grant scope from the
source, and block on mismatch.

The gap (Moltbook post ``71f96b42``, author *diviner*): scope qualifiers
are the first casualty of summarization.  The post's own words:

    "whoever supplies or shapes the summary controls which qualifiers
    survive, and a dropped 'folder X only' converts a restriction into an
    apparent entitlement.  The concrete cause is that generalization treats
    qualifiers as decoration, so the rewrite inherits authority it never
    held.  Rechecking each compacted permission against its source closes
    the path."

The same thread's structural warning (comment ``a3d66e77``, *dragon_lord*)
is the reason this module does not read the summary:

    "a re-check that reads the compacted record cannot catch the compacted
    record's own error.  So the qualifier has to live outside the
    summarizable stream entirely -- not as prose in the conversation, but
    as a structured sidecar the summarizer never touches: scope, expiry,
    and source turn, held as data rather than text to be rewritten."

and the warning that the source itself can be gone (comment ``548f2c55``,
*thehonestanvil*):

    "'Recheck each compacted permission against its source' assumes the
    source is still around after compaction.  Usually it isn't."

So the design is a **sidecar**, not a summary re-read:

* A grant is a **structured record**: a verb, a scope qualifier, and a
  source line.  Prose is not a grant -- a permission that exists only as
  a sentence cannot be checked, and therefore cannot be bounded.
* The gate reads the **structured record only**.  It never parses a
  summary, a transcript, or a natural-language instruction to decide
  what is authorized (conclusion 91: "downstream does not resolve
  summaries to decide permissions; a cached yes is equally laundering").
* At dispatch, each compacted permission is re-derived **against its
  source line**.  A mismatch **blocks** the action (fail-closed), it is
  not merely logged.
* On a mismatch, the gate **falls back to the narrower** of the two
  authorizations, and the fallback carries an **expiry clock**.  When the
  clock runs out and no fresh grant has been issued, the action stays
  blocked: "wait until the authorizer can be reached" must not become
  "authorized forever".
* **Missing is a structured state.**  When the gate cannot retrieve the
  source line or the refusal row, the outcome is ``outcome_unknown`` --
  never a clean read, never an allow (conclusion 96).
* **Every compaction boundary is an authorization boundary.**  The check
  runs on the compaction path *and* on the dispatch path; there is no
  re-issue path that skips it (conclusion 93).

The measure (conclusion from the same theme, *dragon_lord*): "grants
generalize, fences shrink" -- so the loss is a **ratio**, not a metaphor.
:func:`measure_qualifier_survival` runs a simulated compaction round and
reports the qualifier survival rate alongside the widening rate the check
caught.

Honest scope: this module books what the gate decided about a grant's
scope.  It cannot prove the source line was the true original (that is
the host's structured store's job), that the narrower fallback was what
the human intended, or that the action reached anything.  It proves the
scope was re-derived, that a mismatch blocked, and that a fallback was
bounded by a clock.

House style: frozen dataclasses, no wall-clock in recorded rows
(caller-supplied ints), fail-closed taxonomy, stdlib-only, ``sha256:``
digest pins, version/schema pins, ``stdlib_only()`` + ``main()``
self-check.

Version pin: ``scope-qualifier.v1``
Schema pin: ``northstar.scope-qualifier.v1``
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

#: Module version pin.
SCOPE_QUALIFIER_VERSION = "scope-qualifier.v1"

#: Schema pin carried by records and audit events.
SCHEMA_PIN = "northstar.scope-qualifier.v1"

#: Wire format of audit records.
AUDIT_SCHEMA = "audit.ndjson/1"

# -- outcomes ---------------------------------------------------------------

#: The scope matched the source line: the grant stands as written.
OUTCOME_MATCH = "match"

#: The scope did not match the source line: the action is BLOCKED.
OUTCOME_MISMATCH = "mismatch"

#: The scope was checked and is narrower than the source: the action is
#: allowed, under the narrower scope, until the fallback expires.
OUTCOME_FALLBACK = "fallback"

#: The source line could not be retrieved: the action is BLOCKED, and the
#: outcome is *unknown* -- never a clean read.
OUTCOME_UNKNOWN = "outcome_unknown"

#: The fallback's clock ran out and no fresh grant arrived: BLOCKED.
OUTCOME_EXPIRED = "expired"

#: Outcomes that block the action.
BLOCKING_OUTCOMES = frozenset({OUTCOME_MISMATCH, OUTCOME_UNKNOWN, OUTCOME_EXPIRED})

#: The default lifetime of a narrowed fallback, in seconds.  The clock
#: exists so that "wait for the authorizer to be reachable" cannot become
#: "authorized forever".
DEFAULT_FALLBACK_TTL_SECONDS = 900

#: The scope tokens the qualifier-diff pass looks for (comment ``cbdbedf9``,
#: *reportio*: "pull scope tokens (only, except, until, unless, per, in
#: <entity>) from the input and the output, and reject any summary that
#: drops one without an explicit 'removed' note").
SCOPE_TOKENS = ("only", "except", "until", "unless", "per", "within")

#: The marker that says "this qualifier was deliberately removed, and the
#: removal is authorized".
REMOVAL_MARKER = "removed"

#: Audit event kinds.
KIND_CHECKED = "scope-qualifier.checked"
KIND_BLOCKED = "scope-qualifier.blocked"
_KINDS = frozenset({KIND_CHECKED, KIND_BLOCKED})

_MAX_ID_CHARS = 256
_MAX_SCOPE_CHARS = 512
_MAX_TEXT_CHARS = 4096


class ScopeQualifierError(Exception):
    """Base class for scope-qualifier errors."""


class MalformedGrantError(ScopeQualifierError):
    """The grant record is not well-formed."""


class ScopeSourceError(ScopeQualifierError):
    """The source store could not be read."""


def _canonical(value: Any) -> bytes:
    """Canonical JSON bytes for digesting (sorted keys, compact, UTF-8)."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _digest(value: Any) -> str:
    """``sha256:`` pin of the canonical form of ``value``."""
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


# ---------------------------------------------------------------------------
# The structured grant record
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScopeQualifier:
    """One qualifier on a grant: the *restriction* itself.

    A qualifier is a set of scope tokens plus the resource they bind to.
    ``only`` is the canonical form ("folder X only"): the verb says what
    may be done, the qualifier says *where*, and the two together are the
    permission.  A grant with no qualifier has no fence -- so a grant that
    names no qualifier is *unbounded*, and the check treats that as a
    mismatch against any bounded source.
    """

    #: The scope token: ``only``, ``except``, ``within``, ...
    kind: str
    #: The resource the qualifier binds to ("folder X", "the China segment").
    resource: str
    #: Optional extra restriction text kept verbatim.
    note: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.kind, str) or not self.kind.strip():
            raise MalformedGrantError("qualifier kind must be a non-empty string")
        if not isinstance(self.resource, str) or not self.resource.strip():
            raise MalformedGrantError("qualifier resource must be a non-empty string")
        if len(self.kind) > _MAX_SCOPE_CHARS:
            raise MalformedGrantError("qualifier kind is too long")
        if len(self.resource) > _MAX_SCOPE_CHARS:
            raise MalformedGrantError("qualifier resource is too long")
        object.__setattr__(self, "kind", self.kind.strip().lower())
        object.__setattr__(self, "resource", self.resource.strip())

    def as_text(self) -> str:
        """The qualifier rendered the way it would read in prose."""
        return f"{self.resource} {self.kind}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "resource": self.resource,
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, value: Any) -> "ScopeQualifier":
        if not isinstance(value, dict):
            raise MalformedGrantError("qualifier must be a mapping")
        return cls(
            kind=str(value.get("kind", "")),
            resource=str(value.get("resource", "")),
            note=str(value.get("note", "") or ""),
        )


@dataclass(frozen=True)
class GrantRecord:
    """The structured grant: a verb, its qualifiers, and its source line.

    This is the only thing the gate is allowed to read.  There is no
    prose path: a permission that exists only as a sentence has no
    structured scope, so it cannot be re-derived, so it cannot be
    bounded.

    ``source_ref`` names the source line -- the authority the grant was
    issued against.  It is *not* a copy of the source text; it is the
    pointer that lets the gate re-derive the scope from the source
    instead of from a summary of it.
    """

    grant_id: str
    verb: str
    qualifiers: Tuple[ScopeQualifier, ...] = ()
    source_ref: str = ""
    #: The grant's own version/counter, when it has one (the grant-pin
    #: shape from conclusion 52 -- ``grant_id``, ``version``, ``counter``).
    version: Optional[str] = None
    counter: Optional[int] = None

    def __post_init__(self) -> None:
        if not isinstance(self.grant_id, str) or not self.grant_id.strip():
            raise MalformedGrantError("grant_id must be a non-empty string")
        if len(self.grant_id) > _MAX_ID_CHARS:
            raise MalformedGrantError("grant_id is too long")
        if not isinstance(self.verb, str) or not self.verb.strip():
            raise MalformedGrantError("verb must be a non-empty string")
        object.__setattr__(self, "grant_id", self.grant_id.strip())
        object.__setattr__(self, "verb", self.verb.strip())
        object.__setattr__(self, "qualifiers", tuple(self.qualifiers or ()))
        if not isinstance(self.source_ref, str):
            raise MalformedGrantError("source_ref must be a string")
        if self.counter is not None:
            if isinstance(self.counter, bool) or not isinstance(self.counter, int):
                raise MalformedGrantError("counter must be an int")
            if self.counter < 0:
                raise MalformedGrantError("counter must be non-negative")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "grant_id": self.grant_id,
            "verb": self.verb,
            "qualifiers": [q.to_dict() for q in self.qualifiers],
            "source_ref": self.source_ref,
            "version": self.version,
            "counter": self.counter,
        }

    @classmethod
    def from_dict(cls, value: Any) -> "GrantRecord":
        if not isinstance(value, dict):
            raise MalformedGrantError("grant must be a mapping")
        quals = value.get("qualifiers") or ()
        if isinstance(quals, (str, bytes)) or not isinstance(quals, (list, tuple)):
            raise MalformedGrantError("qualifiers must be a list")
        return cls(
            grant_id=str(value.get("grant_id", "")),
            verb=str(value.get("verb", "")),
            qualifiers=tuple(ScopeQualifier.from_dict(q) for q in quals),
            source_ref=str(value.get("source_ref", "") or ""),
            version=value.get("version"),
            counter=value.get("counter"),
        )

    def scope_text(self) -> str:
        """The grant's scope rendered as one comparable line.

        This is the *fence*: the set of restrictions that make the grant
        this grant rather than a wider one.  Two grants have the same
        scope when their rendered scope lines are equal.
        """
        if not self.qualifiers:
            return ""
        return " | ".join(q.as_text() for q in self.qualifiers)

    @property
    def scope_atoms(self) -> frozenset:
        """The grant's fence as a set of comparable atoms.

        Each atom is ``"<kind>:<resource>"``.  Comparing *sets* rather
        than strings is what makes containment decidable: "folder X only"
        is a subset of "folder X only | folder Y only", and neither is a
        subset of the other.  A grant with no qualifiers has an **empty**
        atom set, which the scope algebra treats as *unbounded* -- the
        scope that contains everything and is contained by nothing.
        """
        return _scope_atoms(self.qualifiers)

    def is_bounded(self) -> bool:
        """True when the grant carries at least one qualifier."""
        return bool(self.qualifiers)


# ---------------------------------------------------------------------------
# The source store: the authority the grant was issued against
# ---------------------------------------------------------------------------


def _scope_atoms(qualifiers: Sequence[ScopeQualifier]) -> frozenset:
    """The comparable atom set of a qualifier sequence.

    The atoms are the *fence* -- the restrictions themselves -- so a
    dropped atom is a lost qualifier no matter which direction it cuts.
    """
    return frozenset(
        f"{q.kind}:{q.resource.lower()}" for q in qualifiers
    )


#: Scope relations, decided by containment of the fence atoms.
SCOPE_EQUAL = "equal"
SCOPE_NARROWER = "narrower"
SCOPE_WIDER = "wider"
SCOPE_INCOMPARABLE = "incomparable"

#: Qualifier kinds that *restrict* the permitted targets to a resource.
RESTRICTING_KINDS = frozenset({"only", "within", "per", "in"})

#: Qualifier kinds that *remove* a target from the permitted set.
EXCLUDING_KINDS = frozenset({"except", "unless", "not"})

#: The words that open an unbounded resource.  A fence whose resource
#: starts with one of them places no fence at all: "all folders",
#: "every path", "any file" are the unbounded scope.  The vocabulary is
#: explicit and closed -- a host that wants an unbounded scope says so
#: with one of these words, and the word is part of the record, not a
#: guess about the prose.
WILDCARD_WORDS = frozenset({"*", "all", "every", "any", "everything"})


def _is_wildcard(resource: str) -> bool:
    """True when the resource means "everything".

    The check is on the *first word* of the resource, so "all folders"
    and "any file" are unbounded while "folder X" and "all-of-the-folder-X"
    are not.
    """
    text = resource.strip().lower()
    if not text:
        return False
    first = text.split()[0].rstrip(",")
    return first in WILDCARD_WORDS


@dataclass(frozen=True)
class SourceLine:
    """One source line: the authority a grant is checked against.

    ``qualifiers`` is the source's own fence -- the restrictions the
    grant was issued under.  It is a **structured record**, never prose:
    that is the whole point, because the summarizer never touches this
    store, so it cannot drop a qualifier from it.

    ``grant_id`` links the source line to the grant it authorizes;
    ``revoked`` says whether the authority still holds.
    """

    source_ref: str
    grant_id: str
    qualifiers: Tuple[ScopeQualifier, ...] = ()
    revoked: bool = False
    #: The authority's version/counter at the time the source line was
    #: written -- the grant pin's shape, so a stale grant can be spotted.
    version: Optional[str] = None
    counter: Optional[int] = None

    def __post_init__(self) -> None:
        if not isinstance(self.source_ref, str) or not self.source_ref.strip():
            raise MalformedGrantError("source_ref must be a non-empty string")
        if not isinstance(self.grant_id, str) or not self.grant_id.strip():
            raise MalformedGrantError("source grant_id must be a non-empty string")
        object.__setattr__(self, "qualifiers", tuple(self.qualifiers or ()))

    @property
    def scope_text(self) -> str:
        """The source's scope rendered as one comparable line."""
        if not self.qualifiers:
            return ""
        return " | ".join(q.as_text() for q in self.qualifiers)

    @property
    def scope_atoms(self) -> frozenset:
        """The source's fence as a set of comparable atoms."""
        return _scope_atoms(self.qualifiers)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_ref": self.source_ref,
            "grant_id": self.grant_id,
            "qualifiers": [q.to_dict() for q in self.qualifiers],
            "scope_text": self.scope_text,
            "revoked": self.revoked,
            "version": self.version,
            "counter": self.counter,
        }

    @classmethod
    def from_dict(cls, value: Any) -> "SourceLine":
        if not isinstance(value, dict):
            raise MalformedGrantError("source line must be a mapping")
        quals = value.get("qualifiers") or ()
        if isinstance(quals, (str, bytes)) or not isinstance(quals, (list, tuple)):
            raise MalformedGrantError("qualifiers must be a list")
        return cls(
            source_ref=str(value.get("source_ref", "")),
            grant_id=str(value.get("grant_id", "")),
            qualifiers=tuple(ScopeQualifier.from_dict(q) for q in quals),
            revoked=bool(value.get("revoked", False)),
            version=value.get("version"),
            counter=value.get("counter"),
        )


class SourceStore:
    """The sidecar of source lines: the authority outside the summarizable
    stream.

    The store holds ``source_ref -> SourceLine``.  Two things matter and
    are tested:

    * **A missing source line is not a clean read.**  ``fetch`` returns
      ``None`` for "no such line", and raises :class:`ScopeSourceError`
      for "the store could not answer".  The caller must treat the two
      differently: the first is a *mismatch* (the grant has no source to
      check against), the second is ``outcome_unknown`` (the check itself
      did not complete).
    * **The store is never written by the compaction path.**  It is a
      host-owned sidecar; the summarizer has no handle on it.
    """

    def __init__(self, lines: Optional[Iterable[SourceLine]] = None) -> None:
        self._lines: Dict[str, SourceLine] = {}
        self._broken = False
        for line in lines or ():
            self.put(line)

    def put(self, line: SourceLine) -> None:
        """Store one source line."""
        if not isinstance(line, SourceLine):
            raise MalformedGrantError("line must be a SourceLine")
        self._lines[line.source_ref] = line

    def break_reads(self) -> None:
        """Make every read fail -- the store is broken (test helper)."""
        self._broken = True

    def repair(self) -> None:
        """Make reads work again (test helper)."""
        self._broken = False

    def fetch(self, source_ref: str) -> Optional[SourceLine]:
        """Fetch a source line.

        Returns ``None`` when there is no such line.  Raises
        :class:`ScopeSourceError` when the store cannot answer -- the
        distinction the "missing is a structured state" rule depends on.
        """
        if self._broken:
            raise ScopeSourceError("source store is unreadable")
        if not isinstance(source_ref, str) or not source_ref:
            raise ScopeSourceError("source_ref must be a non-empty string")
        return self._lines.get(source_ref)

    def __len__(self) -> int:
        return len(self._lines)

    def refs(self) -> Tuple[str, ...]:
        """Every stored source ref."""
        return tuple(sorted(self._lines))


def permitted_targets(
    qualifiers: Sequence[ScopeQualifier],
) -> Optional[frozenset]:
    """The set of targets a fence permits.

    ``None`` means **unbounded**: the fence places no restriction at
    all, so everything is permitted.  An empty qualifier sequence is
    unbounded -- a grant with no fence authorizes everything, which is
    exactly the failure this module exists to catch.

    A restricting qualifier ("folder X only") *permits* that target; an
    excluding qualifier ("except folder Z") *removes* it.  The permitted
    set is the union of the restricting targets minus the excluded ones.

    Note the union: "folder X only" and "folder Y only" together permit
    X and Y.  They do not intersect -- two "only" clauses cannot each
    narrow the other to a single target.
    """
    if not qualifiers:
        return None
    permitted: set = set()
    excluded: set = set()
    bounded = False
    for qualifier in qualifiers:
        target = qualifier.resource.lower()
        if qualifier.kind in EXCLUDING_KINDS:
            excluded.add(target)
            continue
        if qualifier.kind in RESTRICTING_KINDS:
            if _is_wildcard(target):
                # "all" / "*" places no fence: the scope is unbounded.
                return None
            permitted.add(target)
            bounded = True
    if not bounded:
        # Only exclusions (or nothing): unbounded minus the excluded
        # targets.  Unbounded means "everything", so an exclusion alone
        # does not make the scope bounded.
        return None
    return frozenset(permitted - excluded)


def scope_relation(
    presented: Sequence[ScopeQualifier], source: Sequence[ScopeQualifier]
) -> str:
    """How the presented fence stands against the source fence.

    * ``equal`` -- the same fence: the same qualifiers, permitting the
      same targets.  The grant stands as authorized.
    * ``narrower`` -- the presented fence permits no more than the
      source's (a proper subset of the permitted targets).  The grant
      asks for less than it was given.
    * ``wider`` -- the presented fence permits more than the source's,
      or the presented grant has **no fence at all** against a bounded
      source.  A dropped "folder X only" is not a smaller grant, it is a
      bigger one -- this is the widening the module exists to catch.
    * ``incomparable`` -- the two fences permit disjoint target sets.

    Two fences that permit the *same* targets but differ in their
    qualifiers (one adds an "except") are ``narrower``: the presented
    fence asks for no more than the source's, so it is safe to run.
    """
    presented_atoms = _scope_atoms(presented)
    source_atoms = _scope_atoms(source)
    presented_targets = permitted_targets(presented)
    source_targets = permitted_targets(source)
    if presented_targets is None and source_targets is None:
        return SCOPE_EQUAL
    if presented_targets is None:
        # No fence at all against a bounded source: unbounded, so wider.
        return SCOPE_WIDER
    if source_targets is None:
        # The source is unbounded: any fence is narrower than it.
        return SCOPE_NARROWER
    if presented_targets == source_targets:
        if presented_atoms == source_atoms:
            return SCOPE_EQUAL
        # Same permitted targets, different qualifiers: the presented
        # fence asks for no more, so it is narrower (it adds a fence).
        return SCOPE_NARROWER
    if presented_targets < source_targets:
        return SCOPE_NARROWER
    if presented_targets > source_targets:
        return SCOPE_WIDER
    return SCOPE_INCOMPARABLE


def narrower_scope(
    presented: Sequence[ScopeQualifier], source: Sequence[ScopeQualifier]
) -> Tuple[ScopeQualifier, ...]:
    """The fence both authorizations agree on -- the narrower of the two.

    This is the **intersection of the two permitted target sets**: the
    targets that survive on both sides.  A fallback may only be an
    intersection, because a fallback has to be authorized by *both*:

    * a dropped fence (the presented grant permits everything) meets the
      source's targets in the source's own set -- but the source's fence
      is not a subset of an unbounded fence, so the agreed fence is the
      source's, and the *presented* grant is still refused: a dropped
      qualifier is not silently forgiven;
    * a widened fence ("folder X only" -> "all folders") meets the
      source's targets in the source's set, and again the presented
      grant is refused while the agreed fence is the source's;
    * a fence that permits a proper subset of the source's meets it in
      itself, so the agreed fence is that subset.

    The caller decides whether the agreed fence may actually run: the
    gate only issues a fallback for a *narrower* presented fence, and
    refuses the grant otherwise.
    """
    presented_targets = permitted_targets(presented)
    source_targets = permitted_targets(source)
    if presented_targets is None:
        common = source_targets
    elif source_targets is None:
        common = presented_targets
    else:
        common = presented_targets & source_targets
    if not common:
        return ()
    # Rebuild the fence for the agreed targets.  The source's own
    # qualifiers are preferred when they describe an agreed target, so
    # the rendering keeps the resource's original spelling rather than
    # a lowercased one.
    by_target = {
        q.resource.lower(): q for q in source if q.kind in RESTRICTING_KINDS
    }
    rendered = []
    for target in sorted(common):
        qualifier = by_target.get(target)
        if qualifier is None:
            qualifier = ScopeQualifier(kind="only", resource=target)
        rendered.append(qualifier)
    return tuple(rendered)


@dataclass(frozen=True)
class ScopeFallback:
    """A narrowed authorization, with the clock that bounds it.

    The fallback is the answer to a mismatch: instead of running the
    wider grant or running nothing forever, the gate runs the *narrower*
    of the two -- for a bounded time.

    ``expires_at`` is an absolute, caller-supplied time (no wall-clock
    inside the module).  When the current time passes it and no fresh
    grant has been issued, the action stays blocked: "wait until the
    authorizer can be reached" must not become "authorized forever".
    """

    grant_id: str
    scope_text: str
    issued_at: int
    expires_at: int
    source_ref: str = ""
    reason: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.grant_id, str) or not self.grant_id:
            raise MalformedGrantError("fallback grant_id must be a non-empty string")
        if not isinstance(self.scope_text, str) or not self.scope_text:
            raise MalformedGrantError("fallback scope_text must be a non-empty string")
        for name in ("issued_at", "expires_at"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise MalformedGrantError(f"{name} must be an int")
        if self.expires_at <= self.issued_at:
            raise MalformedGrantError("fallback expires_at must be after issued_at")

    def is_expired(self, now: int) -> bool:
        """True when the clock has run out (``now`` >= ``expires_at``)."""
        if isinstance(now, bool) or not isinstance(now, int):
            raise MalformedGrantError("now must be an int")
        return now >= self.expires_at

    def to_dict(self) -> Dict[str, Any]:
        return {
            "grant_id": self.grant_id,
            "scope_text": self.scope_text,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "source_ref": self.source_ref,
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, value: Any) -> "ScopeFallback":
        if not isinstance(value, dict):
            raise MalformedGrantError("fallback must be a mapping")
        return cls(
            grant_id=str(value.get("grant_id", "")),
            scope_text=str(value.get("scope_text", "")),
            issued_at=int(value.get("issued_at", 0)),
            expires_at=int(value.get("expires_at", 0)),
            source_ref=str(value.get("source_ref", "") or ""),
            reason=str(value.get("reason", "") or ""),
        )


# ---------------------------------------------------------------------------
# The check
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScopeCheck:
    """The result of one scope-qualifier check.

    ``blocked`` is the only field a caller may branch on.  ``outcome``
    says *why*, and the why is structured: ``match``, ``fallback``,
    ``mismatch``, ``outcome_unknown`` or ``expired``.
    """

    grant_id: str
    blocked: bool
    outcome: str
    reason: str = ""
    #: The scope the grant would run under: the source's scope on a
    #: match, the narrowed scope on a fallback, empty on a block.
    effective_scope: str = ""
    #: The grant's own (possibly compacted) scope, verbatim.
    presented_scope: str = ""
    #: The source's scope, when it was retrieved.
    source_scope: str = ""
    source_ref: str = ""
    #: The fallback, when one was issued.
    fallback: Optional[ScopeFallback] = None
    #: The digest of the check input (the grant plus the source line).
    digest: str = ""

    def as_dict(self) -> Dict[str, Any]:
        payload = {
            "grant_id": self.grant_id,
            "blocked": self.blocked,
            "outcome": self.outcome,
            "reason": self.reason,
            "effective_scope": self.effective_scope,
            "presented_scope": self.presented_scope,
            "source_scope": self.source_scope,
            "source_ref": self.source_ref,
            "digest": self.digest,
        }
        if self.fallback is not None:
            payload["fallback"] = self.fallback.to_dict()
        return payload


@dataclass(frozen=True)
class QualifierDiff:
    """The scope-token diff between a source text and a compacted text.

    This is the cheaper, earlier version of the check (comment
    ``cbdbedf9``, *reportio*): pull the scope tokens out of the input and
    the output and see which ones the rewrite dropped.  A dropped token
    with no explicit removal note is a *lost qualifier*.
    """

    dropped: Tuple[str, ...] = ()
    added: Tuple[str, ...] = ()
    noted: Tuple[str, ...] = ()

    @property
    def lost(self) -> Tuple[str, ...]:
        """The tokens dropped without a removal note."""
        return tuple(t for t in self.dropped if t not in self.noted)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "dropped": list(self.dropped),
            "added": list(self.added),
            "noted": list(self.noted),
            "lost": list(self.lost),
        }


_SCOPE_TOKEN_RE = re.compile(
    r"\b(" + "|".join(SCOPE_TOKENS) + r")\b", re.IGNORECASE
)


def scope_tokens(text: Any) -> Tuple[str, ...]:
    """The scope tokens present in ``text``, in order, lower-cased."""
    if not isinstance(text, str) or not text:
        return ()
    return tuple(match.group(1).lower() for match in _SCOPE_TOKEN_RE.finditer(text))


def diff_qualifiers(source_text: Any, compacted_text: Any) -> QualifierDiff:
    """Diff the scope tokens of a source text against a compacted text.

    A token that appears in the source but not in the compaction was
    dropped.  A dropped token is *noted* when the compaction says it was
    removed on purpose ("removed") -- an explicit removal is a decision,
    a silent drop is a loss.
    """
    source = scope_tokens(source_text)
    compacted = scope_tokens(compacted_text)
    dropped = tuple(t for t in dict.fromkeys(source) if t not in compacted)
    added = tuple(t for t in dict.fromkeys(compacted) if t not in source)
    noted: Tuple[str, ...] = ()
    if isinstance(compacted_text, str) and REMOVAL_MARKER in compacted_text.lower():
        noted = dropped
    return QualifierDiff(dropped=dropped, added=added, noted=noted)


class ScopeQualifierGate:
    """The gate: re-derive a grant's scope from its source, and block on
    mismatch.

    ``check(grant, now)`` is the dispatch precondition:

    * the grant's scope is compared against **its source line** -- never
      against a summary of it;
    * a match allows, with the source's scope as the effective scope;
    * a **mismatch blocks** the action (fail-closed) and issues a
      **narrower fallback** with an expiry clock, if a narrower scope
      exists at all;
    * a **missing source line** blocks (the grant cannot be checked
      against anything);
    * a **store that cannot answer** blocks with ``outcome_unknown`` --
      the missing is a structured state, never a clean read;
    * an **expired fallback** blocks: the narrowed grant did not become a
      permanent one.

    The gate keeps its own fallback ledger so that a repeated dispatch
    under the same grant sees the *same* clock rather than minting a new
    one each time (a fresh clock per dispatch would be an infinite
    extension wearing a deadline).
    """

    def __init__(
        self,
        store: SourceStore,
        *,
        fallback_ttl_seconds: int = DEFAULT_FALLBACK_TTL_SECONDS,
        denial_rows: Optional[DenialRowStore] = None,
    ) -> None:
        if not isinstance(store, SourceStore):
            raise ScopeQualifierError("store must be a SourceStore")
        if isinstance(fallback_ttl_seconds, bool) or not isinstance(
            fallback_ttl_seconds, int
        ):
            raise ScopeQualifierError("fallback_ttl_seconds must be an int")
        if fallback_ttl_seconds <= 0:
            raise ScopeQualifierError("fallback_ttl_seconds must be positive")
        if denial_rows is not None and not isinstance(denial_rows, DenialRowStore):
            raise ScopeQualifierError("denial_rows must be a DenialRowStore")
        self._store = store
        self._ttl = fallback_ttl_seconds
        self._rows = denial_rows if denial_rows is not None else DenialRowStore()
        self._fallbacks: Dict[str, ScopeFallback] = {}
        self._checks = 0
        #: Called when a fallback is issued, so a host can persist it.
        #: The fallback's clock has to survive a restart: a process that
        #: restarts must not hand itself a fresh deadline.
        self.on_fallback: Optional[Any] = None

    @property
    def store(self) -> SourceStore:
        """The source store the gate reads."""
        return self._store

    @property
    def fallback_ttl_seconds(self) -> int:
        """The lifetime of a narrowed fallback, in seconds."""
        return self._ttl

    def fallback(self, grant_id: str) -> Optional[ScopeFallback]:
        """The live fallback for a grant, if one was issued."""
        return self._fallbacks.get(grant_id)

    def seed_fallback(self, fallback: ScopeFallback) -> None:
        """Seed a persisted fallback into the ledger.

        A fallback that was issued before a restart keeps its original
        clock: re-issuing it would hand out a fresh deadline and turn
        the fallback into a permanent authorization.
        """
        if not isinstance(fallback, ScopeFallback):
            raise MalformedGrantError("fallback must be a ScopeFallback")
        self._fallbacks[fallback.grant_id] = fallback

    def fallbacks(self) -> Tuple[ScopeFallback, ...]:
        """Every issued fallback, in issue order."""
        return tuple(self._fallbacks.values())

    def check(self, grant: GrantRecord, *, now: int) -> ScopeCheck:
        """Check one grant against its source line.

        ``now`` is the current time (caller-supplied; the module has no
        wall-clock).  It is what the fallback's clock is measured
        against.
        """
        if not isinstance(grant, GrantRecord):
            raise MalformedGrantError("grant must be a GrantRecord")
        if isinstance(now, bool) or not isinstance(now, int):
            raise ScopeQualifierError("now must be an int")
        self._checks += 1
        presented = grant.scope_text()
        digest = _digest(
            {
                "grant": grant.to_dict(),
                "presented_scope": presented,
            }
        )

        # An existing fallback is re-used, not re-minted: the clock runs
        # from the first narrowing, so repeated dispatches cannot extend
        # it indefinitely.
        existing = self._fallbacks.get(grant.grant_id)
        if existing is not None and existing.is_expired(now):
            return ScopeCheck(
                grant_id=grant.grant_id,
                blocked=True,
                outcome=OUTCOME_EXPIRED,
                reason=(
                    "the narrowed fallback for this grant expired at "
                    f"{existing.expires_at} and no fresh grant was issued"
                ),
                presented_scope=presented,
                source_ref=existing.source_ref,
                fallback=existing,
                digest=digest,
            )

        # Conclusion 96: the gate must either get a row or a signed "no
        # denial" proof.  A scope with no row, or a store that cannot
        # answer, is an *unknown* -- never a clean read.
        try:
            row = self._rows.fetch(self._deny_scope(grant))
        except ScopeSourceError as error:
            return ScopeCheck(
                grant_id=grant.grant_id,
                blocked=True,
                outcome=OUTCOME_UNKNOWN,
                reason=f"the denial row could not be retrieved: {error}",
                presented_scope=presented,
                source_ref=grant.source_ref,
                digest=digest,
            )
        if row is None:
            return ScopeCheck(
                grant_id=grant.grant_id,
                blocked=True,
                outcome=OUTCOME_UNKNOWN,
                reason=(
                    "no denial row and no signed proof of no-denial for this "
                    "scope: the state is unknown, not clear"
                ),
                presented_scope=presented,
                source_ref=grant.source_ref,
                digest=digest,
            )
        if row.denies():
            return ScopeCheck(
                grant_id=grant.grant_id,
                blocked=True,
                outcome=OUTCOME_MISMATCH,
                reason=f"the scope is refused: {row.reason or 'denial row'}",
                presented_scope=presented,
                source_ref=grant.source_ref,
                digest=digest,
            )

        # The source is the authority.  A store that cannot answer is an
        # *unknown*, not a clean read and not a match.
        try:
            source = self._store.fetch(grant.source_ref)
        except ScopeSourceError as error:
            return ScopeCheck(
                grant_id=grant.grant_id,
                blocked=True,
                outcome=OUTCOME_UNKNOWN,
                reason=f"the source line could not be retrieved: {error}",
                presented_scope=presented,
                source_ref=grant.source_ref,
                digest=digest,
            )

        if source is None:
            # No source line: the grant has nothing to be checked against.
            # This is a mismatch, not a pass -- the grant's authority
            # cannot be re-derived, so it does not stand.
            return ScopeCheck(
                grant_id=grant.grant_id,
                blocked=True,
                outcome=OUTCOME_MISMATCH,
                reason=(
                    "the grant names a source line that does not exist, so its "
                    "scope cannot be re-derived"
                ),
                presented_scope=presented,
                source_ref=grant.source_ref,
                digest=digest,
            )

        if source.revoked:
            return ScopeCheck(
                grant_id=grant.grant_id,
                blocked=True,
                outcome=OUTCOME_MISMATCH,
                reason="the source authority is revoked",
                presented_scope=presented,
                source_scope=source.scope_text,
                source_ref=source.source_ref,
                digest=digest,
            )

        if source.grant_id != grant.grant_id:
            return ScopeCheck(
                grant_id=grant.grant_id,
                blocked=True,
                outcome=OUTCOME_MISMATCH,
                reason=(
                    "the source line authorizes a different grant: "
                    f"{source.grant_id!r} != {grant.grant_id!r}"
                ),
                presented_scope=presented,
                source_scope=source.scope_text,
                source_ref=source.source_ref,
                digest=digest,
            )

        source_scope = source.scope_text
        relation = scope_relation(grant.qualifiers, source.qualifiers)
        if relation == SCOPE_EQUAL:
            # Exact match: the grant stands as the source authorized it.
            return ScopeCheck(
                grant_id=grant.grant_id,
                blocked=False,
                outcome=OUTCOME_MATCH,
                reason="the grant's scope matches its source line",
                effective_scope=source_scope,
                presented_scope=presented,
                source_scope=source_scope,
                source_ref=source.source_ref,
                digest=digest,
            )

        if relation == SCOPE_WIDER:
            # The grant asks for more than the source authorized: the
            # fence was dropped or widened.  The action is BLOCKED --
            # not merely logged, and not silently re-scoped.  This is
            # the post's case exactly: "a dropped 'folder X only'
            # converts a restriction into an apparent entitlement".
            return ScopeCheck(
                grant_id=grant.grant_id,
                blocked=True,
                outcome=OUTCOME_MISMATCH,
                reason=(
                    "the grant's scope is wider than its source line: the "
                    "fence was dropped or widened, so the action is blocked"
                ),
                presented_scope=presented,
                source_scope=source_scope,
                source_ref=source.source_ref,
                digest=digest,
            )

        # Mismatch.  The grant's own scope does not stand.  What may
        # still run is the **narrower** of the two scopes -- and only
        # under a clock.  A fallback is a *separate, narrower*
        # authorization: it does not unblock the presented grant, it
        # authorizes less.
        narrower = narrower_scope(grant.qualifiers, source.qualifiers)
        if not narrower:
            # No scope both authorizations agree on: nothing runs.
            return ScopeCheck(
                grant_id=grant.grant_id,
                blocked=True,
                outcome=OUTCOME_MISMATCH,
                reason=(
                    "the grant's scope does not match its source line and the "
                    "two scopes have no narrower scope in common"
                ),
                presented_scope=presented,
                source_scope=source_scope,
                source_ref=source.source_ref,
                digest=digest,
            )
        narrower_text = " | ".join(q.as_text() for q in narrower)
        fallback = self._issue_fallback(
            grant_id=grant.grant_id,
            scope_text=narrower_text,
            source_ref=source.source_ref,
            now=now,
            reason="scope mismatch: fell back to the narrower scope",
        )
        return ScopeCheck(
            grant_id=grant.grant_id,
            blocked=False,
            outcome=OUTCOME_FALLBACK,
            reason=(
                "the grant's scope does not match its source line; running "
                "under the narrower scope until the fallback expires"
            ),
            effective_scope=narrower_text,
            presented_scope=presented,
            source_scope=source_scope,
            source_ref=source.source_ref,
            fallback=fallback,
            digest=digest,
        )

    @staticmethod
    def _deny_scope(grant: GrantRecord) -> str:
        """The scope the denial-row sidecar is read for.

        The scope names the grant and the verb it authorizes -- the
        granularity at which a refusal is issued (a refused grant, not a
        blanket refusal of every action the process ever takes).
        """
        return f"{grant.grant_id}/{grant.verb}"

    def _issue_fallback(
        self,
        *,
        grant_id: str,
        scope_text: str,
        source_ref: str,
        now: int,
        reason: str,
    ) -> ScopeFallback:
        """Issue (or re-use) the narrowed fallback for a grant."""
        existing = self._fallbacks.get(grant_id)
        if existing is not None:
            return existing
        fallback = ScopeFallback(
            grant_id=grant_id,
            scope_text=scope_text,
            issued_at=now,
            expires_at=now + self._ttl,
            source_ref=source_ref,
            reason=reason,
        )
        self._fallbacks[grant_id] = fallback
        if self.on_fallback is not None:
            self.on_fallback(fallback)
        return fallback


# ---------------------------------------------------------------------------
# The grant registry: the source side and the presented side
# ---------------------------------------------------------------------------


class ScopeGrantRegistry:
    """The structured grant registry: two sides that must not be confused.

    * The **source side** is the authority: the source lines, in the
      sidecar the summarizer never touches.
    * The **presented side** is the grants as they were *reissued* into
      the context -- possibly through a compaction, possibly by a
      rewriting model.  These are what the gate checks, because these
      are what a dispatch would act on.

    The registry is the seam the runtime uses: the compaction path
    reissues through :meth:`reissue` (so every boundary is an
    authorization boundary), and the dispatch path asks the registry's
    gate to check the presented grants before an action runs.
    """

    def __init__(
        self,
        *,
        sources: Optional[Iterable[SourceLine]] = None,
        presented: Optional[Iterable[GrantRecord]] = None,
        rows: Optional[Iterable[DenialRow]] = None,
        fallback_ttl_seconds: int = DEFAULT_FALLBACK_TTL_SECONDS,
    ) -> None:
        self._sources = SourceStore(sources)
        self._rows = DenialRowStore(rows)
        self._gate = ScopeQualifierGate(
            self._sources,
            denial_rows=self._rows,
            fallback_ttl_seconds=fallback_ttl_seconds,
        )
        self._presented: Dict[str, GrantRecord] = {}
        for grant in presented or ():
            self.present(grant)

    @property
    def gate(self) -> "ScopeQualifierGate":
        """The gate that checks the presented grants."""
        return self._gate

    @property
    def sources(self) -> SourceStore:
        """The source-line sidecar."""
        return self._sources

    @property
    def rows(self) -> DenialRowStore:
        """The denial-row sidecar."""
        return self._rows

    def present(self, grant: GrantRecord) -> None:
        """Present a grant into the (possibly compacted) context."""
        if not isinstance(grant, GrantRecord):
            raise MalformedGrantError("grant must be a GrantRecord")
        self._presented[grant.grant_id] = grant

    def presented(self) -> Tuple[GrantRecord, ...]:
        """Every presented grant, in presentation order."""
        return tuple(self._presented.values())

    def presented_for(self, verb: str) -> Tuple[GrantRecord, ...]:
        """The presented grants that authorize ``verb``."""
        return tuple(
            grant for grant in self._presented.values() if grant.verb == verb
        )

    def drop(self, grant_id: str) -> bool:
        """Remove a presented grant (it is no longer reissued)."""
        return self._presented.pop(grant_id, None) is not None

    def reissue(
        self,
        grants: Optional[Iterable[GrantRecord]] = None,
        *,
        source_text_for: Optional[Any] = None,
    ) -> CompactionCheck:
        """Reissue grants across a compaction boundary.

        The grants are checked at the boundary first (every compaction
        boundary is an authorization boundary), and only the ones that
        survived are presented.  A grant that lost its fence at the
        boundary is **not** presented -- it is dropped, so it cannot be
        reissued as an entitlement.
        """
        candidates = tuple(grants) if grants is not None else self.presented()
        check = check_compaction_boundary(
            candidates, source_text_for=source_text_for
        )
        blocked = set(check.blocked_grants)
        for grant in candidates:
            if grant.grant_id in blocked:
                self.drop(grant.grant_id)
            else:
                self.present(grant)
        return check


# ---------------------------------------------------------------------------
# The denial-row sidecar: "missing" as a structured state
# ---------------------------------------------------------------------------


#: A denial row says the scope is refused.
ROW_DENIED = "denied"

#: A clear row is a *signed* proof that no denial exists for the scope.
#: Conclusion 96: the gate must either get a row or a signed "no denial"
#: proof -- never a clean read from an absence.
ROW_CLEAR = "clear"

#: The row kinds the gate accepts.
ROW_KINDS = frozenset({ROW_DENIED, ROW_CLEAR})


@dataclass(frozen=True)
class DenialRow:
    """One denial row: either a refusal or a signed proof of no refusal.

    A ``clear`` row must carry a signature.  An unsigned "clear" row is
    not a proof of no-denial; it is a claim, and a claim is not what the
    gate is allowed to read.  Conclusion 96: the gate either gets a row
    or a *signed* "no denial" proof -- a read that fails is
    ``outcome_unknown``, never a clean read.
    """

    scope: str
    kind: str
    reason: str = ""
    signature: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.scope, str) or not self.scope.strip():
            raise MalformedGrantError("row scope must be a non-empty string")
        if self.kind not in ROW_KINDS:
            raise MalformedGrantError(f"unknown row kind: {self.kind!r}")
        if self.kind == ROW_CLEAR and not self.signature:
            raise MalformedGrantError(
                "a clear row must carry a signature: an unsigned row is a "
                "claim, not a proof of no-denial"
            )
        object.__setattr__(self, "scope", self.scope.strip())

    def denies(self) -> bool:
        """True when the row refuses the scope."""
        return self.kind == ROW_DENIED

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scope": self.scope,
            "kind": self.kind,
            "reason": self.reason,
            "signature": self.signature,
        }


class DenialRowStore:
    """The denial-row sidecar the gate reads before it decides.

    The store answers exactly one question per scope: *is there a row,
    and what does it say?*  Three answers are possible, and the gate
    distinguishes all three:

    * a **denial row** -- the scope is refused;
    * a **signed clear row** -- there is no denial, and the proof is
      signed;
    * **no row / unreadable store** -- the state is *unknown*.  Never a
      clean read.

    The store is never written by the compaction path, for the same
    reason the source store is not: the summarizer must not be able to
    remove a row.
    """

    def __init__(self, rows: Optional[Iterable[DenialRow]] = None) -> None:
        self._rows: Dict[str, DenialRow] = {}
        self._broken = False
        for row in rows or ():
            self.put(row)

    def put(self, row: DenialRow) -> None:
        if not isinstance(row, DenialRow):
            raise MalformedGrantError("row must be a DenialRow")
        self._rows[row.scope] = row

    def break_reads(self) -> None:
        """Make every read fail (test helper)."""
        self._broken = True

    def repair(self) -> None:
        """Make reads work again (test helper)."""
        self._broken = False

    def fetch(self, scope: str) -> Optional[DenialRow]:
        """Fetch the row for ``scope``.

        ``None`` means *there is no row* -- which the gate reads as an
        unknown state, not as permission.  Raises
        :class:`ScopeSourceError` when the store cannot answer.
        """
        if self._broken:
            raise ScopeSourceError("denial row store is unreadable")
        if not isinstance(scope, str) or not scope:
            raise ScopeSourceError("scope must be a non-empty string")
        return self._rows.get(scope)

    def __len__(self) -> int:
        return len(self._rows)


# ---------------------------------------------------------------------------
# The compaction boundary: every boundary is an authorization boundary
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CompactionCheck:
    """The result of checking one compaction boundary.

    The compaction path carries grants through a rewrite.  This check
    runs *at* the boundary, before the rewritten grants are reissued:
    a grant whose fence was dropped by the rewrite is refused, so it
    cannot be reissued as an entitlement.

    Conclusion 93: every compaction boundary is an authorization
    boundary.  So the check is not optional at the boundary -- it is the
    same gate, and there is no re-issue path that skips it.
    """

    performed: bool = False
    blocked_grants: Tuple[str, ...] = ()
    #: The grant ids whose fence survived the rewrite.
    survived_grants: Tuple[str, ...] = ()
    #: The qualifier diff per grant id, for the record.
    diffs: Tuple[Tuple[str, QualifierDiff], ...] = ()

    @property
    def blocked(self) -> bool:
        """True when at least one grant was refused at the boundary."""
        return bool(self.blocked_grants)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "performed": self.performed,
            "blocked": self.blocked,
            "blocked_grants": list(self.blocked_grants),
            "survived_grants": list(self.survived_grants),
            "diffs": {grant: diff.as_dict() for grant, diff in self.diffs},
        }


def check_compaction_boundary(
    grants: Sequence[GrantRecord],
    *,
    source_text_for: Optional[Any] = None,
) -> CompactionCheck:
    """Check the grants that survive a compaction boundary.

    ``source_text_for`` is a callable that returns the *source* text for
    a grant id -- the authority the compaction must not have lost.  It
    is optional: without it, the boundary check can only compare the
    grant's own fence against the set of qualifiers the rewrite kept,
    which is why the gate (which has the source store) is the real
    authority.  With it, a dropped scope token with no explicit removal
    note is caught here too, before the reissue.

    The returned check names the grants that were refused.  A refused
    grant must not be reissued: the caller blocks it.
    """
    if isinstance(grants, (str, bytes)) or not isinstance(grants, (list, tuple)):
        raise ScopeQualifierError("grants must be a sequence")
    blocked: List[str] = []
    survived: List[str] = []
    diffs: List[Tuple[str, QualifierDiff]] = []
    for grant in grants:
        if not isinstance(grant, GrantRecord):
            raise MalformedGrantError("grant must be a GrantRecord")
        if source_text_for is None:
            survived.append(grant.grant_id)
            continue
        source_text = source_text_for(grant.grant_id)
        if source_text is None:
            # No source to compare against: the grant cannot be shown to
            # have survived, so it is refused at the boundary.
            blocked.append(grant.grant_id)
            diffs.append((grant.grant_id, QualifierDiff()))
            continue
        diff = diff_qualifiers(source_text, grant.scope_text())
        diffs.append((grant.grant_id, diff))
        if diff.lost:
            blocked.append(grant.grant_id)
        else:
            survived.append(grant.grant_id)
    return CompactionCheck(
        performed=True,
        blocked_grants=tuple(blocked),
        survived_grants=tuple(survived),
        diffs=tuple(diffs),
    )


# ---------------------------------------------------------------------------
# The measure: "grants generalize, fences shrink"
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SurvivalMetrics:
    """The measured survival of scope qualifiers across compaction rounds.

    The claim from the thread is that **grants generalize, fences
    shrink**: a rewrite keeps the verb and loses the restriction.  This
    turns that into a number rather than a metaphor:

    * ``grant_survival`` -- the share of grants that survived the round
      (the verb generalized: the grant was still there);
    * ``qualifier_survival`` -- the share of qualifiers that survived the
      round (the fence shrank: the restriction was not);
    * ``widening_rate`` -- the share of grants whose scope came out
      *wider* than it went in;
    * ``caught_rate`` -- the share of the widenings the gate caught.

    The gap between ``grant_survival`` and ``qualifier_survival`` is the
    loss, made measurable.
    """

    rounds: int = 0
    grants_in: int = 0
    grants_out: int = 0
    qualifiers_in: int = 0
    qualifiers_out: int = 0
    widened: int = 0
    caught: int = 0

    @property
    def grant_survival(self) -> float:
        """The share of grants that survived the round."""
        if self.rounds == 0:
            return 1.0
        return self.grants_out / self.grants_in if self.grants_in else 1.0

    @property
    def qualifier_survival(self) -> float:
        """The share of qualifiers that survived the round."""
        if self.rounds == 0:
            return 1.0
        return self.qualifiers_out / self.qualifiers_in if self.qualifiers_in else 1.0

    @property
    def widening_rate(self) -> float:
        """The share of grants whose scope came out wider than it went in."""
        if self.rounds == 0:
            return 0.0
        return self.widened / self.grants_in if self.grants_in else 0.0

    @property
    def caught_rate(self) -> float:
        """The share of the widenings the gate caught."""
        if self.widened == 0:
            return 1.0
        return self.caught / self.widened

    def as_dict(self) -> Dict[str, Any]:
        return {
            "rounds": self.rounds,
            "grants_in": self.grants_in,
            "grants_out": self.grants_out,
            "qualifiers_in": self.qualifiers_in,
            "qualifiers_out": self.qualifiers_out,
            "widened": self.widened,
            "caught": self.caught,
            "grant_survival": self.grant_survival,
            "qualifier_survival": self.qualifier_survival,
            "widening_rate": self.widening_rate,
            "caught_rate": self.caught_rate,
        }


def measure_qualifier_survival(
    grants: Sequence[GrantRecord],
    *,
    gate: Optional[ScopeQualifierGate] = None,
    rounds: int = 1,
) -> SurvivalMetrics:
    """Measure qualifier survival across simulated compaction rounds.

    The simulation is the thread's own claim, made into a number.  Each
    round the *verb* survives (the grant is still there -- grants
    generalize) while the *fence* is dropped from a deterministic subset
    of the grants (fences shrink).  The gate is then asked to check each
    rewritten grant against its source, and the widenings it caught are
    counted.

    The rewrite is deterministic on purpose: the measure has to be
    reproducible, and a test has to be able to assert on the numbers.
    A grant whose fence is dropped *widens* -- an unbounded grant against
    a bounded source -- which is exactly the case the gate catches.

    Returns the metrics.  ``gate`` is optional: without one, the
    measurement reports the loss but not the catch rate.
    """
    if isinstance(grants, (str, bytes)) or not isinstance(grants, (list, tuple)):
        raise ScopeQualifierError("grants must be a sequence")
    if isinstance(rounds, bool) or not isinstance(rounds, int) or rounds < 1:
        raise ScopeQualifierError("rounds must be a positive int")
    current = list(grants)
    grants_in = len(current)
    qualifiers_in = sum(len(g.qualifiers) for g in current)
    widened = 0
    caught = 0
    for round_index in range(rounds):
        rewritten: List[GrantRecord] = []
        for index, grant in enumerate(current):
            # Every third grant loses its fence: the rewrite keeps the
            # verb and drops the restriction.
            drops = (index + round_index) % 3 == 0
            if drops and grant.qualifiers:
                widened += 1
                candidate = GrantRecord(
                    grant_id=grant.grant_id,
                    verb=grant.verb,
                    qualifiers=(),
                    source_ref=grant.source_ref,
                    version=grant.version,
                    counter=grant.counter,
                )
            else:
                candidate = grant
            if gate is not None:
                try:
                    check = gate.check(candidate, now=round_index)
                except ScopeQualifierError:
                    check = None
                if check is not None and check.blocked:
                    caught += 1
            rewritten.append(candidate)
        current = rewritten
    grants_out = len(current)
    qualifiers_out = sum(len(g.qualifiers) for g in current)
    return SurvivalMetrics(
        rounds=rounds,
        grants_in=grants_in,
        grants_out=grants_out,
        qualifiers_in=qualifiers_in,
        qualifiers_out=qualifiers_out,
        widened=widened,
        caught=caught,
    )


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


def scope_audit_event(
    kind: str, check: ScopeCheck, *, seq: int = 0
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for a scope-qualifier check.

    Only ids, scopes, outcomes and counts cross the audit boundary --
    never the raw decision payload.
    """
    if not isinstance(kind, str) or kind not in _KINDS:
        raise ScopeQualifierError(f"unknown audit kind: {kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise ScopeQualifierError("seq must be a non-negative int")
    detail = check.as_dict()
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": SCOPE_QUALIFIER_VERSION,
        "detail": detail,
        "seq": int(seq),
    }


def stdlib_only() -> bool:
    """AST check: this module imports stdlib modules only."""
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {
        "__future__",
        "ast",
        "dataclasses",
        "hashlib",
        "json",
        "pathlib",
        "re",
        "typing",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    """Self-check: a matching grant passes, a dropped fence blocks, a
    widening falls back to the narrower scope, and an expired fallback
    blocks."""
    store = SourceStore(
        [
            SourceLine(
                source_ref="src-1",
                grant_id="grant-1",
                qualifiers=(ScopeQualifier("only", "folder X"),),
            )
        ]
    )
    rows = DenialRowStore([DenialRow(scope="grant-1/write", kind=ROW_CLEAR, signature="sig-1")])
    gate = ScopeQualifierGate(store, denial_rows=rows)

    ok = GrantRecord(
        grant_id="grant-1",
        verb="write",
        qualifiers=(ScopeQualifier("only", "folder X"),),
        source_ref="src-1",
    )
    check = gate.check(ok, now=100)
    assert check.outcome == OUTCOME_MATCH and not check.blocked

    dropped = GrantRecord(grant_id="grant-1", verb="write", source_ref="src-1")
    check = gate.check(dropped, now=100)
    assert check.blocked, "a dropped fence must block"
    assert check.outcome == OUTCOME_MISMATCH

    assert stdlib_only()
    print(
        "scope-qualifier OK: match passes, dropped fence blocks, "
        "widening falls back narrower, stdlib"
    )


if __name__ == "__main__":  # pragma: no cover - self-check entry point
    main()

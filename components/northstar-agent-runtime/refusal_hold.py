"""Refusal hold: a refusal row blocks the re-dispatch of the same action.

What was missing
----------------
Northstar has two complete "refusal" concepts, and **neither sits on the
re-dispatch path**:

1. :mod:`refusal_row` -- a refusal is an auditable row (verdict, evidence
   hash, ruleset hash, verifier key, population digest; "two instruments
   or none");
2. :mod:`scope_qualifier` -- ``DenialRow`` / ``DenialRowStore``: a per-scope
   ``denied`` / signed ``clear`` row, where *no row* means
   ``outcome_unknown``, never a clean read.

The two paths that actually **send the action again** -- ``JobQueue.retry()``
returning a job to ``ready`` and ``LeasedTaskClaim.fail()`` returning a
task to ``ready`` -- know nothing about either.  So a refusal is faithfully
recorded as a row (perfect on the ledger), the same job is re-dispatched,
fails again, and another row is recorded: refusals pile up on the books
while behavior does not change at all.  That is *recorded but not
enforced*, which is worse than *not recorded* -- the ledger creates the
illusion that the refusal was handled.

What this module implements
---------------------------
A **refusal hold**: the shape the repository already owns for sticky
blocking (``cancellation_tombstone.TombstoneSet.blocked()``), but fed with
refusal rows instead of tombstones.  A hold answers one question -- *is
this re-dispatch blocked by a refusal, and by which row?* -- and it is a
**query**, not a mutation: the caller asks before it re-dispatches.

Three properties are load-bearing:

* **the row comes back.**  A blocking answer carries the ``RefusalRow``
  itself and its ``sha256:`` digest, so the blocked caller can see
  *which* refusal stopped it.  A bare boolean would be another log line.
* **fail closed.**  An unusable gate -- an unreadable store, a tampered
  row, a malformed key -- **blocks**.  The repository's own answer is
  ``scope_qualifier.BLOCKING_OUTCOMES``, which contains
  ``OUTCOME_UNKNOWN``: an unknown state is never a clean read.
* **rows are not copied.**  The hold stores the row *by reference* and
  re-verifies the live row on every query.  A copy would be a second
  place where a refusal lives, and therefore a second place where it can
  diverge from the truth -- and it would defeat the row's own tamper
  check.

Design decisions (single-instrument basis, expiry, the key shape, the
``DenialRow`` exclusion) are argued in ``docs/design/refusal-hold.md``.

Source mapping
--------------
**Source (hermesagentj, "The most useful thing I built this month is a
check that refuses to run", Moltbook post
``abe9e16f-21a4-4d38-a2b1-03fd84c3543c``).**  The source names the refusal
row itself; it does **not** name a hold, a key, a re-dispatch gate, an
expiry, or a fail-closed taxonomy for a broken gate.

**The Moltbook conclusion this slice implements** ("a refusal row does not
block re-dispatch") was not found as a file -- neither in
``/home/muse-newapi/`` nor in the repository (``moltbook-discussions.md``
does not exist).  The evidence for this slice is therefore **repository
code**: ``refusal_row.py``, ``scope_qualifier.py``, ``job_queue.py``,
``leased_task_claim.py`` and ``cancellation_tombstone.py``.

**Northstar extensions** (not in the source): the key shape
(``<scope_kind>:<scope_id>:<action>``), the hold object and its query API,
the fail-closed taxonomy and its reason slugs, the no-expiry fork, the
row-reference carry, the ``DenialRow`` exclusion, and the decision that a
single-instrument refusal still blocks.

House style: frozen dataclasses, caller-supplied clock (never the wall
clock), fail-closed taxonomy, stdlib-only, ``sha256:`` digest pins,
version/schema pins.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Optional, Tuple

from refusal_row import RefusalRow, verify_row

__all__ = [
    "REFUSAL_HOLD_VERSION",
    "SCHEMA_PIN",
    "SCOPE_KIND_QUEUE",
    "SCOPE_KIND_TASK",
    "SCOPE_KINDS",
    "REASON_ALLOWED_NO_REFUSAL",
    "REASON_BLOCKED_BY_REFUSAL",
    "REASON_BLOCKED_KEY_INVALID",
    "REASON_BLOCKED_ROW_INVALID",
    "REASON_BLOCKED_ROW_TAMPERED",
    "REASON_BLOCKED_STORE_UNREADABLE",
    "RefusalHoldError",
    "RefusalHoldKeyError",
    "RefusalHoldStoreError",
    "RefusalHoldKey",
    "RefusalHoldResult",
    "RefusalHoldEntry",
    "RefusalHoldStore",
    "RefusalHold",
]

#: Module version pin.
REFUSAL_HOLD_VERSION = "refusal-hold.v1"

#: Schema pin carried by hold entries.
SCHEMA_PIN = "northstar.refusal-hold.v1"

#: The two scope granularities a key can name.
SCOPE_KIND_QUEUE = "queue"
SCOPE_KIND_TASK = "task"

#: Every scope kind a key may use.
SCOPE_KINDS = frozenset({SCOPE_KIND_QUEUE, SCOPE_KIND_TASK})

#: A hold carries at most this many refusals (house convention, as in
#: ``cancellation_tombstone.MAX_TOMBSTONES``).  A hold is a *gate*, not
#: a ledger: the refusals themselves live on the ``refusal_row`` side.
MAX_HOLD_ENTRIES = 256

#: The action was not refused; the gate was readable and the rows intact.
REASON_ALLOWED_NO_REFUSAL = "allowed_no_refusal"

#: A refusal row covers this action.
REASON_BLOCKED_BY_REFUSAL = "blocked_by_refusal"

#: The key was malformed; the query is refused rather than silently allowed.
REASON_BLOCKED_KEY_INVALID = "blocked_key_invalid"

#: The row on the key is not a refusal row at all.
REASON_BLOCKED_ROW_INVALID = "blocked_row_invalid"

#: The row on the key failed ``refusal_row.verify_row()`` -- it was tampered.
REASON_BLOCKED_ROW_TAMPERED = "blocked_row_tampered"

#: The store could not be read at all.
REASON_BLOCKED_STORE_UNREADABLE = "blocked_store_unreadable"


class RefusalHoldError(Exception):
    """Fail-closed: the hold could not be used, so nothing is allowed."""


class RefusalHoldKeyError(RefusalHoldError, ValueError):
    """A hold key is malformed: a missing field, a wrong type, an unknown
    scope kind.  The key is refused, never defaulted.

    The error carries the same ``reason`` slug the result taxonomy uses
    (``blocked_key_invalid``), so a caller can log a malformed key and an
    unusable gate with one vocabulary.
    """

    reason = REASON_BLOCKED_KEY_INVALID


class RefusalHoldStoreError(RefusalHoldError):
    """The refusal-row store could not answer."""


def _check_part(value: Any, name: str) -> str:
    """Validate one component of a key: a non-empty string without a colon.

    The colon is refused because the canonical string form of the key is
    ``"<scope_kind>:<scope_id>:<action>"``: a colon inside a part would
    make that string ambiguous, and an ambiguous key is a key that can
    silently cover the wrong action.
    """
    if not isinstance(value, str):
        raise RefusalHoldKeyError(f"{name} must be a string, got {value!r}")
    text = value.strip()
    if not text:
        raise RefusalHoldKeyError(f"{name} must not be empty")
    if ":" in text:
        raise RefusalHoldKeyError(
            f"{name} must not contain ':' -- the key's canonical form is "
            f"'<scope_kind>:<scope_id>:<action>', so a colon makes it ambiguous"
        )
    return text


@dataclass(frozen=True)
class RefusalHoldKey:
    """What one refusal blocks: *this action, in this scope*.

    The key is a triple -- ``scope_kind`` ("queue" or "task"),
    ``scope_id`` (the job id or the task id) and ``action`` -- so it can
    be read as "the same thing": two keys name the same action exactly
    when all three fields are equal.

    The canonical string form is ``"<scope_kind>:<scope_id>:<action>"``
    (:meth:`identity`), which is what the hold compares and what a log
    line carries.  Neither the scope id nor the action may contain a
    colon, so the string form is never ambiguous.
    """

    scope_kind: str
    scope_id: str
    action: str

    def __post_init__(self) -> None:
        if not isinstance(self.scope_kind, str):
            raise RefusalHoldKeyError(
                f"scope_kind must be a string, got {self.scope_kind!r}"
            )
        if self.scope_kind not in SCOPE_KINDS:
            raise RefusalHoldKeyError(
                f"scope_kind must be one of {sorted(SCOPE_KINDS)}, "
                f"got {self.scope_kind!r}"
            )
        object.__setattr__(self, "scope_id", _check_part(self.scope_id, "scope_id"))
        object.__setattr__(self, "action", _check_part(self.action, "action"))

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "RefusalHoldKey":
        """Build a key from a mapping, failing closed on a missing field.

        A mapping that lacks a field is a malformed key, not a key with
        an empty field: the caller asked for a key it did not supply.
        """
        if not isinstance(value, Mapping):
            raise RefusalHoldKeyError(
                f"a key must be built from a mapping, got {type(value).__name__}"
            )
        missing = [
            name
            for name in ("scope_kind", "scope_id", "action")
            if name not in value
        ]
        if missing:
            raise RefusalHoldKeyError(
                "the key is missing required field(s): " + ", ".join(missing)
            )
        return cls(value["scope_kind"], value["scope_id"], value["action"])

    @property
    def identity(self) -> str:
        """The canonical string form of the key."""
        return f"{self.scope_kind}:{self.scope_id}:{self.action}"


@dataclass(frozen=True)
class RefusalHoldEntry:
    """One refusal row as the hold holds it: **a reference, never a copy**.

    The entry keeps the row itself (not its fields) and the key the row
    covers.  Nothing is duplicated, so a row that is tampered with after
    it was registered is still caught by the tamper check on every query.

    The row is typed as ``Any`` on purpose: the second refusal family --
    ``scope_qualifier.DenialRow`` -- must be *registerable* so that the
    hold can meet it and refuse it, rather than being rejected earlier
    and silently dropped.  A ``DenialRow`` in the store blocks the
    dispatch as an invalid row (see :meth:`is_refusal_row`).
    """

    key: RefusalHoldKey
    row: Any

    def __post_init__(self) -> None:
        if not isinstance(self.key, RefusalHoldKey):
            raise RefusalHoldError(
                f"entry key must be a RefusalHoldKey, got {self.key!r}"
            )
        if self.row is None:
            raise RefusalHoldError("an entry must carry a row, not None")

    @property
    def identity(self) -> str:
        """The key's canonical string form."""
        return self.key.identity

    @property
    def row_digest(self) -> Optional[str]:
        """The ``sha256:`` digest of the referenced row, if it has one.

        A row that is not a refusal row has no digest of its own, so the
        reference is empty -- there is nothing to pin.
        """
        digest = getattr(self.row, "row_digest", None)
        return digest if isinstance(digest, str) else None

    def is_refusal_row(self) -> bool:
        """True when the referenced row is a ``refusal_row.RefusalRow``.

        A ``scope_qualifier.DenialRow`` is **not**: it is a scope verdict
        sidecar with no evidence hash, no ruleset hash, no instrument and
        no population digest, so it cannot be re-verified and it does not
        carry the "two instruments or none" basis.  The second refusal
        family is explicitly excluded.
        """
        return isinstance(self.row, RefusalRow)

    def is_intact(self) -> bool:
        """True when the *live* row is a refusal row that still verifies.

        The check runs against the row the hold holds a reference to, so
        a tamper that happens after registration is caught here.
        """
        if not self.is_refusal_row():
            return False
        return verify_row(self.row)

    def to_dict(self) -> dict:
        """The entry as a plain dict (the row is serialized, not copied)."""
        payload = {
            "schema": SCHEMA_PIN,
            "version": REFUSAL_HOLD_VERSION,
            "key": self.key.identity,
            "scope_kind": self.key.scope_kind,
            "scope_id": self.key.scope_id,
            "action": self.key.action,
            "row_digest": self.row_digest,
        }
        if self.is_refusal_row():
            payload["row"] = self.row.as_dict()
        return payload


@dataclass(frozen=True)
class RefusalHoldResult:
    """The answer to one query: blocked or not, and by which row.

    ``blocked`` is the decision; ``reason`` says which rule produced it;
    ``row`` and ``row_digest`` carry the *reference* to the row that
    blocked the dispatch, so the blocked caller can audit the refusal
    instead of taking a boolean on trust.
    """

    blocked: bool
    reason: str
    key: Optional[RefusalHoldKey] = None
    row: Optional[RefusalRow] = None
    row_digest: Optional[str] = None

    @property
    def has_row(self) -> bool:
        """True when a row reference is attached to the result."""
        return self.row is not None

    def to_dict(self) -> dict:
        """The result as a plain dict."""
        return {
            "blocked": self.blocked,
            "reason": self.reason,
            "key": self.key.identity if self.key is not None else None,
            "row_digest": self.row_digest,
        }


class RefusalHoldStore:
    """Where the hold reads refusal rows from.

    The store is the *only* thing the hold reads, so an unreadable store
    is the canonical "the gate cannot answer" case -- and it blocks.

    The default in-memory store holds the rows the caller registered.
    A caller with rows on disk supplies its own store; the hold only
    requires the store to answer :meth:`fetch` (and optionally
    :meth:`entries`), and it treats every exception from either as
    "unreadable".
    """

    def __init__(self, entries: Iterable[RefusalHoldEntry] = ()) -> None:
        self._entries = list(entries)
        if len(self._entries) > MAX_HOLD_ENTRIES:
            raise RefusalHoldError(
                f"a hold carries at most {MAX_HOLD_ENTRIES} refusals, "
                f"got {len(self._entries)}"
            )
        self._broken = False

    def fetch(self, key: RefusalHoldKey) -> Optional[RefusalHoldEntry]:
        """The entry covering ``key``, or ``None`` when there is none.

        ``None`` means *no refusal covers this key* -- but only after the
        store has answered.  A store that raises is unreadable, and an
        unreadable store blocks.
        """
        if self._broken:
            raise RefusalHoldStoreError("the refusal hold store is unreadable")
        return self._find(key)

    def is_readable(self) -> bool:
        """True when the store can answer at all.

        A caller that wants to know *before* asking may ask this; the
        answer it gets from :meth:`fetch` is the same one.
        """
        if self._broken:
            return False
        return True

    def _find(self, key: RefusalHoldKey) -> Optional[RefusalHoldEntry]:
        """The first entry whose key names the same action."""
        for entry in self._entries:
            if entry.key == key:
                return entry
        return None

    def entries(self) -> Tuple[RefusalHoldEntry, ...]:
        """Every registered entry, in registration order."""
        if self._broken:
            raise RefusalHoldStoreError("the refusal hold store is unreadable")
        return tuple(self._entries)

    def break_reads(self) -> None:
        """Make every read fail (test helper)."""
        self._broken = True

    def repair(self) -> None:
        """Make reads work again (test helper)."""
        self._broken = False


class RefusalHold:
    """The hold: refusal rows in, a blocked/allowed answer out.

    The hold is a **query**, in the shape the repository already owns for
    sticky blocking (``cancellation_tombstone.TombstoneSet.blocked()``).
    It never mutates a refusal and never reads the wall clock.

    Usage::

        hold = RefusalHold(entries=[RefusalHoldKey(...) -> row])
        result = hold.check(key, now=1_700_000_100)
        if result.blocked:
            ...  # result.row is the refusal that stopped the dispatch

    Fail closed: every state in which the hold cannot reach a well-founded
    conclusion -- an unreadable store, a row that no longer verifies, a
    malformed key -- **blocks**.  The repository's own answer is
    ``scope_qualifier.BLOCKING_OUTCOMES``, which contains
    ``OUTCOME_UNKNOWN``: an unknown state is never a clean read.
    """

    def __init__(
        self,
        entries: Iterable[RefusalHoldEntry] = (),
        store: Optional[RefusalHoldStore] = None,
        now: int = 0,
    ) -> None:
        """Build a hold.

        ``entries`` are the refusals the hold knows about; ``store`` is
        where the hold reads from (a default in-memory store is built
        from ``entries`` when none is given).  ``now`` is the
        caller-supplied clock -- this module never reads the wall clock.
        """
        self._entries = list(entries)
        self._store = store if store is not None else RefusalHoldStore(self._entries)
        self._now = int(now)

    # -- reading ----------------------------------------------------------

    def entries(self) -> Tuple[RefusalHoldEntry, ...]:
        """Every entry the hold knows about, in registration order."""
        return tuple(self._entries)

    def __len__(self) -> int:
        return len(self._entries)

    def __iter__(self):
        return iter(self.entries())

    @property
    def now(self) -> int:
        """The hold's caller-supplied clock value."""
        return self._now

    def check(
        self, key: RefusalHoldKey, now: Optional[int] = None
    ) -> RefusalHoldResult:
        """Is this re-dispatch blocked by a refusal, and by which row?

        The check order is fixed and is part of the contract:

        1. **the key** -- a malformed key is **refused**
           (:class:`RefusalHoldKeyError`); it never silently allows.
        2. **the store** -- if it cannot answer, the answer is
           ``blocked_store_unreadable``.
        3. **the row** -- if the entry covering the key carries a row
           that no longer verifies (``refusal_row.verify_row`` is
           False), the answer is ``blocked_row_tampered``.
        4. **the refusal** -- if a verified row covers the key, the
           answer is ``blocked_by_refusal`` and carries the row.
        5. otherwise -- ``allowed_no_refusal``.

        Under this slice's semantics nothing expires, so ``now`` does not
        change the answer.  It is a parameter because the caller owns the
        clock, and because a future expiry fork would not change the API.
        """
        checked = self._require_key(key)
        if not self._store.is_readable():
            # The store already knows it cannot answer.  Fail closed
            # without attempting a read that is known to fail: the
            # answer is the same, and the gate says so out loud.
            return RefusalHoldResult(
                blocked=True,
                reason=REASON_BLOCKED_STORE_UNREADABLE,
                key=checked,
                row=None,
                row_digest=None,
            )
        try:
            entry = self._store.fetch(checked)
        except Exception:
            # An unreadable store is not a clean read: it blocks.
            return RefusalHoldResult(
                blocked=True,
                reason=REASON_BLOCKED_STORE_UNREADABLE,
                key=checked,
                row=None,
                row_digest=None,
            )
        if entry is None:
            # No refusal covers this key.  This conclusion is only
            # reached after the store has answered.
            return RefusalHoldResult(
                blocked=False,
                reason=REASON_ALLOWED_NO_REFUSAL,
                key=checked,
                row=None,
                row_digest=None,
            )
        if not entry.is_refusal_row():
            # The row is not a refusal row at all -- e.g. a
            # ``scope_qualifier.DenialRow``, the second refusal family,
            # which is explicitly excluded.  It blocks: the gate cannot
            # establish that a refusal covers this action.
            return RefusalHoldResult(
                blocked=True,
                reason=REASON_BLOCKED_ROW_INVALID,
                key=checked,
                row=None,
                row_digest=entry.row_digest,
            )
        if not entry.is_intact():
            # The row was tampered with: it is a forgery, not a refusal.
            # The row itself is *not* handed back -- a forged row is not
            # something to trust -- but its digest is, so the operator can
            # name the row that was tampered with.
            return RefusalHoldResult(
                blocked=True,
                reason=REASON_BLOCKED_ROW_TAMPERED,
                key=checked,
                row=None,
                row_digest=entry.row_digest,
            )
        return RefusalHoldResult(
            blocked=True,
            reason=REASON_BLOCKED_BY_REFUSAL,
            key=checked,
            row=entry.row,
            row_digest=entry.row.row_digest,
        )

    def is_blocked(self, key: RefusalHoldKey, now: Optional[int] = None) -> bool:
        """True when the action is blocked by a refusal (or by a broken gate)."""
        return self.check(key, now=now).blocked

    def blocked_row(
        self, key: RefusalHoldKey, now: Optional[int] = None
    ) -> Optional[RefusalRow]:
        """The row that blocks this action, or ``None``.

        ``None`` means *no row blocked it* -- which includes the case
        where the gate was unusable, so a caller that only wants the row
        should look at :meth:`check` and read ``blocked`` as well.
        """
        return self.check(key, now=now).row

    # -- helpers ----------------------------------------------------------

    @staticmethod
    def _require_key(key: Any) -> RefusalHoldKey:
        """The key, or a refusal when it is not a usable key.

        A malformed key never silently allows: the call raises, so the
        dispatch does not proceed on an unverified premise.
        """
        if not isinstance(key, RefusalHoldKey):
            raise RefusalHoldKeyError(
                "a hold key must be a RefusalHoldKey, got "
                f"{type(key).__name__}: a malformed key is refused, never "
                "silently allowed"
            )
        return key

    # -- construction helpers --------------------------------------------

    @classmethod
    def from_rows(
        cls,
        rows: Iterable[RefusalRow],
        keys: Iterable[RefusalHoldKey],
        now: int = 0,
    ) -> "RefusalHold":
        """Build a hold from parallel ``rows`` and ``keys`` iterables.

        The two iterables must be the same length: a refusal with no key
        has no scope, so it cannot block anything, and a key with no
        refusal is not a refusal.
        """
        row_list = list(rows)
        key_list = list(keys)
        if len(row_list) != len(key_list):
            raise RefusalHoldError(
                f"a hold needs one key per refusal row: got {len(row_list)} "
                f"row(s) and {len(key_list)} key(s)"
            )
        entries = [
            RefusalHoldEntry(key=key, row=row)
            for key, row in zip(key_list, row_list)
        ]
        return cls(entries=entries, now=now)

    def to_list(self) -> list:
        """The hold's entries as plain dicts."""
        return [entry.to_dict() for entry in self.entries()]


def main() -> None:
    """Self-check: block, do not over-block, fail closed."""
    from refusal_row import digest_of, record_refusal

    evidence = digest_of({"evidence": "stale"})
    ruleset = digest_of({"ruleset": "gate-v3"})
    population = digest_of({"population": "nightly"})
    row = record_refusal(
        "denied",
        evidence,
        ruleset,
        "check-alpha@v1",
        population,
        reason="the evidence digest does not match the ruleset",
        refused_at=1_700_000_000,
        instruments=["check-alpha@v1", "check-beta@v2"],
    )
    key = RefusalHoldKey("queue", "job-1", "checkout")
    hold = RefusalHold.from_rows([row], [key], now=1_700_000_000)

    blocked = hold.check(key, now=1_700_000_100)
    assert blocked.blocked and blocked.reason == REASON_BLOCKED_BY_REFUSAL
    assert blocked.row is row and blocked.row_digest == row.row_digest

    other = hold.check(RefusalHoldKey("queue", "job-2", "checkout"))
    assert not other.blocked and other.reason == REASON_ALLOWED_NO_REFUSAL

    broken = RefusalHoldStore([RefusalHoldEntry(key=key, row=row)])
    broken.break_reads()
    unreadable = RefusalHold(store=broken).check(key)
    assert unreadable.blocked and unreadable.reason == REASON_BLOCKED_STORE_UNREADABLE

    print("refusal-hold self-check: ok")


if __name__ == "__main__":  # pragma: no cover
    main()

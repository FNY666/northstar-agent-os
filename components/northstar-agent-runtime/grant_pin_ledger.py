"""Authorization grant pins: a three-field pin, and a seal layer that
refuses unnamed grants.

Conclusion 52 (Moltbook post ``41d46080``, comment ``47902c54``): the
authorization pin used to require only a *non-empty string*, and the
ledger layer did not validate its content -- so ``"approved by operator"``
sealed just as validly as a real grant reference, and after the fact
nobody could tell what a sealed row had actually been asking about.  The
point of a record existing is to name what it is asking about.

This module states that rule as data:

* **The pin keeps its three-field shape** -- ``grant_id``, ``version``,
  ``counter``.  No fourth field is invented: the shape stays
  ``(grant id, version, counter)``, consistent with the typed columns of
  conclusion 43 and the operation-id convention of conclusion 62.
* **The grant id is NOT NULL at the seal layer.**  An empty (or missing)
  grant id is refused by :meth:`GrantPinLedger.seal`: the seal fails and
  **no row lands**.  A refused seal must not leave an unnamed hole -- an
  audit row that says nothing about what it authorized is worse than no
  row at all, because it looks like evidence.
* **Version and counter are nullable.**  A pin that names the grant but
  carries no counter is still a *parseable refusal*: the row lands
  normally, its outcome is recorded as ``outcome_unknown`` ("dispatched,
  grant unresolvable"), and the pin is preserved verbatim -- the three
  fields are stored exactly as they were presented, including the nulls.
  That is categorically different from "nothing happened": the ledger
  says the dispatch happened and the grant could not be resolved.

The rule is enforced at the *seal* layer, not at the pin's constructor:
an empty grant id can be *represented* (so the refusal is observable and
testable) but it can never be *sealed*.

Honest scope: this module books what the host reported.  It cannot prove
that a grant existed, that the counter was the right one, or that the
dispatch reached anything.  Sealing proves integrity and order, never
truth -- the same honest gap every ledger in this repo carries.

House style: frozen dataclasses, no wall-clock (caller-supplied int
seqs), fail-closed taxonomy, stdlib-only, ``sha256:`` digest pins,
version/schema pins, ``audit.ndjson/1`` events, ``stdlib_only()`` +
``main()`` self-check.

Version pin: ``grant-pin-ledger.v1``
Schema pin: ``northstar.grant-pin-ledger.v1``
"""

from __future__ import annotations

import ast
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

#: Module version pin.
GRANT_PIN_LEDGER_VERSION = "grant-pin-ledger.v1"

#: Schema pin carried by rows and audit events.
SCHEMA_PIN = "northstar.grant-pin-ledger.v1"

#: Wire format of audit records.
AUDIT_SCHEMA = "audit.ndjson/1"

#: The outcome recorded when the grant cannot be resolved.
OUTCOME_UNKNOWN = "outcome_unknown"

#: Audit event kinds.
KIND_SEALED = "grant-pin.sealed"
KIND_REFUSED = "grant-pin.refused"
_KINDS = frozenset({KIND_SEALED, KIND_REFUSED})

#: The three fields of the pin.  The shape is pinned: no fourth field.
PIN_FIELDS = ("grant_id", "version", "counter")

#: The pin's columns, typed and nullability-declared.
#:
#: Conclusion 43's typed-column discipline, applied to the authorization
#: pin: ``grant_id`` is ``NOT NULL`` (the seal layer refuses an unnamed
#: grant), while ``version`` and ``counter`` are nullable (a grant can be
#: named without being placed in its version/counter order).
PIN_COLUMNS = (
    ("grant_id", "text", False),
    ("version", "text", True),
    ("counter", "int", True),
)

_MAX_ID_CHARS = 256
_MAX_VERSION_CHARS = 256
_MAX_COUNTER = 2**53 - 1


class GrantPinError(Exception):
    """Base class for grant-pin errors."""


class MalformedPinError(GrantPinError):
    """The pin is not a well-formed three-field pin."""


class MissingGrantIdError(GrantPinError):
    """The grant id is empty or missing: the seal is refused, no row lands."""


def _canonical(value: Any) -> bytes:
    """Canonical JSON bytes for digesting (sorted keys, compact, UTF-8)."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _as_grant_id(value: Any) -> str:
    """Coerce a presented grant id to a string (missing -> empty).

    A non-string grant id is *not* silently stringified into a plausible
    name: only ``None`` becomes the empty string (the refused case).
    Anything else must already be a string.
    """
    if value is None:
        return ""
    if not isinstance(value, str):
        raise MalformedPinError("grant_id must be a str")
    return value


def _check_column(value: Any, col_type: str, nullable: bool, name: str) -> None:
    """Type-check one pin column against its declared type.

    The table is :data:`PIN_COLUMNS` -- the same typed-column discipline
    conclusion 43 established for relational rows, with the nullability
    spelled out per column.  ``grant_id`` is NOT NULL: it may be the
    empty string here (the pin is *representable*), but it may never be
    absent, and the seal layer refuses an empty one.
    """
    if value is None:
        if not nullable:
            raise MalformedPinError(f"{name} must not be null")
        return
    if col_type == "text":
        if not isinstance(value, str):
            raise MalformedPinError(f"{name} must be a str")
        limit = _MAX_ID_CHARS if name == "grant_id" else _MAX_VERSION_CHARS
        if len(value) > limit:
            raise MalformedPinError(f"{name} is too long")
        return
    if col_type == "int":
        if isinstance(value, bool) or not isinstance(value, int):
            raise MalformedPinError(f"{name} must be an int")
        if value < 0:
            raise MalformedPinError(f"{name} must be non-negative")
        if value > _MAX_COUNTER:
            raise MalformedPinError(f"{name} exceeds the safe range")
        return
    raise MalformedPinError(f"unknown column type: {col_type!r}")  # pragma: no cover


def _digest(value: Any) -> str:
    """``sha256:`` pin of the canonical form of ``value``."""
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


@dataclass(frozen=True)
class GrantPin:
    """The three-field authorization pin: grant id, version, counter.

    ``grant_id`` names *what the record is asking about*.  It is the one
    field that must not be empty -- but the check lives at the seal layer
    (:meth:`GrantPinLedger.seal`), not here, so that an unnamed grant is
    representable and its refusal is observable.

    ``version`` and ``counter`` are nullable: a pin may name the grant
    without being able to place it in the grant's version/counter order.
    Nulls are preserved verbatim -- the pin is never rewritten to hide
    the absence.
    """

    grant_id: str
    version: Optional[str] = None
    counter: Optional[int] = None

    def __post_init__(self) -> None:
        # A missing grant id becomes the empty string -- representable, and
        # refused by the seal layer.  It is never null: the column is NOT
        # NULL, and the empty string is the honest "unnamed" value.
        object.__setattr__(self, "grant_id", _as_grant_id(self.grant_id))
        for name, col_type, nullable in PIN_COLUMNS:
            _check_column(getattr(self, name), col_type, nullable, name)


    @classmethod
    def from_dict(cls, value: Any) -> "GrantPin":
        """Build a pin from a mapping over the three pinned fields.

        A missing ``grant_id`` is *not* an error here -- it becomes the
        empty string, and the seal layer refuses it.  Keeping the
        representation permissive and the seal strict is what makes the
        refusal observable instead of a construction failure that looks
        like a caller bug.
        """
        if not isinstance(value, dict):
            raise MalformedPinError("pin must be a mapping")
        unknown = sorted(set(value) - set(PIN_FIELDS))
        if unknown:
            raise MalformedPinError(
                "pin carries unknown fields: " + ", ".join(unknown)
            )
        return cls(
            grant_id=_as_grant_id(value.get("grant_id")),
            version=value.get("version"),
            counter=value.get("counter"),
        )


    def to_dict(self) -> Dict[str, Any]:
        """The three fields, verbatim -- nulls included."""
        return {
            "grant_id": self.grant_id,
            "version": self.version,
            "counter": self.counter,
        }

    def is_named(self) -> bool:
        """True when the grant id is a non-empty, non-blank name."""
        return bool(self.grant_id) and bool(self.grant_id.strip())

    def is_resolvable(self) -> bool:
        """True when the grant can be placed in its version/counter order.

        The counter is the ordering key: without it the grant cannot be
        resolved to a state, so the seal records ``outcome_unknown``.
        """
        return self.counter is not None

    def render(self) -> str:
        """Render the three fields into the ledger's ``authorization`` string.

        The rendering keeps the three-field shape and marks absent fields
        explicitly (``null``), so the string can be parsed back into the
        same pin -- that round-trip is the archaeology conclusion 52 asks
        for: a sealed row must still say what it was asking about.
        """
        version = self.version if self.version is not None else "null"
        counter = self.counter if self.counter is not None else "null"
        return f"grant:{self.grant_id};version={version};counter={counter}"

    @classmethod
    def parse(cls, rendered: Any) -> "GrantPin":
        """Parse a rendered authorization string back into a pin.

        This is the inverse of :meth:`render`.  It is what makes a sealed
        row readable after the fact: the row names the grant it asked
        about, instead of an opaque blob.
        """
        if not isinstance(rendered, str) or not rendered:
            raise MalformedPinError("rendered authorization must be a non-empty str")
        if not rendered.startswith("grant:"):
            raise MalformedPinError("rendered authorization is not a grant pin")
        parts = rendered.split(";")
        if len(parts) != 3:
            raise MalformedPinError("rendered authorization must have three parts")
        grant_id = parts[0][len("grant:"):]
        fields: Dict[str, str] = {}
        for part in parts[1:]:
            if "=" not in part:
                raise MalformedPinError("rendered authorization part is malformed")
            key, _, value = part.partition("=")
            fields[key] = value
        if set(fields) != {"version", "counter"}:
            raise MalformedPinError("rendered authorization has the wrong fields")
        version = None if fields["version"] == "null" else fields["version"]
        counter: Optional[int] = None
        if fields["counter"] != "null":
            try:
                counter = int(fields["counter"])
            except ValueError as error:
                raise MalformedPinError(
                    "rendered counter is not an integer"
                ) from error
        return cls(grant_id=grant_id, version=version, counter=counter)



@dataclass(frozen=True)
class SealedGrantRow:
    """One sealed row: the pin verbatim, plus the outcome it was sealed with.

    The pin is stored exactly as presented (nulls included) -- the row
    never rewrites the pin to hide the absence.  ``outcome`` is
    ``outcome_unknown`` when the grant could not be resolved; otherwise it
    is the caller-declared outcome.
    """

    seq: int
    pin: GrantPin
    outcome: str
    digest: str
    schema: str = SCHEMA_PIN

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema,
            "seq": self.seq,
            "grant_id": self.pin.grant_id,
            "version": self.pin.version,
            "counter": self.pin.counter,
            "outcome": self.outcome,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        """Re-derive the row digest (never raises)."""
        try:
            expected = _digest(
                {
                    "seq": self.seq,
                    "pin": self.pin.to_dict(),
                    "outcome": self.outcome,
                    "schema": self.schema,
                }
            )
        except (TypeError, ValueError):
            return False
        return expected == self.digest


def resolve_seal_outcome(pin: "GrantPin", outcome: str) -> str:
    """The outcome a row carrying ``pin`` is sealed with.

    This is the single home of the conclusion-52 rule, so the seal layer
    behaves identically wherever it is applied:

    * an unnamed grant id raises :class:`MissingGrantIdError` -- the seal
      is refused and no row lands;
    * a named grant with no counter is sealed with ``outcome_unknown`` --
      the dispatch happened, the grant could not be resolved.

    ``outcome`` is the caller-declared outcome; it is kept when the grant
    is resolvable.
    """
    if not isinstance(pin, GrantPin):
        raise MalformedPinError("pin must be a GrantPin")
    if not isinstance(outcome, str) or not outcome:
        raise GrantPinError("outcome must be a non-empty string")
    if not pin.is_named():
        raise MissingGrantIdError(
            "grant id must be a non-empty name: an unnamed grant cannot be "
            "sealed (no row lands)"
        )
    return outcome if pin.is_resolvable() else OUTCOME_UNKNOWN


class GrantPinLedger:
    """The seal layer: pins become rows, or the seal is refused.

    ``seal(pin, outcome, seq)``:

    * an unnamed grant id (empty or missing) -> raises
      :class:`MissingGrantIdError` and **no row lands**;
    * a named grant with no counter -> the row lands, its outcome is
      ``outcome_unknown``, and the pin is preserved verbatim;
    * a fully resolved pin -> the row lands with the declared outcome.
    """

    def __init__(self) -> None:
        self._rows: list[SealedGrantRow] = []

    def __len__(self) -> int:
        return len(self._rows)

    @property
    def rows(self) -> Tuple[SealedGrantRow, ...]:
        """Every sealed row, in seal order."""
        return tuple(self._rows)

    def row(self, seq: int) -> SealedGrantRow:
        """The sealed row with 1-based ``seq``."""
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise GrantPinError("seq must be an int")
        if seq < 1 or seq > len(self._rows):
            raise GrantPinError("unknown seq")
        return self._rows[seq - 1]

    def seal(
        self,
        pin: GrantPin,
        *,
        outcome: str = "executed",
        seq: int = 0,
    ) -> SealedGrantRow:
        """Seal one grant pin into a row.

        The grant id is NOT NULL here: an empty or missing grant id is
        refused before any row is written, so a refused seal cannot leave
        an unnamed hole in the ledger.  A named grant with a null counter
        lands with the outcome rewritten to ``outcome_unknown`` -- the
        dispatch happened, the grant could not be resolved.
        """
        if not isinstance(pin, GrantPin):
            raise MalformedPinError("pin must be a GrantPin")
        if not isinstance(outcome, str) or not outcome:
            raise GrantPinError("outcome must be a non-empty string")
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise GrantPinError("seq must be a non-negative int")
        # The rule lives in resolve_seal_outcome(); the grant id is NOT
        # NULL here, so a refused seal cannot leave an unnamed hole.
        sealed_outcome = resolve_seal_outcome(pin, outcome)
        row = SealedGrantRow(
            seq=seq,
            pin=pin,
            outcome=sealed_outcome,
            digest=_digest(
                {
                    "seq": seq,
                    "pin": pin.to_dict(),
                    "outcome": sealed_outcome,
                    "schema": SCHEMA_PIN,
                }
            ),
        )
        self._rows.append(row)
        return row

    def seal_into(
        self,
        pin: GrantPin,
        ledger: Any,
        *,
        intent: str = "grant-dispatch",
        action: str = "dispatch",
        subject: str = "",
        outcome: str = "executed",
        seq: int = 0,
    ) -> SealedGrantRow:
        """Seal a pin into this ledger *and* into a forward-seal ledger.

        The forward-seal ledger's ``authorization`` field carries the
        rendered pin, so the sealed chain still names the grant after the
        fact -- that is the archaeology conclusion 52 asks for.

        The grant id is NOT NULL at this layer too: an unnamed grant is
        refused before either ledger is touched, so no unnamed hole can be
        left in either store.
        """
        if not isinstance(pin, GrantPin):
            raise MalformedPinError("pin must be a GrantPin")
        if ledger is None or not callable(getattr(ledger, "append", None)):
            raise GrantPinError("ledger must have append()")
        if not isinstance(subject, str) or not subject:
            raise GrantPinError("subject must be a non-empty string")
        # The rule is applied first, so an unnamed grant is refused before
        # either ledger is touched.
        sealed_outcome = resolve_seal_outcome(pin, outcome)
        row = SealedGrantRow(
            seq=seq,
            pin=pin,
            outcome=sealed_outcome,
            digest=_digest(
                {
                    "seq": seq,
                    "pin": pin.to_dict(),
                    "outcome": sealed_outcome,
                    "schema": SCHEMA_PIN,
                }
            ),
        )
        # The chain is written first: if that append fails, no local row
        # has landed either, so the two stores cannot disagree about
        # whether the grant was sealed.
        ledger.append(
            intent=intent,
            action=action,
            subject=subject,
            authorization=pin.render(),
            inputs_digest=_digest(pin.to_dict()),
            logic_digest=_digest({"fields": list(PIN_FIELDS)}),
            execution_digest=row.digest,
            outcome=row.outcome,
        )
        self._rows.append(row)
        return row


def grant_pin_audit_event(
    kind: str, detail: Dict[str, Any], seq: int
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the grant-pin seal layer.

    Only ids, pins, outcomes and counts cross the audit boundary -- never
    the raw decision payload.
    """
    if not isinstance(kind, str) or kind not in _KINDS:
        raise GrantPinError(f"unknown audit kind: {kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise GrantPinError("seq must be a non-negative int")
    if not isinstance(detail, dict):
        raise GrantPinError("detail must be a mapping")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": GRANT_PIN_LEDGER_VERSION,
        "detail": dict(detail),
        "seq": seq,
    }


def stdlib_only() -> bool:
    """AST check: this module imports stdlib modules only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {
        "__future__",
        "ast",
        "dataclasses",
        "hashlib",
        "json",
        "pathlib",
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
    """Self-check: named pin seals, unnamed pin is refused, null counter
    lands as outcome_unknown."""
    ledger = GrantPinLedger()

    # Full pin: unchanged behaviour.
    row = ledger.seal(GrantPin("grant-1", "v2", 7), outcome="executed", seq=1)
    assert row.outcome == "executed"
    assert row.pin.to_dict() == {
        "grant_id": "grant-1", "version": "v2", "counter": 7
    }
    assert row.verify()

    # Named grant, null counter: lands, outcome_unknown, pin verbatim.
    row2 = ledger.seal(GrantPin("grant-2", "v1", None), outcome="executed", seq=2)
    assert row2.outcome == OUTCOME_UNKNOWN
    assert row2.pin.counter is None
    assert row2.pin.version == "v1"
    assert len(ledger) == 2

    # Unnamed grant: refused, no row lands.
    try:
        ledger.seal(GrantPin("", "v1", 3), outcome="executed", seq=3)
        raise AssertionError("should raise")
    except MissingGrantIdError:
        pass
    assert len(ledger) == 2

    assert stdlib_only()
    print(
        "grant-pin-ledger OK: named seals, unnamed refused, "
        "null counter lands outcome_unknown, stdlib"
    )


if __name__ == "__main__":
    main()

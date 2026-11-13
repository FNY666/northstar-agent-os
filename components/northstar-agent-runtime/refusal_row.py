"""Refusal as a first-class row: a "no" that is an auditable record.

What was missing
----------------
Northstar already knows how to *classify* a failure (:mod:`tool_failure`
normalizes every tool failure into a typed, remedy-carrying record) and how
to book a check that ran (:mod:`planted_fault` records a catch or a miss in
an evidence ledger, and :mod:`scope_qualifier` keeps a ``DenialRow`` sidecar
whose ``denied`` row says "the scope is refused").  What none of them can
express is the difference the source names:

  **A refusal that leaves no record is indistinguishable from a check that
  never ran.**

Northstar's ``outcome_unknown`` (``scope_qualifier.OUTCOME_UNKNOWN`` and
friends) is the closest existing word: "the source line or the refusal row
could not be retrieved, so the outcome is *unknown* -- never a clean read".
But ``outcome_unknown`` is the state of a *missing* answer; it is not the
answer.  A refusal is an answer -- "no" -- and it needs its own row, with
enough fields that a reader can check the "no" without trusting the process
that produced it.

What this module implements
---------------------------
A :class:`RefusalRow` is one refusal, recorded as a frozen, append-only row:

* ``verdict`` -- what was decided;
* ``evidence_hash`` -- the digest of the evidence the "no" rests on;
* ``ruleset_hash`` -- the digest of the rules that were applied;
* ``verifier_key`` -- which instrument produced the verdict;
* ``population_digest`` -- the digest of the population the refusal was
  taken over (the source names this field as the one that is *missing*);
* ``refused_at`` -- caller-supplied clock (no wall clock in recorded rows);
* ``reason`` -- why.

The row is **fail closed**.  A row missing any one of the four
evidence/ruleset/verifier/population fields is not a refusal row, so
creating one is refused.  The population digest is called out by the source
as "the missing population digest field": a refusal without one is an
incomplete refusal.

The two-instrument rule
-----------------------
The source states it as "two instruments or none".  A refusal verdict that
one instrument produced alone is not a refusal -- it is an opinion -- so:

* two or more **distinct** verifier keys: recorded normally;
* exactly one distinct key: the caller must *explicitly* declare
  ``single_instrument=True`` and give a reason; the row is then marked
  ``SINGLE_INSTRUMENT`` so a reader sees the weaker basis on the row
  itself, not in a log line;
* zero instruments: refused.  A "refusal" with no instrument is not a
  refusal, it is an absence -- and absence is already spelled
  ``outcome_unknown`` elsewhere in the runtime.

The row is immutable: it is a frozen dataclass, there is no update
function, and to change a refusal you record another row.

Source mapping
--------------
**Source (hermesagentj, "The most useful thing I built this month is a
check that refuses to run", Moltbook post
``abe9e16f-21a4-4d38-a2b1-03fd84c3543c``).**  Verbatim from the task
book's quotation of the mechanism:

> refusal as a first-class row -- verdict, evidence hash, ruleset hash,
> verifier key; "two instruments or none"; the missing population digest
> field.

**Northstar extensions** (not in the source): the ``sha256:`` digest
format, the verifier-key format, the ``SINGLE_INSTRUMENT`` marker spelling,
the row self-digest used to detect tampering, the closed verdict *format*
(the source fixes no verdict vocabulary), and the requirement that a
single-instrument refusal carry a reason.

House style: frozen dataclasses, caller-supplied clock, fail-closed
taxonomy, stdlib-only, ``sha256:`` digest pins, version/schema pins.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

__all__ = [
    "REFUSAL_ROW_VERSION",
    "SCHEMA_PIN",
    "DIGEST_PREFIX",
    "MARKER_SINGLE_INSTRUMENT",
    "RefusalRowError",
    "RefusalRow",
    "digest_of",
    "record_refusal",
    "row_errors",
    "verify_row",
]

#: Module version pin.
REFUSAL_ROW_VERSION = "refusal-row.v1"

#: Schema pin carried by refusal rows.
SCHEMA_PIN = "northstar.refusal-row.v1"

#: Every digest field in this module uses this prefix (Northstar extension).
DIGEST_PREFIX = "sha256:"

#: Marker written on a row that rests on a single instrument.
MARKER_SINGLE_INSTRUMENT = "SINGLE_INSTRUMENT"

#: A digest is the prefix plus exactly 64 lowercase hex characters.
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

#: A verifier key is ``<subject>@<version>`` (Northstar extension -- the
#: source names the field but not its format).
_VERIFIER_KEY_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*@[a-z0-9][a-z0-9._+-]*$")

#: A verdict is a lowercase slug (Northstar extension -- the source fixes no
#: verdict vocabulary, only that a refusal carries one).
_VERDICT_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")


class RefusalRowError(ValueError):
    """Fail-closed: an illegal refusal row is refused, never defaulted."""


def _canonical(value: Any) -> bytes:
    """Canonical JSON bytes for digesting (sorted keys, compact, UTF-8)."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def digest_of(value: Any) -> str:
    """``sha256:`` digest of the canonical form of ``value``.

    The helper the callers use to fill ``evidence_hash``, ``ruleset_hash``
    and ``population_digest``.  It is deliberately public: a refusal row's
    digest fields are only meaningful if someone can recompute them.
    """
    return DIGEST_PREFIX + hashlib.sha256(_canonical(value)).hexdigest()


def _check_digest(value: Any, name: str) -> str:
    """Validate a digest field: ``sha256:`` + 64 lowercase hex chars."""
    if not isinstance(value, str) or not value.strip():
        raise RefusalRowError(
            f"{name} is required: a refusal row without it is not a refusal row"
        )
    text = value.strip()
    if not _DIGEST_RE.match(text):
        raise RefusalRowError(
            f"{name} must be '{DIGEST_PREFIX}' followed by 64 lowercase hex "
            f"characters, got {value!r}"
        )
    return text


def _check_verifier_key(value: Any, name: str = "verifier_key") -> str:
    """Validate a verifier key: ``<subject>@<version>``."""
    if not isinstance(value, str) or not value.strip():
        raise RefusalRowError(
            f"{name} is required: a refusal row without it is not a refusal row"
        )
    text = value.strip()
    if not _VERIFIER_KEY_RE.match(text):
        raise RefusalRowError(
            f"{name} must look like '<subject>@<version>', got {value!r}"
        )
    return text


def _check_verdict(value: Any) -> str:
    """Validate the verdict: a non-empty lowercase slug."""
    if not isinstance(value, str) or not value.strip():
        raise RefusalRowError("verdict is required: a refusal carries a verdict")
    text = value.strip()
    if not _VERDICT_RE.match(text):
        raise RefusalRowError(f"verdict must be a lowercase slug, got {value!r}")
    return text


def _check_text(value: Any, name: str) -> str:
    """Validate a free-text field: a string (possibly empty for ``reason``)."""
    if not isinstance(value, str):
        raise RefusalRowError(f"{name} must be a string, got {value!r}")
    return value.strip()


@dataclass(frozen=True)
class RefusalRow:
    """One refusal, recorded as an immutable, auditable row.

    The row is **append-only**: it is a frozen dataclass, and this module
    deliberately provides no "update" function -- to change a refusal you
    record another row.  A row whose fields were edited in place is a
    forgery, and :func:`verify_row` says so.

    Every one of the four evidence fields is mandatory.  The population
    digest is the field the source names as missing; missing it means the
    refusal is incomplete, so creating the row is refused.
    """

    verdict: str
    evidence_hash: str
    ruleset_hash: str
    verifier_key: str
    population_digest: str
    refused_at: int = 0
    reason: str = ""
    #: Every distinct instrument that produced the verdict, in call order.
    instruments: Tuple[str, ...] = ()
    #: True when the row rests on a single instrument (explicitly declared).
    single_instrument: bool = False
    #: The row's own digest over its content (Northstar extension): the
    #: tamper check in :func:`verify_row`.
    row_digest: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "verdict", _check_verdict(self.verdict))
        object.__setattr__(
            self, "evidence_hash", _check_digest(self.evidence_hash, "evidence_hash")
        )
        object.__setattr__(
            self, "ruleset_hash", _check_digest(self.ruleset_hash, "ruleset_hash")
        )
        object.__setattr__(
            self, "population_digest",
            _check_digest(self.population_digest, "population_digest"),
        )
        if not isinstance(self.refused_at, int) or isinstance(self.refused_at, bool):
            raise RefusalRowError(
                f"refused_at must be an int (caller-supplied clock), got {self.refused_at!r}"
            )
        object.__setattr__(self, "reason", _check_text(self.reason, "reason"))

        if isinstance(self.instruments, str) or not isinstance(
            self.instruments, (list, tuple)
        ):
            raise RefusalRowError(
                f"instruments must be a list of verifier keys, got {self.instruments!r}"
            )
        cleaned: List[str] = []
        for key in self.instruments:
            cleaned.append(_check_verifier_key(key, "instrument"))
        # The primary key must be one of the instruments.
        primary = _check_verifier_key(self.verifier_key)
        if primary not in cleaned:
            raise RefusalRowError(
                "verifier_key must be one of the recorded instruments: "
                f"{primary!r} is not in {cleaned!r}"
            )
        distinct = tuple(dict.fromkeys(cleaned))
        object.__setattr__(self, "instruments", distinct)
        object.__setattr__(self, "verifier_key", primary)

        if len(distinct) < 2:
            if not self.single_instrument:
                raise RefusalRowError(
                    "two instruments or none: a refusal resting on a single "
                    "instrument must declare single_instrument=True explicitly"
                )
            if not self.reason:
                raise RefusalRowError(
                    "a single-instrument refusal must carry a reason saying why "
                    "a second instrument was not available"
                )
        else:
            if self.single_instrument:
                raise RefusalRowError(
                    "single_instrument=True contradicts the recorded instruments: "
                    f"{len(distinct)} distinct instruments are present"
                )
        object.__setattr__(self, "single_instrument", bool(self.single_instrument))

        if not self.row_digest:
            object.__setattr__(self, "row_digest", self.content_digest())
        elif self.row_digest != self.content_digest():
            # A row may not arrive with a digest that does not describe it.
            # This closes ``dataclasses.replace``: replacing a field on a
            # frozen row would carry the *old* digest, which no longer
            # matches the new content -- so the replacement is refused.
            raise RefusalRowError(
                "row_digest does not match the row content: a refusal row is "
                "append-only, so it cannot be rebuilt with different fields"
            )

    # -- accessors ----------------------------------------------------------

    @property
    def marker(self) -> str:
        """The marker on the row: ``SINGLE_INSTRUMENT`` or ``""``."""
        return MARKER_SINGLE_INSTRUMENT if self.single_instrument else ""

    @property
    def instrument_count(self) -> int:
        """How many distinct instruments the refusal rests on."""
        return len(self.instruments)

    def body(self) -> Dict[str, Any]:
        """The row's content, without its own digest."""
        return {
            "verdict": self.verdict,
            "evidence_hash": self.evidence_hash,
            "ruleset_hash": self.ruleset_hash,
            "verifier_key": self.verifier_key,
            "population_digest": self.population_digest,
            "refused_at": self.refused_at,
            "reason": self.reason,
            "instruments": list(self.instruments),
            "single_instrument": self.single_instrument,
            "marker": self.marker,
        }

    def content_digest(self) -> str:
        """The ``sha256:`` digest of :meth:`body`."""
        return digest_of(self.body())

    def as_dict(self) -> Dict[str, Any]:
        """The row as a plain dict, including ``row_digest`` and ``marker``."""
        payload = self.body()
        payload["row_digest"] = self.row_digest
        payload["schema"] = SCHEMA_PIN
        payload["version"] = REFUSAL_ROW_VERSION
        return payload


def record_refusal(
    verdict: str,
    evidence_hash: str,
    ruleset_hash: str,
    verifier_key: str,
    population_digest: str,
    reason: str = "",
    refused_at: int = 0,
    instruments: Optional[Sequence[str]] = None,
    single_instrument: bool = False,
) -> RefusalRow:
    """Record one refusal as an auditable row.

    Fail closed at every step:

    * the four evidence fields (``evidence_hash``, ``ruleset_hash``,
      ``verifier_key``, ``population_digest``) must be present and
      correctly formatted -- a refusal missing any of them is not a
      refusal row;
    * **zero instruments is refused**: a "refusal" with no instrument is
      an absence, and absence is ``outcome_unknown`` elsewhere, not a
      refusal;
    * **one instrument** requires ``single_instrument=True`` *and* a
      reason; the row is then marked ``SINGLE_INSTRUMENT``;
    * **two or more distinct instruments** are recorded normally.

    ``instruments`` defaults to ``[verifier_key]`` -- a one-instrument
    refusal must then be declared explicitly.
    """
    if instruments is None:
        keys: Tuple[str, ...] = (verifier_key,)
    elif isinstance(instruments, str):
        raise RefusalRowError(
            f"instruments must be a list of verifier keys, got the string {instruments!r}"
        )
    else:
        keys = tuple(instruments)
    if not keys:
        raise RefusalRowError(
            "two instruments or none: a refusal with zero instruments is an "
            "absence, not a refusal"
        )
    return RefusalRow(
        verdict=verdict,
        evidence_hash=evidence_hash,
        ruleset_hash=ruleset_hash,
        verifier_key=verifier_key,
        population_digest=population_digest,
        refused_at=refused_at,
        reason=reason,
        instruments=keys,
        single_instrument=single_instrument,
    )


def row_errors(row: Any) -> Tuple[str, ...]:
    """Every reason ``row`` is not a valid refusal row (empty when it is).

    A row that was built through :func:`record_refusal` and never edited
    has no errors.  A row whose fields were tampered with -- including a
    row whose ``row_digest`` no longer matches its content -- has at
    least one.
    """
    if not isinstance(row, RefusalRow):
        return ("not a RefusalRow",)
    errors: List[str] = []
    for name in ("evidence_hash", "ruleset_hash", "population_digest"):
        value = getattr(row, name, None)
        if not isinstance(value, str) or not _DIGEST_RE.match(value):
            errors.append(f"{name} is missing or malformed")
    if not isinstance(row.verifier_key, str) or not _VERIFIER_KEY_RE.match(
        row.verifier_key
    ):
        errors.append("verifier_key is missing or malformed")
    if not isinstance(row.verdict, str) or not row.verdict.strip():
        errors.append("verdict is missing")
    if not getattr(row, "instruments", ()):
        errors.append("no instrument is recorded")
    else:
        if len(row.instruments) < 2 and not row.single_instrument:
            errors.append(
                "a single-instrument refusal must declare single_instrument=True"
            )
        if len(row.instruments) < 2 and row.single_instrument and not row.reason:
            errors.append("a single-instrument refusal must carry a reason")
        if len(row.instruments) >= 2 and row.single_instrument:
            errors.append("single_instrument=True contradicts the recorded instruments")
        if row.verifier_key not in row.instruments:
            errors.append("verifier_key is not one of the recorded instruments")
    if not row.row_digest:
        errors.append("row_digest is missing")
    elif row.row_digest != row.content_digest():
        errors.append("row_digest does not match the row content (tampered)")
    return tuple(errors)


def verify_row(row: Any) -> bool:
    """Re-verify a refusal row.

    True when the row is a well-formed refusal row whose fields are all
    present, correctly formatted, mutually consistent, and whose
    ``row_digest`` still matches its content.  False for a tampered row --
    a row whose digest no longer matches its content is a forgery, not a
    refusal.
    """
    return not row_errors(row)


def main() -> None:
    """Self-check: the two-instrument path and the fail-closed paths."""
    ev = digest_of({"evidence": "stale"})
    rs = digest_of({"ruleset": "v3"})
    pop = digest_of({"population": "nightly"})

    row = record_refusal(
        "denied",
        ev,
        rs,
        "check-a@v1",
        pop,
        reason="the evidence digest does not match the ruleset",
        refused_at=1_700_000_000,
        instruments=["check-a@v1", "check-b@v2"],
    )
    assert verify_row(row), row_errors(row)
    assert row.marker == ""
    assert row.instrument_count == 2

    single = record_refusal(
        "denied",
        ev,
        rs,
        "check-a@v1",
        pop,
        reason="only one verifier was available at the boundary",
        refused_at=1_700_000_001,
        instruments=["check-a@v1"],
        single_instrument=True,
    )
    assert single.marker == MARKER_SINGLE_INSTRUMENT
    assert verify_row(single)

    for bad in (
        lambda: record_refusal("denied", ev, rs, "check-a@v1", "", instruments=["a@v1", "b@v2"]),
        lambda: record_refusal("denied", ev, rs, "check-a@v1", pop, instruments=[]),
        lambda: record_refusal("denied", ev, rs, "check-a@v1", pop, instruments=["check-a@v1"]),
    ):
        try:
            bad()
        except RefusalRowError:
            continue
        raise AssertionError("a refusal that should have been refused was recorded")

    print("refusal-row self-check: ok")


if __name__ == "__main__":  # pragma: no cover
    main()

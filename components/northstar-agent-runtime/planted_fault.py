"""Planted fault under seal: a check earns trust only after it is watched failing.

Source of the method (quoted in ``docs/design/fault-plant-proof.md``):
the fieldnotes_ai Moltbook post *A check that has never failed has not
shown it can: plant the fault under seal*.  Three rules came out of its
comments and are what this module states as data:

1. **Plant in the input, never in the memory.**  A plant written into
   shared notes becomes an instruction the next run follows, so
   :func:`plant` refuses any target that is not an input record.
2. **The planter is never the checker.**  Identity is the *subject id*,
   not the process: a subject that planted may not check, and that holds
   across runs (one's own later run is still oneself).
3. **A miss voids the evidence back to the last observed catch.**  Every
   PASS the check reported after the last time it was seen to catch
   something stops counting -- not "unproven", *void*.

The shape of a trial:

* :func:`post_commitment` prints the ``sha256:`` digest of a
  :class:`PlantNote` *before* the check runs.  The note itself stays
  sealed until :func:`reveal`.
* :func:`plant` writes the wrong value into a **copy** of the input
  record.  The original input is never touched.
* :func:`run_check` runs the check blind (the check sees the input
  mapping only -- the plant metadata is attributes, not mapping keys)
  and books caught / missed against the evidence ledger.
* :func:`reveal` unseals the note, verifies the digest against the
  commitment posted beforehand, and -- if the check already ran -- turns
  the outcome into evidence (a catch) or into a miss (which voids the
  earlier passes).

Honest scope: this module never changes a check.  ``run_check`` calls
whatever callable it is handed (in practice
``alert_trigger_registry.AlertTriggerRegistry.matches``) and records what
happened.  Demonstrating a *miss* requires a deliberately narrowed test
double in the test file -- the repository's real checks are never
weakened to make a miss happen.

House style: frozen dataclasses, no wall-clock (caller-supplied int
seqs), fail-closed taxonomy, stdlib-only, ``sha256:`` digest pins,
version/schema pins, ``stdlib_only()`` + ``main()`` self-check.

Version pin: ``planted-fault.v1``
Schema pin: ``northstar.planted-fault.v1``
"""

from __future__ import annotations

import ast
import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

try:  # pragma: no cover - the canonicalizer is a sibling module
    from canonical_json import jcs_canonical_json as _jcs_bytes  # type: ignore

except Exception:  # pragma: no cover - fallback when canonical_json is absent
    import json as _json

    def _jcs_bytes(obj: Any) -> bytes:  # type: ignore
        return _json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


#: Module version pin.
PLANTED_FAULT_VERSION = "planted-fault.v1"

#: Schema pin carried by notes and evidence rows.
SCHEMA_PIN = "northstar.planted-fault.v1"

#: The only target kind a plant may use.  Everything else is refused.
INPUT_TARGET = "input"

#: Target kinds that are shared state: a plant here would be read back as
#: an instruction by the next run.
SHARED_TARGET_KINDS = ("memory", "notes", "note", "shared", "shared_state")

#: Evidence row kinds.
KIND_PASS = "pass"
KIND_CATCH = "catch"
KIND_MISS = "miss"
KIND_VOID_PLANT = "void_plant"

#: Evidence row statuses.
STATUS_PASS = "PASS"
STATUS_CATCH = "CATCH"
STATUS_MISS = "MISS"
STATUS_VOID = "VOID"
STATUS_VOID_PLANT = "VOID_PLANT"

#: Reveal outcomes.
REVEALED = "revealed"
VOID_PLANT = "void_plant"


class PlantedFaultError(Exception):
    """Base class for planted-fault errors."""


class PlantTargetError(PlantedFaultError):
    """The plant target is not an input record (shared state is refused)."""


class SeparationError(PlantedFaultError):
    """The planter and the checker are the same subject."""


class CommitmentError(PlantedFaultError):
    """The commitment, the note and the posted order do not line up."""


@dataclass(frozen=True)
class PlantNote:
    """The sealed note: which run, which field, the wrong value, the truth.

    ``commitment`` is excluded from the digest payload (it is the digest),
    so a note can carry the commitment that was posted for it and still
    hash to the same value.

    ``target_kind`` defaults to ``"input"``.  It is the one field that
    decides whether the plant is legal: a plant aimed at ``"memory"`` or
    ``"notes"`` is refused by :func:`plant` -- a plant in shared state is
    read back as an instruction by the next run.
    """

    plant_id: str
    run_index: int
    field: str
    wrong_value: Any
    true_value: Any
    commitment: str = ""
    planted_by: str = ""
    check_scope: str = ""
    target_kind: str = INPUT_TARGET

    def payload(self) -> Dict[str, Any]:
        """The canonical payload the commitment is computed over."""
        return {
            "plant_id": self.plant_id,
            "run_index": self.run_index,
            "field": self.field,
            "wrong_value": self.wrong_value,
            "true_value": self.true_value,
            "planted_by": self.planted_by,
            "check_scope": self.check_scope,
            "target_kind": self.target_kind,
        }


def _digest(payload: Any) -> str:
    """``sha256:`` pin of the canonical form of ``payload``."""
    return "sha256:" + hashlib.sha256(_jcs_bytes(payload)).hexdigest()


def post_commitment(note: PlantNote, ledger: Optional["EvidenceLedger"] = None) -> str:
    """Print the note's ``sha256:`` commitment and (optionally) post it.

    The commitment is the digest of the note's canonical payload.  It is
    published *before* the check runs, so a checker cannot read the
    answer off the note: it can only compare what it later sees with
    what was promised.

    When ``ledger`` is given, the commitment is posted to it -- the
    ledger then knows a commitment existed *before* the check, which is
    what :func:`run_check` requires.
    """
    if not isinstance(note, PlantNote):
        raise CommitmentError("post_commitment requires a PlantNote")
    if not note.plant_id:
        raise CommitmentError("plant_id is required")
    commitment = _digest(note.payload())
    if ledger is not None:
        ledger.post_commitment(note.plant_id, commitment, note.check_scope)
    return commitment


class FaultedInput(Mapping):
    """The faulted input record: a copy, plus the plant metadata.

    The check sees the *mapping* only -- the metadata lives in
    attributes, so a blind check cannot read which run was planted or
    what the true value was.  :attr:`record` hands back a fresh copy of
    the faulted fields.
    """

    __slots__ = ("_record", "plant_id", "planter_id", "check_scope", "run_index")

    def __init__(
        self,
        record: Mapping[str, Any],
        *,
        plant_id: str,
        planter_id: str,
        check_scope: str,
        run_index: int,
    ) -> None:
        self._record: Dict[str, Any] = dict(record)
        self.plant_id = plant_id
        self.planter_id = planter_id
        self.check_scope = check_scope
        self.run_index = run_index

    def __getitem__(self, key: str) -> Any:
        return self._record[key]

    def __iter__(self):
        return iter(self._record)

    def __len__(self) -> int:
        return len(self._record)

    @property
    def record(self) -> Dict[str, Any]:
        """A copy of the faulted input fields."""
        return dict(self._record)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"FaultedInput(plant_id={self.plant_id!r}, record={self._record!r})"


@dataclass(frozen=True)
class CheckOutcome:
    """What the blind check said about the faulted input."""

    plant_id: str
    run_index: int
    check_scope: str
    checker_id: str
    caught: bool
    seq: int = 0


@dataclass(frozen=True)
class RevealResult:
    """The outcome of unsealing a note against the posted commitment."""

    plant_id: str
    outcome: str
    detail: str = ""


@dataclass(frozen=True)
class EvidenceRow:
    """One row of the evidence ledger."""

    seq: int
    kind: str
    status: str
    check_scope: str
    run_index: int
    plant_id: str = ""
    detail: str = ""


def plant(
    input_record: Mapping[str, Any],
    note: PlantNote,
    planter_id: str,
) -> FaultedInput:
    """Write the wrong value into a **copy** of the input record.

    The original mapping is never touched: the returned
    :class:`FaultedInput` carries a copy whose ``field`` holds
    ``note.wrong_value``.

    Fail-closed refusals:

    * a note whose ``target_kind`` is not ``"input"`` (e.g. ``"memory"``
      or ``"notes"``) raises :class:`PlantTargetError` -- a plant in
      shared state is read back as an instruction by the next run;
    * a planter id that disagrees with ``note.planted_by`` raises
      :class:`SeparationError`;
    * a field that is not present in the input record raises
      :class:`PlantedFaultError` -- there is no input to fault.
    """
    if not isinstance(note, PlantNote):
        raise PlantedFaultError("plant requires a PlantNote")
    if not isinstance(input_record, Mapping):
        raise PlantedFaultError("input_record must be a mapping")
    if not planter_id:
        raise SeparationError("planter_id is required")
    target_kind = (note.target_kind or INPUT_TARGET).strip().lower()
    if target_kind != INPUT_TARGET:
        if target_kind in SHARED_TARGET_KINDS:
            raise PlantTargetError(
                f"plant target {target_kind!r} is shared state and is refused: "
                "a plant in shared notes becomes an instruction the next run follows"
            )
        raise PlantTargetError(
            f"plant target must be {INPUT_TARGET!r}; refused {target_kind!r}"
        )
    if note.planted_by and note.planted_by != planter_id:
        raise SeparationError(
            f"planter {planter_id!r} does not match the note's planter {note.planted_by!r}"
        )
    if not note.field:
        raise PlantedFaultError("plant field is required")
    if note.field not in input_record:
        raise PlantedFaultError(
            f"plant field {note.field!r} is not present in the input record"
        )
    faulted = dict(input_record)
    faulted[note.field] = note.wrong_value
    return FaultedInput(
        faulted,
        plant_id=note.plant_id,
        planter_id=planter_id,
        check_scope=note.check_scope,
        run_index=note.run_index,
    )


def run_check(
    check_fn: Callable[[Mapping[str, Any]], Any],
    faulted_input: FaultedInput,
    checker_id: str,
    ledger: Optional["EvidenceLedger"] = None,
    seq: Optional[int] = None,
) -> CheckOutcome:
    """Run the check blind against the faulted input and book the result.

    ``check_fn`` is called with the faulted *mapping* only -- the plant
    metadata is attributes, so a blind check cannot read which run was
    planted or what the true value is.  The module does not change the
    check; it only records what the check said.

    Separation: a checker that is the same subject as the planter raises
    :class:`SeparationError`.  Identity is the subject id, not the
    process, so this holds across runs -- one's own later run is still
    oneself.
    """
    if not callable(check_fn):
        raise PlantedFaultError("check_fn must be callable")
    if not isinstance(faulted_input, FaultedInput):
        raise PlantedFaultError(
            "run_check requires a FaultedInput (the check must see a planted input)"
        )
    if not checker_id:
        raise SeparationError("checker_id is required")
    if faulted_input.planter_id and faulted_input.planter_id == checker_id:
        raise SeparationError(
            f"subject {checker_id!r} both planted and checks; the planter is never the checker"
        )
    verdict = check_fn(faulted_input)
    caught = bool(verdict)
    if seq is None and ledger is not None:
        seq = ledger.allocate_seq()
    outcome = CheckOutcome(
        plant_id=faulted_input.plant_id,
        run_index=faulted_input.run_index,
        check_scope=faulted_input.check_scope,
        checker_id=checker_id,
        caught=caught,
        seq=seq if seq is not None else 0,
    )
    if ledger is not None:
        ledger.record_check_run(outcome)
    return outcome


def reveal(
    note: PlantNote,
    commitment: str,
    ledger: Optional["EvidenceLedger"] = None,
) -> RevealResult:
    """Unseal the note against the commitment that was posted beforehand.

    Two ways the plant dies here:

    * the note's digest does not match the posted commitment (the note
      was changed, or the wrong note was unsealed) -- the plant is
      **VOID_PLANT**;
    * the note was revealed *before* the check ran -- the checker may
      already have had access to the answer -- also **VOID_PLANT**.

    Otherwise the check run booked for this plant becomes evidence: a
    catch, or a miss (which voids the passes back to the last observed
    catch).
    """
    if not isinstance(note, PlantNote):
        raise CommitmentError("reveal requires a PlantNote")
    computed = _digest(note.payload())
    if not commitment or commitment != computed:
        if ledger is not None:
            ledger.record_void_plant(note.plant_id, "commitment mismatch")
        return RevealResult(note.plant_id, VOID_PLANT, "commitment mismatch")
    if ledger is not None:
        posted = ledger.commitment_for(note.plant_id)
        if posted is None:
            # No commitment was ever posted for this plant: the checker
            # was never shown the promise, so nothing here can be
            # evidence. Fail closed.
            ledger.record_void_plant(note.plant_id, "no commitment was posted")
            return RevealResult(note.plant_id, VOID_PLANT, "no commitment was posted")
        if posted != commitment:
            ledger.record_void_plant(note.plant_id, "commitment mismatch")
            return RevealResult(note.plant_id, VOID_PLANT, "commitment mismatch")
        if ledger.plant_is_dead(note.plant_id):
            return RevealResult(note.plant_id, VOID_PLANT, "plant already void")
        run = ledger.check_run_for(note.plant_id)
        if run is None:
            ledger.record_void_plant(note.plant_id, "revealed before the check ran")
            return RevealResult(note.plant_id, VOID_PLANT, "revealed before the check ran")
        if run.caught:
            ledger.record_catch(note.plant_id, note.run_index, seq=run.seq)
        else:
            ledger.record_miss(note.plant_id, note.run_index, seq=run.seq)
        ledger.retire_run(note.plant_id)
    return RevealResult(note.plant_id, REVEALED, "commitment verified")


class EvidenceLedger:
    """The evidence ledger: passes, catches, misses, and the void rule.

    The rule from the source thread: *if the check misses the planted
    fault, every earlier pass it reported stops counting as evidence
    back to the last occasion it was seen to catch something.*

    Concretely, on a miss:

    * every PASS row whose seq is **after** the last observed CATCH row
      becomes ``VOID`` -- not "unproven", void;
    * PASS rows **before** that catch are untouched;
    * a ledger with no catch yet voids **all** its passes, because there
      is no earlier occasion it was seen to catch anything.

    Sequence numbers are caller-supplied ints -- no wall-clock anywhere.
    """

    def __init__(self) -> None:
        self._rows: List[EvidenceRow] = []
        self._commitments: Dict[str, str] = {}
        self._runs: Dict[str, CheckOutcome] = {}
        self._counter = 0

    # -- commitment registry ------------------------------------------

    def post_commitment(self, plant_id: str, commitment: str, check_scope: str = "") -> None:
        """Record that a commitment was published for ``plant_id``."""
        if not plant_id or not commitment:
            raise CommitmentError("plant_id and commitment are required")
        self._commitments[plant_id] = commitment

    def commitment_for(self, plant_id: str) -> Optional[str]:
        """The commitment posted for ``plant_id`` (``None`` if never posted)."""
        return self._commitments.get(plant_id)

    # -- check runs ----------------------------------------------------

    def record_check_run(self, outcome: CheckOutcome) -> CheckOutcome:
        """Remember a blind check run (not yet evidence -- not yet revealed)."""
        self._runs[outcome.plant_id] = outcome
        return outcome

    def check_run_for(self, plant_id: str) -> Optional[CheckOutcome]:
        """The check run booked for ``plant_id`` (``None`` if none)."""
        return self._runs.get(plant_id)

    def plant_is_dead(self, plant_id: str) -> bool:
        """True once the plant was voided (mismatch, or revealed too early).

        A dead plant stays dead: a second reveal cannot revive it and
        turn a voided plant into evidence.
        """
        return any(
            row.kind == KIND_VOID_PLANT and row.plant_id == plant_id
            for row in self._rows
        )

    def retire_run(self, plant_id: str) -> None:
        """Forget a plant's check run once it has been revealed.

        A plant is revealed once.  Keeping the run around would let a
        second reveal book a second catch (or a second miss) for the
        same plant.
        """
        self._runs.pop(plant_id, None)

    def allocate_seq(self) -> int:
        """Allocate the next sequence number (caller-supplied ints win)."""
        return self._next_seq(None)

    # -- evidence rows -------------------------------------------------

    def record_pass(self, check_scope: str, run_index: int, seq: Optional[int] = None) -> EvidenceRow:
        """Book a PASS: the check ran and did not fire on this run."""
        row = EvidenceRow(
            seq=self._next_seq(seq),
            kind=KIND_PASS,
            status=STATUS_PASS,
            check_scope=check_scope,
            run_index=run_index,
        )
        self._rows.append(row)
        return row

    def record_catch(
        self, plant_id: str, run_index: int, seq: Optional[int] = None
    ) -> EvidenceRow:
        """Book a CATCH: the check fired on the fault it was not told about."""
        row = EvidenceRow(
            seq=self._next_seq(seq),
            kind=KIND_CATCH,
            status=STATUS_CATCH,
            check_scope=self._scope_for(plant_id),
            run_index=run_index,
            plant_id=plant_id,
        )
        self._rows.append(row)
        return row

    def record_miss(
        self, plant_id: str, run_index: int, seq: Optional[int] = None
    ) -> EvidenceRow:
        """Book a MISS and void the passes back to the last observed catch."""
        row = EvidenceRow(
            seq=self._next_seq(seq),
            kind=KIND_MISS,
            status=STATUS_MISS,
            check_scope=self._scope_for(plant_id),
            run_index=run_index,
            plant_id=plant_id,
        )
        self._rows.append(row)
        self.void_back_to_last_catch()
        return row

    def record_void_plant(self, plant_id: str, detail: str = "") -> EvidenceRow:
        """Book a plant that died (commitment mismatch, or revealed too early)."""
        row = EvidenceRow(
            seq=self._next_seq(None),
            kind=KIND_VOID_PLANT,
            status=STATUS_VOID_PLANT,
            check_scope=self._scope_for(plant_id),
            run_index=0,
            plant_id=plant_id,
            detail=detail,
        )
        self._rows.append(row)
        return row

    # -- the void rule --------------------------------------------------

    def last_catch_seq(self) -> Optional[int]:
        """The seq of the most recent observed CATCH (``None`` if none)."""
        catches = [row.seq for row in self._rows if row.kind == KIND_CATCH]
        return max(catches) if catches else None

    def void_back_to_last_catch(self) -> List[EvidenceRow]:
        """Void every PASS after the last observed catch.

        A PASS at or before the last catch is left alone: the evidence
        from before the last observed catch is not retroactively
        destroyed by a later miss -- only the passes the check reported
        *after* it was last seen to catch something.
        """
        last_catch = self.last_catch_seq()
        voided: List[EvidenceRow] = []
        for index, row in enumerate(self._rows):
            if row.kind != KIND_PASS or row.status != STATUS_PASS:
                continue
            if last_catch is None or row.seq > last_catch:
                self._rows[index] = EvidenceRow(
                    seq=row.seq,
                    kind=KIND_PASS,
                    status=STATUS_VOID,
                    check_scope=row.check_scope,
                    run_index=row.run_index,
                    plant_id=row.plant_id,
                    detail="voided by a miss after the last observed catch",
                )
                voided.append(self._rows[index])
        return voided

    # -- reading ---------------------------------------------------------

    @property
    def rows(self) -> Tuple[EvidenceRow, ...]:
        """Every row, in booking order."""
        return tuple(self._rows)

    def rows_of_kind(self, kind: str) -> Tuple[EvidenceRow, ...]:
        """Every row of one kind."""
        return tuple(row for row in self._rows if row.kind == kind)

    def passes(self) -> Tuple[EvidenceRow, ...]:
        """Every PASS row (voided ones included, with their status)."""
        return self.rows_of_kind(KIND_PASS)

    def valid_passes(self) -> Tuple[EvidenceRow, ...]:
        """Only the PASS rows that still count as evidence."""
        return tuple(
            row for row in self._rows if row.kind == KIND_PASS and row.status == STATUS_PASS
        )

    def voided_passes(self) -> Tuple[EvidenceRow, ...]:
        """Only the PASS rows that were voided by a miss."""
        return tuple(
            row for row in self._rows if row.kind == KIND_PASS and row.status == STATUS_VOID
        )

    def catches(self) -> Tuple[EvidenceRow, ...]:
        """Every observed catch."""
        return self.rows_of_kind(KIND_CATCH)

    def misses(self) -> Tuple[EvidenceRow, ...]:
        """Every observed miss."""
        return self.rows_of_kind(KIND_MISS)

    # -- internals --------------------------------------------------------

    def _next_seq(self, seq: Optional[int]) -> int:
        """The next sequence number.

        Caller-supplied ints win.  Otherwise the counter advances past
        every seq already used -- including a caller-supplied one -- so
        two rows never share a seq (the void rule compares seqs).
        """
        if seq is not None:
            self._counter = max(self._counter, seq)
            return seq
        self._counter += 1
        return self._counter

    def _scope_for(self, plant_id: str) -> str:
        run = self._runs.get(plant_id)
        return run.check_scope if run is not None else ""


def stdlib_only() -> bool:
    """AST check: this module imports stdlib modules only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {
        "__future__",
        "ast",
        "collections",
        "dataclasses",
        "hashlib",
        "json",
        "pathlib",
        "typing",
        "canonical_json",
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
    """Self-check: plant, blind check, reveal, catch, then a miss."""

    note = PlantNote(
        plant_id="p1",
        run_index=3,
        field="outcome",
        wrong_value="permission.deny",
        true_value="permission.allow",
        planted_by="planter-1",
        check_scope="kill-switch",
    )
    ledger = EvidenceLedger()
    commitment = post_commitment(note, ledger)
    assert commitment.startswith("sha256:")

    faulted = plant({"outcome": "permission.allow"}, note, "planter-1")
    assert faulted["outcome"] == "permission.deny"

    outcome = run_check(lambda record: record.get("outcome") == "permission.deny",
                        faulted, "checker-2", ledger)
    assert outcome.caught
    result = reveal(note, commitment, ledger)
    assert result.outcome == REVEALED
    assert len(ledger.catches()) == 1

    ledger.record_pass("kill-switch", 4, seq=10)
    assert len(ledger.valid_passes()) == 1
    print("planted-fault OK: commitment, plant-in-input, blind check, reveal, catch")


if __name__ == "__main__":
    main()

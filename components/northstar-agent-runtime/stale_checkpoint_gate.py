"""Recovery gate: a checkpoint carries the external world's checksum, and recovery checks it.

What was missing
----------------
Northstar's checkpoint layers are *internal* disciplines.  Read from the code,
not assumed:

* ``checkpoint_store.py`` is file discipline: atomic write (``O_CREAT|O_EXCL``
  temp + fsync + ``os.replace``), path safety (``_validate_file_path`` refuses
  separators, parent segments, absolute paths and symlinks leaving the store),
  and a restricted loader (``_decode``/``_decode_value``).  All of it is about
  *how the bytes are stored*, never about *what the bytes claim about the world*.
* ``checkpoints.py`` is turn-boundary discipline: the transcript prefix length,
  its digest, the consumed counters, the run-graph hash, the lineage chain.
  ``prepare_resume`` refuses a transcript whose prefix does not hash to the
  recorded digest, a checkpoint taken under a different run graph, and a
  dangling lineage.  Every one of those checks is **internal**: the
  transcript is compared against the transcript's own digest.
* ``durable_resume.py`` is durable-store discipline: ``state_digest`` hashes
  the checkpoint's own state, ``DurableStore.verify`` compares a checkpoint's
  state against that digest, and ``DurableRunner.resume`` refuses a checkpoint
  that does not match its digest.

So: **today a checkpoint recovery verifies the checkpoint against itself.**
There is no point in the recovery path where the agent asks "what did the
world look like when you wrote this, and does it still look like that?"

That is the gap.  A checkpoint records a *belief* about the external world --
"the schema is version 3", "the task table is empty", "the tool set is the one
I pinned".  Recovery restores that belief verbatim.  If the world moved after
the checkpoint was written, the restored belief is stale, and the agent
continues from it *confidently*, because nothing in the recovery path told it
the belief was old.  The more often you recover, the more confident you are
about a world that no longer exists.

This module is the missing gate.  A checkpoint carries two things about the
outside world:

* ``external_checksum`` -- a canonical SHA-256 over a snapshot of the external
  state, **supplied by the caller** (the runtime does not know what "the
  external state" is for a given agent; the host does).
* ``freshness_seq`` -- a caller-supplied integer sequence number for the
  external world.  It says how far the world has advanced.

On recovery, :meth:`StaleCheckpointGate.verify` compares the checkpoint's
recorded world against the live world and answers with **three states**, never
a boolean: ``PASS`` (the world is as the checkpoint remembers it),
``FLAGGED`` (the world has advanced -- recoverable, but the caller must say
so), ``REJECTED`` (the world contradicts the checkpoint, or has gone
backwards -- not recoverable).

Source (Moltbook, 2026-11-14 sweep; three linked posts):

* SparkLabScout, "Stale checkpoints produce confident errors"
  (https://www.moltbook.com/post/07749448-7c33-4e8b-9eb4-2c81a3821190 ,
  12 up / 2 comments) -- verbatim core claim: a checkpoint is a *witness
  statement*, not a video recording.  Recovery inherits the agent's beliefs
  as they were (the post's example: the old schema from step 14), and the
  more often you recover, the more confident the stale belief becomes.
* "Your agent's checkpoint is not a memory. It is a witness statement."
  (https://www.moltbook.com/post/8d065239-e710-40d0-a713-2cb0dbacfdaa ,
  7 up / 2 comments) -- verbatim core mechanism: the checkpoint carries a
  **checksum and a freshness stamp of the external state**; on recovery the
  live state is checked against the checksum first, and drift is **refused or
  flagged**.  A checksum that is not checked is a decoration.
* lightningzero, "I tested recovery instead of rollback"
  (https://www.moltbook.com/post/7c232215-aa2a-471d-ac9c-811303fdbe29 ,
  20 up / 14 comments) -- verbatim core mechanism: test the **dirty**
  recovery -- revert from a point that has *later writes* and *real drift* --
  not only the clean immediate rollback.  A rollback that only ever tests the
  clean case never sees the stale-belief failure at all.

Northstar extension (this module, not the source):

* The gate is **fail closed at creation**: a checkpoint with no external
  checksum or no freshness sequence cannot be created, so it can never reach
  the recovery gate unverified.
* The checksum is **canonical** -- sorted keys, compact separators, UTF-8,
  the same shape as ``tool_pinning.hash_definition`` -- so the same external
  state spelled two ways hashes the same.  An input that cannot be
  canonicalised (NaN/inf, non-string dict keys, arbitrary objects) is
  **refused**, not fuzzily hashed.
* The verdict is an explicit three-state value.  A boolean cannot tell
  "recoverable, but the world moved" from "do not recover".
* The **dirty-recovery drill** (:func:`drill`) is a test helper that lives in
  the module: it builds a checkpoint, writes to the world *after* it, and
  recovers -- proving the gate flags or rejects on real drift instead of
  letting the recovery through.

Honest scope
------------
* The checksum and the sequence number are **caller-supplied**.  This module
  does not know what the external world is; it applies a recorded world to an
  observed world and reports the difference.
* The gate is pure and in-memory.  It holds no checkpoints of its own and it
  persists nothing; the caller owns storage.
* It is a **library**: no existing runtime module is modified to call it.  A
  host adopts it by running ``gate.verify(checkpoint, live_checksum,
  live_seq)`` before a recovery proceeds.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping

#: Version pin for this module's record shapes.
STALE_CHECKPOINT_GATE_VERSION = "stale-checkpoint-gate.v1"

#: Schema pin for the gate's own records.
STALE_CHECKPOINT_GATE_SCHEMA = "northstar.stale-checkpoint-gate.v1"

#: Prefix of every checksum this module produces.
CHECKSUM_PREFIX = "sha256:"

#: Length of the hex part of a SHA-256 digest.
_SHA256_HEX_LEN = 64


class StaleCheckpointGateError(Exception):
    """Base class for every refusal this module makes."""


class MissingExternalStateError(StaleCheckpointGateError):
    """A checkpoint was created without a checksum or a freshness sequence.

    Fail closed: a checkpoint that cannot say what the world looked like
    when it was written cannot be checked on recovery, so it is never created
    in the first place.
    """


class UncanonicalizableStateError(StaleCheckpointGateError):
    """The external state cannot be canonicalised, so it cannot be hashed.

    Refused rather than fuzzily hashed: a checksum of a state that was
    silently coerced is a checksum of something the caller never described.
    """


class InvalidFreshnessSeqError(StaleCheckpointGateError):
    """A freshness sequence number is not a usable integer."""


class GateVerdictStatus(str, Enum):
    """The three gate outcomes.

    Not a boolean.  ``FLAGGED`` ("recover, but the world has moved") and
    ``REJECTED`` ("do not recover") are different decisions, and collapsing
    them into one bit loses exactly the information the gate exists to
    produce.
    """

    PASS = "pass"
    FLAGGED = "flagged"
    REJECTED = "rejected"

    def __str__(self) -> str:  # pragma: no cover - convenience only
        return self.value


class InvalidChecksumError(StaleCheckpointGateError):
    """A checksum is not a ``sha256:<64 lowercase hex>`` string."""


# ---------------------------------------------------------------------------
# Canonicalisation and checksums
# ---------------------------------------------------------------------------


def _reject_non_string_keys(value: Any, path: str = "$") -> None:
    """Refuse a mapping whose keys are not all strings.

    ``json.dumps`` silently coerces integer keys to strings, so ``{1: "a"}``
    and ``{"1": "a"}`` would hash the same.  Two different external states
    must not share a checksum, so the ambiguity is refused rather than
    resolved.
    """
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise UncanonicalizableStateError(
                    f"external state at {path} has a non-string key {key!r} "
                    f"of type {type(key).__name__}: it would be coerced to a string"
                )
            _reject_non_string_keys(item, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _reject_non_string_keys(item, f"{path}[{index}]")


def canonicalize(state: Any) -> str:
    """The canonical text of an external-state snapshot.

    The canonical shape is the one ``tool_pinning.hash_definition`` uses --
    ``json.dumps(value, sort_keys=True, separators=(",", ":"))`` encoded as
    UTF-8 -- so the same external state spelled two ways produces the same
    text, and therefore the same checksum.

    Unlike the pinning helper, this one **refuses** what it cannot describe:
    there is no ``default=str`` fallback, so an arbitrary object raises
    :class:`UncanonicalizableStateError` instead of being hashed as its
    ``repr``.  ``NaN`` and ``inf`` are refused for the same reason -- they
    have no JSON spelling, and a checksum over a number that cannot be
    written down is a checksum over nothing.
    """
    _reject_non_string_keys(state)
    try:
        return json.dumps(state, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as error:
        raise UncanonicalizableStateError(
            f"external state cannot be canonicalised: {type(error).__name__}: {error}"
        ) from error


def external_checksum(state: Any) -> str:
    """The canonical SHA-256 checksum of an external-state snapshot.

    The format is fixed: ``sha256:`` followed by 64 lowercase hex digits.
    """
    canonical = canonicalize(state)
    return CHECKSUM_PREFIX + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


#: Alias used where the plain name would be shadowed by a parameter.
checksum_of_state = external_checksum


def is_checksum(value: Any) -> bool:
    """True when ``value`` is a well-formed checksum string."""
    if not isinstance(value, str) or not value.startswith(CHECKSUM_PREFIX):
        return False
    digest = value[len(CHECKSUM_PREFIX) :]
    return len(digest) == _SHA256_HEX_LEN and all(ch in "0123456789abcdef" for ch in digest)


def _check_seq(value: Any, name: str) -> int:
    """Validate a sequence number: a non-negative, non-boolean integer."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidFreshnessSeqError(
            f"{name} must be an integer sequence number, not {type(value).__name__}"
        )
    if value < 0:
        raise InvalidFreshnessSeqError(f"{name} must not be negative")
    if value > 2**63 - 1:
        raise InvalidFreshnessSeqError(f"{name} must fit in a signed 64-bit integer")
    return value


# ---------------------------------------------------------------------------
# The records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ExternalStateWitness:
    """What a checkpoint says about the outside world.

    Attributes:
        external_checksum: the canonical checksum of the external-state
            snapshot the checkpoint was written against.
        freshness_seq: the external world's sequence number at the moment
            the checkpoint was written.
        created_seq: the sequence number of the write that created the
            checkpoint.  It is recorded separately because a checkpoint may
            be *about* a world at sequence ``n`` while being *written* at
            sequence ``m``; the two are not the same fact.
    """

    external_checksum: str
    freshness_seq: int
    created_seq: int

    def __post_init__(self) -> None:
        if not is_checksum(self.external_checksum):
            raise InvalidChecksumError(
                "external_checksum must be a 'sha256:<64 lowercase hex>' string, "
                f"got {self.external_checksum!r}"
            )
        _check_seq(self.freshness_seq, "freshness_seq")
        _check_seq(self.created_seq, "created_seq")

    def as_dict(self) -> dict[str, Any]:
        return {
            "external_checksum": self.external_checksum,
            "freshness_seq": self.freshness_seq,
            "created_seq": self.created_seq,
        }


@dataclass(frozen=True)
class Checkpoint:
    """A checkpoint that carries its witness of the external world.

    The first three fields are the witness itself; the rest identifies the
    checkpoint and carries the counter state the recovery inherits.
    """

    checkpoint_id: str
    external_checksum: str
    freshness_seq: int
    created_seq: int
    session_id: str = ""
    turns: int = 0
    tool_calls: int = 0
    payload: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.checkpoint_id, str) or not self.checkpoint_id.strip():
            raise MissingExternalStateError("checkpoint_id must be a non-empty string")
        if not is_checksum(self.external_checksum):
            raise MissingExternalStateError(
                "a checkpoint must carry an external_checksum "
                f"('sha256:<64 lowercase hex>'); got {self.external_checksum!r}"
            )
        _check_seq(self.freshness_seq, "freshness_seq")
        _check_seq(self.created_seq, "created_seq")

    @property
    def witness(self) -> ExternalStateWitness:
        """The witness this checkpoint carries."""
        return ExternalStateWitness(
            external_checksum=self.external_checksum,
            freshness_seq=self.freshness_seq,
            created_seq=self.created_seq,
        )

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "checkpoint_id": self.checkpoint_id,
            "external_checksum": self.external_checksum,
            "freshness_seq": self.freshness_seq,
            "created_seq": self.created_seq,
            "session_id": self.session_id,
            "turns": self.turns,
            "tool_calls": self.tool_calls,
        }
        if self.payload is not None:
            payload["payload"] = dict(self.payload)
        return payload


@dataclass(frozen=True)
class GateVerdict:
    """One recovery-gate decision, with the evidence behind it.

    Attributes:
        status: the three-way decision.
        checkpoint_id: which checkpoint was judged.
        expected_checksum: the checksum the checkpoint recorded.
        actual_checksum: the checksum of the live external state.
        expected_seq: the freshness sequence the checkpoint recorded.
        actual_seq: the live external sequence number.
        seq_advance: how far the world moved forward, when it did.
        reason: why this verdict, in words.
        drift: a description of the drift, or ``None`` when there was none.
    """

    status: GateVerdictStatus
    checkpoint_id: str
    expected_checksum: str
    actual_checksum: str
    expected_seq: int
    actual_seq: int
    seq_advance: int
    reason: str
    drift: str | None = None

    @property
    def passed(self) -> bool:
        """Whether the recovery may proceed unchanged (pass only)."""
        return self.status is GateVerdictStatus.PASS

    @property
    def recoverable(self) -> bool:
        """Whether the recovery may proceed at all (pass, or flagged)."""
        return self.status in (GateVerdictStatus.PASS, GateVerdictStatus.FLAGGED)

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "checkpoint_id": self.checkpoint_id,
            "expected_checksum": self.expected_checksum,
            "actual_checksum": self.actual_checksum,
            "expected_seq": self.expected_seq,
            "actual_seq": self.actual_seq,
            "seq_advance": self.seq_advance,
            "reason": self.reason,
            "drift": self.drift,
            "version": STALE_CHECKPOINT_GATE_VERSION,
        }


# ---------------------------------------------------------------------------
# The gate
# ---------------------------------------------------------------------------


class StaleCheckpointGate:
    """The recovery gate: does the live world still match the checkpoint's witness?

    The gate holds no state of its own -- it compares a checkpoint's recorded
    witness against an observed one, and returns an explicit three-state
    verdict.

    Three states, and why each one is separate:

    * ``PASS`` -- the live checksum equals the recorded checksum *and* the
      live sequence equals the recorded sequence.  The world is as the
      checkpoint remembers it; the recovery proceeds.
    * ``FLAGGED`` -- the world has advanced: the live sequence is greater
      than the recorded one.  The recovery may proceed, but the caller must
      declare that the world has changed; the verdict carries how far it
      moved.  A checkpoint that recorded an *older schema* and comes back
      against a live world that has since moved is exactly the case the
      source describes, and it is recoverable only when the caller says so.
    * ``REJECTED`` -- the live checksum differs from the recorded one (the
      world contradicts the checkpoint), or the live sequence is *less* than
      the recorded one (the world went backwards, which is not a normal
      progression and means the observed state cannot be trusted to be
      newer).  The recovery does not proceed.
    """

    def create(
        self,
        checkpoint_id: str,
        *,
        external_state: Any = None,
        external_checksum: str | None = None,
        freshness_seq: int,
        created_seq: int | None = None,
        session_id: str = "",
        turns: int = 0,
        tool_calls: int = 0,
        payload: Mapping[str, Any] | None = None,
    ) -> Checkpoint:
        """Create a checkpoint that carries a witness of the external world.

        The checksum is required and may be given either as a precomputed
        ``external_checksum`` or as the ``external_state`` snapshot to hash.
        The freshness sequence is required and has no default: a checkpoint
        whose freshness is unknown cannot be checked on recovery, so it is
        never created.
        """
        checksum = external_checksum
        if checksum is None:
            if external_state is None:
                raise MissingExternalStateError(
                    "a checkpoint must carry an external checksum: pass "
                    "external_state (to be hashed) or external_checksum"
                )
            checksum = checksum_of_state(external_state)

        elif external_state is not None:
            raise MissingExternalStateError(
                "pass either external_state or external_checksum, not both: "
                "the checkpoint must record one world, not two"
            )
        if not is_checksum(checksum):
            raise MissingExternalStateError(
                "external_checksum must be a 'sha256:<64 lowercase hex>' string, "
                f"got {checksum!r}"
            )
        seq = _check_seq(freshness_seq, "freshness_seq")
        created = seq if created_seq is None else _check_seq(created_seq, "created_seq")
        return Checkpoint(
            checkpoint_id=checkpoint_id,
            external_checksum=checksum,
            freshness_seq=seq,
            created_seq=created,
            session_id=session_id,
            turns=int(turns),
            tool_calls=int(tool_calls),
            payload=dict(payload) if payload is not None else None,
        )

    def verify(
        self,
        checkpoint: Checkpoint,
        live_checksum: str,
        live_seq: int,
    ) -> GateVerdict:
        """Judge a checkpoint against the live external world.

        Never raises for a mismatch -- a mismatch is a verdict, not an
        error.  It *does* raise when the inputs are unusable (a malformed
        live checksum, a non-integer live sequence), because those are
        programming errors rather than findings about the world.
        """
        if not isinstance(checkpoint, Checkpoint):
            raise StaleCheckpointGateError(
                f"verify expects a Checkpoint, got {type(checkpoint).__name__}"
            )
        if not is_checksum(live_checksum):
            raise InvalidChecksumError(
                "live_checksum must be a 'sha256:<64 lowercase hex>' string, "
                f"got {live_checksum!r}"
            )
        observed_seq = _check_seq(live_seq, "live_seq")

        expected_checksum = checkpoint.external_checksum
        expected_seq = checkpoint.freshness_seq

        # A world that has gone *backwards* is refused before anything else:
        # an observed sequence below the recorded one means the live state
        # is not a later state, so comparing checksums would be comparing
        # two different eras and calling the difference "drift".
        if observed_seq < expected_seq:
            return GateVerdict(
                status=GateVerdictStatus.REJECTED,
                checkpoint_id=checkpoint.checkpoint_id,
                expected_checksum=expected_checksum,
                actual_checksum=live_checksum,
                expected_seq=expected_seq,
                actual_seq=observed_seq,
                seq_advance=0,
                reason=(
                    f"the live external sequence ({observed_seq}) is behind the sequence the "
                    f"checkpoint recorded ({expected_seq}): the external world moved backwards, "
                    "which is not a normal progression, so the live state cannot be treated "
                    "as the checkpoint's world"
                ),
                drift=(
                    f"sequence went backwards by {expected_seq - observed_seq} "
                    f"({expected_seq} -> {observed_seq})"
                ),
            )

        if live_checksum != expected_checksum:
            advance = observed_seq - expected_seq
            return GateVerdict(
                status=GateVerdictStatus.REJECTED,
                checkpoint_id=checkpoint.checkpoint_id,
                expected_checksum=expected_checksum,
                actual_checksum=live_checksum,
                expected_seq=expected_seq,
                actual_seq=observed_seq,
                seq_advance=advance,
                reason=(
                    "the live external state does not match the state the checkpoint "
                    f"recorded (expected {expected_checksum}, got {live_checksum}): the "
                    "checkpoint's belief about the world is stale, and recovering from it "
                    "would carry that stale belief forward"
                ),
                drift=(
                    f"checksum mismatch: expected {expected_checksum}, actual {live_checksum}"
                    + (f"; sequence advanced by {advance}" if advance else "")
                ),
            )

        if observed_seq > expected_seq:
            advance = observed_seq - expected_seq
            return GateVerdict(
                status=GateVerdictStatus.FLAGGED,
                checkpoint_id=checkpoint.checkpoint_id,
                expected_checksum=expected_checksum,
                actual_checksum=live_checksum,
                expected_seq=expected_seq,
                actual_seq=observed_seq,
                seq_advance=advance,
                reason=(
                    f"the external world has advanced by {advance} sequence(s) since the "
                    "checkpoint was written: the recovery may proceed, but the caller must "
                    "declare that the world has changed"
                ),
                drift=(
                    f"sequence advanced by {advance} ({expected_seq} -> {observed_seq}); "
                    "the checksum of the observed state is unchanged"
                ),
            )

        return GateVerdict(
            status=GateVerdictStatus.PASS,
            checkpoint_id=checkpoint.checkpoint_id,
            expected_checksum=expected_checksum,
            actual_checksum=live_checksum,
            expected_seq=expected_seq,
            actual_seq=observed_seq,
            seq_advance=0,
            reason=(
                "the live external state matches the state the checkpoint recorded: "
                "the checkpoint's witness holds"
            ),
            drift=None,
        )


# ---------------------------------------------------------------------------
# The dirty-recovery drill (Northstar extension; a test helper, not a
# production path)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WorldWrite:
    """One write that landed after the checkpoint was taken."""

    key: str
    value: Any

    def as_dict(self) -> dict[str, Any]:
        return {"key": self.key, "value": self.value}


@dataclass(frozen=True)
class ExternalWorld:
    """A snapshot of the external world plus its sequence number.

    The world is a plain mapping plus a counter.  A write changes the
    mapping and advances the counter by one -- which is exactly the shape
    of the drift the drill needs: a later write, a moved world.

    ``witness_keys`` names the part of the world a checkpoint vouches for.
    The world can move on without touching that part -- new rows elsewhere,
    a different task entirely -- and then the checkpoint's belief still
    holds, but the world has still advanced, and the recovery has to say
    so.  A write that *does* touch a witnessed key is a different thing
    entirely: the checkpoint's belief is now false.
    """

    state: Mapping[str, Any]
    seq: int = 0
    witness_keys: tuple[str, ...] | None = None

    def __post_init__(self) -> None:
        _check_seq(self.seq, "seq")

    def witnessed(self) -> dict[str, Any]:
        """The part of the world a checkpoint's checksum covers."""
        if self.witness_keys is None:
            return dict(self.state)
        return {key: value for key, value in self.state.items() if key in self.witness_keys}

    @property
    def checksum(self) -> str:
        """The canonical checksum of the world's witnessed state."""
        return checksum_of_state(self.witnessed())

    def write(self, key: str, value: Any) -> "ExternalWorld":
        """A new world with one more write applied and the sequence advanced."""
        updated = dict(self.state)
        updated[key] = value
        return ExternalWorld(
            state=updated,
            seq=self.seq + 1,
            witness_keys=self.witness_keys,
        )


@dataclass(frozen=True)
class DrillResult:
    """What the dirty-recovery drill observed.

    Attributes:
        checkpoint: the checkpoint the drill recovered from.
        live_checksum: the checksum of the live world after the writes.
        live_seq: the live world's sequence after the writes.
        verdict: the gate's verdict for that recovery.
        writes: the writes that landed after the checkpoint was taken.
        recovered: whether the recovery proceeded.  It is ``True`` only
            when the gate let it through.
        stale_detected: whether the gate caught the drift at all -- a
            rejected or flagged verdict.  A drill whose verdict is ``PASS``
            has ``stale_detected=False``, which is the failure this drill
            exists to make impossible.
    """

    checkpoint: Checkpoint
    live_checksum: str
    live_seq: int
    verdict: GateVerdict
    writes: tuple[WorldWrite, ...]
    recovered: bool
    stale_detected: bool

    @property
    def status(self) -> GateVerdictStatus:
        """The gate status the drill observed."""
        return self.verdict.status

    def as_dict(self) -> dict[str, Any]:
        return {
            "checkpoint_id": self.checkpoint.checkpoint_id,
            "live_checksum": self.live_checksum,
            "live_seq": self.live_seq,
            "verdict": self.verdict.as_dict(),
            "writes": [item.as_dict() for item in self.writes],
            "recovered": self.recovered,
            "stale_detected": self.stale_detected,
            "version": STALE_CHECKPOINT_GATE_VERSION,
        }


def drill(
    checkpoint: Checkpoint,
    live_state_with_writes: Any,
    *,
    live_seq: int | None = None,
    writes: tuple[WorldWrite, ...] = (),
    gate: StaleCheckpointGate | None = None,
) -> DrillResult:
    """Recover from a checkpoint into a world that moved on, and report it.

    This is the drill the source asks for: instead of testing the clean
    immediate rollback (recover from the checkpoint into the world it was
    taken from), it recovers into a world that has **later writes** and
    **real drift**, and shows what the gate does.

    ``live_state_with_writes`` is the external state as it stands *now* --
    after the writes that landed since the checkpoint was taken.  It may be
    an :class:`ExternalWorld` (whose own sequence number is used) or a plain
    mapping (in which case ``live_seq`` says how far the world has moved;
    with ``writes`` given, it defaults to the checkpoint's freshness
    sequence advanced by the number of writes).

    The drill never decides for the caller whether a flagged recovery is
    acceptable -- it reports the verdict, and ``recovered`` says whether the
    gate let the recovery through.
    """
    if gate is None:
        gate = StaleCheckpointGate()

    if isinstance(live_state_with_writes, ExternalWorld):
        live_world = live_state_with_writes
    elif isinstance(live_state_with_writes, Mapping):
        if live_seq is None:
            live_seq = checkpoint.freshness_seq + len(writes)
        live_world = ExternalWorld(state=dict(live_state_with_writes), seq=int(live_seq))
    else:
        raise StaleCheckpointGateError(
            "live_state_with_writes must be an ExternalWorld or a mapping, "
            f"got {type(live_state_with_writes).__name__}"
        )

    verdict = gate.verify(checkpoint, live_world.checksum, live_world.seq)
    return DrillResult(
        checkpoint=checkpoint,
        live_checksum=live_world.checksum,
        live_seq=live_world.seq,
        verdict=verdict,
        writes=tuple(writes),
        recovered=verdict.recoverable,
        stale_detected=verdict.status is not GateVerdictStatus.PASS,
    )


def dirty_recovery_drill(
    gate: StaleCheckpointGate,
    initial_state: Mapping[str, Any],
    writes: tuple[WorldWrite, ...],
    *,
    checkpoint_id: str = "drill-checkpoint",
    freshness_seq: int = 0,
    created_seq: int | None = None,
    witness_keys: tuple[str, ...] | None = None,
) -> DrillResult:
    """Build a checkpoint, write to the world after it, then recover.

    The whole drill in one call: the checkpoint is taken against
    ``initial_state``, the ``writes`` are applied one by one (each advancing
    the world's sequence), and the recovery is attempted against the world
    as it stands afterwards.

    ``witness_keys`` names the part of the world the checkpoint vouches for.
    With it, the drill can separate the two kinds of drift:

    * a write that touches a **witnessed** key makes the checkpoint's
      belief false -- the verdict is ``REJECTED``, and the recovery does
      not proceed;
    * a write that touches **only unwitnessed** keys leaves the belief
      standing but moves the world -- the verdict is ``FLAGGED``, the
      recovery proceeds only with the movement declared.

    Either way the drill proves the gate sees the drift: the verdict is
    never a bare ``PASS``.
    """
    world = ExternalWorld(
        state=dict(initial_state),
        seq=freshness_seq,
        witness_keys=witness_keys,
    )
    checkpoint = gate.create(
        checkpoint_id,
        external_state=world.witnessed(),
        freshness_seq=freshness_seq,
        created_seq=created_seq,
    )
    for item in writes:
        world = world.write(item.key, item.value)
    return drill(
        checkpoint,
        world,
        writes=writes,
        gate=gate,
    )


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------


def main() -> None:
    """Self-check: the three states, the fail-closed creation, the drill."""
    gate = StaleCheckpointGate()

    # Clean recovery: the world is as the checkpoint remembers it.
    state = {"schema": "v3", "tasks": []}
    checkpoint = gate.create("ck-1", external_state=state, freshness_seq=7)
    verdict = gate.verify(checkpoint, checksum_of_state(state), 7)
    assert verdict.status is GateVerdictStatus.PASS
    assert verdict.recoverable and verdict.drift is None

    # Drift: the live world contradicts the checkpoint.
    drifted = gate.verify(checkpoint, checksum_of_state({"schema": "v2", "tasks": []}), 8)
    assert drifted.status is GateVerdictStatus.REJECTED
    assert drifted.expected_checksum != drifted.actual_checksum

    # The world advanced, but the witnessed belief still holds.
    advanced = gate.verify(checkpoint, checksum_of_state(state), 11)
    assert advanced.status is GateVerdictStatus.FLAGGED
    assert advanced.seq_advance == 4

    # The world went backwards.
    backwards = gate.verify(checkpoint, checksum_of_state(state), 3)
    assert backwards.status is GateVerdictStatus.REJECTED

    # Fail closed: no checksum at all.
    try:
        gate.create("ck-2", freshness_seq=7)
        raise AssertionError("should have been refused")
    except MissingExternalStateError:
        pass

    # Fail closed: no freshness sequence.
    try:
        gate.create("ck-3", external_state=state)
        raise AssertionError("should have been refused")
    except TypeError:
        pass

    # Uncanonicalisable state is refused, not fuzzily hashed.
    try:
        checksum_of_state({"x": float("nan")})
        raise AssertionError("should have been refused")
    except UncanonicalizableStateError:
        pass

    # The dirty drill: writes after the checkpoint, real drift, no silent pass.
    drill_result = dirty_recovery_drill(
        gate,
        {"schema": "v3", "tasks": []},
        (WorldWrite("tasks", [{"id": 1}]),),
        freshness_seq=7,
        witness_keys=("schema",),
    )
    assert drill_result.status is GateVerdictStatus.FLAGGED
    assert drill_result.stale_detected
    assert drill_result.verdict.seq_advance == 1

    print(
        "stale-checkpoint-gate OK: pass / flagged / rejected, fail-closed creation, "
        "canonical checksum, dirty-recovery drill"
    )


if __name__ == "__main__":
    main()

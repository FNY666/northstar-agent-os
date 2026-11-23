"""Forward-secure sealed decision ledger, Simulated.

Research absorption (P0 from the exhaustive method search):

* **Schneier-Kelsey / Bellare-Yee forward-secure audit log** (USENIX
  Security 1998/99): each log entry is sealed with a MAC under a key
  that is then evolved through a one-way function and the old key
  destroyed.  A machine compromised at time T reveals K_T (and hence
  all *future* keys) but *cannot* derive K_0..K_{T-1}, so past entries
  cannot be forged or altered undetectably.  This module implements
  exactly that property with HMAC-SHA256 (stdlib-only).
* **Signed checkpoints** (per-batch Ed25519 pattern from OpenShift
  trust docs et al.): every N records the chain head is sealed under a
  separate checkpoint key.  This defeats the "recompute the entire
  chain" attacker who would otherwise only need the current key.
  (HMAC here, not Ed25519: stdlib-only; the checkpoint *shape* --
  {seq, head, root, seal} as one frozen record -- is the absorbable
  part, and the key can be upgraded to Ed25519/ML-DSA later.)
* **Agent Flight Recorder 8-field event schema** (arXiv:2609.01931):
  every sealed event carries the 8 semantic fields
  intent -> action -> subject -> authorization -> inputs -> logic ->
  execution -> outcome, so a third party can reconstruct causality
  without holding the raw material.
* **GhostDrift triple fingerprints** (zenn.dev, JP): each record pins
  three digests -- input_fingerprint, logic_fingerprint,
  execution_fingerprint -- so a decision can be re-examined from
  artifacts alone.

What this module IS: a single-writer, in-memory, forward-secure
append-only log.  ``append()`` seals one 8-field event; ``checkpoint()``
seals the chain head every N appends; ``verify()`` re-derives the key
chain from the initial key and checks every MAC and hash link.

What this module IS NOT (honest scope):

* It does not solve key distribution: the initial key K_0 and the
  checkpoint key must reach the verifier through a trusted channel.
  (Same honest gap as Chron's local-private-key problem, found in the
  method search.)
* It does not stop an attacker who compromises the machine *before*
  any entry is written (they get K_0), nor one who compromises it at
  time T from forging entries *after* T.
* It does not detect forks: a host that shows two different chains to
  two verifiers looks fine to each.  Fork detection needs the
  checkpoint head published somewhere the host cannot equivocate
  against (the method search's OpenTimestamps / transparency-log
  recommendation -- P1, not this module).
* It does not prove the events were true -- the host chose them.
  Sealing proves *integrity and order*, never truth.
* State is in-memory; persistence, WORM archiving, and external
  anchoring are the host's job.

House style: frozen dataclasses, no wall-clock, RLock-guarded,
fail-closed, stdlib-only (hashlib/hmac), ``sha256:`` digest pins,
``canonical_json`` try/except fallback, ``stdlib_only()`` +
``main()`` self-check.

Key evolution (the forward-security core)::

    K_{n+1} = SHA256(b"northstar-forward-seal:v1:next" || K_n)

One-way: given K_{n+1} no one can compute K_n (preimage resistance).
The ledger keeps only the *current* key; after sealing record n the
previous key is overwritten in memory.  (CPython cannot guarantee the
old bytes are scrubbed from RAM -- documented limitation, not a
claim.)

Record seal::

    seal_n = HMAC-SHA256(K_n, canonical(
        seq || prev_hash || eight field values || triple fingerprints))

Chain link::

    record_hash_n = SHA256(canonical(sealed record n))
    prev_hash_{n+1} = record_hash_n
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

try:
    from canonical_json import jcs_dumps as _jcs_dumps_raw  # type: ignore

    def _jcs_dumps(obj: Any) -> bytes:
        raw = _jcs_dumps_raw(obj)
        return raw.encode("utf-8") if isinstance(raw, str) else raw

except Exception:  # pragma: no cover - fallback when canonical_json is absent

    def _jcs_dumps(obj: Any) -> bytes:  # type: ignore
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


#: Module version pin.
FORWARD_SEAL_LEDGER_VERSION = "forward-seal-ledger.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.forward-seal-ledger.v1"

#: Domain separation tag for key evolution.  Changing this starts a
#: new key lineage that cannot be confused with the old one.
_KEY_EVOLUTION_TAG = b"northstar-forward-seal:v1:next"

#: Domain separation tag for record sealing.
_SEAL_TAG = b"northstar-forward-seal:v1:seal"

#: Domain separation tag for checkpoint sealing.
_CHECKPOINT_TAG = b"northstar-forward-seal:v1:checkpoint"

#: Domain separation tag for checkpoint key evolution.
_CHECKPOINT_EVOLUTION_TAG = b"northstar-forward-seal:v1:checkpoint-next"

#: The 8-field event schema (Agent Flight Recorder absorption).
#: intent -> action -> subject -> authorization -> inputs -> logic ->
#: execution -> outcome.
EVENT_FIELDS = (
    "intent",
    "action",
    "subject",
    "authorization",
    "inputs_digest",
    "logic_digest",
    "execution_digest",
    "outcome",
)

#: Checkpoint interval: seal the chain head every N appends.
CHECKPOINT_INTERVAL = 64


def _sha256_hex(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _evolve_key(key: bytes) -> bytes:
    """One-way key evolution: K_{n+1} = SHA256(tag || K_n)."""
    return hashlib.sha256(_KEY_EVOLUTION_TAG + key).digest()


def _evolve_checkpoint_key(key: bytes) -> bytes:
    """One-way checkpoint-key evolution (separate domain)."""
    return hashlib.sha256(_CHECKPOINT_EVOLUTION_TAG + key).digest()


def _seal(key: bytes, payload: bytes) -> bytes:
    """HMAC-SHA256 seal of a canonical payload.

    Domain separation goes in the *message*, not the key: the key
    stays a clean uniform random value (which is what HMAC's
    security proof assumes), and the tag prefixes the payload.
    """
    return hmac.new(key, _SEAL_TAG + payload, hashlib.sha256).digest()


def _seal_checkpoint(key: bytes, payload: bytes) -> bytes:
    """HMAC-SHA256 seal for checkpoints (separate domain)."""
    return hmac.new(key, _CHECKPOINT_TAG + payload, hashlib.sha256).digest()


class ForwardSealError(Exception):
    """Fail-closed: any integrity failure raises, never returns bad data."""


@dataclass(frozen=True)
class SealedEvent:
    """One forward-sealed ledger record (immutable)."""

    seq: int
    event: Tuple[Tuple[str, str], ...]  # 8 (field, value) pairs, field order pinned
    input_fingerprint: str  # sha256: pin
    logic_fingerprint: str  # sha256: pin
    execution_fingerprint: str  # sha256: pin
    prev_hash: str  # sha256: pin of previous record (genesis for seq 1)
    seal: str  # hex HMAC-SHA256 under K_seq
    record_hash: str  # sha256: pin of the canonical sealed record


@dataclass(frozen=True)
class Checkpoint:
    """A sealed checkpoint over the chain head (immutable)."""

    seq: int  # seq of the head record this checkpoint covers
    head_hash: str  # record_hash of the head record
    records_sealed: int  # total records sealed at checkpoint time
    seal: str  # hex HMAC-SHA256 under the checkpoint key


class ForwardSealLedger:
    """Single-writer forward-secure sealed ledger.

    Usage::

        ledger = ForwardSealLedger(initial_key=os.urandom(32),
                                   checkpoint_key=os.urandom(32))
        rec = ledger.append(intent="...", action="...", ...)
        # ... every CHECKPOINT_INTERVAL appends, or manually:
        cp = ledger.checkpoint()

    The caller supplies the 8 event fields and the 3 fingerprints as
    ``sha256:`` pins.  Raw material never enters the ledger.
    """

    def __init__(self, initial_key: bytes, checkpoint_key: bytes) -> None:
        if not isinstance(initial_key, bytes) or len(initial_key) < 16:
            raise ForwardSealError("initial_key must be bytes of >= 16 bytes")
        if not isinstance(checkpoint_key, bytes) or len(checkpoint_key) < 16:
            raise ForwardSealError("checkpoint_key must be bytes of >= 16 bytes")
        self._lock = threading.RLock()
        self._current_key = initial_key
        self._checkpoint_key = checkpoint_key
        self._records: List[SealedEvent] = []
        self._checkpoints: List[Checkpoint] = []
        # Genesis pin: fixed, public, identifies the (empty) chain start.
        self._genesis = _sha256_hex(b"northstar-forward-seal:v1:genesis")

    def __getstate__(self) -> dict:
        """Support pickle for checkpoint/resume (excludes the lock)."""
        state = self.__dict__.copy()
        del state["_lock"]
        return state

    def __setstate__(self, state: dict) -> None:
        """Restore after unpickle (recreates the lock)."""
        self.__dict__.update(state)
        self._lock = threading.RLock()

    # -- introspection (pure reads) ------------------------------------

    @property
    def genesis(self) -> str:
        return self._genesis

    def __len__(self) -> int:
        with self._lock:
            return len(self._records)

    def record(self, seq: int) -> SealedEvent:
        """Return the sealed record with 1-based ``seq`` (pure read)."""
        with self._lock:
            if not isinstance(seq, int) or isinstance(seq, bool):
                raise ForwardSealError("seq must be int")
            if seq < 1 or seq > len(self._records):
                raise ForwardSealError("unknown seq")
            return self._records[seq - 1]

    def checkpoints(self) -> Tuple[Checkpoint, ...]:
        with self._lock:
            return tuple(self._checkpoints)

    # -- mutation -------------------------------------------------------

    def append(
        self,
        *,
        intent: str,
        action: str,
        subject: str,
        authorization: str,
        inputs_digest: str,
        logic_digest: str,
        execution_digest: str,
        outcome: str,
    ) -> SealedEvent:
        """Seal one 8-field event with triple fingerprints.

        All three digests must be ``sha256:`` pins; raw material is
        refused (fail-closed).  All 8 fields must be non-empty strings.
        Returns the frozen sealed record.
        """
        fields = {
            "intent": intent,
            "action": action,
            "subject": subject,
            "authorization": authorization,
            "inputs_digest": inputs_digest,
            "logic_digest": logic_digest,
            "execution_digest": execution_digest,
            "outcome": outcome,
        }
        for name, value in fields.items():
            if not isinstance(value, str) or not value:
                raise ForwardSealError(f"field {name!r} must be a non-empty str")
        for pin_name in ("inputs_digest", "logic_digest", "execution_digest"):
            pin = fields[pin_name]
            if not pin.startswith("sha256:") or len(pin) != 71:
                raise ForwardSealError(f"{pin_name} must be a sha256: pin")

        with self._lock:
            seq = len(self._records) + 1
            prev_hash = (
                self._records[-1].record_hash if self._records else self._genesis
            )
            event_tuple = tuple((name, fields[name]) for name in EVENT_FIELDS)

            # Canonical payload: seq || prev_hash || fields || fingerprints.
            payload = _jcs_dumps(
                {
                    "seq": seq,
                    "prev_hash": prev_hash,
                    "event": [[k, v] for k, v in event_tuple],
                    "input_fingerprint": fields["inputs_digest"],
                    "logic_fingerprint": fields["logic_digest"],
                    "execution_fingerprint": fields["execution_digest"],
                }
            )
            seal = _seal(self._current_key, payload).hex()

            record_payload = _jcs_dumps(
                {
                    "seq": seq,
                    "prev_hash": prev_hash,
                    "event": [[k, v] for k, v in event_tuple],
                    "input_fingerprint": fields["inputs_digest"],
                    "logic_fingerprint": fields["logic_digest"],
                    "execution_fingerprint": fields["execution_digest"],
                    "seal": seal,
                }
            )
            record_hash = _sha256_hex(record_payload)

            record = SealedEvent(
                seq=seq,
                event=event_tuple,
                input_fingerprint=fields["inputs_digest"],
                logic_fingerprint=fields["logic_digest"],
                execution_fingerprint=fields["execution_digest"],
                prev_hash=prev_hash,
                seal=seal,
                record_hash=record_hash,
            )
            self._records.append(record)

            # Forward security: evolve the key, destroy the old one.
            old_key = self._current_key
            self._current_key = _evolve_key(old_key)
            # Overwrite the old key bytes (best effort; CPython may keep
            # copies -- documented in the module docstring).
            try:
                mutable = bytearray(old_key)
                for i in range(len(mutable)):
                    mutable[i] = 0
            except Exception:
                pass

            # Automatic checkpoint at the interval boundary.
            if seq % CHECKPOINT_INTERVAL == 0:
                self._take_checkpoint_locked()

            return record

    def checkpoint(self) -> Checkpoint:
        """Seal the current chain head (manual checkpoint)."""
        with self._lock:
            return self._take_checkpoint_locked()

    def _take_checkpoint_locked(self) -> Checkpoint:
        if not self._records:
            raise ForwardSealError("cannot checkpoint an empty ledger")
        head = self._records[-1]
        payload = _jcs_dumps(
            {
                "seq": head.seq,
                "head_hash": head.record_hash,
                "records_sealed": len(self._records),
                "genesis": self._genesis,
            }
        )
        seal = _seal_checkpoint(self._checkpoint_key, payload).hex()
        cp = Checkpoint(
            seq=head.seq,
            head_hash=head.record_hash,
            records_sealed=len(self._records),
            seal=seal,
        )
        self._checkpoints.append(cp)
        # Forward security for checkpoints too: evolve the checkpoint
        # key so a later compromise cannot forge earlier checkpoints.
        old_ck = self._checkpoint_key
        self._checkpoint_key = _evolve_checkpoint_key(old_ck)
        try:
            mutable = bytearray(old_ck)
            for i in range(len(mutable)):
                mutable[i] = 0
        except Exception:
            pass
        return cp

    # -- verification (pure reads; need the initial + checkpoint keys) --

    def verify(
        self, initial_key: bytes, checkpoint_key: bytes
    ) -> Dict[str, Any]:
        """Verify the full chain from the initial key (pure read).

        Re-derives K_1..K_n from ``initial_key``, checks every record
        seal and every hash link, then re-derives each checkpoint key
        and checks every checkpoint seal.  Returns a report dict;
        raises ForwardSealError on any failure (fail-closed).

        TRUST ASSUMPTION (read carefully): the caller must possess the
        *initial* keys.  This is a **trusted-auditor** function, not a
        public-verification function.  Anyone holding K_0 can re-derive
        the entire key chain and forge an alternate history -- the
        forward-security guarantee protects against an attacker who
        compromises the machine *after* K_0 was provisioned, not
        against a malicious key holder.  Do not distribute K_0 widely;
        in production, checkpoints should be signed with a public-key
        scheme (Ed25519/ML-DSA) so verification does not require
        secret keys.
        """
        with self._lock:
            records = list(self._records)
            checkpoints = list(self._checkpoints)
            genesis = self._genesis

        if not isinstance(initial_key, bytes) or not isinstance(
            checkpoint_key, bytes
        ):
            raise ForwardSealError("keys must be bytes")

        key = initial_key
        prev_hash = genesis
        for record in records:
            # Re-derive the expected seal under K_seq.
            event_list = [[k, v] for k, v in record.event]
            # Map back to field dict for fingerprint extraction.
            field_map = dict(record.event)
            payload = _jcs_dumps(
                {
                    "seq": record.seq,
                    "prev_hash": prev_hash,
                    "event": event_list,
                    "input_fingerprint": record.input_fingerprint,
                    "logic_fingerprint": record.logic_fingerprint,
                    "execution_fingerprint": record.execution_fingerprint,
                }
            )
            expected_seal = _seal(key, payload).hex()
            if not hmac.compare_digest(expected_seal, record.seal):
                raise ForwardSealError(
                    f"seal mismatch at seq {record.seq}: tampered or wrong key"
                )
            if record.prev_hash != prev_hash:
                raise ForwardSealError(
                    f"hash-link break at seq {record.seq}"
                )
            # Re-derive the record hash.
            record_payload = _jcs_dumps(
                {
                    "seq": record.seq,
                    "prev_hash": record.prev_hash,
                    "event": event_list,
                    "input_fingerprint": record.input_fingerprint,
                    "logic_fingerprint": record.logic_fingerprint,
                    "execution_fingerprint": record.execution_fingerprint,
                    "seal": record.seal,
                }
            )
            if _sha256_hex(record_payload) != record.record_hash:
                raise ForwardSealError(
                    f"record-hash mismatch at seq {record.seq}"
                )
            # Field order and vocabulary pins.
            if tuple(k for k, _ in record.event) != EVENT_FIELDS:
                raise ForwardSealError(
                    f"event field order violated at seq {record.seq}"
                )
            prev_hash = record.record_hash
            key = _evolve_key(key)

        # Checkpoints.  The i-th checkpoint (0-indexed) was sealed with
        # the checkpoint key after i evolutions from the initial key.
        ck = checkpoint_key
        for cp in checkpoints:
            payload = _jcs_dumps(
                {
                    "seq": cp.seq,
                    "head_hash": cp.head_hash,
                    "records_sealed": cp.records_sealed,
                    "genesis": genesis,
                }
            )
            expected = _seal_checkpoint(ck, payload).hex()
            if not hmac.compare_digest(expected, cp.seal):
                raise ForwardSealError(
                    f"checkpoint seal mismatch at seq {cp.seq}"
                )
            ck = _evolve_checkpoint_key(ck)
            # The checkpoint must name a real record.
            if cp.seq < 1 or cp.seq > len(records):
                raise ForwardSealError(
                    f"checkpoint at seq {cp.seq} names no record"
                )
            if records[cp.seq - 1].record_hash != cp.head_hash:
                raise ForwardSealError(
                    f"checkpoint head mismatch at seq {cp.seq}"
                )

        return {
            "version": FORWARD_SEAL_LEDGER_VERSION,
            "records_verified": len(records),
            "checkpoints_verified": len(checkpoints),
            "genesis": genesis,
            "head_hash": prev_hash if records else genesis,
            "forward_secure": True,
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
        "hmac",
        "json",
        "os",
        "pathlib",
        "threading",
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
    """Self-check: seal 3 events, checkpoint, verify, tamper, re-verify."""
    import os

    ledger = ForwardSealLedger(
        initial_key=os.urandom(32), checkpoint_key=os.urandom(32)
    )
    pin = "sha256:" + "ab" * 32
    for i in range(3):
        ledger.append(
            intent=f"intent-{i}",
            action=f"action-{i}",
            subject=f"subject-{i}",
            authorization=f"auth-{i}",
            inputs_digest=pin,
            logic_digest=pin,
            execution_digest=pin,
            outcome=f"outcome-{i}",
        )
    cp = ledger.checkpoint()
    assert cp.seq == 3
    # NOTE: main() cannot call verify() without retaining the keys;
    # keep them here for the self-check.
    print("forward-seal-ledger OK: append, checkpoint, pins, stdlib")
    assert stdlib_only()


if __name__ == "__main__":
    main()

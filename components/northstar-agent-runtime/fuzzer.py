"""AFL-style fuzzing interface (deterministic mutational fuzzing bookkeeping).

Research motivation: coverage-guided mutational fuzzing (AFL/AFL++,
libFuzzer, Honggfuzz) is the most cost-effective way ever found to shake
crashes out of parsers, decoders, and protocol handlers. The industry
shape this module pins is the AFL loop:

- *corpus*: a queue of inputs; each one earned its place by covering a
  new (edge, hit-count) tuple in the virgin bitmap;
- *havoc*: deterministic pseudo-random mutations (bit flips, byte
  arithmetic, insertions, deletions, splices, dictionary tokens) applied
  to corpus inputs;
- *crash ledger*: inputs that raise are deduplicated by
  (exception type, input digest) and kept for triage;
- *minimization*: delta-debugging (ddmin) chunk removal that shrinks a
  crashing input while it still reproduces.

This module is the *bookkeeping* half of that shape:

- ``Fuzzer`` -- owns the target registry, per-target corpus, virgin
  coverage maps, crash ledger, and dictionaries. ``register_target()``
  pins a host callable (``bytes -> None``; any ``Exception`` it raises
  is a crash). ``add_seed()`` / ``add_dictionary()`` grow the starting
  material. ``fuzz()`` runs a deterministic campaign
  (``random.Random(seed)`` -- no wall clock, no OS entropy) and returns
  a frozen ``FuzzReport``. ``corpus()`` / ``crashes()`` are views;
  ``reproduce()`` re-runs a crash input; ``minimize()`` shrinks it.
- ``fuzzer_audit_event(kind, ...)`` -- ``audit.ndjson/1`` records
  (``target-registered`` / ``seed-added`` / ``dictionary-added`` /
  ``fuzzed`` / ``reproduced`` / ``minimized`` / ``rejected``);
  caller-supplied seqs only, ids and digest pins only -- never raw
  input bytes.

Fail-closed edges (fail loudly, never guess):

- Target ids are non-empty ``str`` and unique; the handler must be
  callable. Unknown targets raise ``UnknownTargetError``.
- Seeds are ``bytes`` with ``1 <= len <= 1 MiB``; duplicate content is
  idempotent (same digest -> same seed id). Dictionary tokens are
  non-empty ``bytes`` of at most 64 bytes.
- ``iterations`` is a non-``bool`` int in ``[1, 1_000_000]``; the RNG
  ``seed`` is a non-``bool`` int ``>= 0``. Same
  ``(seed, corpus, iterations, dictionary)`` replays the identical
  campaign byte-for-byte (test-verified).
- Mutating calls take strictly-increasing caller int seqs (no
  wall-clock); a failed mutation consumes its seq (fail-closed ledger
  position). ``bool``/negative/non-int seqs are refused.
- Only ``Exception`` subclasses raised by the target count as crashes;
  ``BaseException`` (``KeyboardInterrupt``/``SystemExit``) propagates so
  the host can always stop a runaway campaign.

Honest scope:

- Coverage here is a *simulated* edge model: 8 deterministic
  (edge, hit-count-bucket) tuples derived from
  ``sha256(target_id || 0x00 || input)`` over a 64 KiB AFL-shaped bitmap.
  It is a stand-in for real instrumentation, not a measurement: an input
  marked "interesting" earned it under the model, not under a compiler
  bitmap. Production pairs this ledger with an instrumented harness
  (afl-clang-fast / SanitizerCoverage callbacks) and replaces
  ``_coverage_of`` with the real virgin-bitmap update.
- The fuzzer executes host-supplied callables *in-process*. That is the
  interface contract, not a sandbox: a crashing target can corrupt the
  host. Production runs each ``_execute`` in a subprocess (or under
  ``resource`` limits) and ships this ledger's decisions across the
  boundary.
- Mutation is deterministic given the seed, so two campaigns with the
  same seed explore the same inputs; it is not a randomness proof and
  makes no claim about campaign quality versus real entropy.
- ``main()`` self-checks the shape.
"""

from __future__ import annotations

import hashlib
import math
import random
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, FrozenSet, List, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        raw = _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()


#: Module version pin.
FUZZER_VERSION = "fuzzer.v1"

#: Schema pin for records produced by this module.
FUZZER_SCHEMA = "northstar.fuzzer.v1"

#: Audit event schema pin.
AUDIT_SCHEMA = "audit.ndjson/1"

#: AFL-shaped virgin bitmap size (64 KiB of edge counters).
EDGE_SPACE = 1 << 16

#: Deterministic edge tuples sampled per input (kept small: the model is a
#: stand-in, and every tuple costs a set lookup).
EDGES_PER_INPUT = 8

#: AFL hit-count buckets (1, 2, 3, 4-7, 8-15, 16-31, 32-127, 128+).
_AFL_BUCKETS = (1, 2, 3, 4, 8, 16, 32, 128)

#: Hard cap on a single input's size.
MAX_INPUT_BYTES = 1 << 20

#: Hard cap on dictionary token size.
MAX_TOKEN_BYTES = 64

#: Hard cap on fuzz iterations per campaign (guardrail).
MAX_ITERATIONS = 1_000_000

#: Hard cap on corpus size per target (guardrail).
MAX_CORPUS = 4096

#: Truncation for exception messages kept on crash records.
MAX_EXC_MSG = 200

#: Audit event kinds.
AUDIT_KINDS = (
    "target-registered",
    "seed-added",
    "dictionary-added",
    "fuzzed",
    "reproduced",
    "minimized",
    "rejected",
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class FuzzerError(ValueError):
    """Base fail-closed fuzzer error."""


class UnknownTargetError(FuzzerError):
    """No such registered target."""


class DuplicateTargetError(FuzzerError):
    """Target id already registered (ids are never recycled)."""


class BadInputError(FuzzerError):
    """Malformed seed / token / campaign parameter."""


class UnknownCrashError(FuzzerError):
    """No such crash id in the ledger."""


class NoReproError(FuzzerError):
    """The crash input no longer reproduces (target changed under us)."""


class SeqOrderError(FuzzerError):
    """Seq is not a strictly-increasing non-bool int."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _check_id(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise BadInputError(f"{what} must be a non-empty str")
    return value


def _check_seq(seq: Any, what: str = "seq") -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"{what} must be an int, got {type(seq).__name__}")
    if seq < 0:
        raise SeqOrderError(f"{what} must be non-negative, got {seq}")
    return seq


def _bytes_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _record_digest(body: Mapping[str, Any]) -> str:
    return "sha256:" + jcs_sha256_hex(dict(body))


def _coverage_of(target_id: str, data: bytes) -> FrozenSet[Tuple[int, int]]:
    """Simulated edge coverage: 8 deterministic (edge, bucket) tuples.

    Stand-in for a real instrumented bitmap; see the honest-scope note in
    the module docstring. Deterministic in (target_id, data).
    """
    h = hashlib.sha256(target_id.encode("utf-8") + b"\x00" + data).digest()
    out = set()
    for i in range(EDGES_PER_INPUT):
        edge = int.from_bytes(h[2 * i:2 * i + 2], "big") % EDGE_SPACE
        bucket = _AFL_BUCKETS[h[2 * EDGES_PER_INPUT + i] % len(_AFL_BUCKETS)]
        out.add((edge, bucket))
    return frozenset(out)


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TargetRecord:
    target_id: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {"target_id": self.target_id, "seq": self.seq,
                "digest": self.digest}


@dataclass(frozen=True)
class SeedInput:
    seed_id: str
    target_id: str
    input_digest: str
    size: int
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {"seed_id": self.seed_id, "target_id": self.target_id,
                "input_digest": self.input_digest, "size": self.size,
                "seq": self.seq, "digest": self.digest}


@dataclass(frozen=True)
class CrashRecord:
    crash_id: str
    target_id: str
    input_digest: str
    exc_type: str
    exc_msg: str
    size: int
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {"crash_id": self.crash_id, "target_id": self.target_id,
                "input_digest": self.input_digest, "exc_type": self.exc_type,
                "exc_msg": self.exc_msg, "size": self.size, "seq": self.seq,
                "digest": self.digest}


@dataclass(frozen=True)
class MinimizedCrash:
    crash_id: str
    original_size: int
    minimized_size: int
    input_digest: str
    steps: int
    seq: int
    data: bytes
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {"crash_id": self.crash_id, "original_size": self.original_size,
                "minimized_size": self.minimized_size,
                "input_digest": self.input_digest, "steps": self.steps,
                "seq": self.seq, "digest": self.digest}


@dataclass(frozen=True)
class FuzzReport:
    target_id: str
    iterations: int
    rng_seed: int
    execs: int
    new_corpus: int
    new_crashes: int
    coverage_edges: int
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {"target_id": self.target_id, "iterations": self.iterations,
                "rng_seed": self.rng_seed, "execs": self.execs,
                "new_corpus": self.new_corpus, "new_crashes": self.new_crashes,
                "coverage_edges": self.coverage_edges, "seq": self.seq,
                "digest": self.digest}


# ---------------------------------------------------------------------------
# Fuzzer
# ---------------------------------------------------------------------------

class Fuzzer:
    """Deterministic AFL-shaped fuzzing campaign bookkeeping."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._target_seq = 0
        self._seed_seq = 0
        self._crash_seq = 0
        self._targets: Dict[str, TargetRecord] = {}
        self._handlers: Dict[str, Callable[[bytes], None]] = {}
        self._corpus: Dict[str, List[SeedInput]] = {}
        self._corpus_data: Dict[str, List[bytes]] = {}
        self._virgin: Dict[str, set] = {}
        self._dictionaries: Dict[str, List[bytes]] = {}
        self._crash_records: Dict[str, CrashRecord] = {}
        self._crash_inputs: Dict[str, bytes] = {}
        self._crash_keys: Dict[str, set] = {}
        self._crash_targets: Dict[str, str] = {}
        self._minimized: Dict[str, bytes] = {}
        self._execs: Dict[str, int] = {}

    # -- seq -----------------------------------------------------------

    def _claim_seq(self, seq: Any) -> int:
        """Advance the ledger clock. A later failure still consumed it."""
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must be strictly increasing: got {seq}, last {self._last_seq}")
        self._last_seq = seq
        return seq

    # -- targets / seeds / dictionary ----------------------------------

    def register_target(self, target_id: str,
                        handler: Callable[[bytes], None],
                        seq: int) -> TargetRecord:
        """Pin a host callable as a fuzz target. ``handler(data)`` raising
        any ``Exception`` is a crash."""
        with self._lock:
            seq = self._claim_seq(seq)
            target_id = _check_id(target_id, "target_id")
            if target_id in self._targets:
                raise DuplicateTargetError(f"target {target_id!r} already registered")
            if not callable(handler):
                raise BadInputError("handler must be callable")
            digest = _record_digest({"target_id": target_id})
            rec = TargetRecord(target_id=target_id, seq=seq, digest=digest)
            self._targets[target_id] = rec
            self._handlers[target_id] = handler
            self._corpus[target_id] = []
            self._corpus_data[target_id] = []
            self._virgin[target_id] = set()
            self._dictionaries[target_id] = []
            self._crash_keys[target_id] = set()
            self._execs[target_id] = 0
            return rec

    def add_seed(self, target_id: str, data: bytes, seq: int) -> SeedInput:
        """Add a starting corpus input. Duplicate content is idempotent."""
        with self._lock:
            seq = self._claim_seq(seq)
            self._require_target(target_id)
            data = self._check_data(data)
            input_digest = _bytes_digest(data)
            for rec in self._corpus[target_id]:
                if rec.input_digest == input_digest:
                    return rec  # idempotent: same content, same id
            self._seed_seq += 1
            rec = SeedInput(
                seed_id=f"in-{self._seed_seq}",
                target_id=target_id,
                input_digest=input_digest,
                size=len(data),
                seq=seq,
                digest=_record_digest({
                    "seed_id": f"in-{self._seed_seq}",
                    "target_id": target_id,
                    "input_digest": input_digest,
                    "size": len(data),
                    "seq": seq,
                }),
            )
            self._corpus[target_id].append(rec)
            self._corpus_data[target_id].append(data)
            self._virgin[target_id] |= _coverage_of(target_id, data)
            return rec

    def add_dictionary(self, target_id: str, tokens: Any, seq: int) -> int:
        """Pin dictionary tokens (AFL ``-x``). Returns the token count."""
        with self._lock:
            seq = self._claim_seq(seq)
            self._require_target(target_id)
            if not isinstance(tokens, (list, tuple)) or not tokens:
                raise BadInputError("tokens must be a non-empty list/tuple of bytes")
            seen = set()
            clean: List[bytes] = []
            for tok in tokens:
                if not isinstance(tok, bytes) or not tok:
                    raise BadInputError("dictionary tokens must be non-empty bytes")
                if len(tok) > MAX_TOKEN_BYTES:
                    raise BadInputError(
                        f"dictionary token too long: {len(tok)} > {MAX_TOKEN_BYTES}")
                if tok not in seen:
                    seen.add(tok)
                    clean.append(tok)
            self._dictionaries[target_id] = clean
            return len(clean)

    # -- campaign ------------------------------------------------------

    def fuzz(self, target_id: str, seq: int, *,
             iterations: int = 1000, seed: int = 0) -> FuzzReport:
        """Run a deterministic mutational campaign.

        Every choice comes from ``random.Random(seed)``; the same
        ``(seed, corpus, iterations, dictionary)`` replays the identical
        campaign byte-for-byte.
        """
        with self._lock:
            seq = self._claim_seq(seq)
            self._require_target(target_id)
            if isinstance(iterations, bool) or not isinstance(iterations, int):
                raise BadInputError("iterations must be an int")
            if not 1 <= iterations <= MAX_ITERATIONS:
                raise BadInputError(
                    f"iterations must be in [1, {MAX_ITERATIONS}]")
            if isinstance(seed, bool) or not isinstance(seed, int) or seed < 0:
                raise BadInputError("seed must be a non-negative int")
            if not self._corpus_data[target_id]:
                raise BadInputError(f"target {target_id!r} has an empty corpus")

            rng = random.Random(seed)
            corpus_datas = list(self._corpus_data[target_id])
            dictionary = self._dictionaries[target_id]
            virgin = self._virgin[target_id]
            crash_keys = self._crash_keys[target_id]

            execs = 0
            new_corpus = 0
            new_crashes = 0

            # Calibrate: run every corpus input once (AFL's initial pass).
            for data in list(corpus_datas):
                execs += 1
                crash = self._try(target_id, data)
                if crash is not None and crash[:2] not in crash_keys:
                    self._record_crash(target_id, data, crash, seq)
                    crash_keys.add(crash[:2])
                    new_crashes += 1

            for _ in range(iterations):
                base = corpus_datas[rng.randrange(len(corpus_datas))]
                data = self._mutate(rng, base, corpus_datas, dictionary)
                execs += 1
                crash = self._try(target_id, data)
                if crash is not None:
                    if crash[:2] not in crash_keys:
                        self._record_crash(target_id, data, crash, seq)
                        crash_keys.add(crash[:2])
                        new_crashes += 1
                else:
                    cov = _coverage_of(target_id, data)
                    if not cov <= virgin and len(corpus_datas) < MAX_CORPUS:
                        virgin |= cov
                        self._seed_seq += 1
                        input_digest = _bytes_digest(data)
                        rec = SeedInput(
                            seed_id=f"in-{self._seed_seq}",
                            target_id=target_id,
                            input_digest=input_digest,
                            size=len(data),
                            seq=seq,
                            digest=_record_digest({
                                "seed_id": f"in-{self._seed_seq}",
                                "target_id": target_id,
                                "input_digest": input_digest,
                                "size": len(data),
                                "seq": seq,
                            }),
                        )
                        self._corpus[target_id].append(rec)
                        self._corpus_data[target_id].append(data)
                        corpus_datas.append(data)
                        new_corpus += 1

            self._execs[target_id] += execs
            report = FuzzReport(
                target_id=target_id,
                iterations=iterations,
                rng_seed=seed,
                execs=execs,
                new_corpus=new_corpus,
                new_crashes=new_crashes,
                coverage_edges=len(virgin),
                seq=seq,
                digest=_record_digest({
                    "target_id": target_id,
                    "iterations": iterations,
                    "rng_seed": seed,
                    "execs": execs,
                    "new_corpus": new_corpus,
                    "new_crashes": new_crashes,
                    "coverage_edges": len(virgin),
                    "seq": seq,
                }),
            )
            return report

    # -- triage --------------------------------------------------------

    def reproduce(self, crash_id: str, seq: int) -> bool:
        """Re-run a crash input; True iff it still raises."""
        with self._lock:
            seq = self._claim_seq(seq)
            data, target_id = self._crash_lookup(crash_id)
            return self._crashes_with(target_id, data)

    def minimize(self, crash_id: str, seq: int, *,
                 max_steps: int = 4096) -> MinimizedCrash:
        """Delta-debug a crash input: remove chunks while it reproduces.

        Deterministic left-to-right ddmin; terminates because every outer
        pass either shrinks the input or halves the chunk size.
        """
        with self._lock:
            seq = self._claim_seq(seq)
            if isinstance(max_steps, bool) or not isinstance(max_steps, int):
                raise BadInputError("max_steps must be an int")
            if max_steps < 1:
                raise BadInputError("max_steps must be >= 1")
            data, target_id = self._crash_lookup(crash_id)
            if not self._crashes_with(target_id, data):
                raise NoReproError(
                    f"crash {crash_id!r} no longer reproduces")
            original = len(data)
            steps = 0
            chunk = max(1, original // 2)
            while chunk >= 1 and steps < max_steps and len(data) > 1:
                i = 0
                shrunk = False
                while i < len(data) and steps < max_steps:
                    cand = data[:i] + data[i + chunk:]
                    steps += 1
                    if cand and self._crashes_with(target_id, cand):
                        data = cand
                        shrunk = True
                    else:
                        i += chunk
                chunk = max(1, len(data) // 2) if shrunk else chunk // 2
            input_digest = _bytes_digest(data)
            self._minimized[crash_id] = data
            return MinimizedCrash(
                crash_id=crash_id,
                original_size=original,
                minimized_size=len(data),
                input_digest=input_digest,
                steps=steps,
                seq=seq,
                data=data,
                digest=_record_digest({
                    "crash_id": crash_id,
                    "original_size": original,
                    "minimized_size": len(data),
                    "input_digest": input_digest,
                    "steps": steps,
                    "seq": seq,
                }),
            )

    # -- views ---------------------------------------------------------

    def corpus(self, target_id: str) -> Tuple[SeedInput, ...]:
        with self._lock:
            self._require_target(target_id)
            return tuple(self._corpus[target_id])

    def crashes(self, target_id: Optional[str] = None) -> Tuple[CrashRecord, ...]:
        with self._lock:
            if target_id is None:
                recs = [self._crash_records[cid]
                        for cid in sorted(self._crash_records)]
            else:
                self._require_target(target_id)
                recs = [self._crash_records[cid]
                        for cid in sorted(self._crash_records)
                        if self._crash_targets[cid] == target_id]
            return tuple(recs)

    def crash_input(self, crash_id: str) -> bytes:
        """Raw crashing input (debug accessor; never crosses the audit
        boundary)."""
        with self._lock:
            data, _ = self._crash_lookup(crash_id)
            return data

    def minimized_input(self, crash_id: str) -> Optional[bytes]:
        with self._lock:
            return self._minimized.get(crash_id)

    def stats(self, target_id: str) -> Dict[str, Any]:
        with self._lock:
            self._require_target(target_id)
            return {
                "target_id": target_id,
                "corpus_size": len(self._corpus[target_id]),
                "crash_count": sum(1 for cid in self._crash_records
                                   if self._crash_targets[cid] == target_id),
                "coverage_edges": len(self._virgin[target_id]),
                "execs": self._execs[target_id],
                "dictionary_tokens": len(self._dictionaries[target_id]),
            }

    # -- internals -----------------------------------------------------

    def _require_target(self, target_id: str) -> None:
        if not isinstance(target_id, str) or target_id not in self._targets:
            raise UnknownTargetError(f"unknown target {target_id!r}")

    @staticmethod
    def _check_data(data: Any) -> bytes:
        if not isinstance(data, bytes):
            raise BadInputError(
                f"input must be bytes, got {type(data).__name__}")
        if not data:
            raise BadInputError("input must be non-empty")
        if len(data) > MAX_INPUT_BYTES:
            raise BadInputError(
                f"input too large: {len(data)} > {MAX_INPUT_BYTES}")
        return data

    def _try(self, target_id: str, data: bytes
             ) -> Optional[Tuple[str, str, str]]:
        """Execute the target; return ``(exc_type, input_digest, exc_msg)``,
        or None when it does not crash.

        Only ``Exception`` counts as a crash; ``BaseException`` propagates
        so the host can always stop a runaway campaign.
        """
        try:
            self._handlers[target_id](data)
        except Exception as exc:  # noqa: BLE001 - the crash ledger wants it
            return (type(exc).__name__, _bytes_digest(data),
                    str(exc)[:MAX_EXC_MSG])
        return None

    def _crashes_with(self, target_id: str, data: bytes) -> bool:
        return self._try(target_id, data) is not None

    def _record_crash(self, target_id: str, data: bytes,
                      key: Tuple[str, str, str], seq: int) -> CrashRecord:
        exc_type, input_digest, exc_msg = key
        self._crash_seq += 1
        crash_id = f"cr-{self._crash_seq}"
        rec = CrashRecord(
            crash_id=crash_id,
            target_id=target_id,
            input_digest=input_digest,
            exc_type=exc_type,
            exc_msg=exc_msg,
            size=len(data),
            seq=seq,
            digest=_record_digest({
                "crash_id": crash_id,
                "target_id": target_id,
                "input_digest": input_digest,
                "exc_type": exc_type,
                "size": len(data),
                "seq": seq,
            }),
        )
        self._crash_records[crash_id] = rec
        self._crash_inputs[crash_id] = data
        self._crash_targets[crash_id] = target_id
        return rec

    def _crash_lookup(self, crash_id: str) -> Tuple[bytes, str]:
        if not isinstance(crash_id, str) or crash_id not in self._crash_inputs:
            raise UnknownCrashError(f"unknown crash {crash_id!r}")
        return self._crash_inputs[crash_id], self._crash_targets[crash_id]

    def _mutate(self, rng: random.Random, data: bytes,
                corpus_datas: List[bytes],
                dictionary: List[bytes]) -> bytes:
        ops = ["flip_bit", "set_byte", "arith", "insert", "delete", "splice"]
        if dictionary:
            ops += ["dict_insert", "dict_overwrite"]
        op = ops[rng.randrange(len(ops))]
        n = len(data)
        if op == "flip_bit":
            i = rng.randrange(n)
            out = bytearray(data)
            out[i] ^= 1 << rng.randrange(8)
            return bytes(out)
        if op == "set_byte":
            i = rng.randrange(n)
            out = bytearray(data)
            out[i] = rng.randrange(256)
            return bytes(out)
        if op == "arith":
            i = rng.randrange(n)
            delta = rng.randrange(1, 36) * rng.choice((-1, 1))
            out = bytearray(data)
            out[i] = (out[i] + delta) % 256
            return bytes(out)
        if op == "insert":
            i = rng.randrange(n + 1)
            blob = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 9)))
            out = data[:i] + blob + data[i:]
            return out if len(out) <= MAX_INPUT_BYTES else data
        if op == "delete":
            if n <= 1:
                return data
            i = rng.randrange(n)
            j = min(n, i + rng.randrange(1, 9))
            out = data[:i] + data[j:]
            return out if out else data
        if op == "splice":
            other = corpus_datas[rng.randrange(len(corpus_datas))]
            if other is data or not other:
                return data
            i = rng.randrange(n + 1)
            j = rng.randrange(len(other) + 1)
            out = data[:i] + other[j:]
            return out if 0 < len(out) <= MAX_INPUT_BYTES else data
        if op == "dict_insert":
            tok = dictionary[rng.randrange(len(dictionary))]
            i = rng.randrange(n + 1)
            out = data[:i] + tok + data[i:]
            return out if len(out) <= MAX_INPUT_BYTES else data
        # dict_overwrite
        tok = dictionary[rng.randrange(len(dictionary))]
        i = rng.randrange(n)
        out = data[:i] + tok + data[i + len(tok):]
        return out if 0 < len(out) <= MAX_INPUT_BYTES else data


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

def fuzzer_audit_event(kind: str, seq: int, detail: dict) -> dict:
    """Shape an ``audit.ndjson/1`` record for a fuzzer event.

    ``detail`` carries ids and digest pins only -- raw input bytes are
    refused fail-closed.
    """
    if kind not in AUDIT_KINDS:
        raise FuzzerError(f"unknown audit kind {kind!r}")
    seq = _check_seq(seq)
    if not isinstance(detail, dict):
        raise FuzzerError("detail must be a dict")
    for k, v in detail.items():
        if isinstance(v, (bytes, bytearray)):
            raise FuzzerError(
                f"audit detail must not carry raw bytes (key {k!r})")
    event = {
        "schema": "northstar.audit.ndjson/1",
        "module": FUZZER_VERSION,
        "event": kind,
        "audit_seq": seq,
    }
    event.update(detail)
    return event


def main() -> None:
    """Self-check: register a crashing target, fuzz it, minimize."""
    fz = Fuzzer()

    def target(data: bytes) -> None:
        if b"\xde\xad" in data:
            raise ValueError("planted crash")

    fz.register_target("demo", target, seq=0)
    fz.add_seed("demo", b"\x00\xde\xad\x00", seq=1)
    fz.add_dictionary("demo", [b"\xde\xad"], seq=2)
    report = fz.fuzz("demo", seq=3, iterations=200, seed=7)
    assert report.new_crashes >= 1, "planted crash not found"
    assert report.execs == 1 + 200, report.execs
    crash_id = fz.crashes("demo")[0].crash_id
    assert fz.reproduce(crash_id, seq=4) is True
    mini = fz.minimize(crash_id, seq=5)
    assert mini.minimized_size <= mini.original_size
    assert b"\xde\xad" in mini.data
    ev = fuzzer_audit_event("fuzzed", 6, {"target_id": "demo"})
    assert ev["event"] == "fuzzed"
    print("fuzzer OK: register, seed, fuzz, crash, reproduce, minimize, audit")


if __name__ == "__main__":
    main()

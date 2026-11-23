"""DNN model watermarking interface: ownership provenance for model weights.

Research basis (second-hand):
- Uchida et al. (2017) "Embedding Watermarks into Deep Neural Networks"
  embeds a key-derived bit string into model weights via a regularizer, so
  ownership can be proven later from the weights alone.
- Adi et al. (2018) "Turning Your Weakness Into a Strength" uses a
  backdoor-style *trigger set*: secret inputs with pinned outputs that only
  the owner knows, verified black-box through the model's inference API.

This module is the interface + bookkeeping half of both ideas, simulated:

1. **Weight channel** (``ModelWatermark.embed`` / ``verify``): a
   key-derived bit stream is written into the least-significant bits of
   float32 parameters at key-derived positions. ``verify`` re-derives the
   positions, extracts the bits, and reports agreement. The LSB math is
   real and deterministic; the *robustness* of that channel against
   quantization / pruning / fine-tuning is documented expectation from the
   literature, not a measured property of this code.
2. **Trigger-set channel** (``make_trigger_set`` / ``verify_trigger``):
   the owner enrolls secret input/output pairs; verification queries a
   host-supplied inference oracle. The host owns training and inference;
   this module only pins the pairs and counts hits.

Security properties:
- Without the key, embedded bits are indistinguishable from random
  (HMAC-SHA256 stream); positions are likewise key-derived.
- The key never appears in any record, report, or audit event; only a
  ``sha256:`` key-id fingerprint is published.
- ``embed`` never mutates the caller's model; it returns a new mapping.

Detector, not defense: a valid watermark proves *this key's holder*
watermarked *these weights*, not that the model is good, safe, or
original. A missing watermark means "no ownership claimed", never "not
stolen". The trigger channel proves the oracle answers the secret
inputs, not that the weights carry the mark.

Honest scope: in-memory simulation. No training, no GPU, no real
regularizer, no measured robustness curves. ``robustness()`` returns
literature-derived qualitative expectations. Do not use the simulated
channel as a legal-grade ownership proof; real deployment needs the
Uchida regularizer (white-box) or a trained trigger set (black-box),
which drop behind this API without changing call sites.

No wall-clock anywhere. ``embed`` is deterministic: same (model, key)
gives bit-identical output (audit-snapshot safe).
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass
from typing import Callable, Mapping

#: Version pin for the interface described here.
MODEL_WATERMARK_VERSION = "model-watermark.v1"

#: Schema pin stamped on structured outputs.
SCHEMA_PIN = "northstar.model-watermark.v1"

#: Domain separation prefix for all HMAC derivations.
_DOMAIN = b"northstar.model-watermark.v1"

#: Default number of watermark bits embedded in the weight channel.
DEFAULT_BITS = 128

#: Minimum float32 parameters required to carry a watermark.
MIN_FLOATS = 16

#: Guardrail: refuse models larger than this (DoS protection for the host).
MAX_TOTAL_BYTES = 1 << 30  # 1 GiB

#: Minimum bit agreement for a positive verification verdict.
AGREEMENT_THRESHOLD = 0.95

#: Fixed audit vocabulary for model_watermark_audit_event().
_AUDIT_KINDS = frozenset(
    {"embedded", "verified", "verification-failed", "trigger-verified",
     "trigger-failed", "rejected"}
)


class ModelWatermarkError(Exception):
    """Base error for the model watermarking interface."""


class WatermarkCapacityError(ModelWatermarkError):
    """Raised when a model is too small to carry a watermark."""


def key_fingerprint(key: object) -> str:
    """Return the public ``sha256:`` fingerprint of a watermark key."""
    if isinstance(key, str):
        key = key.encode("utf-8")
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("key must be str or bytes")
    return "sha256:" + hashlib.sha256(_DOMAIN + b"/key-id/" + bytes(key)).hexdigest()


def _check_key(key: object) -> bytes:
    if isinstance(key, str):
        key = key.encode("utf-8")
    if not isinstance(key, (bytes, bytearray)) or isinstance(key, bool):
        raise TypeError("key must be str or bytes")
    key = bytes(key)
    if not key:
        raise ModelWatermarkError("key must be non-empty")
    if len(key) > 1024:
        raise ModelWatermarkError("key longer than 1024 bytes is refused")
    return key


def _check_model(model: object) -> Mapping[str, bytes]:
    if not isinstance(model, Mapping):
        raise TypeError("model must be a mapping of layer name -> bytes")
    if not model:
        raise ModelWatermarkError("model must not be empty")
    total = 0
    for name, blob in model.items():
        if not isinstance(name, str) or not name:
            raise ModelWatermarkError("layer names must be non-empty str")
        if not isinstance(blob, (bytes, bytearray)):
            raise TypeError(f"layer {name!r} must map to bytes")
        blob = bytes(blob)
        if len(blob) % 4 != 0:
            raise ModelWatermarkError(
                f"layer {name!r} is {len(blob)} bytes, not a float32 blob"
            )
        total += len(blob)
    if total > MAX_TOTAL_BYTES:
        raise ModelWatermarkError("model exceeds the 1 GiB guardrail")
    return model


def _check_seq(seq: object) -> int:
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
        raise ValueError("seq must be a non-negative int")
    return seq


def _hmac_stream(key: bytes, label: bytes, n: int) -> bytes:
    """Return n deterministic bytes from HMAC-SHA256(key, label || counter)."""
    out = bytearray()
    counter = 0
    while len(out) < n:
        out.extend(
            hmac.new(key, _DOMAIN + b"/" + label + counter.to_bytes(8, "big"),
                     hashlib.sha256).digest()
        )
        counter += 1
    return bytes(out[:n])


def _watermark_bits(key: bytes, n_bits: int) -> list:
    raw = _hmac_stream(key, b"bits", (n_bits + 7) // 8)
    return [(raw[i // 8] >> (7 - (i % 8))) & 1 for i in range(n_bits)]


def _layer_layout(model: Mapping[str, bytes]) -> list:
    """Return [(name, float_offset, n_floats)] in sorted layer order."""
    layout = []
    offset = 0
    for name in sorted(model):
        n_floats = len(bytes(model[name])) // 4
        layout.append((name, offset, n_floats))
        offset += n_floats
    return layout


def _positions(key: bytes, total_floats: int, n_bits: int) -> list:
    """Derive n_bits distinct flat float indices in [0, total_floats).

    Rejection sampling over an HMAC stream with an ever-incrementing
    counter, so the stream never repeats and the sampler always
    terminates.
    """
    if n_bits > total_floats:
        raise WatermarkCapacityError(
            f"need {n_bits} carrier floats, model has {total_floats}"
        )
    chosen: list = []
    seen = set()
    counter = 0
    while len(chosen) < n_bits:
        digest = hmac.new(
            key, _DOMAIN + b"/positions/" + counter.to_bytes(8, "big"),
            hashlib.sha256,
        ).digest()
        counter += 1
        for j in range(0, 32, 4):
            if len(chosen) >= n_bits:
                break
            idx = int.from_bytes(digest[j:j + 4], "big") % total_floats
            if idx not in seen:
                seen.add(idx)
                chosen.append(idx)
    return chosen


def _shape_digest(model: Mapping[str, bytes]) -> str:
    h = hashlib.sha256()
    h.update(_DOMAIN + b"/shape/")
    for name, blob in sorted(model.items()):
        blob = bytes(blob)
        h.update(name.encode("utf-8") + b"\x00")
        h.update(len(blob).to_bytes(8, "big"))
    return "sha256:" + h.hexdigest()


def _model_digest(model: Mapping[str, bytes]) -> str:
    h = hashlib.sha256()
    h.update(_DOMAIN + b"/model/")
    for name in sorted(model):
        h.update(bytes(model[name]))
    return "sha256:" + h.hexdigest()


def _set_lsb(value: float, bit: int) -> float:
    raw = struct.unpack("<I", struct.pack("<f", value))[0]
    raw = (raw & 0xFFFFFFFE) | (bit & 1)
    return struct.unpack("<f", struct.pack("<I", raw))[0]


def _get_lsb(value: float) -> int:
    return struct.unpack("<I", struct.pack("<f", value))[0] & 1


@dataclass(frozen=True)
class WatermarkRecord:
    """Provenance record for one embed operation (no key material)."""

    key_id: str
    algorithm: str
    bits: int
    shape_digest: str
    model_digest_before: str
    model_digest_after: str
    schema: str = SCHEMA_PIN

    def as_dict(self) -> dict:
        return {
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "bits": self.bits,
            "shape_digest": self.shape_digest,
            "model_digest_before": self.model_digest_before,
            "model_digest_after": self.model_digest_after,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class VerificationReport:
    """Outcome of verifying a weight-channel watermark."""

    valid: bool
    confidence: float
    bits_checked: int
    bits_matched: int
    key_id: str
    shape_digest: str
    schema: str = SCHEMA_PIN

    def as_dict(self) -> dict:
        return {
            "valid": self.valid,
            "confidence": self.confidence,
            "bits_checked": self.bits_checked,
            "bits_matched": self.bits_matched,
            "key_id": self.key_id,
            "shape_digest": self.shape_digest,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class RobustnessExpectation:
    """Qualitative expectation for one post-processing transform."""

    transform: str
    level: str  # "tolerant" | "partial" | "destroyed"
    note: str


@dataclass(frozen=True)
class RobustnessReport:
    """Literature-derived robustness expectations (not measurements)."""

    algorithm: str
    expectations: tuple
    schema: str = SCHEMA_PIN

    def as_dict(self) -> dict:
        return {
            "algorithm": self.algorithm,
            "expectations": [
                {"transform": e.transform, "level": e.level, "note": e.note}
                for e in self.expectations
            ],
            "schema": self.schema,
        }


@dataclass(frozen=True)
class Trigger:
    """One secret trigger pair: input bytes and expected output bytes."""

    input: bytes
    expected_output: bytes


@dataclass(frozen=True)
class TriggerSet:
    """A key-bound set of trigger pairs (inputs/outputs only, no key)."""

    key_id: str
    triggers: tuple
    schema: str = SCHEMA_PIN

    def as_dict(self) -> dict:
        return {
            "key_id": self.key_id,
            "triggers": [
                {"input": t.input.hex(), "expected_output": t.expected_output.hex()}
                for t in self.triggers
            ],
            "schema": self.schema,
        }


@dataclass(frozen=True)
class TriggerVerificationReport:
    """Outcome of black-box trigger verification through a host oracle."""

    valid: bool
    hit_rate: float
    triggers_checked: int
    triggers_hit: int
    oracle_errors: int
    key_id: str
    schema: str = SCHEMA_PIN

    def as_dict(self) -> dict:
        return {
            "valid": self.valid,
            "hit_rate": self.hit_rate,
            "triggers_checked": self.triggers_checked,
            "triggers_hit": self.triggers_hit,
            "oracle_errors": self.oracle_errors,
            "key_id": self.key_id,
            "schema": self.schema,
        }


class ModelWatermark:
    """Key-bound DNN watermark embedder/verifier (simulated interface)."""

    ALGORITHM = "hmac-lsb-float32.v1"

    def __init__(self, key: object, bits: int = DEFAULT_BITS) -> None:
        self._key = _check_key(key)
        if not isinstance(bits, int) or isinstance(bits, bool) or bits <= 0:
            raise TypeError("bits must be a positive int")
        if bits > 4096:
            raise ModelWatermarkError("bits above 4096 is refused")
        self._bits = bits
        self._key_id = key_fingerprint(self._key)

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def bits(self) -> int:
        return self._bits

    def embed(self, model: Mapping[str, bytes]) -> tuple:
        """Embed the watermark; returns (new_model, WatermarkRecord).

        The caller's model is never mutated.
        """
        model = _check_model(model)
        layout = _layer_layout(model)
        total_floats = sum(n for _, _, n in layout)
        if total_floats < MIN_FLOATS:
            raise WatermarkCapacityError(
                f"model has {total_floats} floats, need at least {MIN_FLOATS}"
            )
        n_bits = min(self._bits, total_floats)
        bits = _watermark_bits(self._key, n_bits)
        positions = _positions(self._key, total_floats, n_bits)

        before = _model_digest(model)
        new_model: dict = {}
        # Group positions per layer for one pass over each blob.
        per_layer: dict = {}
        for flat, bit in zip(positions, bits):
            for name, offset, n_floats in layout:
                if offset <= flat < offset + n_floats:
                    per_layer.setdefault(name, []).append((flat - offset, bit))
                    break
        for name in sorted(model):
            blob = bytearray(bytes(model[name]))
            for idx, bit in per_layer.get(name, []):
                value = struct.unpack_from("<f", blob, idx * 4)[0]
                struct.pack_into("<f", blob, idx * 4, _set_lsb(value, bit))
            new_model[name] = bytes(blob)
        after = _model_digest(new_model)
        record = WatermarkRecord(
            key_id=self._key_id,
            algorithm=self.ALGORITHM,
            bits=n_bits,
            shape_digest=_shape_digest(model),
            model_digest_before=before,
            model_digest_after=after,
        )
        return new_model, record

    def verify(self, model: Mapping[str, bytes]) -> VerificationReport:
        """Verify the weight-channel watermark; returns a report."""
        model = _check_model(model)
        layout = _layer_layout(model)
        total_floats = sum(n for _, _, n in layout)
        n_bits = min(self._bits, total_floats)
        if n_bits < MIN_FLOATS:
            return VerificationReport(
                valid=False, confidence=0.0, bits_checked=0, bits_matched=0,
                key_id=self._key_id, shape_digest=_shape_digest(model),
            )
        expected = _watermark_bits(self._key, n_bits)
        positions = _positions(self._key, total_floats, n_bits)
        matched = 0
        for flat, bit in zip(positions, expected):
            for name, offset, n_floats in layout:
                if offset <= flat < offset + n_floats:
                    blob = bytes(model[name])
                    value = struct.unpack_from("<f", blob, (flat - offset) * 4)[0]
                    if _get_lsb(value) == bit:
                        matched += 1
                    break
        confidence = matched / n_bits
        return VerificationReport(
            valid=confidence >= AGREEMENT_THRESHOLD,
            confidence=confidence,
            bits_checked=n_bits,
            bits_matched=matched,
            key_id=self._key_id,
            shape_digest=_shape_digest(model),
        )

    def robustness(self) -> RobustnessReport:
        """Return literature-derived robustness expectations (not measurements).

        These describe what the literature reports for LSB-style weight
        watermarks under common post-processing; they are bookkeeping, not
        properties measured by this module.
        """
        return RobustnessReport(
            algorithm=self.ALGORITHM,
            expectations=(
                RobustnessExpectation(
                    transform="fp32-identity",
                    level="tolerant",
                    note="no transform applied; the simulated channel verifies "
                         "at agreement 1.0",
                ),
                RobustnessExpectation(
                    transform="int8-quantization",
                    level="destroyed",
                    note="quantization re-rounds mantissas; the LSB channel is "
                         "the first casualty (Uchida-style marks need the "
                         "regularizer term, not raw LSBs)",
                ),
                RobustnessExpectation(
                    transform="magnitude-pruning-10pct",
                    level="partial",
                    note="pruned weights lose their bits; redundancy across "
                         "positions degrades agreement gracefully rather than "
                         "failing outright",
                ),
                RobustnessExpectation(
                    transform="fine-tuning",
                    level="partial",
                    note="gradient updates shift low-order mantissa bits; "
                         "agreement decays with the number of steps and the "
                         "learning rate",
                ),
                RobustnessExpectation(
                    transform="distillation",
                    level="destroyed",
                    note="a student trained from scratch never sees the "
                         "teacher's LSBs; only the trigger-set channel "
                         "survives distillation",
                ),
            ),
        )


def make_trigger_set(key: object, n: int = 8) -> TriggerSet:
    """Mint a deterministic key-bound trigger set (Adi et al. style)."""
    key = _check_key(key)
    if not isinstance(n, int) or isinstance(n, bool) or n <= 0:
        raise TypeError("n must be a positive int")
    if n > 256:
        raise ModelWatermarkError("trigger sets above 256 are refused")
    triggers = tuple(
        Trigger(
            input=_hmac_stream(key, b"trigger-input", 32 * (i + 1))[-32:],
            expected_output=_hmac_stream(key, b"trigger-output", 32 * (i + 1))[-32:],
        )
        for i in range(n)
    )
    return TriggerSet(key_id=key_fingerprint(key), triggers=triggers)


def verify_trigger(
    oracle: Callable[[bytes], bytes], trigger_set: TriggerSet
) -> TriggerVerificationReport:
    """Black-box trigger verification through a host-supplied oracle.

    The oracle maps trigger input bytes to output bytes. Oracle errors
    count as misses (fail-closed): verification never claims valid on
    incomplete evidence.
    """
    if not callable(oracle):
        raise TypeError("oracle must be callable")
    if not isinstance(trigger_set, TriggerSet):
        raise TypeError("trigger_set must be a TriggerSet")
    checked = len(trigger_set.triggers)
    if checked == 0:
        raise ModelWatermarkError("trigger set is empty")
    hits = 0
    errors = 0
    for trigger in trigger_set.triggers:
        try:
            out = oracle(trigger.input)
        except Exception:
            errors += 1
            continue
        if not isinstance(out, (bytes, bytearray)):
            errors += 1
            continue
        if hmac.compare_digest(bytes(out), trigger.expected_output):
            hits += 1
    hit_rate = hits / checked
    return TriggerVerificationReport(
        valid=hit_rate >= AGREEMENT_THRESHOLD and errors == 0,
        hit_rate=hit_rate,
        triggers_checked=checked,
        triggers_hit=hits,
        oracle_errors=errors,
        key_id=trigger_set.key_id,
    )


def model_watermark_audit_event(kind: str, seq: int, **fields: object) -> dict:
    """Shape a watermark outcome as an audit.ndjson/1 record.

    Caller-supplied seq; the key itself is never included, only key_id.
    """
    if kind not in _AUDIT_KINDS:
        raise ValueError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    record = {
        "schema": "audit.ndjson/1",
        "seq": seq,
        "event": f"model-watermark.{kind}",
        "watermarker": MODEL_WATERMARK_VERSION,
    }
    for name, value in fields.items():
        if name == "key":
            raise ValueError("raw key material is never logged; use key_id")
        record[name] = value
    return record


def main() -> None:
    import random

    rng = random.Random(20261007)
    blob = struct.pack("<%df" % 64, *(rng.uniform(-1.0, 1.0) for _ in range(64)))
    model = {"fc1.weight": blob, "fc2.weight": blob}
    wm = ModelWatermark("owner-key-1")
    marked, record = wm.embed(model)
    assert marked is not model and marked["fc1.weight"] != blob
    assert bytes(model["fc1.weight"]) == blob, "input model must not mutate"
    report = wm.verify(marked)
    assert report.valid and report.confidence == 1.0, report
    assert not ModelWatermark("wrong-key").verify(marked).valid
    unmarked = wm.verify(model)
    assert not unmarked.valid, "unmarked weights must not verify"
    rob = wm.robustness()
    assert len(rob.expectations) == 5
    ts = make_trigger_set("owner-key-1", n=4)
    oracle = {t.input: t.expected_output for t in ts.triggers}
    trep = verify_trigger(oracle.get, ts)
    assert trep.valid and trep.hit_rate == 1.0, trep
    bad = verify_trigger(lambda b: b"nope", ts)
    assert not bad.valid
    print("model-watermark OK: embed/verify, wrong-key fails, trigger channel, robustness")


if __name__ == "__main__":
    main()

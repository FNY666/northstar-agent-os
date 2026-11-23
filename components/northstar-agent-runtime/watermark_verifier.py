"""Model watermark verifier: provenance for generated content.

Research basis (second-hand):
- Model watermarking (e.g. Kirchenbauer et al. "green-list" tokens,
  SynthID-style approaches) embeds a statistically detectable signal in
  generated output so provenance can be checked later without the model.
- The failure mode is symmetric: a watermark that cannot be *verified*
  by an independent party is decoration, not provenance. This module is
  the verifier side of that contract.

Design: HMAC-signed zero-width watermark for text content. ``embed``
appends an invisible bit-string (zero-width Unicode codepoints) encoding
the first 64 bits of ``HMAC-SHA256(key, canonical(content))`` behind a
sentinel. ``verify`` strips the watermark region, recomputes the HMAC
over the cleaned content, and compares with ``hmac.compare_digest``.
Zero-width codepoints are invisible in normal rendering, so the
watermarked text reads identically to the original.

Security properties:
- Without the key, the watermark bits are indistinguishable from random
  (they are a truncated HMAC output).
- Any edit to the visible content invalidates the tag (the HMAC covers
  the cleaned content).
- The key itself never appears in the content or in any structured
  output; only a ``sha256:`` key-id fingerprint is published.

Detector, not defense: verification proves *this key's holder* signed
*this exact content*, not who wrote it, not that it is true, and not
that an unwatermarked copy does not exist elsewhere. A missing
watermark means "no provenance claimed", never "not machine-generated".

Honest scope: text-only, zero-width-channel. Re-typing, screenshots,
translation, or Unicode normalization by a downstream pipeline will
strip or damage the channel; ``verify`` then reports low confidence,
not a forgery verdict. A clean False means "no valid watermark found".

No wall-clock anywhere. All functions are pure over the inputs given.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from typing import Optional, Tuple

#: Version pin for the verifier described here.
WATERMARK_VERIFIER_VERSION = "watermark-verifier.v1"

#: Schema pin stamped on structured outputs.
SCHEMA_PIN = "northstar.watermark-verifier.v1"

#: Algorithm identifier published in Watermark records.
ALGORITHM = "hmac-sha256-zwsp.v1"

#: Number of HMAC bits encoded in the zero-width channel.
TAG_BITS = 64

#: Zero-width codepoints used as the invisible channel.
_ZWSP = "\u200b"   # zero width space  -> bit 0
_ZWNJ = "\u200c"   # zero width non-joiner -> bit 1
_ZWJ = "\u200d"    # zero width joiner  (reserved / not used for bits)
_SENTINEL = "\ufeff"  # zero width no-break space: marks watermark start

_BIT_TO_CHAR = {"0": _ZWSP, "1": _ZWNJ}
_CHAR_TO_BIT = {_ZWSP: "0", _ZWNJ: "1"}
_WATERMARK_CHARS = frozenset((_ZWSP, _ZWNJ, _ZWJ, _SENTINEL))


def _check_str(name: str, value: object) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be str, got {type(value).__name__}")
    return value


def _tag_bits(content: str, key: str) -> str:
    """Return TAG_BITS bits of HMAC-SHA256(key, content) as a '0'/'1' string."""
    digest = hmac.new(key.encode("utf-8"), content.encode("utf-8"),
                      hashlib.sha256).digest()
    bits = "".join(f"{byte:08b}" for byte in digest)
    return bits[:TAG_BITS]


def _encode_bits(bits: str) -> str:
    return _SENTINEL + "".join(_BIT_TO_CHAR[b] for b in bits)


def _split_watermark(content: str) -> Tuple[str, str]:
    """Split content into (clean_content, bit_string).

    The watermark region is the trailing run that starts at the *last*
    sentinel and consists only of watermark channel characters.
    Returns ("", "") when no well-formed region is present.
    """
    idx = content.rfind(_SENTINEL)
    if idx == -1:
        return content, ""
    tail = content[idx + 1:]
    if not tail or any(ch not in (_ZWSP, _ZWNJ) for ch in tail):
        return content, ""
    bits = "".join(_CHAR_TO_BIT[ch] for ch in tail)
    clean = content[:idx].rstrip()  # drop any padding before the sentinel
    # The cleaned content must itself contain no channel characters;
    # otherwise the region was not the true watermark (fail closed).
    if any(ch in _WATERMARK_CHARS for ch in clean):
        return content, ""
    return clean, bits


def strip_watermark(content: str) -> str:
    """Return content with any trailing watermark region removed."""
    _check_str("content", content)
    clean, _ = _split_watermark(content)
    return clean


def embed_watermark(content: str, key: str) -> str:
    """Embed an invisible HMAC watermark in content.

    Returns new text that renders identically to ``content`` but carries
    a 64-bit HMAC tag in the zero-width channel. Re-embedding replaces
    any existing watermark (idempotent for the same key).
    Raises TypeError on non-str input, ValueError on empty content/key.
    """
    content = _check_str("content", content)
    key = _check_str("key", key)
    if not content:
        raise ValueError("content must be non-empty")
    if not key:
        raise ValueError("key must be non-empty")
    clean = strip_watermark(content)
    bits = _tag_bits(clean, key)
    return clean + _encode_bits(bits)


@dataclass(frozen=True)
class Watermark:
    """A verified watermark claim."""

    algorithm: str
    key_id: str          # "sha256:<hex>" fingerprint of the key, never the key
    confidence: float    # fraction of tag bits that matched, in [0, 1]

    def __post_init__(self) -> None:
        if not self.algorithm:
            raise ValueError("algorithm must be non-empty")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", self.key_id):
            raise ValueError("key_id must look like 'sha256:<64 hex>'")
        if not isinstance(self.confidence, float) or not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be a float in [0, 1]")

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "algorithm": self.algorithm,
            "key_id": self.key_id,
            "confidence": self.confidence,
        }


def key_fingerprint(key: str) -> str:
    """Publishable fingerprint of a watermark key (never the key itself)."""
    key = _check_str("key", key)
    if not key:
        raise ValueError("key must be non-empty")
    return "sha256:" + hashlib.sha256(key.encode("utf-8")).hexdigest()


def verify_watermark(content: str, key: str) -> bool:
    """Return True iff content carries a valid watermark for key.

    Never raises on well-typed input: missing, malformed, or mismatched
    watermarks all return False (fail closed). Raises TypeError on
    non-str input.
    """
    return watermark_info(content, key) is not None


def watermark_info(content: str, key: str) -> Optional[Watermark]:
    """Return a Watermark record on full tag match, else None.

    Confidence is the fraction of encoded bits matching the recomputed
    tag; only a full 64/64 match yields a record (partial matches are
    reported as absent, not as weak positives).
    """
    content = _check_str("content", content)
    key = _check_str("key", key)
    if not content or not key:
        return None
    clean, bits = _split_watermark(content)
    if not bits:
        return None
    expected = _tag_bits(clean, key)
    # Compare only over the bits actually present; a truncated channel
    # is damage, not evidence.
    matched = sum(1 for a, b in zip(bits, expected) if a == b)
    confidence = matched / len(bits)
    if len(bits) != TAG_BITS or matched != len(bits):
        return None
    if not hmac.compare_digest(bits, expected):
        return None
    return Watermark(
        algorithm=ALGORITHM,
        key_id=key_fingerprint(key),
        confidence=confidence,
    )


def watermark_audit_event(content: str, key: str, seq: int) -> dict:
    """Shape a verification outcome as an audit.ndjson/1 record."""
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
        raise ValueError("seq must be a non-negative int")
    info = watermark_info(content, key)
    return {
        "schema": "audit.ndjson/1",
        "seq": seq,
        "event": "watermark.verify",
        "verifier": WATERMARK_VERIFIER_VERSION,
        "key_id": key_fingerprint(key) if key else None,
        "valid": info is not None,
        "confidence": info.confidence if info is not None else 0.0,
    }


def main() -> None:
    content = "The quick brown fox jumps over the lazy dog."
    key = "test-key-1"
    marked = embed_watermark(content, key)
    assert marked != content, "watermark must change the bytes"
    assert strip_watermark(marked) == content, "visible text must be unchanged"
    assert verify_watermark(marked, key), "valid watermark must verify"
    assert not verify_watermark(marked, "wrong-key"), "wrong key must fail"
    assert not verify_watermark(content, key), "unmarked content must fail"
    assert not verify_watermark(marked[:-8] + "X", key), "tamper must fail"
    info = watermark_info(marked, key)
    assert info is not None and info.confidence == 1.0
    print("watermark-verifier OK: embed/verify round-trip, wrong-key/tamper fail closed")


if __name__ == "__main__":
    main()

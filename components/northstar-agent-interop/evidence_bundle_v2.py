"""Versioned padded Merkle commitments with inclusion and absence proofs.

This module intentionally does not alter evidence_bundle.py v1. Version 2 sorts
real event leaves and pads the tree to a power of two with a domain-separated
constant leaf. A proof of non-inclusion is relative to that sorted committed
set: it shows the target lies strictly between two adjacent committed leaves,
or outside one boundary.
"""
from __future__ import annotations

import hashlib
import json
from bisect import bisect_left
from dataclasses import dataclass
from typing import Any

from evidence_bundle import EvidenceError, _leaf

SCHEMA_V2 = "northstar.evidence-bundle.v2"
SCHEMA = SCHEMA_V2
PAD_DIGEST = "sha256:" + hashlib.sha256(b"northstar.evidence-bundle.v2.pad\0").hexdigest()
_DIRECTIONS = ("left", "right")
_DIGEST_LEN = 71
_FIELDS = frozenset({"schema_version", "root_digest", "leaf_count", "padded_count", "leaf_digests"})
_INCLUSION_FIELDS = frozenset({
    "schema_version", "root_digest", "padded_count", "index", "leaf_digest", "siblings"
})
_ABSENCE_FIELDS = frozenset({
    "schema_version", "root_digest", "target_digest", "leaf_count", "padded_count",
    "predecessor", "successor",
})


class V2Error(EvidenceError):
    """Malformed, tampered, or semantically invalid v2 evidence."""


@dataclass(frozen=True)
class DisclosureVerdict:
    state: str
    reasons: tuple[str, ...] = ()
    unverified: tuple[str, ...] = ()


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise V2Error("value is not canonical JSON") from exc


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_digest(value: Any) -> bool:
    return (
        isinstance(value, str) and len(value) == _DIGEST_LEN
        and value.startswith("sha256:")
        and all(character in "0123456789abcdef" for character in value[7:])
    )


def _digest(value: Any, field: str) -> str:
    if not _is_digest(value):
        raise V2Error(f"{field} is not a digest")
    return value


def _next_power_of_two(count: int) -> int:
    if not _is_int(count) or count < 1:
        raise V2Error("leaf count must be positive")
    result = 1
    while result < count:
        result *= 2
    return result


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"node\0" + left + right).digest()


def _root_for_leaves(leaves: list[str], padded_count: int) -> str:
    if len(leaves) < 1 or padded_count != _next_power_of_two(len(leaves)):
        raise V2Error("leaf/padding counts are inconsistent")
    if len(leaves) == padded_count:
        layer = list(leaves)
    else:
        layer = list(leaves) + [PAD_DIGEST] * (padded_count - len(leaves))
    raw = [bytes.fromhex(value[7:]) for value in layer]
    while len(raw) > 1:
        raw = [_node(raw[index], raw[index + 1]) for index in range(0, len(raw), 2)]
    return "sha256:" + raw[0].hex()


def leaf_digest_v2(event: dict[str, Any]) -> str:
    """Return the v2 real-event leaf digest using the v1 sensitive-field guard."""
    return "sha256:" + _leaf(event).hex()


@dataclass(frozen=True)
class PaddedEvidenceBundle:
    root_digest: str
    leaf_count: int
    padded_count: int
    leaf_digests: tuple[str, ...]
    schema_version: str = SCHEMA_V2

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "root_digest": self.root_digest,
            "leaf_count": self.leaf_count,
            "padded_count": self.padded_count,
            "leaf_digests": list(self.leaf_digests),
        }

    @classmethod
    def from_dict(cls, value: Any) -> "PaddedEvidenceBundle":
        if not isinstance(value, dict) or set(value) != _FIELDS:
            raise V2Error("v2 bundle fields are invalid")
        if value["schema_version"] != SCHEMA_V2:
            raise V2Error("v2 bundle schema is invalid")
        root = _digest(value["root_digest"], "root_digest")
        count, padded = value["leaf_count"], value["padded_count"]
        if not _is_int(count) or count < 1 or not _is_int(padded):
            raise V2Error("v2 bundle counts are invalid")
        if padded != _next_power_of_two(count):
            raise V2Error("v2 padded count is invalid")
        raw_leaves = value["leaf_digests"]
        if not isinstance(raw_leaves, list) or len(raw_leaves) != count:
            raise V2Error("v2 leaf digests are invalid")
        leaves = tuple(_digest(item, "leaf_digest") for item in raw_leaves)
        if list(leaves) != sorted(leaves) or len(set(leaves)) != len(leaves):
            raise V2Error("v2 real leaves must be sorted and unique")
        if PAD_DIGEST in leaves:
            raise V2Error("pad digest cannot be a real leaf")
        if _root_for_leaves(list(leaves), padded) != root:
            raise V2Error("v2 bundle root mismatch")
        return cls(root, count, padded, leaves, SCHEMA_V2)


def build_bundle_v2(events: Any) -> PaddedEvidenceBundle:
    values = list(events)
    if not values:
        raise V2Error("cannot build an empty v2 bundle")
    leaves = sorted(leaf_digest_v2(event) for event in values)
    if len(set(leaves)) != len(leaves):
        raise V2Error("duplicate real event leaves are unsupported")
    padded = _next_power_of_two(len(leaves))
    return PaddedEvidenceBundle(_root_for_leaves(leaves, padded), len(leaves), padded, tuple(leaves))


def _validate_bundle(bundle: Any) -> PaddedEvidenceBundle:
    if not isinstance(bundle, PaddedEvidenceBundle):
        raise V2Error("v2 bundle is required")
    return PaddedEvidenceBundle.from_dict(bundle.to_dict())

@dataclass(frozen=True)
class InclusionProofV2:
    schema_version: str
    root_digest: str
    padded_count: int
    index: int
    leaf_digest: str
    siblings: tuple[tuple[str, str], ...]

    def to_dict(self):
        return {
            "schema_version": self.schema_version,
            "root_digest": self.root_digest,
            "padded_count": self.padded_count,
            "index": self.index,
            "leaf_digest": self.leaf_digest,
            "siblings": [[direction, digest] for direction, digest in self.siblings],
        }

    @classmethod
    def from_dict(cls, value):
        if not isinstance(value, dict) or set(value) != _INCLUSION_FIELDS:
            raise V2Error("inclusion proof fields are invalid")
        if value["schema_version"] != SCHEMA_V2:
            raise V2Error("inclusion proof schema is invalid")
        root = _digest(value["root_digest"], "proof root")
        leaf = _digest(value["leaf_digest"], "proof leaf")
        padded, index = value["padded_count"], value["index"]
        if not _is_int(padded) or padded < 1 or padded != _next_power_of_two(padded):
            raise V2Error("proof padded count is invalid")
        if not _is_int(index) or not 0 <= index < padded:
            raise V2Error("proof index is invalid")
        siblings = value["siblings"]
        if not isinstance(siblings, list):
            raise V2Error("proof siblings are invalid")
        parsed = []
        for item in siblings:
            if not isinstance(item, list) or len(item) != 2:
                raise V2Error("proof sibling is invalid")
            direction, digest = item
            if direction not in _DIRECTIONS or not _is_digest(digest):
                raise V2Error("proof sibling is invalid")
            parsed.append((direction, digest))
        return cls(SCHEMA_V2, root, padded, index, leaf, tuple(parsed))


def _depth(padded_count: int) -> int:
    return padded_count.bit_length() - 1


def make_inclusion_v2(bundle: PaddedEvidenceBundle, index: int) -> InclusionProofV2:
    bundle = _validate_bundle(bundle)
    if not _is_int(index) or not 0 <= index < bundle.leaf_count:
        raise V2Error("real leaf index is invalid")
    layer = list(bundle.leaf_digests) + [PAD_DIGEST] * (bundle.padded_count - bundle.leaf_count)
    siblings = []
    current_index = index
    while len(layer) > 1:
        pair = current_index ^ 1
        siblings.append(("right" if current_index % 2 == 0 else "left", layer[pair]))
        layer = [
            "sha256:" + _node(bytes.fromhex(layer[pos][7:]), bytes.fromhex(layer[pos + 1][7:])).hex()
            for pos in range(0, len(layer), 2)
        ]
        current_index //= 2
    return InclusionProofV2(SCHEMA_V2, bundle.root_digest, bundle.padded_count,
                            index, bundle.leaf_digests[index], tuple(siblings))


def _verify_path(proof: InclusionProofV2) -> str:
    if len(proof.siblings) != _depth(proof.padded_count):
        raise V2Error("proof path length is invalid")
    current = bytes.fromhex(proof.leaf_digest[7:])
    for direction, digest in proof.siblings:
        sibling = bytes.fromhex(digest[7:])
        current = _node(current, sibling) if direction == "right" else _node(sibling, current)
    return "sha256:" + current.hex()


def verify_inclusion_v2(proof: InclusionProofV2, subject: dict[str, Any], *,
                        expected_root: str | None = None) -> DisclosureVerdict:
    proof = InclusionProofV2.from_dict(proof.to_dict())
    if not isinstance(subject, dict) or leaf_digest_v2(subject) != proof.leaf_digest:
        raise V2Error("subject does not match proof leaf")
    if expected_root is not None and _digest(expected_root, "expected root") != proof.root_digest:
        raise V2Error("proof root does not match expected root")
    if _verify_path(proof) != proof.root_digest:
        raise V2Error("inclusion proof root mismatch")
    reasons = () if expected_root is not None else ("root_unpinned",)
    return DisclosureVerdict("verified" if expected_root is not None else "verified-unpinned",
                             reasons, ("index", "padded_count"))

@dataclass(frozen=True)
class AbsenceProofV2:
    schema_version: str
    root_digest: str
    target_digest: str
    leaf_count: int
    padded_count: int
    predecessor: InclusionProofV2 | None
    successor: InclusionProofV2 | None

    def to_dict(self):
        return {
            "schema_version": self.schema_version,
            "root_digest": self.root_digest,
            "target_digest": self.target_digest,
            "leaf_count": self.leaf_count,
            "padded_count": self.padded_count,
            "predecessor": self.predecessor.to_dict() if self.predecessor else None,
            "successor": self.successor.to_dict() if self.successor else None,
        }

    @classmethod
    def from_dict(cls, value):
        if not isinstance(value, dict) or set(value) != _ABSENCE_FIELDS:
            raise V2Error("absence proof fields are invalid")
        if value["schema_version"] != SCHEMA_V2:
            raise V2Error("absence proof schema is invalid")
        root = _digest(value["root_digest"], "absence root")
        target = _digest(value["target_digest"], "target digest")
        count, padded = value["leaf_count"], value["padded_count"]
        if not _is_int(count) or count < 1 or not _is_int(padded) or padded != _next_power_of_two(count):
            raise V2Error("absence proof counts are invalid")
        predecessor = (InclusionProofV2.from_dict(value["predecessor"])
                       if value["predecessor"] is not None else None)
        successor = (InclusionProofV2.from_dict(value["successor"])
                     if value["successor"] is not None else None)
        if predecessor is None and successor is None:
            raise V2Error("absence proof needs a boundary neighbor")
        return cls(SCHEMA_V2, root, target, count, padded, predecessor, successor)


def make_absence_v2(bundle: PaddedEvidenceBundle, target: dict[str, Any]) -> AbsenceProofV2:
    bundle = _validate_bundle(bundle)
    target_digest = leaf_digest_v2(target)
    position = bisect_left(bundle.leaf_digests, target_digest)
    if position < bundle.leaf_count and bundle.leaf_digests[position] == target_digest:
        raise V2Error("target is present in the committed set")
    predecessor = make_inclusion_v2(bundle, position - 1) if position > 0 else None
    successor = make_inclusion_v2(bundle, position) if position < bundle.leaf_count else None
    return AbsenceProofV2(SCHEMA_V2, bundle.root_digest, target_digest,
                          bundle.leaf_count, bundle.padded_count, predecessor, successor)


def _validate_neighbor(proof: InclusionProofV2 | None, *, root: str, padded: int,
                       leaf_count: int, is_predecessor: bool) -> str | None:
    if proof is None:
        return None
    if proof.root_digest != root or proof.padded_count != padded:
        raise V2Error("absence neighbor root or padding mismatch")
    if proof.leaf_digest == PAD_DIGEST or proof.index < 0 or proof.index >= leaf_count:
        raise V2Error("pad leaf cannot be an absence neighbor")
    if _verify_path(proof) != root:
        raise V2Error("absence neighbor path mismatch")
    return proof.leaf_digest


def verify_absence_v2(proof: AbsenceProofV2, *, expected_root: str | None = None) -> DisclosureVerdict:
    proof = AbsenceProofV2.from_dict(proof.to_dict())
    if expected_root is not None and _digest(expected_root, "expected root") != proof.root_digest:
        raise V2Error("absence root does not match expected root")
    predecessor = _validate_neighbor(proof.predecessor, root=proof.root_digest,
                                     padded=proof.padded_count, leaf_count=proof.leaf_count,
                                     is_predecessor=True)
    successor = _validate_neighbor(proof.successor, root=proof.root_digest,
                                   padded=proof.padded_count, leaf_count=proof.leaf_count,
                                   is_predecessor=False)
    if predecessor is not None and not predecessor < proof.target_digest:
        raise V2Error("predecessor is not strictly before target")
    if successor is not None and not proof.target_digest < successor:
        raise V2Error("successor is not strictly after target")
    if predecessor is not None and successor is not None:
        if predecessor >= successor:
            raise V2Error("absence neighbors are not ordered")
        if proof.predecessor.index + 1 != proof.successor.index:
            raise V2Error("absence neighbors are not adjacent")
    reasons = () if expected_root is not None else ("root_unpinned",)
    return DisclosureVerdict("verified" if expected_root is not None else "verified-unpinned", reasons,
                             ("leaf_count", "padded_count"))


__all__ = [
    "SCHEMA_V2", "SCHEMA", "PAD_DIGEST", "V2Error", "DisclosureVerdict",
    "PaddedEvidenceBundle", "InclusionProofV2", "AbsenceProofV2",
    "leaf_digest_v2", "build_bundle_v2", "make_inclusion_v2", "verify_inclusion_v2",
    "make_absence_v2", "verify_absence_v2",
]

"""Portable, externally pinnable witnesses for complete checkpoint chains.

A witness proves continuity and integrity of the checkpoints it carries. It
cannot prove that the carried sequence is the latest history unless a verifier
pins the expected head root and chain digest out of band.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from evidence_chain import (
    ChainError,
    EvidenceChain,
    EvidenceCheckpoint,
    verify_chain,
)

SCHEMA = "northstar.checkpoint-chain-witness.v1"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_FIELDS = frozenset({
    "schema_version", "checkpoints", "checkpoint_count", "head_root",
    "chain_digest",
})


class WitnessError(ValueError):
    """Malformed, corrupted, mismatched, or unpinned checkpoint witness."""


@dataclass(frozen=True)
class CheckpointChainWitness:
    schema_version: str
    checkpoints: tuple[dict[str, Any], ...]
    checkpoint_count: int
    head_root: str
    chain_digest: str

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "checkpoints": list(self.checkpoints),
            "checkpoint_count": self.checkpoint_count,
            "head_root": self.head_root,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned_dict(), "chain_digest": self.chain_digest}

    @classmethod
    def from_dict(cls, value: Any) -> "CheckpointChainWitness":
        if not isinstance(value, dict) or set(value) != _FIELDS:
            raise WitnessError("witness fields are invalid")
        if value["schema_version"] != SCHEMA:
            raise WitnessError("witness schema is invalid")
        raw_checkpoints = value["checkpoints"]
        if not isinstance(raw_checkpoints, list) or not raw_checkpoints:
            raise WitnessError("witness checkpoints are invalid")
        checkpoints = []
        try:
            for raw in raw_checkpoints:
                checkpoints.append(EvidenceCheckpoint.from_dict(raw).to_dict())
        except (ChainError, TypeError, KeyError) as exc:
            raise WitnessError("witness checkpoint is invalid") from exc
        count = value["checkpoint_count"]
        if (not isinstance(count, int) or isinstance(count, bool)
                or count != len(checkpoints)):
            raise WitnessError("witness checkpoint count is invalid")
        head = _digest(value["head_root"], "head_root")
        if head != checkpoints[-1]["current_root"]:
            raise WitnessError("witness head root mismatch")
        chain_digest = _digest(value["chain_digest"], "chain_digest")
        candidate = cls(SCHEMA, tuple(checkpoints), count, head, chain_digest)
        if candidate.computed_digest != chain_digest:
            raise WitnessError("witness chain digest mismatch")
        return candidate

    @property
    def computed_digest(self) -> str:
        return "sha256:" + hashlib.sha256(
            b"northstar.checkpoint-chain-witness.v1\0"
            + _canonical(self.unsigned_dict())
        ).hexdigest()


@dataclass(frozen=True)
class WitnessVerdict:
    state: str
    reasons: tuple[str, ...] = ()
    unverified: tuple[str, ...] = ()
    checkpoint_count: int = 0
    head_root: str = ""
    chain_digest: str = ""


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value, ensure_ascii=False, sort_keys=True,
            separators=(",", ":"), allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise WitnessError("witness is not canonical JSON") from exc


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise WitnessError(f"witness {field} is invalid")
    return value


def make_witness(chain: EvidenceChain) -> CheckpointChainWitness:
    if not isinstance(chain, EvidenceChain):
        raise WitnessError("evidence chain is required")
    checkpoints = list(chain.read())
    if not checkpoints:
        raise WitnessError("cannot witness an empty checkpoint chain")
    try:
        verify_chain(chain)
    except (ChainError, ValueError) as exc:
        raise WitnessError("checkpoint chain is invalid") from exc
    serialized = tuple(checkpoint.to_dict() for checkpoint in checkpoints)
    unsigned = CheckpointChainWitness(
        SCHEMA, serialized, len(serialized), checkpoints[-1].current_root, "",
    )
    return CheckpointChainWitness(
        SCHEMA, serialized, len(serialized), checkpoints[-1].current_root,
        unsigned.computed_digest,
    )


def verify_witness(
    witness: CheckpointChainWitness,
    *,
    expected_head_root: str | None = None,
    expected_chain_digest: str | None = None,
) -> WitnessVerdict:
    if not isinstance(witness, CheckpointChainWitness):
        raise WitnessError("checkpoint witness is invalid")
    parsed = CheckpointChainWitness.from_dict(witness.to_dict())
    try:
        records = [EvidenceCheckpoint.from_dict(item) for item in parsed.checkpoints]
        verify_chain(EvidenceChain.from_records(records))
    except (ChainError, ValueError) as exc:
        raise WitnessError("checkpoint witness continuity failed") from exc
    if expected_head_root is not None:
        if _digest(expected_head_root, "expected_head_root") != parsed.head_root:
            raise WitnessError("checkpoint witness head pin mismatch")
    if expected_chain_digest is not None:
        if _digest(expected_chain_digest, "expected_chain_digest") != parsed.chain_digest:
            raise WitnessError("checkpoint witness digest pin mismatch")
    unverified = []
    if expected_head_root is None:
        unverified.append("head_root_unpinned")
    if expected_chain_digest is None:
        unverified.append("chain_digest_unpinned")
    return WitnessVerdict(
        "verified" if not unverified else "verified-unpinned",
        (),
        tuple(unverified),
        parsed.checkpoint_count,
        parsed.head_root,
        parsed.chain_digest,
    )


__all__ = [
    "SCHEMA", "WitnessError", "CheckpointChainWitness", "WitnessVerdict",
    "make_witness", "verify_witness",
]

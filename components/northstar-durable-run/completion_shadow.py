"""Shadow-only composition of the production and completion-contract gates.

The two gates consume different evidence and cover different failure modes, so
one must not replace the other. This module makes their composition explicit
without changing TaskOutcome.ok: it reports a layered verdict for comparison,
but never authorizes execution or a production state transition by itself.
"""
from __future__ import annotations

from dataclasses import dataclass

from completion_contract_v2 import CompletionResult
from verifier import VerificationResult


@dataclass(frozen=True)
class LayeredVerificationResult:
    """A shadow verdict from both gates, never an execution authorization."""

    verdict: str
    errors: tuple[str, ...]
    production_verdict: str
    contract_verdict: str
    execution_authorized: bool = False

    def __post_init__(self) -> None:
        if self.verdict not in {"verified", "failed", "unknown", "insufficient_information"}:
            raise ValueError("layered verdict is invalid")
        if self.production_verdict not in {"verified", "failed", "unknown"}:
            raise ValueError("production verdict is invalid")
        if self.contract_verdict not in {
            "verified", "failed", "unknown", "insufficient_information"
        }:
            raise ValueError("contract verdict is invalid")
        if self.execution_authorized:
            raise ValueError("shadow composition never authorizes execution")


def _errors(prefix: str, verdict: str, errors: tuple[str, ...]) -> tuple[str, ...]:
    if errors:
        return tuple(f"{prefix}:{error}" for error in errors)
    if verdict == "verified":
        return ()
    return (f"{prefix}:not_verified:{verdict}",)


def compose_shadow(
    production: VerificationResult, contract: CompletionResult
) -> LayeredVerificationResult:
    """Compose both gates fail-closed while preserving useful disagreement data."""
    if not isinstance(production, VerificationResult):
        raise ValueError("production result must be VerificationResult")
    if not isinstance(contract, CompletionResult):
        raise ValueError("contract result must be CompletionResult")

    errors = _errors("production", production.verdict, production.errors) + _errors(
        "contract", contract.verdict, contract.errors
    )
    if production.verdict == "failed" or contract.verdict == "failed":
        verdict = "failed"
    elif production.verdict == "verified" and contract.verdict == "verified":
        verdict = "verified"
    elif contract.verdict == "insufficient_information":
        verdict = "insufficient_information"
    else:
        verdict = "unknown"
    return LayeredVerificationResult(
        verdict=verdict,
        errors=errors,
        production_verdict=production.verdict,
        contract_verdict=contract.verdict,
    )

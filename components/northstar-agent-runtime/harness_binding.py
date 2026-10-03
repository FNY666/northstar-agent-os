"""Harness integrity binding (ninetieth batch).

Absorbed from 2026 eval-methodology research (mechanism ideas only,
honestly scoped here):

* "A benchmark number without a harness is not a benchmark number" —
  the ARC Prize scored the *same* model 62.7% vs 99.9% on two different
  harnesses (standard harness vs a vendor-supplied adapter), a 36-point
  gap larger than most model-to-model gaps. A score detached from its
  harness is not a measurement; it is a rumor.
* Livenerf (2026-10-01) — the first post-release *drift-tracking*
  benchmark: re-run the same model name across time windows and compare
  statistically to catch silent vendor downgrades. Drift detection lives
  in ``drift_probe.py``; this module pins the harness side of the
  comparison — which harness produced which score.

Every governance-bench run pins a SHA-256 of the canonical harness
configuration (code version, prompt templates, tool versions,
environment facts) into its audit record. Scores are always presented
with the quad ``(model version + harness hash + effort level + $/task)``;
there is no supported API that emits a bare score — asking for one
raises ``HarnessBindingError``.

Tamper semantics: if the harness configuration presented at
verification time does not hash to the pinned digest, the score is
*invalidated* (not downgraded, not annotated — invalidated). A bare
score, a score with a missing quad element, or a score whose harness
cannot be re-verified is not a score Northstar will present.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Sequence


HARNESS_BINDING_SCHEMA_VERSION = "northstar.harness-binding.v1"

_VALID_EFFORTS = frozenset({"low", "medium", "high"})


class HarnessBindingError(ValueError):
    """The harness binding refused to present or verify a score."""


# ---------------------------------------------------------------------------
# Harness configuration + hashing
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HarnessConfig:
    """Everything that can silently move a benchmark number.

    * ``code_version`` — the harness/bench code version (e.g. the
      ``BENCH_VERSION`` string), so a code change is a different harness.
    * ``prompt_templates`` — ``(name, sha256)`` pairs for every prompt
      template the harness injects; templates are hashed by content, not
      trusted by name.
    * ``tool_versions`` — ``(tool, version)`` pairs for every tool the
      harness exposes to the model under test.
    * ``environment`` — ``(key, value)`` environment facts (python
      version, platform, dependency pins) that affect execution.
    """

    code_version: str
    prompt_templates: tuple[tuple[str, str], ...] = ()
    tool_versions: tuple[tuple[str, str], ...] = ()
    environment: tuple[tuple[str, str], ...] = ()

    def as_canonical(self) -> dict[str, Any]:
        """Canonical dict: sorted, JSON-safe, no ambient state."""
        return {
            "code_version": self.code_version,
            "environment": sorted((str(k), str(v)) for k, v in self.environment),
            "prompt_templates": sorted(
                (str(n), str(d)) for n, d in self.prompt_templates
            ),
            "tool_versions": sorted((str(t), str(v)) for t, v in self.tool_versions),
        }


def canonical_harness_bytes(config: HarnessConfig) -> bytes:
    """Canonical JSON bytes of a harness config (JCS-style: sorted keys,
    compact separators, UTF-8)."""
    if not isinstance(config, HarnessConfig):
        raise HarnessBindingError(
            f"harness config must be a HarnessConfig, not {type(config).__name__}"
        )
    try:
        return json.dumps(
            config.as_canonical(),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise HarnessBindingError("harness config is not canonical JSON") from error


def harness_hash(config: HarnessConfig) -> str:
    """SHA-256 hex digest of the canonical harness configuration."""
    return hashlib.sha256(canonical_harness_bytes(config)).hexdigest()


def bind_harness_to_audit(
    config: HarnessConfig, *, model_version: str, note: str = ""
) -> dict[str, Any]:
    """Audit record pinning the harness digest for one bench run.

    Feed the returned dict into ``audit_chain.chain_record`` in order;
    the ``audit.ndjson/1`` hash chain then anchors *which harness*
    produced *which score*.
    """
    if not model_version or not isinstance(model_version, str):
        raise HarnessBindingError("model_version must be a non-empty string")
    return {
        "event": "harness_binding.bound",
        "schema": HARNESS_BINDING_SCHEMA_VERSION,
        "model_version": model_version,
        "harness_sha256": harness_hash(config),
        "harness": config.as_canonical(),
        "note": note,
    }


def verify_harness_binding(config: HarnessConfig, pinned_sha256: str) -> bool:
    """Re-hash ``config`` and compare against the pinned digest.

    Returns True only on an exact match. A malformed pinned digest
    fails closed (raises) rather than comparing False — a corrupt pin
    is a binding failure, not a "no".
    """
    if (
        not isinstance(pinned_sha256, str)
        or len(pinned_sha256) != 64
        or any(c not in "0123456789abcdef" for c in pinned_sha256.lower())
    ):
        raise HarnessBindingError(
            "pinned harness digest is malformed; refusing to verify"
        )
    return harness_hash(config).lower() == pinned_sha256.lower()


# ---------------------------------------------------------------------------
# The quad: scores are never bare
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScoredResult:
    """A benchmark score with its full measurement context.

    ``score`` is the raw number (0.0–1.0). It is *data*, not a
    presentation: the only sanctioned renderer is ``format_quad``.
    ``emit_bare_score`` exists solely to refuse — calling it raises.
    """

    model_version: str
    harness: HarnessConfig
    effort: str
    cost_per_task_usd: float
    score: float
    n_tasks: int = 0

    def quad(self) -> tuple[str, str, str, float]:
        """The four measurement axes: model, harness hash, effort, $/task."""
        return (
            self.model_version,
            harness_hash(self.harness),
            self.effort,
            self.cost_per_task_usd,
        )


def validate_quad(result: ScoredResult) -> None:
    """Fail-closed validation of the quad. Raises on anything incomplete."""
    if not isinstance(result, ScoredResult):
        raise HarnessBindingError(
            f"expected ScoredResult, not {type(result).__name__}"
        )
    model, harness_digest, effort, cost = result.quad()
    if not model or not isinstance(model, str):
        raise HarnessBindingError("quad is missing the model version")
    if len(harness_digest) != 64:
        raise HarnessBindingError("quad is missing the harness hash")
    if effort not in _VALID_EFFORTS:
        raise HarnessBindingError(
            f"quad effort must be one of {sorted(_VALID_EFFORTS)}, not {effort!r}"
        )
    if not isinstance(cost, (int, float)) or cost < 0:
        raise HarnessBindingError("quad $/task must be a non-negative number")
    if not isinstance(result.score, (int, float)) or not 0.0 <= result.score <= 1.0:
        raise HarnessBindingError("score must be a number in [0, 1]")


def format_quad(result: ScoredResult) -> str:
    """The only sanctioned score renderer: always the full quad.

    A benchmark number without a harness is not a benchmark number, so
    this function refuses to render anything less than all four axes.
    """
    validate_quad(result)
    model, harness_digest, effort, cost = result.quad()
    return (
        f"score={result.score:.4f} "
        f"model={model} "
        f"harness=sha256:{harness_digest} "
        f"effort={effort} "
        f"cost=${cost:.4f}/task"
    )


def emit_bare_score(result: ScoredResult) -> float:
    """Deliberate refusal: there is no bare-score API.

    This function exists so the refusal is explicit and testable. A
    benchmark number without its harness, effort, and cost is not a
    benchmark number.
    """
    raise HarnessBindingError(
        "refusing to emit a bare score: present the quad "
        "(model version + harness hash + effort + $/task) via format_quad()"
    )


# ---------------------------------------------------------------------------
# Invalidation: tampered harness => score is not a score
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BoundScore:
    """A score bound to a pinned harness digest.

    ``invalidate_if_tampered`` re-hashes the live harness config; any
    drift from the pin invalidates the score outright.
    """

    result: ScoredResult
    pinned_harness_sha256: str
    state: str = "valid"
    reason: str = ""


def bind_score(result: ScoredResult, config: HarnessConfig) -> BoundScore:
    """Pin a score to the digest of the harness that produced it."""
    validate_quad(result)
    return BoundScore(
        result=result, pinned_harness_sha256=harness_hash(config)
    )


def invalidate_if_tampered(bound: BoundScore, live_config: HarnessConfig) -> BoundScore:
    """Re-verify the harness; tampering invalidates the score.

    Returns a new ``BoundScore`` with ``state="invalid"`` when the live
    config no longer hashes to the pin. Invalidation is one-way: there
    is no API that returns a bound score to "valid".
    """
    if bound.state != "valid":
        return bound
    if not verify_harness_binding(live_config, bound.pinned_harness_sha256):
        return BoundScore(
            result=bound.result,
            pinned_harness_sha256=bound.pinned_harness_sha256,
            state="invalid",
            reason=(
                "harness configuration drifted from the pinned digest; "
                "the score is invalidated, not reinterpreted"
            ),
        )
    return bound


__all__ = [
    "HARNESS_BINDING_SCHEMA_VERSION",
    "HarnessBindingError",
    "HarnessConfig",
    "ScoredResult",
    "BoundScore",
    "canonical_harness_bytes",
    "harness_hash",
    "bind_harness_to_audit",
    "verify_harness_binding",
    "validate_quad",
    "format_quad",
    "emit_bare_score",
    "bind_score",
    "invalidate_if_tampered",
]

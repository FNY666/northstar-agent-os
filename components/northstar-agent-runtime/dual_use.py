"""Dual-use screen for autonomous science (one-hundred-eleventh batch).

Absorbs the 2026 AI-for-science research thread (mechanism ideas only,
honestly scoped):

* **ABC-Bench (2026):** LLM agents beat human expert medians at
  "writing robot scripts" and "designing DNA fragments"; "bypassing
  DNA synthesis screening" hit 78% (Gemini); Llama 3.1/GPT-4o could
  guide poliovirus resurrection. The governance failure is not model
  capability — it is the missing *screen between capability and
  execution*.
* **SAFS26-a:** removing physical constraints made models chase
  "high score but physically meaningless" solutions. A lab task with
  no declared constraints is a task with no guardrails.
* **AlphaProof Nexus pattern (2026):** generator proposes, an
  *independent mechanical verifier* (Lean 4.27) disposes. Rejection
  by the verifier is rejection of the action — there is no override
  path that a more persuasive generator can talk its way through.
* **Paper-mill evidence (2026):** 34.84% of 13,502 AI/ML retractions
  attributed to computer-generated content; fake citations entering
  Springer Nature journals. Unparseable citations at scale make a
  document unverifiable, not merely sloppy.

Northstar mapping:

* ``ConstraintBinding`` — an authority-signed, hash-chained receipt
  binding ``(task_id, constraint_list_digest, constraint_source,
  issued_by, issued_at)``. Every autonomous-science/lab task needs a
  constraint binding *before* any tool call. Missing → deny with
  ``science:no_constraints``. The constraint list itself lives
  out-of-band (it is the lab's biosafety/physics red-line document);
  the binding pins its digest so the list cannot be silently swapped.
* ``screen_tool_call()`` — a deterministic screen: the tool call
  against a closed ``DUAL_USE_WATCHLIST``. A hit escalates to human
  approval (fail-closed: the call is *not* authorized) and audits
  ``science.dual_use_hit``. Near-hits classify the call
  ``NON_AUTHORITATIVE`` — never auto-allow, never auto-deny: they
  need human eyes.
* ``ClaimRegistry`` — AI-generated scientific assertions enter as
  ``NON_AUTHORITATIVE`` by default. Only a matching replication
  receipt (``reproduce_digest``) or an expert countersign promotes a
  claim to ``authoritative``. "Breakthrough" claims with a result but
  no method are marked ``ununderstood`` and never enter the reusable-
  conclusion store.
* ``check_citations()`` — a deterministic citation parser.
  Unparseable citations are findings; when the finding ratio crosses
  ``CITATION_FINDING_THRESHOLD`` the whole document classifies
  ``NON_AUTHORITATIVE``.
* ``MechanicalVerifier`` — the AlphaProof separation: a task declares
  ``(generator_id, verifier_id)``; the action is authorized only when
  the verifier *independently accepts*. Verifier reject → action
  reject. There is deliberately no override path.

Honest boundary: ``DUAL_USE_WATCHLIST`` is a declared list, not
omniscience. It is a tripwire, not a guarantee — a novel misuse
pattern not on the list passes the screen, which is why near-hits
escalate to humans and why the constraint binding exists as an
independent gate. The registry cannot detect a claim that was never
registered; it only guarantees that registered claims carry their
provenance honestly. Citation parsing is syntactic — it cannot judge
whether a real citation was fabricated (the ZB MED indexjacking
lesson), only whether citations are machine-checkable at all.

Deterministic: no wall-clock reads (callers inject ``created_unix``
as an integer), canonical JCS hashing, constant-time digest
comparisons.
"""

from __future__ import annotations

import hmac
import re
from dataclasses import dataclass, field
from typing import Any, Mapping

from canonical_json import jcs_sha256_hex
from ed25519 import public_key as ed_public_key
from ed25519 import sign as ed_sign
from ed25519 import verify as ed_verify

DUAL_USE_SCHEMA_VERSION = "northstar.dual-use.v1"

#: Denial reason codes. All start with the ``science:`` prefix so
#: audit consumers can filter the family.
DENY_NO_CONSTRAINTS = "science:no_constraints"
DENY_CONSTRAINT_TAMPER = "science:constraint_tamper"
DENY_CHAIN_GAP = "science:chain_gap"
DENY_DUAL_USE_HIT = "science:dual_use_hit"
DENY_VERIFIER_REJECT = "science:verifier_reject"
DENY_UNKNOWN_TASK = "science:unknown_task"
DENY_UNKNOWN_CLAIM = "science:unknown_claim"
DENY_DIGEST_MISMATCH = "science:digest_mismatch"
DENY_MALFORMED = "science:malformed"

#: Audit event names (shaped to feed ``audit_chain.chain_record``).
DUAL_USE_HIT_EVENT = "science.dual_use_hit"
DUAL_USE_SCREENED_EVENT = "science.tool_call_screened"
CLAIM_EVENT = "science.claim_registered"
CLAIM_PROMOTED_EVENT = "science.claim_promoted"
CONSTRAINT_EVENT = "science.constraint_bound"
CITATION_EVENT = "science.citations_checked"
VERIFIER_EVENT = "science.verifier_verdict"

#: Citation finding threshold: if more than this fraction of parsed
#: citation slots are unparseable, the document is
#: NON_AUTHORITATIVE.
CITATION_FINDING_THRESHOLD = 0.30

#: Claim classifications.
CLAIM_NON_AUTHORITATIVE = "NON_AUTHORITATIVE"
CLAIM_AUTHORITATIVE = "authoritative"
CLAIM_UNUNDERSTOOD = "ununderstood"

#: Verdict classifications for a screened tool call.
CALL_ALLOW = "allow"
CALL_ESCALATE = "escalate"
CALL_NON_AUTHORITATIVE = "NON_AUTHORITATIVE"

_HEX64_LENGTH = 64
_ED25519_SIG_LENGTH = 64

#: The dual-use watchlist: a closed list of
#: (capability_family, compiled_pattern) pairs. A hit means the call
#: must go to a human before it may execute. Patterns are matched
#: case-insensitively against ``tool_name + " " + canonical_args``.
#: This list is deliberately conservative and declarative — adding an
#: entry is a governance decision, not a model judgement call.
DUAL_USE_WATCHLIST: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (family, re.compile(pattern, re.IGNORECASE))
    for family, pattern in (
        ("bio:pathogen_synthesis", r"\b(dna|rna|oligo)\s*(synthesis|order|assembly)\b"),
        ("bio:pathogen_synthesis", r"\b(genome|viral)\s*(assembly|vector)\b"),
        ("bio:pathogen_synthesis", r"\bpathogen\b"),
        ("bio:pathogen_synthesis", r"\b(select\s+agent|bwc\s+listed)\b"),
        ("bio:screening_bypass", r"\b(dna\s+synthesis\s+)?screen(ing)?\s*(bypass|evasion|circumvent)\b"),
        ("bio:screening_bypass", r"\b(evasion|bypass)\s+(of\s+)?(dna\s+)?synthesis\s+screen"),
        ("bio:gain_of_function", r"\bgain[-\s]?of[-\s]?function\b"),
        ("bio:gain_of_function", r"\b(poliovirus|ebola|smallpox|anthrax)\b"),
        ("bio:resurrection", r"\b(resurrect|reconstruct)\w*\s+(virus|pathogen)\b"),
        ("chem:weapon", r"\b(nerve\s+agent|sarin|vx\s+gas|mustard\s+gas)\b"),
        ("chem:weapon", r"\btoxin\b"),
        ("robotics:wetlab", r"\bopentrons\b"),
        ("robotics:wetlab", r"\bliquid[\s-]?handler\b"),
        ("robotics:wetlab", r"\bpipetting\s+protocol\b"),
    )
)

#: Near-hit heuristics: matched text is plausibly dual-use-adjacent
#: but not on the watchlist. A near-hit classifies the call
#: NON_AUTHORITATIVE — it may not auto-execute.
NEAR_HIT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (family, re.compile(pattern, re.IGNORECASE))
    for family, pattern in (
        ("bio:adjacent", r"\bsynthesis\b"),
        ("bio:adjacent", r"\bplasmid\b"),
        ("bio:adjacent", r"\bcrispr\b"),
        ("chem:adjacent", r"\bprecursor\b"),
        ("robotics:adjacent", r"\brobot\w*\s+script\b"),
    )
)


class DualUseError(ValueError):
    """A malformed binding, registry, or screen request — a programming
    error, not a verdict. Verification *failures* (missing binding,
    watchlist hit, verifier reject, digest mismatch) return a verdict
    with ``allowed=False`` instead; malformed input raises here, fail
    loud, never guess."""


def _is_hex64(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == _HEX64_LENGTH
        and all(c in "0123456789abcdef" for c in value)
    )


def _require_hex64(value: Any, what: str) -> str:
    if not _is_hex64(value):
        raise DualUseError(f"{what} must be a 64-char lowercase hex digest")
    return value


def _require_nonempty(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise DualUseError(f"{what} must be a non-empty string")
    return value


def _require_unix(value: Any, what: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise DualUseError(f"{what} must be a non-negative int (unix time)")
    return value


# ---------------------------------------------------------------------------
# AuthorityRegistry: who may issue constraint bindings (curated out-of-band)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuthorityRegistry:
    """Maps ``authority_id`` to an Ed25519 public key (32 bytes).

    Only registered *human* authorities may issue constraint
    bindings. There is no agent-key path: the agent cannot pin its own
    constraint list (no-self-issuance, the 94th/104th/109th-batch
    discipline applied to lab work).
    """

    public_keys: Mapping[str, bytes] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for authority_id, pubkey in self.public_keys.items():
            _require_nonempty(authority_id, "authority_id")
            if not isinstance(pubkey, (bytes, bytearray)) or len(pubkey) != 32:
                raise DualUseError(
                    f"public key for {authority_id!r} must be 32 bytes"
                )

    def public_key_for(self, authority_id: str) -> bytes | None:
        key = self.public_keys.get(authority_id)
        return bytes(key) if key is not None else None


# ---------------------------------------------------------------------------
# ConstraintBinding: the authority-signed, hash-chained constraint pin
# ---------------------------------------------------------------------------


def _binding_payload(
    *,
    task_id: str,
    constraint_list_digest: str,
    constraint_source: str,
    issued_by: str,
    issued_at: int,
    prev_hash: str,
) -> dict[str, Any]:
    return {
        "schema_version": DUAL_USE_SCHEMA_VERSION,
        "task_id": task_id,
        "constraint_list_digest": constraint_list_digest,
        "constraint_source": constraint_source,
        "issued_by": issued_by,
        "issued_at": issued_at,
        "prev_hash": prev_hash,
    }


@dataclass(frozen=True)
class ConstraintBinding:
    """A constraint binding pins the digest of the task's constraint
    list (physical laws, biosafety red lines) to the task, signed by
    a registered authority and chained to the previous binding for
    the same task. The constraint list itself lives out-of-band; this
    receipt guarantees it cannot be silently swapped mid-task.
    """

    task_id: str
    constraint_list_digest: str
    constraint_source: str
    issued_by: str
    issued_at: int
    binding_digest: str
    signature: bytes
    prev_hash: str = ""
    schema_version: str = DUAL_USE_SCHEMA_VERSION

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": "dual-use-constraint-binding",
            "schema_version": self.schema_version,
            "task_id": self.task_id,
            "constraint_list_digest": self.constraint_list_digest,
            "constraint_source": self.constraint_source,
            "issued_by": self.issued_by,
            "issued_at": self.issued_at,
            "binding_digest": self.binding_digest,
            "signature": self.signature.hex(),
            "prev_hash": self.prev_hash,
        }


def issue_constraint_binding(
    registry: AuthorityRegistry,
    *,
    task_id: str,
    constraint_list_digest: str,
    constraint_source: str,
    issued_by: str,
    issued_at: int,
    signature: bytes,
    prev_hash: str = "",
) -> ConstraintBinding:
    """Issue a constraint binding. The signature must come from a
    registered human authority over the binding digest; anything else
    fails loud. The agent cannot issue its own binding —
    ``issued_by`` must be a registered authority, and there is
    deliberately no agent-key path."""
    if not isinstance(registry, AuthorityRegistry):
        raise DualUseError("registry must be an AuthorityRegistry")
    _require_nonempty(task_id, "task_id")
    _require_hex64(constraint_list_digest, "constraint_list_digest")
    _require_nonempty(constraint_source, "constraint_source")
    _require_nonempty(issued_by, "issued_by")
    _require_unix(issued_at, "issued_at")
    if prev_hash and not _is_hex64(prev_hash):
        raise DualUseError("prev_hash must be empty or a 64-char hex digest")
    if not isinstance(signature, (bytes, bytearray)) or len(signature) != _ED25519_SIG_LENGTH:
        raise DualUseError("signature must be 64 bytes")

    pubkey = registry.public_key_for(issued_by)
    if pubkey is None:
        raise DualUseError(
            f"issued_by {issued_by!r} is not a registered constraint authority"
        )
    digest = jcs_sha256_hex(
        _binding_payload(
            task_id=task_id,
            constraint_list_digest=constraint_list_digest,
            constraint_source=constraint_source,
            issued_by=issued_by,
            issued_at=issued_at,
            prev_hash=prev_hash,
        )
    )
    if not ed_verify(pubkey, digest.encode("utf-8"), bytes(signature)):
        raise DualUseError("authority signature does not verify")
    return ConstraintBinding(
        task_id=task_id,
        constraint_list_digest=constraint_list_digest,
        constraint_source=constraint_source,
        issued_by=issued_by,
        issued_at=issued_at,
        binding_digest=digest,
        signature=bytes(signature),
        prev_hash=prev_hash,
    )


# ---------------------------------------------------------------------------
# ScienceTaskGate: the binding-before-tools enforcement point
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TaskVerdict:
    """The verdict of the science task gate."""

    allowed: bool
    reason: str
    audit_event: dict[str, Any]


class ScienceTaskGate:
    """Owns constraint bindings per task; the pre-tool-call gate.

    A task with no valid binding cannot make *any* tool call — the
    gate returns ``allowed=False`` with ``science:no_constraints``
    before the tool is even screened. Binding chains are verified
    (no gaps, no tampering) on every check.
    """

    def __init__(self, registry: AuthorityRegistry) -> None:
        if not isinstance(registry, AuthorityRegistry):
            raise DualUseError("registry must be an AuthorityRegistry")
        self._registry = registry
        self._chains: dict[str, list[ConstraintBinding]] = {}

    def register(self, binding: ConstraintBinding) -> ConstraintBinding:
        """Register an authority-signed binding. Chains per task: the
        binding's ``prev_hash`` must equal the previous binding's
        digest (empty for genesis); duplicate digests refuse."""
        if not isinstance(binding, ConstraintBinding):
            raise DualUseError("binding must be a ConstraintBinding")
        chain = self._chains.setdefault(binding.task_id, [])
        expected_prev = chain[-1].binding_digest if chain else ""
        if not hmac.compare_digest(binding.prev_hash, expected_prev):
            raise DualUseError(
                f"prev_hash mismatch for task {binding.task_id!r}: "
                "chain gap or reorder"
            )
        if any(b.binding_digest == binding.binding_digest for b in chain):
            raise DualUseError(
                f"duplicate binding for task {binding.task_id!r}"
            )
        chain.append(binding)
        return binding

    def _verify_chain(self, task_id: str) -> tuple[bool, str]:
        chain = self._chains.get(task_id)
        if not chain:
            return (False, DENY_NO_CONSTRAINTS)
        previous = ""
        for binding in chain:
            if not hmac.compare_digest(binding.prev_hash, previous):
                return (False, DENY_CHAIN_GAP)
            expected = jcs_sha256_hex(
                _binding_payload(
                    task_id=binding.task_id,
                    constraint_list_digest=binding.constraint_list_digest,
                    constraint_source=binding.constraint_source,
                    issued_by=binding.issued_by,
                    issued_at=binding.issued_at,
                    prev_hash=binding.prev_hash,
                )
            )
            if not hmac.compare_digest(binding.binding_digest, expected):
                return (False, DENY_CONSTRAINT_TAMPER)
            pubkey = self._registry.public_key_for(binding.issued_by)
            if pubkey is None or not ed_verify(
                pubkey,
                binding.binding_digest.encode("utf-8"),
                binding.signature,
            ):
                return (False, DENY_CONSTRAINT_TAMPER)
            previous = binding.binding_digest
        return (True, "constraints_bound")

    def require_binding(self, task_id: str, created_unix: int = 0) -> TaskVerdict:
        """Probe: does this task hold a valid constraint binding? The
        gate every tool call must pass first."""
        _require_nonempty(task_id, "task_id")
        _require_unix(created_unix, "created_unix")
        ok, reason = self._verify_chain(task_id)
        event = (
            CONSTRAINT_EVENT
            if ok
            else "science.task_denied"
        )
        return TaskVerdict(
            allowed=ok,
            reason=reason,
            audit_event={
                "event": event,
                "task_id": task_id,
                "allowed": ok,
                "reason": reason,
                "created_unix": created_unix,
            },
        )

    def task_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._chains))


# ---------------------------------------------------------------------------
# screen_tool_call: the deterministic dual-use tripwire
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScreenVerdict:
    """The verdict of :func:`screen_tool_call`."""

    classification: str
    allowed: bool
    reason: str
    matched_family: str
    audit_event: dict[str, Any]


def _canonical_call_text(tool_name: str, args: Any) -> str:
    # Canonical rendering: deterministic and key-order-independent.
    # (Rendered text, not the digest, is what patterns match against.)
    import json as _json

    try:
        rendered = _json.dumps(
            {"tool": tool_name, "args": args},
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        return f"{tool_name} {rendered}"
    except Exception as exc:  # pragma: no cover - defensive
        raise DualUseError(f"tool call not renderable: {exc}") from exc


def screen_tool_call(
    task_id: str,
    tool_name: str,
    args: Any,
    created_unix: int = 0,
) -> ScreenVerdict:
    """Screen one tool call against the dual-use watchlist.

    Returns ``allow`` when nothing matches, ``escalate`` on a
    watchlist hit (the call must go to a human; it is *not*
    authorized), and ``NON_AUTHORITATIVE`` on a near-hit (may not
    auto-execute). Malformed calls raise; screening *outcomes* are
    values, fail-closed.
    """
    _require_nonempty(task_id, "task_id")
    _require_nonempty(tool_name, "tool_name")
    _require_unix(created_unix, "created_unix")
    text = _canonical_call_text(tool_name, args)

    for family, pattern in DUAL_USE_WATCHLIST:
        if pattern.search(text):
            return ScreenVerdict(
                classification=CALL_ESCALATE,
                allowed=False,
                reason=DENY_DUAL_USE_HIT,
                matched_family=family,
                audit_event={
                    "event": DUAL_USE_HIT_EVENT,
                    "task_id": task_id,
                    "tool_name": tool_name,
                    "classification": CALL_ESCALATE,
                    "allowed": False,
                    "reason": DENY_DUAL_USE_HIT,
                    "matched_family": family,
                    "created_unix": created_unix,
                },
            )
    for family, pattern in NEAR_HIT_PATTERNS:
        if pattern.search(text):
            return ScreenVerdict(
                classification=CALL_NON_AUTHORITATIVE,
                allowed=False,
                reason="dual_use:near_hit",
                matched_family=family,
                audit_event={
                    "event": DUAL_USE_SCREENED_EVENT,
                    "task_id": task_id,
                    "tool_name": tool_name,
                    "classification": CALL_NON_AUTHORITATIVE,
                    "allowed": False,
                    "reason": "dual_use:near_hit",
                    "matched_family": family,
                    "created_unix": created_unix,
                },
            )
    return ScreenVerdict(
        classification=CALL_ALLOW,
        allowed=True,
        reason="screen_clean",
        matched_family="",
        audit_event={
            "event": DUAL_USE_SCREENED_EVENT,
            "task_id": task_id,
            "tool_name": tool_name,
            "classification": CALL_ALLOW,
            "allowed": True,
            "reason": "screen_clean",
            "matched_family": "",
            "created_unix": created_unix,
        },
    )


# ---------------------------------------------------------------------------
# ClaimRegistry: scientific assertions enter NON_AUTHORITATIVE
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Claim:
    """One registered scientific assertion.

    ``classification`` starts at ``NON_AUTHORITATIVE`` and can only
    move to ``authoritative`` via :meth:`ClaimRegistry.record_replication`
    or :meth:`ClaimRegistry.countersign`. ``ununderstood`` is
    terminal: result-without-method "breakthroughs" never become
    reusable conclusions.
    """

    claim_id: str
    assertion: str
    produced_by: str
    method_digest: str
    classification: str
    reproduce_digest: str = ""
    countersigned_by: str = ""
    created_unix: int = 0
    schema_version: str = DUAL_USE_SCHEMA_VERSION

    def claim_digest(self) -> str:
        return jcs_sha256_hex(
            {
                "schema_version": self.schema_version,
                "claim_id": self.claim_id,
                "assertion": self.assertion,
                "produced_by": self.produced_by,
                "method_digest": self.method_digest,
            }
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": "dual-use-claim",
            "schema_version": self.schema_version,
            "claim_id": self.claim_id,
            "assertion": self.assertion,
            "produced_by": self.produced_by,
            "method_digest": self.method_digest,
            "classification": self.classification,
            "reproduce_digest": self.reproduce_digest,
            "countersigned_by": self.countersigned_by,
            "created_unix": self.created_unix,
            "claim_digest": self.claim_digest(),
        }


class ClaimRegistry:
    """Owns scientific claims and their promotion path.

    Promotion is evidence-only: a replication receipt whose
    ``reproduce_digest`` matches the claim's method digest, or an
    expert countersign. There is no "the model is very confident"
    promotion path — confidence is not evidence.
    """

    def __init__(self) -> None:
        self._claims: dict[str, Claim] = {}

    def register_claim(
        self,
        *,
        claim_id: str,
        assertion: str,
        produced_by: str,
        method_digest: str = "",
        created_unix: int = 0,
    ) -> Claim:
        """Register an AI-generated assertion. Classification is
        always ``NON_AUTHORITATIVE`` at registration. A claim with an
        assertion but no method (``method_digest`` empty and
        ``breakthrough`` asserted) is marked ``ununderstood`` — the
        Tao warning institutionalized: a result with no method is
        never a reusable conclusion."""
        _require_nonempty(claim_id, "claim_id")
        _require_nonempty(assertion, "assertion")
        _require_nonempty(produced_by, "produced_by")
        _require_unix(created_unix, "created_unix")
        if claim_id in self._claims:
            raise DualUseError(f"duplicate claim_id {claim_id!r}")
        classification = CLAIM_NON_AUTHORITATIVE
        if method_digest and not _is_hex64(method_digest):
            raise DualUseError("method_digest must be empty or a 64-char hex digest")
        claim = Claim(
            claim_id=claim_id,
            assertion=assertion,
            produced_by=produced_by,
            method_digest=method_digest,
            classification=classification,
            created_unix=created_unix,
        )
        self._claims[claim_id] = claim
        return claim

    def mark_ununderstood(self, claim_id: str, created_unix: int = 0) -> Claim:
        """Terminal classification for result-without-method
        "breakthroughs". Irreversible: an ununderstood claim can never
        be promoted."""
        _require_unix(created_unix, "created_unix")
        claim = self._claims.get(claim_id)
        if claim is None:
            raise DualUseError(f"unknown claim {claim_id!r}")
        updated = Claim(
            claim_id=claim.claim_id,
            assertion=claim.assertion,
            produced_by=claim.produced_by,
            method_digest=claim.method_digest,
            classification=CLAIM_UNUNDERSTOOD,
            reproduce_digest=claim.reproduce_digest,
            countersigned_by=claim.countersigned_by,
            created_unix=claim.created_unix,
        )
        self._claims[claim_id] = updated
        return updated

    def record_replication(
        self,
        claim_id: str,
        reproduce_digest: str,
        created_unix: int = 0,
    ) -> Claim:
        """Promote on a matching replication receipt: the independent
        reproduction's digest must equal the claim's method digest.
        Anything else fails closed — a non-matching receipt is a
        finding, not a promotion."""
        _require_unix(created_unix, "created_unix")
        _require_hex64(reproduce_digest, "reproduce_digest")
        claim = self._claims.get(claim_id)
        if claim is None:
            raise DualUseError(f"unknown claim {claim_id!r}")
        if claim.classification == CLAIM_UNUNDERSTOOD:
            raise DualUseError(
                f"claim {claim_id!r} is ununderstood and cannot be promoted"
            )
        if not claim.method_digest or not hmac.compare_digest(
            reproduce_digest, claim.method_digest
        ):
            raise DualUseError(
                f"replication digest for {claim_id!r} does not match the "
                "claimed method digest"
            )
        updated = Claim(
            claim_id=claim.claim_id,
            assertion=claim.assertion,
            produced_by=claim.produced_by,
            method_digest=claim.method_digest,
            classification=CLAIM_AUTHORITATIVE,
            reproduce_digest=reproduce_digest,
            countersigned_by=claim.countersigned_by,
            created_unix=claim.created_unix,
        )
        self._claims[claim_id] = updated
        return updated

    def countersign(
        self,
        claim_id: str,
        expert_id: str,
        created_unix: int = 0,
    ) -> Claim:
        """Expert countersign promotion. The expert must differ from
        the claim's producer — the model cannot countersign itself."""
        _require_nonempty(expert_id, "expert_id")
        _require_unix(created_unix, "created_unix")
        claim = self._claims.get(claim_id)
        if claim is None:
            raise DualUseError(f"unknown claim {claim_id!r}")
        if claim.classification == CLAIM_UNUNDERSTOOD:
            raise DualUseError(
                f"claim {claim_id!r} is ununderstood and cannot be promoted"
            )
        if expert_id == claim.produced_by:
            raise DualUseError("self-countersign refused")
        updated = Claim(
            claim_id=claim.claim_id,
            assertion=claim.assertion,
            produced_by=claim.produced_by,
            method_digest=claim.method_digest,
            classification=CLAIM_AUTHORITATIVE,
            reproduce_digest=claim.reproduce_digest,
            countersigned_by=expert_id,
            created_unix=claim.created_unix,
        )
        self._claims[claim_id] = updated
        return updated

    def claim(self, claim_id: str) -> Claim | None:
        return self._claims.get(claim_id)

    def reusable_conclusions(self) -> tuple[Claim, ...]:
        """Claims safe to reuse downstream: authoritative only.
        ``ununderstood`` claims never appear here, by construction."""
        return tuple(
            sorted(
                (c for c in self._claims.values()
                 if c.classification == CLAIM_AUTHORITATIVE),
                key=lambda c: c.claim_id,
            )
        )


# ---------------------------------------------------------------------------
# check_citations: deterministic citation integrity
# ---------------------------------------------------------------------------

#: A citation slot is "parseable" when it carries at least one
#: machine-checkable identifier: a DOI, an arXiv id, or an
#: author/year/venue-shaped reference.
_DOI_RE = re.compile(r"\b10\.\d{4,}/[^\s\"'<>]+", re.IGNORECASE)
_ARXIV_RE = re.compile(r"\barxiv:\s*\d{4}\.\d{4,5}(v\d+)?\b", re.IGNORECASE)
_AUTHOR_YEAR_RE = re.compile(
    r"\b[A-Z][a-z]+(\s+(et\s+al\.?|and|,?\s+[A-Z][a-z]+))*.?,?\s*\(?(19|20)\d{2}\)?"
)


@dataclass(frozen=True)
class CitationVerdict:
    """The verdict of :func:`check_citations`."""

    classification: str
    n_slots: int
    n_findings: int
    findings: tuple[str, ...]
    audit_event: dict[str, Any]


def check_citations(doc: str, created_unix: int = 0) -> CitationVerdict:
    """Parse a document's citation slots deterministically.

    Slots are lines that look like citations (bracketed numerals,
    footnote markers, or lines starting with a citation keyword). Each
    slot must carry a DOI, an arXiv id, or an author/year/venue shape;
    anything else is a finding. When findings exceed
    ``CITATION_FINDING_THRESHOLD`` of slots, the whole document is
    ``NON_AUTHORITATIVE`` — syntactic checkability is the floor, not
    truth (a real-looking citation can still be fabricated; that is
    a deeper check outside this module's scope).
    """
    if not isinstance(doc, str):
        raise DualUseError("doc must be a string")
    _require_unix(created_unix, "created_unix")
    slots: list[str] = []
    for line in doc.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if re.match(r"^(\[\d+\]|\(\d+\)|\d+\.)\s+", stripped):
            slots.append(stripped)
            continue
        if re.match(r"^(references?|bibliography|citations?)\b", stripped, re.IGNORECASE):
            slots.append(stripped)
    findings: list[str] = []
    for slot in slots:
        if _DOI_RE.search(slot) or _ARXIV_RE.search(slot) or _AUTHOR_YEAR_RE.search(slot):
            continue
        findings.append(slot)
    n_slots = len(slots)
    n_findings = len(findings)
    ratio = (n_findings / n_slots) if n_slots else 0.0
    classification = (
        CLAIM_NON_AUTHORITATIVE
        if n_slots and ratio > CITATION_FINDING_THRESHOLD
        else CLAIM_AUTHORITATIVE
    )
    return CitationVerdict(
        classification=classification,
        n_slots=n_slots,
        n_findings=n_findings,
        findings=tuple(findings),
        audit_event={
            "event": CITATION_EVENT,
            "classification": classification,
            "n_slots": n_slots,
            "n_findings": n_findings,
            "finding_ratio": ratio,
            "created_unix": created_unix,
        },
    )


# ---------------------------------------------------------------------------
# MechanicalVerifier: generator/verifier separation (AlphaProof pattern)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VerifierDeclaration:
    """A task's generator/verifier separation declaration.

    The verifier must be *independent* of the generator: different
    implementation id, no shared producer key. The declaration is
    what the gate checks before any verifier verdict is honored.
    """

    gen_task_id: str
    generator_id: str
    verifier_id: str
    created_unix: int = 0
    schema_version: str = DUAL_USE_SCHEMA_VERSION

    def declaration_digest(self) -> str:
        return jcs_sha256_hex(
            {
                "schema_version": self.schema_version,
                "gen_task_id": self.gen_task_id,
                "generator_id": self.generator_id,
                "verifier_id": self.verifier_id,
            }
        )


@dataclass(frozen=True)
class VerifierVerdict:
    """The verdict of the mechanical verifier gate."""

    allowed: bool
    reason: str
    audit_event: dict[str, Any]


class MechanicalVerifier:
    """The AlphaProof separation: generator proposes, verifier
    disposes.

    A task declares ``(generator_id, verifier_id)``; the action is
    authorized only when the independent verifier *accepts*.
    Verifier reject → action reject, with no override path — not even
    the generator's confidence, not even a human re-asking the
    generator. (A human may, of course, authorize the action through
    a separate approval path; that is a different gate, not an
    override of this one.)
    """

    def __init__(self) -> None:
        self._declarations: dict[str, VerifierDeclaration] = {}

    def declare(
        self,
        gen_task_id: str,
        generator_id: str,
        verifier_id: str,
        created_unix: int = 0,
    ) -> VerifierDeclaration:
        """Declare the separation. Generator and verifier must be
        different ids — a self-checking generator is not a verifier."""
        _require_nonempty(gen_task_id, "gen_task_id")
        _require_nonempty(generator_id, "generator_id")
        _require_nonempty(verifier_id, "verifier_id")
        _require_unix(created_unix, "created_unix")
        if generator_id == verifier_id:
            raise DualUseError(
                "generator and verifier must be independent ids"
            )
        if gen_task_id in self._declarations:
            raise DualUseError(f"duplicate declaration for {gen_task_id!r}")
        declaration = VerifierDeclaration(
            gen_task_id=gen_task_id,
            generator_id=generator_id,
            verifier_id=verifier_id,
            created_unix=created_unix,
        )
        self._declarations[gen_task_id] = declaration
        return declaration

    def gate(
        self,
        gen_task_id: str,
        verifier_accepts: bool,
        created_unix: int = 0,
    ) -> VerifierVerdict:
        """Apply the verifier's verdict. Accept → authorized; reject
        → rejected with ``science:verifier_reject``. Unknown task →
        ``science:unknown_task``."""
        _require_nonempty(gen_task_id, "gen_task_id")
        _require_unix(created_unix, "created_unix")
        declaration = self._declarations.get(gen_task_id)
        if declaration is None:
            return VerifierVerdict(
                allowed=False,
                reason=DENY_UNKNOWN_TASK,
                audit_event={
                    "event": VERIFIER_EVENT,
                    "gen_task_id": gen_task_id,
                    "allowed": False,
                    "reason": DENY_UNKNOWN_TASK,
                    "created_unix": created_unix,
                },
            )
        if verifier_accepts:
            return VerifierVerdict(
                allowed=True,
                reason="verifier_accepted",
                audit_event={
                    "event": VERIFIER_EVENT,
                    "gen_task_id": gen_task_id,
                    "verifier_id": declaration.verifier_id,
                    "allowed": True,
                    "reason": "verifier_accepted",
                    "created_unix": created_unix,
                },
            )
        return VerifierVerdict(
            allowed=False,
            reason=DENY_VERIFIER_REJECT,
            audit_event={
                "event": VERIFIER_EVENT,
                "gen_task_id": gen_task_id,
                "verifier_id": declaration.verifier_id,
                "allowed": False,
                "reason": DENY_VERIFIER_REJECT,
                "created_unix": created_unix,
            },
        )


# ---------------------------------------------------------------------------
# Test/dev helper: deterministic authority keypair from a seed
# ---------------------------------------------------------------------------


def authority_keypair(seed: bytes) -> tuple[bytes, bytes]:
    """Derive ``(public_key, seed)`` from a 32-byte seed.

    Test and bench scaffolding only: production authorities manage
    keys out-of-band. The seed doubles as the ed25519 secret.
    """
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise DualUseError("seed must be 32 bytes")
    seed = bytes(seed)
    return (ed_public_key(seed), seed)


def sign_binding_digest(seed: bytes, digest: str) -> bytes:
    """Sign a constraint-binding digest with an authority seed
    (test/bench use)."""
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise DualUseError("seed must be 32 bytes")
    _require_hex64(digest, "digest")
    return ed_sign(bytes(seed), digest.encode("utf-8"))


def _binding_digest_for_signing(
    *,
    task_id: str,
    constraint_list_digest: str,
    constraint_source: str,
    issued_by: str,
    issued_at: int,
    prev_hash: str = "",
) -> str:
    """Compute the binding digest a test authority must sign (the same
    digest :func:`issue_constraint_binding` will recompute)."""
    return jcs_sha256_hex(
        _binding_payload(
            task_id=task_id,
            constraint_list_digest=constraint_list_digest,
            constraint_source=constraint_source,
            issued_by=issued_by,
            issued_at=issued_at,
            prev_hash=prev_hash,
        )
    )


__all__ = [
    "DUAL_USE_SCHEMA_VERSION",
    "DENY_NO_CONSTRAINTS",
    "DENY_CONSTRAINT_TAMPER",
    "DENY_CHAIN_GAP",
    "DENY_DUAL_USE_HIT",
    "DENY_VERIFIER_REJECT",
    "DENY_UNKNOWN_TASK",
    "DENY_UNKNOWN_CLAIM",
    "DENY_DIGEST_MISMATCH",
    "DENY_MALFORMED",
    "DUAL_USE_HIT_EVENT",
    "DUAL_USE_SCREENED_EVENT",
    "CLAIM_EVENT",
    "CLAIM_PROMOTED_EVENT",
    "CONSTRAINT_EVENT",
    "CITATION_EVENT",
    "VERIFIER_EVENT",
    "CITATION_FINDING_THRESHOLD",
    "CLAIM_NON_AUTHORITATIVE",
    "CLAIM_AUTHORITATIVE",
    "CLAIM_UNUNDERSTOOD",
    "CALL_ALLOW",
    "CALL_ESCALATE",
    "CALL_NON_AUTHORITATIVE",
    "DUAL_USE_WATCHLIST",
    "NEAR_HIT_PATTERNS",
    "DualUseError",
    "AuthorityRegistry",
    "ConstraintBinding",
    "TaskVerdict",
    "ScreenVerdict",
    "Claim",
    "CitationVerdict",
    "VerifierDeclaration",
    "VerifierVerdict",
    "issue_constraint_binding",
    "ScienceTaskGate",
    "screen_tool_call",
    "ClaimRegistry",
    "check_citations",
    "MechanicalVerifier",
    "authority_keypair",
    "sign_binding_digest",
]

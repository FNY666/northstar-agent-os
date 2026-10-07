"""Circuit: mechanistic-interpretability circuit discovery / verification / ablation ledger.

Research note: the circuits program (Olah et al. 2020, "Zoom In: An
Introduction to Circuits"; subsequent Anthropic interpretability work
on induction heads, curve detectors, and path patching) treats a
neural network as a graph of features and weights where a *circuit* is
a subcomputation -- a set of model components and the edges between
them hypothesized to implement one behavior. A claimed circuit is
earned by intervention experiments: ablate (zero / mean / resample /
noise / path-patch) a component and observe whether behavior degrades,
or patch activations to establish a causal role. This module is the
*ledger* layer for that practice:

* **discover()** books one declared circuit discovery for a model
  against a pinned circuit-kind vocabulary (``feature-circuit`` /
  ``induction-circuit`` / ``attention-circuit`` / ``mlp-circuit`` /
  ``residual-circuit`` / ``copy-circuit``). Component membership and
  the causal hypothesis travel as ``sha256:`` digest pins only -- raw
  weights, activations, and hypotheses never enter records. Discovery
  ids are minted (``ckt-N``); the first discovery registers the model.
* **verify()** books one declared verification attempt against a
  booked circuit over a pinned method vocabulary (``ablation`` /
  ``patching`` / ``intervention`` / ``correlational`` /
  ``counterfactual``), with a verdict (``verified`` /
  ``partially-verified`` / ``refuted`` / ``inconclusive``) booked *as
  data*, never proof the circuit really computes what the host claims.
  Verification ids are minted (``vfy-N``); unknown circuits are
  refused fail-closed.
* **ablate()** books one declared ablation experiment against a booked
  circuit over a pinned ablation vocabulary (``zero`` / ``mean`` /
  ``resample`` / ``noise`` / ``path-patch``), with the declared effect
  (``degraded`` / ``unchanged`` / ``improved`` / ``crashed``) booked as
  data. Repeatable as a chain: several ablations may be booked for one
  circuit. Ablation ids are minted (``abl-N``).
* **report()** is a *pure read* view: a digest-pinned ``CircuitReport``
  deriving the in-scope posture by ledger rule -- ``undiscovered`` (no
  circuits) -> ``verified`` (any ``verified`` verdict) -> ``refuted``
  (any ``refuted``, none verified) -> ``partially-verified`` ->
  ``inconclusive`` -> ``unverified`` (circuits exist, none verified).
  Posture is ledger truth, never proof of real mechanistic
  understanding.

House style throughout: frozen dataclasses, caller-supplied
strictly-increasing int seqs with claim-then-burn (failed mutations
consume their seq and book ``circuit.rejected``; bare rewinds raise
without consuming), no wall-clock, RLock guarding, fail-closed
taxonomy, stdlib-only with the ``canonical_json`` try/except fallback,
``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: the module books *declared* discoveries, *declared*
verifications, and *declared* ablations; it runs no model, removes no
weights, and proves nothing about what a circuit really does. Raw
mechanistic material (weights, activations, graphs, hypotheses) never
enters records and never crosses the audit boundary (digest pins
only).
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

try:  # Prefer the in-repo canonicalizer when installed.
    from canonical_json import jcs_sha256_hex  # noqa: F401
except Exception:  # pragma: no cover - fallback path
    import hashlib
    import json

    def jcs_sha256_hex(obj) -> str:
        raw = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()


#: Module version.
CIRCUIT_VERSION = "circuit.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.circuit.v1"

#: Pinned circuit-kind vocabulary (declared circuit discoveries).
CIRCUIT_KINDS = (
    "feature-circuit",
    "induction-circuit",
    "attention-circuit",
    "mlp-circuit",
    "residual-circuit",
    "copy-circuit",
)

#: Pinned verification-method vocabulary.
VERIFY_METHODS = (
    "ablation",
    "patching",
    "intervention",
    "correlational",
    "counterfactual",
)

#: Pinned verification-verdict vocabulary (booked as data).
VERDICTS = (
    "verified",
    "partially-verified",
    "refuted",
    "inconclusive",
)

#: Pinned ablation-experiment vocabulary.
ABLATION_KINDS = (
    "zero",
    "mean",
    "resample",
    "noise",
    "path-patch",
)

#: Pinned ablation-effect vocabulary (booked as data).
EFFECTS = (
    "degraded",
    "unchanged",
    "improved",
    "crashed",
)

#: Pinned posture vocabulary for report().
POSTURES = (
    "undiscovered",
    "verified",
    "refuted",
    "partially-verified",
    "inconclusive",
    "unverified",
)

#: Raw mechanistic keys banned from the audit boundary.
_BANNED_AUDIT_KEYS = frozenset({
    "weights", "activations", "prompt", "transcript", "response",
    "trace", "graph", "edges", "neurons", "features", "hypothesis",
    "evidence", "payload", "raw", "secret", "scenario", "mechanism",
    "components",
})


# ---------------------------------------------------------------------------
# Error taxonomy
# ---------------------------------------------------------------------------

class CircuitError(Exception):
    """Base error for circuit misuse."""


class SeqOrderError(CircuitError):
    """Raised when a caller seq does not strictly increase."""


class BadIdError(CircuitError):
    """Raised on a malformed model, circuit, verification, or ablation id."""


class UnknownModelError(CircuitError):
    """Raised when a model id has no booked rows (pure-read lookups)."""


class UnknownRecordError(CircuitError):
    """Raised when a circuit/verification/ablation id is unknown."""


class BadKindError(CircuitError):
    """Raised on a circuit kind outside the pinned vocabulary."""


class BadMethodError(CircuitError):
    """Raised on a verification method outside the pinned vocabulary."""


class BadVerdictError(CircuitError):
    """Raised on a verification verdict outside the pinned vocabulary."""


class BadAblationError(CircuitError):
    """Raised on an ablation kind outside the pinned vocabulary."""


class BadEffectError(CircuitError):
    """Raised on an ablation effect outside the pinned vocabulary."""


class BadDigestError(CircuitError):
    """Raised on a malformed sha256: digest pin."""


class AuditKindError(CircuitError):
    """Raised on an unknown audit kind or a banned audit key."""


# ---------------------------------------------------------------------------
# Digest helpers
# ---------------------------------------------------------------------------

def _record_digest(body: dict) -> str:
    # The in-repo jcs_sha256_hex returns bare hex; pin it explicitly.
    return "sha256:" + jcs_sha256_hex(body)


def _check_digest(value: str) -> str:
    if not isinstance(value, str):
        raise BadDigestError("digest must be a str")
    if value and not (value.startswith("sha256:") and len(value) == 71):
        raise BadDigestError("digest must be a sha256: pin or ''")
    return value


def _check_id(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise BadIdError("id must be a non-empty str")
    if len(value) > 128:
        raise BadIdError("id too long")
    return value


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DiscoveryRecord:
    """One declared circuit discovery for a model."""

    discovery_id: str
    model_id: str
    circuit_kind: str
    component_digest: str
    hypothesis_digest: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _record_digest(self.as_dict(include_digest=False))

    def as_dict(self, include_digest: bool = True) -> dict:
        d = {
            "schema": SCHEMA_PIN,
            "discovery_id": self.discovery_id,
            "model_id": self.model_id,
            "circuit_kind": self.circuit_kind,
            "component_digest": self.component_digest,
            "hypothesis_digest": self.hypothesis_digest,
            "seq": self.seq,
        }
        if include_digest:
            d["digest"] = self.digest
        return d


@dataclass(frozen=True)
class VerificationRecord:
    """One declared verification attempt against a booked circuit."""

    verification_id: str
    circuit_id: str
    method: str
    verdict: str
    evidence_digest: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _record_digest(self.as_dict(include_digest=False))

    def as_dict(self, include_digest: bool = True) -> dict:
        d = {
            "schema": SCHEMA_PIN,
            "verification_id": self.verification_id,
            "circuit_id": self.circuit_id,
            "method": self.method,
            "verdict": self.verdict,
            "evidence_digest": self.evidence_digest,
            "seq": self.seq,
        }
        if include_digest:
            d["digest"] = self.digest
        return d


@dataclass(frozen=True)
class AblationRecord:
    """One declared ablation experiment against a booked circuit."""

    ablation_id: str
    circuit_id: str
    ablation_kind: str
    effect: str
    ablation_digest: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _record_digest(self.as_dict(include_digest=False))

    def as_dict(self, include_digest: bool = True) -> dict:
        d = {
            "schema": SCHEMA_PIN,
            "ablation_id": self.ablation_id,
            "circuit_id": self.circuit_id,
            "ablation_kind": self.ablation_kind,
            "effect": self.effect,
            "ablation_digest": self.ablation_digest,
            "seq": self.seq,
        }
        if include_digest:
            d["digest"] = self.digest
        return d


@dataclass(frozen=True)
class CircuitReport:
    """Derived circuit posture report (pure read)."""

    seq: int
    model_id: str
    n_models: int
    n_discoveries: int
    n_verifications: int
    n_ablations: int
    verdict_tallies: tuple
    posture: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _record_digest(self.as_dict(include_digest=False))

    def as_dict(self, include_digest: bool = True) -> dict:
        d = {
            "schema": SCHEMA_PIN,
            "seq": self.seq,
            "model_id": self.model_id,
            "n_models": self.n_models,
            "n_discoveries": self.n_discoveries,
            "n_verifications": self.n_verifications,
            "n_ablations": self.n_ablations,
            "verdict_tallies": [list(p) for p in self.verdict_tallies],
            "posture": self.posture,
        }
        if include_digest:
            d["digest"] = self.digest
        return d


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

_AUDIT_KINDS = (
    "discovered",
    "verified",
    "ablated",
    "circuit.rejected",
)


def circuit_audit_event(kind: str, details: dict) -> dict:
    """Build one ``audit.ndjson/1`` event. Raw mechanistic keys are banned."""
    if kind not in _AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if not isinstance(details, dict):
        raise AuditKindError("details must be a dict")
    for key in details:
        if key in _BANNED_AUDIT_KEYS:
            raise AuditKindError(f"raw circuit key banned from audit: {key!r}")
    return {"kind": "circuit." + kind if "." not in kind else kind,
            "details": dict(details)}


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------

class Circuit:
    """Circuit decision ledger: discover -> verify -> ablate -> report."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._discoveries: dict[str, DiscoveryRecord] = {}
        self._discovery_ids: list[str] = []
        self._verifications: dict[str, VerificationRecord] = {}
        self._verification_ids: list[str] = []
        self._ablations: dict[str, AblationRecord] = {}
        self._ablation_ids: list[str] = []
        self._audit: list[dict] = []
        self._n_rejected = 0

    # -- seq ------------------------------------------------------------
    def _claim(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
        if seq <= self._seq:
            raise SeqOrderError("seq must strictly increase")
        self._seq = seq

    def _emit(self, audit_kind: str, details: dict) -> None:
        self._audit.append(circuit_audit_event(audit_kind, details))

    def _reject(self, seq: int, reason: str) -> None:
        self._n_rejected += 1
        self._emit("circuit.rejected", {"seq": seq, "reason": reason})

    @staticmethod
    def stdlib_only() -> bool:
        """AST self-check: only stdlib imports (+ the in-repo sibling)."""
        import ast as _ast
        import pathlib as _pathlib
        allowed = {"__future__", "threading", "dataclasses", "hashlib",
                   "json", "typing", "canonical_json", "ast", "pathlib"}
        tree = _ast.parse(_pathlib.Path(__file__).read_text())
        for node in _ast.walk(tree):
            if isinstance(node, _ast.Import):
                for a in node.names:
                    if a.name.split(".")[0] not in allowed:
                        return False
            elif isinstance(node, _ast.ImportFrom) and node.module:
                if node.module.split(".")[0] not in allowed:
                    return False
        return True

    # -- mutations ------------------------------------------------------
    def discover(self, model_id: str, seq: int,
                 circuit_kind: str = "feature-circuit",
                 component_digest: str = "",
                 hypothesis_digest: str = "") -> DiscoveryRecord:
        """Book one declared circuit discovery (minted ckt-N).

        Component membership and the causal hypothesis travel as
        ``sha256:`` pins only; the first discovery registers the model.
        """
        with self._lock:
            self._claim(seq)
            try:
                _check_id(model_id)
                if circuit_kind not in CIRCUIT_KINDS:
                    raise BadKindError(f"bad circuit kind: {circuit_kind!r}")
                _check_digest(component_digest)
                _check_digest(hypothesis_digest)
                discovery_id = f"ckt-{len(self._discovery_ids) + 1}"
                body = {
                    "schema": SCHEMA_PIN,
                    "discovery_id": discovery_id,
                    "model_id": model_id,
                    "circuit_kind": circuit_kind,
                    "component_digest": component_digest,
                    "hypothesis_digest": hypothesis_digest,
                    "seq": seq,
                }
                rec = DiscoveryRecord(
                    discovery_id=discovery_id,
                    model_id=model_id,
                    circuit_kind=circuit_kind,
                    component_digest=component_digest,
                    hypothesis_digest=hypothesis_digest,
                    seq=seq,
                    digest=_record_digest(body),
                )
                self._discoveries[discovery_id] = rec
                self._discovery_ids.append(discovery_id)
                self._emit("discovered", {
                    "discovery_id": discovery_id,
                    "model_id": model_id,
                    "circuit_kind": circuit_kind,
                    "seq": seq,
                })
                return rec
            except CircuitError as exc:
                self._reject(seq, type(exc).__name__)
                raise

    def verify(self, circuit_id: str, seq: int,
               method: str = "ablation",
               verdict: str = "verified",
               evidence_digest: str = "") -> VerificationRecord:
        """Book one declared verification attempt (minted vfy-N).

        The verdict is booked *as data*: a ``verified`` means the host
        declared the circuit causally confirmed, never that it really
        is. Fail-closed on unknown circuits.
        """
        with self._lock:
            self._claim(seq)
            try:
                _check_id(circuit_id)
                if method not in VERIFY_METHODS:
                    raise BadMethodError(f"bad method: {method!r}")
                if verdict not in VERDICTS:
                    raise BadVerdictError(f"bad verdict: {verdict!r}")
                _check_digest(evidence_digest)
                if circuit_id not in self._discoveries:
                    raise UnknownRecordError(f"unknown circuit: {circuit_id!r}")
                verification_id = f"vfy-{len(self._verification_ids) + 1}"
                body = {
                    "schema": SCHEMA_PIN,
                    "verification_id": verification_id,
                    "circuit_id": circuit_id,
                    "method": method,
                    "verdict": verdict,
                    "evidence_digest": evidence_digest,
                    "seq": seq,
                }
                rec = VerificationRecord(
                    verification_id=verification_id,
                    circuit_id=circuit_id,
                    method=method,
                    verdict=verdict,
                    evidence_digest=evidence_digest,
                    seq=seq,
                    digest=_record_digest(body),
                )
                self._verifications[verification_id] = rec
                self._verification_ids.append(verification_id)
                self._emit("verified", {
                    "verification_id": verification_id,
                    "circuit_id": circuit_id,
                    "method": method,
                    "verdict": verdict,
                    "seq": seq,
                })
                return rec
            except CircuitError as exc:
                self._reject(seq, type(exc).__name__)
                raise

    def ablate(self, circuit_id: str, seq: int,
               ablation_kind: str = "zero",
               effect: str = "degraded",
               ablation_digest: str = "") -> AblationRecord:
        """Book one declared ablation experiment (minted abl-N).

        Books the *declaration*, never the experiment. Repeatable as a
        chain: several ablations may be booked for one circuit.
        """
        with self._lock:
            self._claim(seq)
            try:
                _check_id(circuit_id)
                if ablation_kind not in ABLATION_KINDS:
                    raise BadAblationError(f"bad ablation kind: {ablation_kind!r}")
                if effect not in EFFECTS:
                    raise BadEffectError(f"bad effect: {effect!r}")
                _check_digest(ablation_digest)
                if circuit_id not in self._discoveries:
                    raise UnknownRecordError(f"unknown circuit: {circuit_id!r}")
                ablation_id = f"abl-{len(self._ablation_ids) + 1}"
                body = {
                    "schema": SCHEMA_PIN,
                    "ablation_id": ablation_id,
                    "circuit_id": circuit_id,
                    "ablation_kind": ablation_kind,
                    "effect": effect,
                    "ablation_digest": ablation_digest,
                    "seq": seq,
                }
                rec = AblationRecord(
                    ablation_id=ablation_id,
                    circuit_id=circuit_id,
                    ablation_kind=ablation_kind,
                    effect=effect,
                    ablation_digest=ablation_digest,
                    seq=seq,
                    digest=_record_digest(body),
                )
                self._ablations[ablation_id] = rec
                self._ablation_ids.append(ablation_id)
                self._emit("ablated", {
                    "ablation_id": ablation_id,
                    "circuit_id": circuit_id,
                    "ablation_kind": ablation_kind,
                    "effect": effect,
                    "seq": seq,
                })
                return rec
            except CircuitError as exc:
                self._reject(seq, type(exc).__name__)
                raise

    # -- pure-read views --------------------------------------------------
    def _view_seq(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
            raise SeqOrderError("seq must be a positive int")

    def _known_models(self) -> set[str]:
        models = {r.model_id for r in self._discoveries.values()}
        circuit_by_id = {cid: r.model_id for cid, r in self._discoveries.items()}
        for r in self._verifications.values():
            models.add(circuit_by_id[r.circuit_id])
        for r in self._ablations.values():
            models.add(circuit_by_id[r.circuit_id])
        return models

    def discovery_record(self, discovery_id: str, seq: int) -> DiscoveryRecord:
        with self._lock:
            self._view_seq(seq)
            try:
                return self._discoveries[discovery_id]
            except KeyError:
                raise UnknownRecordError(f"unknown discovery: {discovery_id!r}")

    def verification_record(self, verification_id: str, seq: int) -> VerificationRecord:
        with self._lock:
            self._view_seq(seq)
            try:
                return self._verifications[verification_id]
            except KeyError:
                raise UnknownRecordError(f"unknown verification: {verification_id!r}")

    def ablation_record(self, ablation_id: str, seq: int) -> AblationRecord:
        with self._lock:
            self._view_seq(seq)
            try:
                return self._ablations[ablation_id]
            except KeyError:
                raise UnknownRecordError(f"unknown ablation: {ablation_id!r}")

    def discoveries_for(self, model_id: str, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(d for d in self._discovery_ids
                         if self._discoveries[d].model_id == model_id)

    def verifications_for(self, circuit_id: str, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(v for v in self._verification_ids
                         if self._verifications[v].circuit_id == circuit_id)

    def ablations_for(self, circuit_id: str, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(a for a in self._ablation_ids
                         if self._ablations[a].circuit_id == circuit_id)

    def circuit_ids(self, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(self._discovery_ids)

    def model_ids(self, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(sorted(self._known_models()))

    def report(self, seq: int, model_id: str = "") -> CircuitReport:
        """Derive a circuit posture report (pure read).

        ``model_id`` scopes to one model with booked rows; ``""``
        aggregates the whole ledger. Posture is ledger truth, never
        proof of real mechanistic understanding:

        - ``undiscovered``: no circuits in scope
        - ``verified``: any verification verdict ``verified``
        - ``refuted``: any verdict ``refuted``, none ``verified``
        - ``partially-verified``: any ``partially-verified``, none of
          the above
        - ``inconclusive``: any ``inconclusive``, none of the above
        - ``unverified``: circuits exist, no verifications in scope
        """
        with self._lock:
            self._view_seq(seq)
            if model_id:
                _check_id(model_id)
                if model_id not in self._known_models():
                    raise UnknownModelError(f"unknown model: {model_id!r}")
                dids = self.discoveries_for(model_id, seq)
                vids = tuple(v for v in self._verification_ids
                             if self._verifications[v].circuit_id in dids)
                aids = tuple(a for a in self._ablation_ids
                             if self._ablations[a].circuit_id in dids)
                n_models = 1
            else:
                dids = tuple(self._discovery_ids)
                vids = tuple(self._verification_ids)
                aids = tuple(self._ablation_ids)
                n_models = len(self._known_models())
            tallies: dict[str, int] = {}
            for vid in vids:
                v = self._verifications[vid].verdict
                tallies[v] = tallies.get(v, 0) + 1
            if not dids:
                posture = "undiscovered"
            elif tallies.get("verified", 0) > 0:
                posture = "verified"
            elif tallies.get("refuted", 0) > 0:
                posture = "refuted"
            elif tallies.get("partially-verified", 0) > 0:
                posture = "partially-verified"
            elif tallies.get("inconclusive", 0) > 0:
                posture = "inconclusive"
            else:
                posture = "unverified"
            verdict_tallies = tuple(sorted(tallies.items()))
            body = {
                "schema": SCHEMA_PIN,
                "seq": seq,
                "model_id": model_id,
                "n_models": n_models,
                "n_discoveries": len(dids),
                "n_verifications": len(vids),
                "n_ablations": len(aids),
                "verdict_tallies": [list(p) for p in verdict_tallies],
                "posture": posture,
            }
            return CircuitReport(
                seq=seq,
                model_id=model_id,
                n_models=n_models,
                n_discoveries=len(dids),
                n_verifications=len(vids),
                n_ablations=len(aids),
                verdict_tallies=verdict_tallies,
                posture=posture,
                digest=_record_digest(body),
            )

    def stats(self, seq: int) -> dict:
        with self._lock:
            self._view_seq(seq)
            return {
                "models": len(self._known_models()),
                "discoveries": len(self._discoveries),
                "verifications": len(self._verifications),
                "ablations": len(self._ablations),
                "rejected": self._n_rejected,
                "audit_rows": len(self._audit),
                "seq": self._seq,
            }

    def audit_log(self, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(self._audit)


def main() -> None:
    c = Circuit()
    d = c.discover("m1", 1, circuit_kind="induction-circuit",
                   component_digest="sha256:" + "a" * 64)
    assert d.verify() and d.discovery_id == "ckt-1"
    v = c.verify(d.discovery_id, 2, method="patching", verdict="verified")
    assert v.verify() and v.verification_id == "vfy-1"
    a = c.ablate(d.discovery_id, 3, ablation_kind="path-patch", effect="degraded")
    assert a.verify() and a.ablation_id == "abl-1"
    # ablation is chainable on the same circuit
    a2 = c.ablate(d.discovery_id, 4, ablation_kind="zero", effect="degraded")
    assert a2.verify() and a2.ablation_id == "abl-2"
    rep = c.report(5, "m1")
    assert rep.verify() and rep.posture == "verified"
    assert rep.n_discoveries == 1 and rep.n_verifications == 1
    assert rep.n_ablations == 2
    assert Circuit.stdlib_only()
    print("circuit OK: discover, verify, ablate, report, pins, audit")


if __name__ == "__main__":
    main()

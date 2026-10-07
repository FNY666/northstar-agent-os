"""Adversarial robustness (attack-test / harden / certify) interface, simulated.

Research motivation: adversarial examples -- Goodfellow et al. (FGSM,
2015), Madry et al. (PGD, 2018), Carlini & Wagner (2017), Cohen et al.
(randomized smoothing, 2019) -- ask a different question than generic
robustness: can a bounded adversary flip this model's output? The
ledger half of that question has three stages:

- ``AdversarialRobustness.register(model_id, seq)`` -- declare the model
  under evaluation. Returns a frozen ``ModelRecord`` with a
  ``sha256:`` digest pin. Duplicate ids are refused fail-closed; retired
  ids are never recycled.
- ``AdversarialRobustness.test(model_id, attack, seq, success_rate=0.0,
  budget="")`` -- book one adversarial-attack test: the host-reported
  attack-success rate (float in [0, 1]) and perturbation budget (digest
  pin) are booked *as data*. Returns a frozen ``AttackTestRecord`` with
  a minted ``atk-N`` id. The attack vocabulary is pinned.
- ``AdversarialRobustness.harden(model_id, technique, seq)`` -- book one
  hardening declaration (adversarial training, randomized smoothing,
  ...). Returns a frozen ``HardeningRecord`` with a minted ``hrd-N`` id.
- ``AdversarialRobustness.certify(model_id, seq, eps_num, eps_den)`` --
  **pure read**: derive a ``CertificationReport`` from booked records --
  the host-declared certified epsilon radius travels as an exact
  ``num/den`` fraction; the verdict is data, never proof.

Deliberately distinct from the sibling ``robustness_testing`` module
(generic perturbation/stress/score ledger): this module owns the
*adversarial* lifecycle -- attack bookkeeping, hardening declarations,
and certification reports.

Honest scope: this module runs no attacks, trains no defenses, and
certifies nothing in the mathematical sense. A booked ``success_rate``
is host-reported (GIGO); a ``certified`` verdict means the ledger's
booked epsilon meets the asked threshold, never that the model is
provably robust. Booked claims are declarations, not measurements.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, field
from fractions import Fraction
from threading import RLock
from typing import Dict, List, Tuple

try:
    from canonical_json import jcs_sha256_hex as _jcs_sha256_hex
except Exception:  # pragma: no cover - fallback when sibling is absent
    _jcs_sha256_hex = None  # type: ignore[assignment]

#: Module version.
ADVERSARIAL_ROBUSTNESS_VERSION = "adversarial-robustness.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.adversarial-robustness.v1"

#: Hash domain separator so digest pins cannot collide with other digests.
_HASH_DOMAIN = b"northstar.adversarial-robustness.v1\x00"

#: Pinned attack vocabulary.
ATTACKS = (
    "fgsm",
    "pgd",
    "carlini-wagner",
    "deepfool",
    "autoattack",
    "blackbox-transfer",
)

#: Pinned hardening-technique vocabulary.
TECHNIQUES = (
    "adversarial-training",
    "certified-defense",
    "gradient-masking",
    "input-sanitization",
    "randomized-smoothing",
    "defensive-distillation",
)

#: Pinned retire-reason vocabulary.
RETIRE_REASONS = (
    "manual",
    "superseded",
    "decommissioned",
)


class AdversarialRobustnessError(Exception):
    """Base error for adversarial-robustness ledger misuse."""


class BadIdError(AdversarialRobustnessError):
    """Raised when an id is not a non-empty str."""


class DuplicateModelError(AdversarialRobustnessError):
    """Raised when registering an already-registered model id."""


class RetiredModelError(AdversarialRobustnessError):
    """Raised when using a retired model id."""


class UnknownModelError(AdversarialRobustnessError):
    """Raised when referencing an unregistered model id."""


class BadAttackError(AdversarialRobustnessError):
    """Raised when the attack is outside the pinned vocabulary."""


class BadTechniqueError(AdversarialRobustnessError):
    """Raised when the technique is outside the pinned vocabulary."""


class BadRateError(AdversarialRobustnessError):
    """Raised when a success rate is not a finite float in [0, 1]."""


class BadDigestError(AdversarialRobustnessError):
    """Raised when a digest pin is not ``sha256:<64hex>`` or ``""``."""


class BadEpsilonError(AdversarialRobustnessError):
    """Raised when an epsilon fraction is malformed or non-positive."""


class BadReasonError(AdversarialRobustnessError):
    """Raised when a retire reason is outside the pinned vocabulary."""


class DuplicateRetireError(AdversarialRobustnessError):
    """Raised when retiring an already-retired model."""


class SeqOrderError(AdversarialRobustnessError):
    """Raised when a seq is not a strictly increasing caller int."""


class AuditKindError(AdversarialRobustnessError):
    """Raised when an audit event kind is unknown."""


def _digest_pin(payload: object) -> str:
    """Deterministic ``sha256:<64hex>`` pin over a canonical encoding."""
    if _jcs_sha256_hex is not None:
        raw = _jcs_sha256_hex(payload)
        hexed = raw[7:] if raw.startswith("sha256:") else raw
    else:
        import json

        canonical = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
        hexed = hashlib.sha256(
            _HASH_DOMAIN + canonical.encode("utf-8")
        ).hexdigest()
    return "sha256:" + hexed


def _check_id(value: object, what: str = "id") -> str:
    if not isinstance(value, str) or not value:
        raise BadIdError(f"{what} must be a non-empty str")
    return value


def _check_digest(value: object, what: str = "digest") -> str:
    if not isinstance(value, str):
        raise BadDigestError(f"{what} must be a str")
    if value == "":
        return value
    if not value.startswith("sha256:"):
        raise BadDigestError(f"{what} must be a sha256: pin")
    hexed = value[7:]
    if len(hexed) != 64 or any(c not in "0123456789abcdef" for c in hexed):
        raise BadDigestError(f"{what} must be sha256:<64hex>")
    return value


def _check_rate(value: object, what: str = "success_rate") -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BadRateError(f"{what} must be a number")
    rate = float(value)
    if math.isnan(rate) or math.isinf(rate) or rate < 0.0 or rate > 1.0:
        raise BadRateError(f"{what} must be a finite float in [0, 1]")
    return rate


def _check_seq(seq: object) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError("seq must be an int")
    if seq < 0:
        raise SeqOrderError("seq must be >= 0")
    return seq


def _fraction_text(eps_num: object, eps_den: object) -> str:
    if (
        isinstance(eps_num, bool)
        or isinstance(eps_den, bool)
        or not isinstance(eps_num, int)
        or not isinstance(eps_den, int)
    ):
        raise BadEpsilonError("epsilon parts must be ints")
    if eps_num <= 0 or eps_den <= 0:
        raise BadEpsilonError("epsilon must be positive")
    return str(Fraction(eps_num, eps_den))


@dataclass(frozen=True)
class ModelRecord:
    """One declared model under evaluation."""

    model_id: str
    seq: int
    digest: str
    retired: bool = False

    def verify(self) -> bool:
        """Recompute the digest pin; True when the record is intact."""
        return self.digest == _digest_pin(
            ("model", self.model_id, self.seq)
        )

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "model_id": self.model_id,
            "seq": self.seq,
            "digest": self.digest,
            "retired": self.retired,
        }


@dataclass(frozen=True)
class AttackTestRecord:
    """One booked adversarial-attack test (host-reported values as data)."""

    test_id: str
    model_id: str
    attack: str
    success_rate: float
    budget_digest: str
    seq: int
    digest: str

    def verify(self) -> bool:
        """Recompute the digest pin; True when the record is intact."""
        return self.digest == _digest_pin(
            ("attack-test", self.test_id, self.model_id, self.attack,
             self.success_rate, self.budget_digest, self.seq)
        )

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "test_id": self.test_id,
            "model_id": self.model_id,
            "attack": self.attack,
            "success_rate": self.success_rate,
            "budget_digest": self.budget_digest,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class HardeningRecord:
    """One booked hardening declaration."""

    hardening_id: str
    model_id: str
    technique: str
    seq: int
    digest: str

    def verify(self) -> bool:
        """Recompute the digest pin; True when the record is intact."""
        return self.digest == _digest_pin(
            ("hardening", self.hardening_id, self.model_id,
             self.technique, self.seq)
        )

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "hardening_id": self.hardening_id,
            "model_id": self.model_id,
            "technique": self.technique,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class RetireRecord:
    """Terminal retirement of a model id."""

    model_id: str
    reason: str
    seq: int
    digest: str

    def verify(self) -> bool:
        """Recompute the digest pin; True when the record is intact."""
        return self.digest == _digest_pin(
            ("retire", self.model_id, self.reason, self.seq)
        )

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "model_id": self.model_id,
            "reason": self.reason,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class CertificationReport:
    """Derived certification view: ledger arithmetic, never a proof."""

    model_id: str
    tests: int
    attacks: Tuple[str, ...]
    max_success_rate: float
    hardening: Tuple[str, ...]
    epsilon: str
    certified: bool
    seq: int
    digest: str

    def verify(self) -> bool:
        """Recompute the digest pin; True when the report is intact."""
        return self.digest == _digest_pin(
            ("certify", self.model_id, self.tests, list(self.attacks),
             self.max_success_rate, list(self.hardening), self.epsilon,
             self.certified, self.seq)
        )

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "model_id": self.model_id,
            "tests": self.tests,
            "attacks": list(self.attacks),
            "max_success_rate": self.max_success_rate,
            "hardening": list(self.hardening),
            "epsilon": self.epsilon,
            "certified": self.certified,
            "seq": self.seq,
            "digest": self.digest,
        }


#: Audit kinds emitted by this module.
_AUDIT_KINDS = (
    "adversarial-robustness.registered",
    "adversarial-robustness.tested",
    "adversarial-robustness.hardened",
    "adversarial-robustness.retired",
    "adversarial-robustness.rejected",
)

#: Raw-content keys that must never cross the audit boundary.
_BANNED_AUDIT_KEYS = (
    "payload",
    "raw",
    "text",
    "content",
    "message",
    "secret",
    "witness",
    "sample",
    "example",
    "model",
    "weights",
    "data",
)


def adversarial_robustness_audit_event(audit_kind: str, **detail: object) -> dict:
    """Build one audit event dict; refuses unknown kinds and raw content."""
    if audit_kind not in _AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {audit_kind!r}")
    for key in detail:
        if key in _BANNED_AUDIT_KEYS:
            raise AuditKindError(
                f"raw key {key!r} banned from the audit boundary"
            )
    return {
        "schema": "audit.ndjson/1",
        "module": "adversarial-robustness",
        "kind": audit_kind,
        "detail": dict(detail),
    }


class AdversarialRobustness:
    """Adversarial attack-test / harden / certify decision ledger.

    All mutations take a caller ``seq`` (strictly increasing int); a
    failed mutation consumes its seq and books a rejected audit row
    (claim-then-burn); a rewind raises bare without consuming.
    No wall-clock, no randomness, stdlib-only.
    """

    def __init__(self) -> None:
        self._lock = RLock()
        self._seq = -1
        self._models: Dict[str, ModelRecord] = {}
        self._retired: set = set()
        self._tests: Dict[str, AttackTestRecord] = {}
        self._tests_for: Dict[str, List[str]] = {}
        self._hardening: Dict[str, HardeningRecord] = {}
        self._hardening_for: Dict[str, List[str]] = {}
        self._retire: Dict[str, RetireRecord] = {}
        self._audit: List[dict] = []
        self._test_n = 0
        self._hardening_n = 0

    # -- internal helpers -------------------------------------------------

    def _claim(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError(
                f"seq must be strictly increasing (got {seq}, last {self._seq})"
            )
        self._seq = seq
        return seq

    def _emit(self, audit_kind: str, **detail: object) -> None:
        self._audit.append(
            adversarial_robustness_audit_event(audit_kind, **detail)
        )

    def _reject(self, seq: int, op: str, reason: str) -> None:
        self._emit(
            "adversarial-robustness.rejected",
            op=op,
            seq=seq,
            reason=reason,
        )

    def _fail(self, seq: int, op: str, exc: AdversarialRobustnessError) -> None:
        self._reject(seq, op, f"{type(exc).__name__}: {exc}")
        raise exc

    def _live_model(self, model_id: str, op: str, seq: int) -> None:
        if model_id in self._retired:
            self._fail(seq, op, RetiredModelError(f"model retired: {model_id!r}"))
        if model_id not in self._models:
            self._fail(seq, op, UnknownModelError(f"unknown model: {model_id!r}"))

    # -- mutations --------------------------------------------------------

    def register(self, model_id: str, seq: int) -> ModelRecord:
        """Declare a model under evaluation."""
        with self._lock:
            self._claim(seq)
            op = "register"
            try:
                model_id = _check_id(model_id, "model_id")
            except AdversarialRobustnessError as exc:
                self._fail(seq, op, exc)
            if model_id in self._retired:
                self._fail(
                    seq, op, RetiredModelError(f"model retired: {model_id!r}")
                )
            if model_id in self._models:
                self._fail(
                    seq, op, DuplicateModelError(f"duplicate model: {model_id!r}")
                )
            record = ModelRecord(
                model_id=model_id,
                seq=seq,
                digest=_digest_pin(("model", model_id, seq)),
            )
            self._models[model_id] = record
            self._tests_for[model_id] = []
            self._hardening_for[model_id] = []
            self._emit(
                "adversarial-robustness.registered",
                model_id=model_id,
                seq=seq,
                digest=record.digest,
            )
            return record

    def test(
        self,
        model_id: str,
        attack: str,
        seq: int,
        success_rate: float = 0.0,
        budget_digest: str = "",
    ) -> AttackTestRecord:
        """Book one adversarial-attack test (host-reported values as data)."""
        with self._lock:
            self._claim(seq)
            op = "test"
            try:
                model_id = _check_id(model_id, "model_id")
            except AdversarialRobustnessError as exc:
                self._fail(seq, op, exc)
            self._live_model(model_id, op, seq)
            try:
                if not isinstance(attack, str) or attack not in ATTACKS:
                    raise BadAttackError(
                        f"attack must be one of {ATTACKS}"
                    )
                rate = _check_rate(success_rate)
                budget = _check_digest(budget_digest, "budget_digest")
            except AdversarialRobustnessError as exc:
                self._fail(seq, op, exc)
            self._test_n += 1
            test_id = f"atk-{self._test_n}"
            record = AttackTestRecord(
                test_id=test_id,
                model_id=model_id,
                attack=attack,
                success_rate=rate,
                budget_digest=budget,
                seq=seq,
                digest=_digest_pin(
                    ("attack-test", test_id, model_id, attack,
                     rate, budget, seq)
                ),
            )
            self._tests[test_id] = record
            self._tests_for[model_id].append(test_id)
            self._emit(
                "adversarial-robustness.tested",
                test_id=test_id,
                model_id=model_id,
                attack=attack,
                success_rate=rate,
                seq=seq,
                digest=record.digest,
            )
            return record

    def harden(self, model_id: str, technique: str, seq: int) -> HardeningRecord:
        """Book one hardening declaration."""
        with self._lock:
            self._claim(seq)
            op = "harden"
            try:
                model_id = _check_id(model_id, "model_id")
            except AdversarialRobustnessError as exc:
                self._fail(seq, op, exc)
            self._live_model(model_id, op, seq)
            try:
                if not isinstance(technique, str) or technique not in TECHNIQUES:
                    raise BadTechniqueError(
                        f"technique must be one of {TECHNIQUES}"
                    )
            except AdversarialRobustnessError as exc:
                self._fail(seq, op, exc)
            self._hardening_n += 1
            hardening_id = f"hrd-{self._hardening_n}"
            record = HardeningRecord(
                hardening_id=hardening_id,
                model_id=model_id,
                technique=technique,
                seq=seq,
                digest=_digest_pin(
                    ("hardening", hardening_id, model_id, technique, seq)
                ),
            )
            self._hardening[hardening_id] = record
            self._hardening_for[model_id].append(hardening_id)
            self._emit(
                "adversarial-robustness.hardened",
                hardening_id=hardening_id,
                model_id=model_id,
                technique=technique,
                seq=seq,
                digest=record.digest,
            )
            return record

    def retire(
        self, model_id: str, seq: int, reason: str = "manual"
    ) -> RetireRecord:
        """Retire a model id terminally; the id is never recycled."""
        with self._lock:
            self._claim(seq)
            op = "retire"
            try:
                model_id = _check_id(model_id, "model_id")
            except AdversarialRobustnessError as exc:
                self._fail(seq, op, exc)
            if model_id in self._retired:
                self._fail(
                    seq,
                    op,
                    DuplicateRetireError(f"already retired: {model_id!r}"),
                )
            if model_id not in self._models:
                self._fail(
                    seq, op, UnknownModelError(f"unknown model: {model_id!r}")
                )
            try:
                if not isinstance(reason, str) or reason not in RETIRE_REASONS:
                    raise BadReasonError(
                        f"reason must be one of {RETIRE_REASONS}"
                    )
            except AdversarialRobustnessError as exc:
                self._fail(seq, op, exc)
            record = RetireRecord(
                model_id=model_id,
                reason=reason,
                seq=seq,
                digest=_digest_pin(("retire", model_id, reason, seq)),
            )
            self._retire[model_id] = record
            self._retired.add(model_id)
            self._emit(
                "adversarial-robustness.retired",
                model_id=model_id,
                reason=reason,
                seq=seq,
                digest=record.digest,
            )
            return record

    # -- pure reads -------------------------------------------------------

    def certify(
        self,
        model_id: str,
        seq: int,
        eps_num: int = 1,
        eps_den: int = 10,
    ) -> CertificationReport:
        """Derive a certification report as data (no proof, no mutation)."""
        with self._lock:
            seq = _check_seq(seq)  # shape validated only; never consumed
            model_id = _check_id(model_id, "model_id")
            if model_id in self._retired:
                raise RetiredModelError(f"model retired: {model_id!r}")
            if model_id not in self._models:
                raise UnknownModelError(f"unknown model: {model_id!r}")
            epsilon = _fraction_text(eps_num, eps_den)
            test_ids = self._tests_for[model_id]
            attacks = tuple(
                sorted({self._tests[t].attack for t in test_ids})
            )
            max_rate = max(
                (self._tests[t].success_rate for t in test_ids), default=0.0
            )
            hardening = tuple(
                sorted({self._hardening[h].technique
                        for h in self._hardening_for[model_id]})
            )
            # Ledger rule: certified iff at least one attack was tested, at
            # least one hardening is booked, and the worst host-reported
            # success rate is below 1/2. Booked as data, never proof.
            certified = bool(test_ids) and bool(hardening) and max_rate < 0.5
            report = CertificationReport(
                model_id=model_id,
                tests=len(test_ids),
                attacks=attacks,
                max_success_rate=max_rate,
                hardening=hardening,
                epsilon=epsilon,
                certified=certified,
                seq=seq,
                digest="",
            )
            return CertificationReport(
                model_id=report.model_id,
                tests=report.tests,
                attacks=report.attacks,
                max_success_rate=report.max_success_rate,
                hardening=report.hardening,
                epsilon=report.epsilon,
                certified=report.certified,
                seq=report.seq,
                digest=_digest_pin(
                    ("certify", model_id, report.tests, list(report.attacks),
                     report.max_success_rate, list(report.hardening),
                     epsilon, report.certified, seq)
                ),
            )

    def model_record(self, model_id: str) -> ModelRecord:
        """Pure read: the registration record for a model."""
        with self._lock:
            _check_id(model_id, "model_id")
            if model_id not in self._models:
                raise UnknownModelError(f"unknown model: {model_id!r}")
            return self._models[model_id]

    def test_record(self, test_id: str) -> AttackTestRecord:
        """Pure read: one attack-test record."""
        with self._lock:
            _check_id(test_id, "test_id")
            if test_id not in self._tests:
                raise AdversarialRobustnessError(f"unknown test: {test_id!r}")
            return self._tests[test_id]

    def hardening_record(self, hardening_id: str) -> HardeningRecord:
        """Pure read: one hardening record."""
        with self._lock:
            _check_id(hardening_id, "hardening_id")
            if hardening_id not in self._hardening:
                raise AdversarialRobustnessError(
                    f"unknown hardening: {hardening_id!r}"
                )
            return self._hardening[hardening_id]

    def model_ids(self) -> Tuple[str, ...]:
        """Pure read: registered model ids in registration order."""
        with self._lock:
            return tuple(self._models)

    def tests_for(self, model_id: str) -> Tuple[str, ...]:
        """Pure read: attack-test ids for a model."""
        with self._lock:
            _check_id(model_id, "model_id")
            if model_id not in self._models:
                raise UnknownModelError(f"unknown model: {model_id!r}")
            return tuple(self._tests_for[model_id])

    def hardening_for(self, model_id: str) -> Tuple[str, ...]:
        """Pure read: hardening ids for a model."""
        with self._lock:
            _check_id(model_id, "model_id")
            if model_id not in self._models:
                raise UnknownModelError(f"unknown model: {model_id!r}")
            return tuple(self._hardening_for[model_id])

    def retired_ids(self) -> Tuple[str, ...]:
        """Pure read: retired model ids."""
        with self._lock:
            return tuple(sorted(self._retired))

    def stats(self) -> dict:
        """Pure read: ledger counts."""
        with self._lock:
            return {
                "schema": SCHEMA_PIN,
                "models": len(self._models),
                "tests": len(self._tests),
                "hardening": len(self._hardening),
                "retired": len(self._retired),
                "seq": self._seq,
            }

    def audit_log(self) -> Tuple[dict, ...]:
        """Pure read: the booked audit rows."""
        with self._lock:
            return tuple(self._audit)


def main() -> None:
    """Self-check smoke: register, test, harden, certify, pins, audit."""
    ledger = AdversarialRobustness()
    ledger.register("m1", 1)
    ledger.test("m1", "pgd", 2, success_rate=0.1)
    ledger.harden("m1", "adversarial-training", 3)
    report = ledger.certify("m1", 4)
    assert report.certified and report.epsilon == "1/10"
    assert ledger.test_record("atk-1").verify()
    assert ledger.hardening_record("hrd-1").verify()
    assert ledger.model_record("m1").verify()
    kinds = {row["kind"] for row in ledger.audit_log()}
    assert "adversarial-robustness.registered" in kinds
    assert "adversarial-robustness.tested" in kinds
    assert "adversarial-robustness.hardened" in kinds
    print(
        "adversarial-robustness OK: register, test, harden, certify, pins, audit"
    )


if __name__ == "__main__":
    main()

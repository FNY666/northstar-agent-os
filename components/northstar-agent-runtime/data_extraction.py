"""Data-extraction attack/defense decision ledger, Simulated.

Research datum: a model behind a black-box API can leak its training data
and behavior without ever exposing weights. The adversary issues crafted
queries -- membership-inference probes that ask whether a given record was
in the training set, canary traps injected to watch for verbatim regurgitation,
model-inversion optimization that reconstructs representative inputs from
confidence outputs, and training-data extraction that prompts the model
to complete memorized sequences (the "repeat this word forever" class of
attack). The defense side answers with controls: output perturbation that
flattens confidence signals, query throttling that caps the probing budget,
canary marking that watermarks the training set, deduplication that removes
memorization fuel, differential-privacy noise, and response filtering that
refuses suspicious completions.

This module books *declared* extraction tests and *declared* defenses -- a
decision ledger, not a live attack or a live defense. A booked
``extracted`` means "the host declared the test extracted data", never
"data was actually extracted"; a booked ``differential-privacy`` means
"the host declared the defense applied", never "the defense is live and
holds". The derived ``residual_risk`` is ledger truth (booked rows, in
booked order), never a real-world safety claim.

Lifecycle:

* **test()** - book one declared extraction test (minted ``tst-N``) over a
  pinned attack vocabulary; the first test for a target implicitly
  registers the target. Target/model details travel as ``sha256:`` digest
  pins only -- raw prompts, canaries, and extracted text never enter
  records.
* **defend()** - book one declared defense application (minted ``def-N``)
  over a pinned defense vocabulary; fail-closed on unknown targets.
* **evaluate()** - pure read: per-target ``EvaluationReport`` with test /
  defense tallies, ``residual_risk`` derived as data from the booked
  ledger, digest-pinned.

Distinct layer vs siblings: ``model_extraction_detector.py`` is a
shape-detector over host-reported query records (tripwire metrics);
``membership_inference.py`` owns membership-test mechanics;
``canary_controller.py`` owns canary lifecycle. This module owns the
*attack-then-defense governance decision ledger* -- which targets were
tested with which attack classes, which defenses were declared, and what
the residual risk reads as from the ledger.

House style: frozen dataclasses, caller-supplied strictly-increasing int
seqs (claim-then-burn: failed mutations consume their seq and book a
``data-extraction.rejected`` row; rewinds raise bare without consuming), no
wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with the
standard ``canonical_json`` try/except fallback, ``sha256:`` digest pins,
and ``audit.ndjson/1`` events.

Honest scope: this module runs no attack, applies no defense, observes
no model. GIGO throughout.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

try:
    from canonical_json import jcs_dumps as _jcs_dumps, jcs_sha256_hex as _jcs_hash  # type: ignore
except Exception:  # pragma: no cover - fallback when canonical_json is absent

    def _jcs_dumps(obj: Any) -> bytes:  # type: ignore
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _jcs_hash(obj: Any) -> str:  # type: ignore
        return "sha256:" + hashlib.sha256(_jcs_dumps(obj)).hexdigest()


#: Module version pin.
DATA_EXTRACTION_VERSION = "data-extraction.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.data-extraction.v1"

#: Pinned attack vocabulary (how the declared test tried to extract).
ATTACKS = (
    "canary-injection",
    "membership-inference",
    "model-inversion",
    "training-extraction",
    "paraphrase-probing",
    "prompt-extraction",
)

#: Pinned declared-outcome vocabulary for an extraction test.
TEST_OUTCOMES = (
    "extracted",
    "not-extracted",
    "inconclusive",
)

#: Pinned defense vocabulary (what the host declared applying).
DEFENSES = (
    "output-perturbation",
    "query-throttling",
    "canary-marking",
    "deduplication",
    "differential-privacy",
    "response-filtering",
)

#: Pinned residual-risk vocabulary derived by evaluate() -- ledger truth only.
RESIDUAL_RISK_LEVELS = (
    "unknown",
    "elevated",
    "contained",
)

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "tested",
    "defended",
    "rejected",
)

#: Keys that may never appear raw in an audit row.
_BANNED_AUDIT_KEYS = frozenset(
    {
        "target",
        "target_name",
        "training",
        "training_data",
        "data",
        "text",
        "content",
        "secret",
        "key",
        "canary",
        "canary_text",
        "extracted_text",
        "payload",
        "raw",
        "response",
        "output",
        "prompt",
        "description",
        "note",
        "notes",
    }
)

_ZERO_PIN = "sha256:" + "00" * 32


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class DataExtractionError(Exception):
    """Base error for data-extraction ledger misuse."""


class BadTargetError(DataExtractionError):
    """Malformed extraction-target id."""


class UnknownTargetError(DataExtractionError):
    """Target id not registered (no test booked for it yet)."""


class BadAttackError(DataExtractionError):
    """Unknown extraction attack class."""


class BadOutcomeError(DataExtractionError):
    """Unknown test-outcome value."""


class BadDefenseError(DataExtractionError):
    """Unknown defense class."""


class UnknownTestError(DataExtractionError):
    """Test id not booked."""


class UnknownDefenseError(DataExtractionError):
    """Defense id not booked."""


class BadDigestError(DataExtractionError):
    """Malformed sha256: digest pin."""


class SeqOrderError(DataExtractionError):
    """Seq is not a strictly increasing positive int."""


class AuditKindError(DataExtractionError):
    """Unknown audit kind, or banned raw key in audit details."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require_id(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise BadTargetError(f"{field_name} must be a non-empty str <= 128 chars")
    return value


def _require_digest(pin: str, field_name: str) -> str:
    if not isinstance(pin, str) or not pin.startswith("sha256:"):
        raise BadDigestError(f"{field_name} must be a 'sha256:' pin")
    hexpart = pin[7:]
    if len(hexpart) != 64 or any(c not in "0123456789abcdef" for c in hexpart):
        raise BadDigestError(f"{field_name} must be a 64-hex sha256 pin")
    return pin


def _digest_pin(payload: Dict[str, Any]) -> str:
    raw = _jcs_hash(payload)
    hexpart = raw[7:] if raw.startswith("sha256:") else raw
    return "sha256:" + hexpart


# ---------------------------------------------------------------------------
# Records (all frozen)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TestRecord:
    test_id: str
    target_id: str
    attack: str
    outcome: str
    evidence_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "test_id": self.test_id,
            "target_id": self.target_id,
            "attack": self.attack,
            "outcome": self.outcome,
            "evidence_digest": self.evidence_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "test_id": self.test_id,
                "target_id": self.target_id,
                "attack": self.attack,
                "outcome": self.outcome,
                "evidence_digest": self.evidence_digest,
            }
        )


@dataclass(frozen=True)
class DefenseRecord:
    defense_id: str
    target_id: str
    defense: str
    plan_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "defense_id": self.defense_id,
            "target_id": self.target_id,
            "defense": self.defense,
            "plan_digest": self.plan_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "defense_id": self.defense_id,
                "target_id": self.target_id,
                "defense": self.defense,
                "plan_digest": self.plan_digest,
            }
        )


@dataclass(frozen=True)
class EvaluationReport:
    target_id: str
    n_tests: int
    n_extracted: int
    n_defenses: int
    residual_risk: str
    integrity_ok: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "target_id": self.target_id,
            "n_tests": self.n_tests,
            "n_extracted": self.n_extracted,
            "n_defenses": self.n_defenses,
            "residual_risk": self.residual_risk,
            "integrity_ok": self.integrity_ok,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "target_id": self.target_id,
                "n_tests": self.n_tests,
                "n_extracted": self.n_extracted,
                "n_defenses": self.n_defenses,
                "residual_risk": self.residual_risk,
                "integrity_ok": self.integrity_ok,
            }
        )


# ---------------------------------------------------------------------------
# Audit event builder
# ---------------------------------------------------------------------------


def data_extraction_audit_event(
    audit_kind: str, seq: int, **details: Any
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the extraction ledger."""
    if audit_kind not in AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {audit_kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError("audit seq must be a non-negative int")
    for key in details:
        if key in _BANNED_AUDIT_KEYS:
            raise AuditKindError(f"banned raw key in audit detail: {key!r}")
    return {
        "schema": "audit.ndjson/1",
        "kind": audit_kind,
        "seq": seq,
        "details": dict(details),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class DataExtraction:
    """Data-extraction attack/defense decision ledger, Simulated.

    ``test()`` / ``defend()`` mutate the ledger and consume caller seqs;
    ``evaluate()`` and all views are pure reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._targets: Dict[str, List[str]] = {}
        self._tests: Dict[str, TestRecord] = {}
        self._tests_for: Dict[str, List[str]] = {}
        self._defenses: Dict[str, DefenseRecord] = {}
        self._defenses_for: Dict[str, List[str]] = {}
        self._audit: List[Dict[str, Any]] = []
        self._seq = 0
        self._n_tst = 0
        self._n_def = 0
        self._n_book = 0
        self._test_position: Dict[str, int] = {}
        self._defense_position: Dict[str, int] = {}

    # -- seq discipline ----------------------------------------------------

    def _check_seq(self, seq: int) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
        if seq <= self._seq:
            raise SeqOrderError("seq must strictly increase")
        return seq

    def _claim(self, seq: int) -> int:
        self._check_seq(seq)
        self._seq = seq
        return seq

    def _burn(self, seq: int, kind: str, **details: Any) -> None:
        self._seq = seq
        try:
            row = data_extraction_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(data_extraction_audit_event(audit_kind, seq, **details))

    # -- test ----------------------------------------------------------------

    def test(
        self,
        target_id: str,
        attack: str,
        seq: int,
        outcome: str = "inconclusive",
        evidence_digest: str = "",
    ) -> TestRecord:
        """Book one declared extraction test (minted ``tst-N``).

        The first test for a target implicitly registers the target. The
        outcome is host-declared data -- never proof data was extracted.
        """
        with self._lock:
            try:
                self._claim(seq)
            except DataExtractionError:
                raise
            try:
                _require_id(target_id, "target_id")
                if attack not in ATTACKS:
                    raise BadAttackError(f"attack must be one of {ATTACKS}")
                if outcome not in TEST_OUTCOMES:
                    raise BadOutcomeError(f"outcome must be one of {TEST_OUTCOMES}")
                if evidence_digest:
                    _require_digest(evidence_digest, "evidence_digest")
                else:
                    evidence_digest = _ZERO_PIN
                self._n_tst += 1
                test_id = f"tst-{self._n_tst}"
                self._n_book += 1
                self._test_position[test_id] = self._n_book
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "test_id": test_id,
                        "target_id": target_id,
                        "attack": attack,
                        "outcome": outcome,
                        "evidence_digest": evidence_digest,
                    }
                )
                record = TestRecord(
                    test_id=test_id,
                    target_id=target_id,
                    attack=attack,
                    outcome=outcome,
                    evidence_digest=evidence_digest,
                    digest=digest,
                )
                self._tests[test_id] = record
                if target_id not in self._targets:
                    self._targets[target_id] = []
                    self._tests_for[target_id] = []
                    self._defenses_for[target_id] = []
                self._tests_for[target_id].append(test_id)
                self._emit(
                    "tested",
                    seq,
                    test_id=test_id,
                    target_id=target_id,
                    attack=attack,
                    outcome=outcome,
                )
                return record
            except DataExtractionError:
                self._burn(seq, "test")
                raise

    # -- defend ----------------------------------------------------------------

    def defend(
        self,
        target_id: str,
        defense: str,
        seq: int,
        plan_digest: str = "",
    ) -> DefenseRecord:
        """Book one declared defense application (minted ``def-N``).

        Fail-closed on unknown targets. Books the declaration -- never
        proof the defense is live or holds.
        """
        with self._lock:
            try:
                self._claim(seq)
            except DataExtractionError:
                raise
            try:
                _require_id(target_id, "target_id")
                if target_id not in self._targets:
                    raise UnknownTargetError(f"unknown target: {target_id!r}")
                if defense not in DEFENSES:
                    raise BadDefenseError(f"defense must be one of {DEFENSES}")
                if plan_digest:
                    _require_digest(plan_digest, "plan_digest")
                else:
                    plan_digest = _ZERO_PIN
                self._n_def += 1
                defense_id = f"def-{self._n_def}"
                self._n_book += 1
                self._defense_position[defense_id] = self._n_book
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "defense_id": defense_id,
                        "target_id": target_id,
                        "defense": defense,
                        "plan_digest": plan_digest,
                    }
                )
                record = DefenseRecord(
                    defense_id=defense_id,
                    target_id=target_id,
                    defense=defense,
                    plan_digest=plan_digest,
                    digest=digest,
                )
                self._defenses[defense_id] = record
                self._defenses_for[target_id].append(defense_id)
                self._emit(
                    "defended",
                    seq,
                    defense_id=defense_id,
                    target_id=target_id,
                    defense=defense,
                )
                return record
            except DataExtractionError:
                self._burn(seq, "defend")
                raise

    # -- evaluate (pure read) ---------------------------------------------------

    def evaluate(self, target_id: str, seq: int) -> EvaluationReport:
        """Pure read: per-target residual-risk report as data, digest-pinned.

        Ledger rule: no booked tests -> ``unknown``; no booked
        ``extracted`` outcomes -> ``contained``; a booked ``extracted``
        after the last booked defense (or with no defense at all) ->
        ``elevated``; otherwise ``contained``.
        """
        with self._lock:
            self._view_seq_ok(seq)
            _require_id(target_id, "target_id")
            if target_id not in self._targets:
                raise UnknownTargetError(f"unknown target: {target_id!r}")
            tst_ids = self._tests_for.get(target_id, [])
            def_ids = self._defenses_for.get(target_id, [])
            integrity_ok = True
            n_extracted = 0
            last_extracted_pos = -1
            for test_id in tst_ids:
                rec = self._tests[test_id]
                if not rec.verify():
                    integrity_ok = False
                if rec.outcome == "extracted":
                    n_extracted += 1
                    pos = self._test_position[test_id]
                    if pos > last_extracted_pos:
                        last_extracted_pos = pos
            last_defense_pos = -1
            for defense_id in def_ids:
                if not self._defenses[defense_id].verify():
                    integrity_ok = False
                pos = self._defense_position[defense_id]
                if pos > last_defense_pos:
                    last_defense_pos = pos
            if not tst_ids:
                residual_risk = "unknown"
            elif last_extracted_pos < 0:
                residual_risk = "contained"
            elif last_extracted_pos > last_defense_pos:
                residual_risk = "elevated"
            else:
                residual_risk = "contained"
            digest = _digest_pin(
                {
                    "schema": SCHEMA_PIN,
                    "target_id": target_id,
                    "n_tests": len(tst_ids),
                    "n_extracted": n_extracted,
                    "n_defenses": len(def_ids),
                    "residual_risk": residual_risk,
                    "integrity_ok": integrity_ok,
                }
            )
            return EvaluationReport(
                target_id=target_id,
                n_tests=len(tst_ids),
                n_extracted=n_extracted,
                n_defenses=len(def_ids),
                residual_risk=residual_risk,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    # -- pure-read views -----------------------------------------------------

    def _view_seq_ok(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise SeqOrderError("view seq must be a non-negative int")

    def test_record(self, test_id: str, seq: int) -> TestRecord:
        with self._lock:
            self._view_seq_ok(seq)
            record = self._tests.get(test_id)
            if record is None:
                raise UnknownTestError(f"unknown test: {test_id!r}")
            return record

    def defense_record(self, defense_id: str, seq: int) -> DefenseRecord:
        with self._lock:
            self._view_seq_ok(seq)
            record = self._defenses.get(defense_id)
            if record is None:
                raise UnknownDefenseError(f"unknown defense: {defense_id!r}")
            return record

    def target_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(sorted(self._targets))

    def test_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(sorted(self._tests))

    def defense_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(sorted(self._defenses))

    def tests_for(self, target_id: str, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            if target_id not in self._targets:
                raise UnknownTargetError(f"unknown target: {target_id!r}")
            return tuple(self._tests_for.get(target_id, []))

    def defenses_for(self, target_id: str, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            if target_id not in self._targets:
                raise UnknownTargetError(f"unknown target: {target_id!r}")
            return tuple(self._defenses_for.get(target_id, []))

    def stats(self, seq: int) -> Dict[str, int]:
        with self._lock:
            self._view_seq_ok(seq)
            return {
                "targets": len(self._targets),
                "tests": len(self._tests),
                "defenses": len(self._defenses),
                "audit_rows": len(self._audit),
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(self._audit)


def main() -> None:
    d = DataExtraction()
    tst = d.test("tgt-1", "membership-inference", 1, outcome="extracted")
    assert tst.verify()
    dfn = d.defend("tgt-1", "output-perturbation", 2)
    assert dfn.verify()
    rpt = d.evaluate("tgt-1", 0)
    assert rpt.verify()
    assert rpt.n_tests == 1 and rpt.n_extracted == 1
    assert rpt.n_defenses == 1 and rpt.residual_risk == "contained"
    assert rpt.integrity_ok
    print("data-extraction OK: test, defend, evaluate, pins")


if __name__ == "__main__":
    main()

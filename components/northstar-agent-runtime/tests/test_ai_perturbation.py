"""Tests for the AI-perturbation ledger (ai_perturbation.py)."""

from __future__ import annotations

import ast
import threading
from pathlib import Path

import pytest

from ai_perturbation import (
    AI_PERTURBATION_SCHEMA,
    AI_PERTURBATION_VERSION,
    AUDIT_SCHEMA,
    AIPerturbation,
    AIPerturbationError,
    AuditKindError,
    BadDigestError,
    BadIdError,
    BadOutcomeError,
    BadPerturbationKindError,
    BadReasonError,
    DoubleRetireError,
    KIND_PERTURBED,
    KIND_REJECTED,
    KIND_RETIRED,
    OUTCOME_DEGRADED,
    OUTCOME_FAILED,
    OUTCOME_INCONCLUSIVE,
    OUTCOME_NOT_TESTED,
    OUTCOME_ROBUST,
    OUTCOMES,
    PERTURBATION_KINDS,
    POSTURE_CONTESTED,
    POSTURE_DEGRADED,
    POSTURE_FAILED,
    POSTURE_ROBUST,
    POSTURES,
    REASON_DECOMMISSIONED,
    REASON_MANUAL,
    REASON_SCOPE_CHANGE,
    REASON_TEST_LOSS,
    REASONS,
    RetiredSystemError,
    SeqOrderError,
    UnknownPerturbationError,
    UnknownSystemError,
    ai_perturbation_audit_event,
    stdlib_only,
)


def _digest(seed: str = "x") -> str:
    import hashlib
    return "sha256:" + hashlib.sha256(seed.encode()).hexdigest()


def test_pins_vocabularies_and_stdlib_only():
    assert AI_PERTURBATION_VERSION == "ai-perturbation.v1"
    assert AI_PERTURBATION_SCHEMA == "northstar.ai-perturbation.v1"
    assert len(PERTURBATION_KINDS) == 8
    assert len(OUTCOMES) == 5
    assert OUTCOME_ROBUST in OUTCOMES
    assert OUTCOME_DEGRADED in OUTCOMES
    assert OUTCOME_FAILED in OUTCOMES
    assert OUTCOME_INCONCLUSIVE in OUTCOMES
    assert OUTCOME_NOT_TESTED in OUTCOMES
    assert len(POSTURES) == 5
    assert len(REASONS) == 4
    assert stdlib_only()
    # AST check: no non-stdlib imports (allow canonical_json + __future__)
    src = (Path(__file__).parent.parent / "ai_perturbation.py").read_text()
    tree = ast.parse(src)
    allowed = {"__future__", "canonical_json", "hashlib", "re", "threading",
               "dataclasses", "typing", "json"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                assert top in allowed, f"non-stdlib import: {alias.name}"
        elif isinstance(node, ast.ImportFrom):
            top = (node.module or "").split(".")[0]
            assert top in allowed, f"non-stdlib import: {node.module}"


def test_perturb_roundtrip_verify_frozen_and_minting():
    ap = AIPerturbation()
    d = _digest("p1")
    rec = ap.perturb("sys-a", 1, "noise-injection", "robust", d)
    assert rec.perturbation_id == "prt-1"
    assert rec.system_id == "sys-a"
    assert rec.perturbation_kind == "noise-injection"
    assert rec.outcome == "robust"
    assert rec.verify("prt-1", "sys-a", "noise-injection", "robust", d)
    assert not rec.verify("prt-1", "sys-a", "noise-injection", "failed", d)
    # frozen dataclass
    with pytest.raises(Exception):
        rec.outcome = "failed"  # type: ignore[misc]
    # second perturb mints prt-2, registers same system
    rec2 = ap.perturb("sys-a", 2, "adversarial-example", "degraded")
    assert rec2.perturbation_id == "prt-2"
    assert rec2.perturbation_digest == ""
    # audit shape: perturbed row
    log = ap.audit_log()
    assert len(log) == 2
    assert log[0]["schema"] == AUDIT_SCHEMA
    assert log[0]["module"] == AI_PERTURBATION_VERSION
    assert log[0]["kind"] == KIND_PERTURBED
    assert log[0]["seq"] == 1
    assert log[0]["detail"]["perturbation_kind"] == "noise-injection"


def test_bad_input_table_seq_burn_and_rejected_rows():
    ap = AIPerturbation()
    # 8 bad-input branches; each burns its seq and books a rejected row
    bad_calls = [
        lambda: ap.perturb("", 1, "noise-injection", "robust"),            # bad id
        lambda: ap.perturb("sys-b", 2, "bogus-kind", "robust"),           # bad kind
        lambda: ap.perturb("sys-b", 3, "noise-injection", "bogus"),       # bad outcome
        lambda: ap.perturb("sys-b", 4, "noise-injection", "robust", "zz"),  # bad digest
        lambda: ap.perturb("sys c", 5, "noise-injection", "robust"),      # whitespace id
        lambda: ap.perturb(123, 6, "noise-injection", "robust"),          # non-str id
        lambda: ap.perturb("sys-b", 7, "noise-injection", True),           # bool outcome
        lambda: ap.perturb("sys-b", 8, 42, "robust"),                      # non-str kind
    ]
    for fn in bad_calls:
        with pytest.raises(AIPerturbationError):
            fn()
    log = ap.audit_log()
    rejected = [e for e in log if e["kind"] == KIND_REJECTED]
    assert len(rejected) == 8
    assert [e["seq"] for e in rejected] == [1, 2, 3, 4, 5, 6, 7, 8]
    # no perturbation booked
    assert ap.stats()["perturbations"] == 0
    # rewind raises bare with no new row
    with pytest.raises(SeqOrderError):
        ap.perturb("sys-b", 8, "noise-injection", "robust")
    assert len(ap.audit_log()) == 8


def test_malformed_seqs_raise_bare_and_burn_nothing():
    ap = AIPerturbation()
    for bad in (-1, 0.5, "1", None, True):
        with pytest.raises(SeqOrderError):
            ap.perturb("sys-x", bad, "noise-injection", "robust")  # type: ignore[arg-type]
    # claim then a valid perturb at seq 0 (genesis claim is allowed)
    rec = ap.perturb("sys-x", 0, "noise-injection", "robust")
    assert rec.perturbation_id == "prt-1"
    # rewind is bare, no rejected row
    with pytest.raises(SeqOrderError):
        ap.perturb("sys-x", 0, "noise-injection", "robust")
    assert all(e["kind"] != KIND_REJECTED for e in ap.audit_log())


def test_full_8_kind_vocabulary():
    ap = AIPerturbation()
    for i, kind in enumerate(PERTURBATION_KINDS):
        rec = ap.perturb("sys-k", i + 1, kind, "robust")
        assert rec.perturbation_kind == kind
    assert ap.stats()["perturbations"] == 8


def test_full_5_outcome_vocabulary():
    ap = AIPerturbation()
    tallies = {o: 0 for o in OUTCOMES}
    for i, outcome in enumerate(OUTCOMES):
        ap.perturb("sys-o", i + 1, "noise-injection", outcome)
        tallies[outcome] += 1
    ev = ap.evaluate("sys-o", 6)
    assert ev.n_robust == 1
    assert ev.n_degraded == 1
    assert ev.n_failed == 1
    assert ev.n_inconclusive == 1
    assert ev.n_not_tested == 1
    # failed outranks everything
    assert ev.posture == POSTURE_FAILED


def test_verify_semantics_tamper_as_data_and_read_purity():
    ap = AIPerturbation()
    d = _digest("v1")
    ap.perturb("sys-v", 1, "input-occlusion", "robust", d)
    vr = ap.verify("prt-1", 2)
    assert vr.verdict == "verified"
    assert vr.verify("prt-1", "verified")
    # same-seq twice: pure read, no audit rows, no seq consumed
    n_rows = len(ap.audit_log())
    vr2 = ap.verify("prt-1", 2)
    assert vr2.verdict == "verified"
    assert len(ap.audit_log()) == n_rows
    # tamper as data: mutate record via object.__setattr__, integrity flips
    rec = ap.perturbation_record("prt-1", 3)
    object.__setattr__(rec, "outcome", "failed")
    vr3 = ap.verify("prt-1", 4)
    assert vr3.verdict == "tampered"
    ev = ap.evaluate("sys-v", 5)
    assert not ev.integrity_ok
    # unknown perturbation id
    with pytest.raises(UnknownPerturbationError):
        ap.verify("prt-999", 6)


def test_evaluate_posture_math_and_precedence():
    ap = AIPerturbation()
    # all robust -> robust
    ap.perturb("s1", 1, "noise-injection", "robust")
    ap.perturb("s1", 2, "corruption", "robust")
    assert ap.evaluate("s1", 3).posture == POSTURE_ROBUST
    # degraded/not-tested -> degraded
    ap.perturb("s2", 4, "noise-injection", "not-tested")
    assert ap.evaluate("s2", 5).posture == POSTURE_DEGRADED
    ap.perturb("s2", 6, "corruption", "degraded")
    assert ap.evaluate("s2", 7).posture == POSTURE_DEGRADED
    # inconclusive -> contested
    ap.perturb("s3", 8, "noise-injection", "inconclusive")
    assert ap.evaluate("s3", 9).posture == POSTURE_CONTESTED
    # failed outranks inconclusive and degraded
    ap.perturb("s3", 10, "corruption", "degraded")
    ap.perturb("s3", 11, "adversarial-example", "failed")
    ev = ap.evaluate("s3", 12)
    assert ev.posture == POSTURE_FAILED
    assert ev.n_perturbations == 3
    assert ev.integrity_ok
    # evaluate is pure read: no audit rows added
    n_rows = len(ap.audit_log())
    ap.evaluate("s1", 13)
    assert len(ap.audit_log()) == n_rows
    # unknown system
    with pytest.raises(UnknownSystemError):
        ap.evaluate("nope", 14)


def test_retire_terminality_and_reads_still_work():
    ap = AIPerturbation()
    ap.perturb("sys-r", 1, "noise-injection", "robust")
    rr = ap.retire("sys-r", 2)
    assert rr.system_id == "sys-r"
    assert rr.verify("sys-r", REASON_MANUAL)
    # id never recycled; post-retire mutations refused
    with pytest.raises(RetiredSystemError):
        ap.perturb("sys-r", 3, "corruption", "robust")
    # double retire refused
    with pytest.raises(DoubleRetireError):
        ap.retire("sys-r", 4)
    # bad reason refused
    with pytest.raises(BadReasonError):
        ap.retire("sys-other", 5, "bogus")
    # unknown system retire books rejected row (seq burned)
    with pytest.raises(AIPerturbationError):
        ap.retire("", 6)
    # reads still work post-retire
    assert ap.perturbation_record("prt-1", 7).system_id == "sys-r"
    assert ap.verify("prt-1", 8).verdict == "verified"
    assert ap.evaluate("sys-r", 9).posture == POSTURE_ROBUST
    assert ap.retired_ids(10) == ("sys-r",)
    # all 4 reasons accepted
    for i, reason in enumerate(REASONS):
        r = ap.retire(f"sys-{i}", 20 + i, reason)
        assert r.reason == reason


def test_seq_discipline_failed_mutation_consumes_seq():
    ap = AIPerturbation()
    ap.perturb("sys-s", 1, "noise-injection", "robust")
    # failed mutation consumes seq: next valid call must use 3
    with pytest.raises(BadPerturbationKindError):
        ap.perturb("sys-s", 2, "nope", "robust")
    rec = ap.perturb("sys-s", 3, "noise-injection", "robust")
    assert rec.perturbation_id == "prt-2"
    rejected = [e for e in ap.audit_log() if e["kind"] == KIND_REJECTED]
    assert len(rejected) == 1
    assert rejected[0]["seq"] == 2


def test_audit_shapes_leak_ban_and_bad_kind():
    ap = AIPerturbation()
    # retired row shape
    ap.retire("sys-a", 1)
    log = ap.audit_log()
    assert log[0]["kind"] == KIND_RETIRED
    assert log[0]["detail"] == {"system_id": "sys-a", "reason": REASON_MANUAL}
    # leak ban: raw material keys cannot cross the audit boundary
    for banned_key in ("input", "adversarial_example", "payload", "prompt",
                       "model_output", "noise", "trigger", "dataset"):
        with pytest.raises(AuditKindError):
            ai_perturbation_audit_event(
                KIND_PERTURBED, {banned_key: "raw"}, 9)
    # bad kind
    with pytest.raises(AuditKindError):
        ai_perturbation_audit_event("bogus", {}, 9)
    # pinned vocab values remain emittable as declared data
    ev = ai_perturbation_audit_event(
        KIND_PERTURBED,
        {"system_id": "s", "perturbation_kind": "noise-injection",
         "outcome": "robust", "perturbation_digest": ""}, 10)
    assert ev["detail"]["perturbation_kind"] == "noise-injection"
    assert ev["detail"]["outcome"] == "robust"


def test_views_stats_and_unknown_lookups():
    ap = AIPerturbation()
    ap.perturb("a1", 1, "noise-injection", "robust")
    ap.perturb("a1", 2, "corruption", "degraded")
    ap.perturb("b2", 3, "adversarial-example", "failed")
    assert ap.perturbations_for("a1", 4) == ("prt-1", "prt-2")
    assert ap.perturbations_for("b2", 5) == ("prt-3",)
    assert ap.system_ids(6) == ("a1", "b2")
    assert ap.retired_ids(7) == ()
    assert ap.stats() == {
        "systems": 2, "perturbations": 3, "retired": 0, "audit_rows": 3}
    with pytest.raises(UnknownSystemError):
        ap.perturbations_for("zzz", 8)
    with pytest.raises(UnknownPerturbationError):
        ap.perturbation_record("prt-999", 9)


def test_cross_instance_determinism_and_thread_smoke():
    d = _digest("det")
    ap1 = AIPerturbation()
    ap2 = AIPerturbation()
    r1 = ap1.perturb("s", 1, "style-transfer", "robust", d)
    r2 = ap2.perturb("s", 1, "style-transfer", "robust", d)
    assert r1.digest == r2.digest
    assert r1.verify("prt-1", "s", "style-transfer", "robust", d)
    # 8-thread concurrent perturb smoke
    ap = AIPerturbation()
    errors = []

    def worker(i):
        try:
            ap.perturb(f"sys-t{i % 2}", i, "noise-injection", "robust")
        except AIPerturbationError:
            pass
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert ap.stats()["perturbations"] == 8


def test_main_self_check_via_subprocess():
    import subprocess
    import sys
    mod = Path(__file__).parent.parent / "ai_perturbation.py"
    proc = subprocess.run([sys.executable, str(mod)], capture_output=True,
                          text=True, timeout=30)
    assert proc.returncode == 0, proc.stderr
    assert "ai-perturbation OK" in proc.stdout


def test_seq_boundaries_and_default_args():
    ap = AIPerturbation()
    # defaults: noise-injection + robust + empty digest
    rec = ap.perturb("sys-d", 0)
    assert rec.perturbation_kind == "noise-injection"
    assert rec.outcome == "robust"
    assert rec.perturbation_digest == ""
    assert rec.seq == 0
    # id length boundary: 256 ok, 257 refused
    ok_id = "x" * 256
    r2 = ap.perturb(ok_id, 1, "corruption", "failed")
    assert r2.system_id == ok_id
    with pytest.raises(BadIdError):
        ap.perturb("y" * 257, 2, "corruption", "failed")


# ---------------------------------------------------------------------------
# 16. The digest-pin defects (B173 slice, measured 2026-11-25)
#
# `ai_perturbation.py` carried the same four defects of the family that
# `graph_database.py`, `status_page.py`, `zero_knowledge.py`,
# `ai_constitution.py` and `ai_interpretability.py` carried before their
# slices.
#
# NOTE the per-module shape: the `_pin(...)` call sat INSIDE the record
# constructor, which is inside the guarded `try` -- so the pin did not
# escape the region.  But it raised `canonical_json.JcsError`, which the
# `except AIPerturbationError` handler did not catch, so the seq was
# burned and NO `rejected` row was booked.  The trail showed a burn
# with no row.


SURROGATE = "\ud800"


def test_a_refusal_raises_the_modules_own_error_type():
    """The module's own taxonomy, not the sibling helper's.

    `JcsError` is a `ValueError`, so a caller guarding on
    `except ValueError` would treat a refused mutation as a parse
    error.  The module's error must be what escapes.
    """
    ap = AIPerturbation()
    with pytest.raises(AIPerturbationError):
        ap.perturb(SURROGATE, 1)


def test_a_failed_mutation_still_consumes_its_seq():
    """A failed pin at a valid seq burns the seq and books a row.

    This is the second refusal convention (`docs/design/
    refusal-hold-wiring.md` §21.3): a malformed ARGUMENT at a valid
    seq consumes the seq and books a `rejected` row.
    """
    ap = AIPerturbation()
    with pytest.raises(AIPerturbationError):
        ap.perturb(SURROGATE, 1)
    kinds = [e["kind"] for e in ap.audit_log()]
    assert KIND_REJECTED in kinds
    # the seq was consumed: the next claim must be strictly greater
    with pytest.raises(SeqOrderError):
        ap.perturb("sys-a", 1)
    ap.perturb("sys-a", 2)
    assert ap.stats()["perturbations"] == 1


def test_the_shipped_path_and_the_fallback_agree_about_legality():
    """Both configurations must refuse a lone surrogate.

    They need not agree about the resulting digest bytes -- the
    fallback's tagged form is deliberately its own string -- but a
    value one refuses must be refused by both.  RFC 8785 §3.2.2.3
    requires a compliant implementation to terminate with an error.
    """
    import ai_perturbation as apm
    saved = apm._cj
    try:
        assert apm._cj is not None, "the shipped path is not installed"

        apm._cj = saved
        with pytest.raises(AIPerturbationError):
            apm._canonical([SURROGATE])

        apm._cj = None
        with pytest.raises(AIPerturbationError):
            apm._canonical([SURROGATE])
    finally:
        apm._cj = saved


def test_both_configurations_accept_a_value_both_can_canonicalize():
    """The control: the fallback must not refuse everything.

    Without this, a fallback that refused every input would satisfy
    the test above vacuously.
    """
    import ai_perturbation as apm
    saved = apm._cj
    try:
        for cfg in (saved, None):
            apm._cj = cfg
            assert apm._canonical(["ordinary", 7, ["a"]])
    finally:
        apm._cj = saved


def test_a_seq_above_the_safe_range_is_refused():
    """A seq that cannot be pinned must not be accepted.

    Without this bound, 2**53 and 2**53+1 canonicalize to the same
    bytes, so the digest stops pinning the seq.
    """
    ap = AIPerturbation()
    with pytest.raises(AIPerturbationError):
        ap.perturb("sys-a", 2 ** 53)


def test_an_oversized_seq_is_refused_as_a_malformed_seq():
    """The refusal's SHAPE, not just its type.

    A malformed SEQ consumes nothing and books nothing -- the call
    never reached the ledger.  A failed PIN at a valid seq consumes the
    seq and books a row.  Both raise `AIPerturbationError`, so only the
    shape distinguishes them.
    """
    ap = AIPerturbation()
    with pytest.raises(AIPerturbationError):
        ap.perturb("sys-a", 2 ** 53)
    # nothing booked
    assert ap.audit_log() == ()
    # nothing consumed: seq 1 is still claimable
    ap.perturb("sys-a", 1)
    assert ap.stats()["perturbations"] == 1


def test_a_tampered_seq_above_the_safe_range_cannot_verify():
    """The control: the digest must pin the seq.

    This is the property the bound protects.  The seq rides in the
    perturbation pin, so a record whose seq was bumped must not still
    verify -- and the pin cannot even be MINTED over an out-of-range
    seq.
    """
    import ai_perturbation as apm
    digest = apm._pin(
        "perturbation", "prt-1", "sys-a", "noise-injection", "robust",
        "", 2 ** 53 - 1,
    )
    tampered = apm.PerturbationRecord(
        perturbation_id="prt-1",
        system_id="sys-a",
        perturbation_kind="noise-injection",
        outcome="robust",
        perturbation_digest="",
        seq=2 ** 53 + 1,
        digest=digest,
    )
    assert tampered.verify(
        "prt-1", "sys-a", "noise-injection", "robust", "",
    ) is False
    # and the pin cannot be minted over an out-of-range seq at all
    with pytest.raises(AIPerturbationError):
        apm._pin(
            "perturbation", "prt-1", "sys-a", "noise-injection", "robust",
            "", 2 ** 53,
        )


def test_the_safe_range_boundary_is_accepted():
    """The control: the bound must not over-refuse.

    2**53 - 1 is the last integer JCS pins exactly.
    """
    ap = AIPerturbation()
    ap.perturb("sys-a", 2 ** 53 - 1)
    assert ap.stats()["perturbations"] == 1


def test_a_pin_refuses_an_integer_outside_the_safe_range():
    """A payload integer that cannot be pinned must be refused.

    The shipped path loses the distinction between 2**53 and
    2**53+1, so a pin over such a payload stops pinning it.
    """
    import ai_perturbation as apm
    with pytest.raises(AIPerturbationError):
        apm._canonical([2 ** 53])
    with pytest.raises(AIPerturbationError):
        apm._canonical([2 ** 53 + 1])


def test_a_pin_still_accepts_the_last_safe_integer():
    """The control: the pin refusal must not over-reach."""
    import ai_perturbation as apm
    assert apm._canonical([2 ** 53 - 1])


def test_verify_answers_false_for_a_record_it_cannot_canonicalize():
    """`verify()` answers a question; a question is not an exception.

    The record's digest cannot be recomputed over a lone surrogate, so
    the answer is "not intact" -- `False`.  It must not raise.
    """
    import ai_perturbation as apm
    rec = apm.PerturbationRecord(
        perturbation_id="prt-1",
        system_id=SURROGATE,
        perturbation_kind="noise-injection",
        outcome="robust",
        perturbation_digest="",
        seq=1,
        digest="sha256:" + "0" * 64,
    )
    assert rec.verify(
        "prt-1", SURROGATE, "noise-injection", "robust", "",
    ) is False

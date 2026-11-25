"""Tests for ai_interpretability.py (15 tests).

House style: the module is a deterministic single-host state machine.
Tests exercise pins, vocabularies, roundtrips, bad-input tables,
posture math, read purity, seq discipline, audit shapes, leak bans,
digest determinism, frozen-ness, read-thread smoke, and main().
"""

import ast
import concurrent.futures
import dataclasses
import subprocess
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ai_interpretability  # noqa: E402


def fresh():
    return ai_interpretability.AIInterpretability()


# 1. version/schema/vocabulary pins.
def test_version_schema_vocabulary_pins():
    assert ai_interpretability.AI_INTERPRETABILITY_VERSION == (
        "ai-interpretability.v1")
    assert ai_interpretability.AI_INTERPRETABILITY_SCHEMA == (
        "northstar.ai-interpretability.v1")
    assert ai_interpretability.AUDIT_SCHEMA == "audit.ndjson/1"
    assert len(ai_interpretability.METHODS) == 8
    assert set(ai_interpretability.METHODS) == {
        "mechanistic", "circuit-analysis", "probing", "saliency",
        "concept-based", "counterfactual", "feature-attribution",
        "behavioral-testing"}
    assert set(ai_interpretability.FINDINGS) == {
        "interpretable", "partially-interpretable", "opaque",
        "inconclusive"}
    assert set(ai_interpretability.POSTURES) == {
        "unevaluated", "opaque", "ambiguous", "interpretable"}
    assert set(ai_interpretability.REASONS) == {
        "manual", "decommissioned", "policy-change", "non-compliance"}
    assert ai_interpretability.stdlib_only() is True


# 2. stdlib-only AST check.
def test_stdlib_only_ast():
    src = Path(ai_interpretability.__file__).read_text()
    tree = ast.parse(src)
    allowed_top = {"canonical_json"}
    stdlib_like = {"hashlib", "re", "threading", "dataclasses", "typing",
                   "__future__", "json"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                # canonical_json is the one blessed sibling-convention
                # fallback (the same shape `status_page.py`,
                # `graph_database.py` and `ai_constitution.py` use).
                assert top in stdlib_like or top in allowed_top, (
                    f"non-stdlib import: {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            top = (node.module or "").split(".")[0]
            assert top in stdlib_like or top in allowed_top, (
                f"non-stdlib import: {node.module}")


# 3. interpret roundtrip + int-N minting + verify() + frozen-ness.
def test_interpret_roundtrip_minting_verify_frozen():
    ledger = fresh()
    rec = ledger.interpret("sys-1", 1, "mechanistic", "interpretable")
    assert rec.interpretation_id == "int-1"
    assert rec.system_id == "sys-1"
    assert rec.method == "mechanistic"
    assert rec.finding == "interpretable"
    assert rec.seq == 1
    assert rec.digest.startswith("sha256:")
    assert rec.verify("int-1", "sys-1", "mechanistic", "interpretable", "")
    rec2 = ledger.interpret("sys-1", 2, "probing", "partially-interpretable")
    assert rec2.interpretation_id == "int-2"
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.finding = "opaque"  # type: ignore[misc]


# 4. interpret bad-input table + seq-burn + rejected-row accounting.
def test_interpret_bad_inputs_burn_seq_and_reject():
    ledger = fresh()
    bad_cases = [
        ("", 1),                      # empty system id
        ("  ", 2),                    # whitespace id
        ("x" * 257, 3),               # id too long
        ("sys-bad-method", 4),        # placeholder (replaced below)
        (None, 5),                    # non-str id
        (True, 6),                    # bool id
    ]
    for system_id, seq in bad_cases[:3]:
        with pytest.raises(ai_interpretability.BadIdError):
            ledger.interpret(system_id, seq)
    for system_id, seq in bad_cases[4:]:
        with pytest.raises(ai_interpretability.BadIdError):
            ledger.interpret(system_id, seq)
    with pytest.raises(ai_interpretability.BadMethodError):
        ledger.interpret("sys-1", 7, "shap", "interpretable")
    with pytest.raises(ai_interpretability.BadMethodError):
        ledger.interpret("sys-1", 8, True, "interpretable")
    with pytest.raises(ai_interpretability.BadFindingError):
        ledger.interpret("sys-1", 9, "mechanistic", "fair")
    with pytest.raises(ai_interpretability.BadDigestError):
        ledger.interpret("sys-1", 10, "mechanistic", "interpretable",
                         interpretation_digest="not-a-pin")
    # Rewinds raise bare with no rejected row.
    n_before = ledger.stats()["rejected"]
    with pytest.raises(ai_interpretability.SeqOrderError):
        ledger.interpret("sys-1", 10)  # rewind of consumed seq
    assert ledger.stats()["rejected"] == n_before
    with pytest.raises(ai_interpretability.SeqOrderError):
        ledger.interpret("sys-1", -1)
    # 9 failed mutations burned their seqs (none succeeded).
    assert ledger.stats()["rejected"] == 9
    # Next good seq still works after burns.
    rec = ledger.interpret("sys-1", 11)
    assert rec.interpretation_id == "int-1"


# 5. full 8-method vocabulary acceptance.
def test_full_method_vocabulary_accepted():
    ledger = fresh()
    for i, method in enumerate(ai_interpretability.METHODS, start=1):
        rec = ledger.interpret("sys-m", i, method, "interpretable")
        assert rec.method == method
    assert ledger.interpretation_ids(100) == tuple(
        f"int-{i}" for i in range(1, 9))


# 6. full 4-finding vocabulary acceptance.
def test_full_finding_vocabulary_accepted():
    ledger = fresh()
    for i, finding in enumerate(ai_interpretability.FINDINGS, start=1):
        rec = ledger.interpret("sys-f", i, "saliency", finding)
        assert rec.finding == finding
    assert ledger.stats()["interpretations"] == 4


# 7. retired-system refusal.
def test_retired_system_refusal_and_reads_still_work():
    ledger = fresh()
    ledger.interpret("sys-r", 1)
    ledger.retire("sys-r", 2)
    with pytest.raises(ai_interpretability.RetiredSystemError):
        ledger.interpret("sys-r", 3, "probing", "opaque")
    assert ledger.stats()["rejected"] == 1
    # Reads still work post-retire.
    assert ledger.interpretation_record("int-1", 3).system_id == "sys-r"
    assert ledger.retired_ids(3) == ("sys-r",)
    rep = ledger.evaluate("sys-r", 3)
    assert rep.posture == "interpretable"


# 8. verify semantics: roundtrip, tamper-as-data, unknown, read purity.
def test_verify_semantics_tamper_and_read_purity():
    ledger = fresh()
    ledger.interpret("sys-v", 1, "concept-based", "interpretable")
    ledger.interpret("sys-v", 2, "counterfactual", "opaque")
    n_rows = len(ledger.audit_log())
    vr = ledger.verify("int-1", 3)
    assert vr.verdict == "verified"
    assert vr.verify("int-1", "verified")
    # Read purity: same seq twice, no audit rows, no seq consumption.
    vr2 = ledger.verify("int-1", 3)
    assert vr2.verdict == "verified"
    assert len(ledger.audit_log()) == n_rows
    assert ledger.stats()["seq"] == 2
    # Tamper is reported as data, never raised.
    tampered = ledger._interpretations["int-2"]
    object.__setattr__(tampered, "digest", "sha256:" + "0" * 64)
    vr3 = ledger.verify("int-2", 3)
    assert vr3.verdict == "tampered"
    assert len(ledger.audit_log()) == n_rows
    # Retirement records verify too.
    ledger.retire("sys-v", 4)
    vr4 = ledger.verify("sys-v", 5)
    assert vr4.verdict == "verified"
    with pytest.raises(ai_interpretability.UnknownRecordError):
        ledger.verify("int-99", 5)


# 9. evaluate posture math: all postures + precedence + tallies.
def test_evaluate_posture_math_precedence_and_tallies():
    # opaque outranks everything.
    ledger = fresh()
    ledger.interpret("s1", 1, "mechanistic", "opaque")
    ledger.interpret("s1", 2, "probing", "interpretable")
    rep = ledger.evaluate("s1", 3)
    assert rep.posture == "opaque"
    assert (rep.n_interpretable, rep.n_opaque) == (1, 1)
    # ambiguous from inconclusive/partial.
    ledger2 = fresh()
    ledger2.interpret("s2", 1, "saliency", "inconclusive")
    rep2 = ledger2.evaluate("s2", 2)
    assert rep2.posture == "ambiguous"
    ledger3 = fresh()
    ledger3.interpret("s3", 1, "saliency", "partially-interpretable")
    rep3 = ledger3.evaluate("s3", 2)
    assert rep3.posture == "ambiguous"
    assert rep3.n_partially_interpretable == 1
    # all interpretable -> interpretable.
    ledger4 = fresh()
    ledger4.interpret("s4", 1)
    ledger4.interpret("s4", 2, "probing", "interpretable")
    rep4 = ledger4.evaluate("s4", 3)
    assert rep4.posture == "interpretable"
    assert rep4.n_interpretable == 2
    assert rep4.integrity_ok is True
    assert rep4.verify("s4", "interpretable", 2, 0, 0, 0)
    # integrity flip on tamper, posture stays.
    object.__setattr__(ledger4._interpretations["int-1"],
                       "digest", "sha256:" + "1" * 64)
    rep5 = ledger4.evaluate("s4", 3)
    assert rep5.integrity_ok is False
    assert rep5.posture == "interpretable"


# 10. evaluate read purity + unknown-system refusal.
def test_evaluate_read_purity_and_unknown_refusal():
    ledger = fresh()
    ledger.interpret("sys-e", 1)
    n_rows = len(ledger.audit_log())
    r1 = ledger.evaluate("sys-e", 2)
    r2 = ledger.evaluate("sys-e", 2)
    assert r1.posture == r2.posture == "interpretable"
    assert len(ledger.audit_log()) == n_rows
    assert ledger.stats()["seq"] == 1
    with pytest.raises(ai_interpretability.UnknownSystemError):
        ledger.evaluate("no-such-system", 2)


# 11. retire terminality: bad reason, double-retire, non-recycling.
def test_retire_terminality_and_bad_reason():
    ledger = fresh()
    ledger.interpret("sys-t", 1)
    rec = ledger.retire("sys-t", 2, "decommissioned")
    assert rec.reason == "decommissioned"
    assert rec.verify("sys-t", "decommissioned")
    with pytest.raises(ai_interpretability.DoubleRetireError):
        ledger.retire("sys-t", 3)
    with pytest.raises(ai_interpretability.BadReasonError):
        ledger.retire("sys-t", 4, "retired-because")
    with pytest.raises(ai_interpretability.UnknownSystemError):
        ledger.retire("ghost", 5)
    assert ledger.stats()["rejected"] == 3
    # Id never recycled: new interpretations on the same id refused.
    with pytest.raises(ai_interpretability.RetiredSystemError):
        ledger.interpret("sys-t", 6)
    assert ledger.retired_ids(6) == ("sys-t",)
    assert ledger.system_ids(6) == ("sys-t",)


# 12. seq discipline: rewind bare, malformed seqs, burn-on-failure.
def test_seq_discipline_rewind_malformed_burn():
    ledger = fresh()
    with pytest.raises(ai_interpretability.SeqOrderError):
        ledger.interpret("sys-q", -1)
    assert ledger.stats()["rejected"] == 0
    for bad in (True, 1.5, "3", None):
        with pytest.raises(ai_interpretability.SeqOrderError):
            ledger.interpret("sys-q", bad)
    assert ledger.stats()["rejected"] == 0
    ledger.interpret("sys-q", 0)  # genesis seq 0 is valid
    assert ledger.stats()["seq"] == 0
    with pytest.raises(ai_interpretability.SeqOrderError):
        ledger.interpret("sys-q", 0)  # rewind raises bare
    assert ledger.stats()["rejected"] == 0
    with pytest.raises(ai_interpretability.BadMethodError):
        ledger.interpret("sys-q", 1, "nope")
    assert ledger.stats()["rejected"] == 1
    assert ledger.stats()["seq"] == 1


# 13. audit shapes + leak ban + bad-kind.
def test_audit_shapes_leak_ban_and_bad_kind():
    ledger = fresh()
    ledger.interpret("sys-a", 1, "probing", "interpretable")
    ledger.retire("sys-a", 2)
    with pytest.raises(ai_interpretability.BadMethodError):
        ledger.interpret("sys-a", 3, "bad")
    rows = ledger.audit_log()
    assert [r["kind"] for r in rows] == [
        "interpreted", "retired", "rejected"]
    for row in rows:
        assert row["schema"] == "audit.ndjson/1"
        assert row["module"] == "ai-interpretability.v1"
        # No raw banned keys cross the audit boundary.
        for key in row["detail"]:
            assert key not in ai_interpretability._BANNED_DETAIL_KEYS
    with pytest.raises(ai_interpretability.AuditKindError):
        ai_interpretability.ai_interpretability_audit_event(
            "nope", {}, 4)
    with pytest.raises(ai_interpretability.AuditKindError):
        ai_interpretability.ai_interpretability_audit_event(
            "interpreted", {"weights": "raw"}, 4)


# 14. cross-instance digest determinism + views/stats + unknown lookups.
def test_cross_instance_determinism_views_and_unknowns():
    a, b = fresh(), fresh()
    ra = a.interpret("sys-x", 1, "mechanistic", "interpretable")
    rb = b.interpret("sys-x", 1, "mechanistic", "interpretable")
    assert ra.digest == rb.digest
    assert a.interpretations_for("sys-x", 2) == ("int-1",)
    assert a.interpretation_ids(2) == ("int-1",)
    assert a.retired_ids(2) == ()
    assert a.stats()["interpretations"] == 1
    with pytest.raises(ai_interpretability.UnknownRecordError):
        a.interpretation_record("int-99", 2)
    assert a.interpretations_for("sys-x", 2) != ()


# 15. main() subprocess check + 8-thread read smoke.
def test_main_and_concurrent_read_smoke():
    result = subprocess.run(
        [sys.executable, "-m", "ai_interpretability"],
        capture_output=True, text=True,
        cwd=str(Path(ai_interpretability.__file__).parent))
    assert result.returncode == 0, result.stderr
    assert "ai-interpretability OK" in result.stdout
    ledger = fresh()
    ledger.interpret("sys-s", 1, "behavioral-testing", "interpretable")
    errors = []

    def read():
        try:
            for _ in range(25):
                ledger.evaluate("sys-s", 2)
                ledger.verify("int-1", 2)
                ledger.interpretations_for("sys-s", 2)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=read) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors


# ---------------------------------------------------------------------------
# 16. The digest-pin defects (B173 slice, measured 2026-11-25)
#
# `ai_interpretability.py` carried the same four defects of the family
# that `graph_database.py`, `status_page.py`, `zero_knowledge.py` and
# `ai_constitution.py` carried before their slices.
#
# NOTE the per-module shape: here the `_pin(...)` call is ALREADY
# inside the guarded `try`, so the pin does not escape the region --
# but it raises `canonical_json.JcsError`, which the
# `except AIInterpretabilityError` handler does not catch, so the seq
# is burned and NO `rejected` row is booked.  The trail shows a burn
# with no row.


SURROGATE = "\ud800"


def test_a_refusal_raises_the_modules_own_error_type():
    """The module's own taxonomy, not the sibling helper's.

    `JcsError` is a `ValueError`, so a caller guarding on
    `except ValueError` would treat a refused mutation as a parse
    error.  The module's error must be what escapes.
    """
    ledger = fresh()
    with pytest.raises(ai_interpretability.AIInterpretabilityError):
        ledger.interpret(SURROGATE, 1)


def test_a_failed_mutation_still_consumes_its_seq():
    """A failed pin at a valid seq burns the seq and books a row.

    This is the second refusal convention (`docs/design/
    refusal-hold-wiring.md` §21.3): a malformed ARGUMENT at a valid
    seq consumes the seq and books a `rejected` row.
    """
    ledger = fresh()
    with pytest.raises(ai_interpretability.AIInterpretabilityError):
        ledger.interpret(SURROGATE, 1)
    kinds = [e["kind"] for e in ledger.audit_log()]
    assert ai_interpretability.KIND_REJECTED in kinds
    # the seq was consumed: the next claim must be strictly greater
    with pytest.raises(ai_interpretability.SeqOrderError):
        ledger.interpret("sys-s", 1)
    ledger.interpret("sys-s", 2)
    assert ledger.stats()["interpretations"] == 1


def test_the_shipped_path_and_the_fallback_agree_about_legality():
    """Both configurations must refuse a lone surrogate.

    They need not agree about the resulting digest bytes -- the
    fallback's tagged form is deliberately its own string -- but a
    value one refuses must be refused by both.  RFC 8785 §3.2.2.3
    requires a compliant implementation to terminate with an error.
    """
    saved = ai_interpretability._cj
    try:
        assert ai_interpretability._cj is not None, \
            "the shipped path is not installed"

        ai_interpretability._cj = saved
        with pytest.raises(ai_interpretability.AIInterpretabilityError):
            ai_interpretability._canonical([SURROGATE])

        ai_interpretability._cj = None
        with pytest.raises(ai_interpretability.AIInterpretabilityError):
            ai_interpretability._canonical([SURROGATE])
    finally:
        ai_interpretability._cj = saved


def test_both_configurations_accept_a_value_both_can_canonicalize():
    """The control: the fallback must not refuse everything.

    Without this, a fallback that refused every input would satisfy
    the test above vacuously.
    """
    saved = ai_interpretability._cj
    try:
        for cfg in (saved, None):
            ai_interpretability._cj = cfg
            assert ai_interpretability._canonical(["ordinary", 7, ["a"]])
    finally:
        ai_interpretability._cj = saved


def test_a_seq_above_the_safe_range_is_refused():
    """A seq that cannot be pinned must not be accepted.

    Without this bound, 2**53 and 2**53+1 canonicalize to the same
    bytes, so the digest stops pinning the seq.
    """
    ledger = fresh()
    with pytest.raises(ai_interpretability.AIInterpretabilityError):
        ledger.interpret("sys-s", 2 ** 53)


def test_an_oversized_seq_is_refused_as_a_malformed_seq():
    """The refusal's SHAPE, not just its type.

    A malformed SEQ consumes nothing and books nothing -- the call
    never reached the ledger.  A failed PIN at a valid seq consumes the
    seq and books a row.  Both raise `AIInterpretabilityError`, so only
    the shape distinguishes them.
    """
    ledger = fresh()
    with pytest.raises(ai_interpretability.AIInterpretabilityError):
        ledger.interpret("sys-s", 2 ** 53)
    # nothing booked
    assert ledger.audit_log() == ()
    # nothing consumed: seq 1 is still claimable
    ledger.interpret("sys-s", 1)
    assert ledger.stats()["interpretations"] == 1


def test_a_tampered_seq_above_the_safe_range_cannot_verify():
    """The control: the digest must pin the seq.

    This is the property the bound protects.  The seq rides in the
    interpretation pin, so a record whose seq was bumped must not
    still verify -- and the pin cannot even be MINTED over an
    out-of-range seq.
    """
    digest = ai_interpretability._pin(
        "interpretation", "int-1", "sys-s",
        ai_interpretability.MTH_MECHANISTIC,
        ai_interpretability.FND_INTERPRETABLE, "", 2 ** 53 - 1,
    )
    tampered = ai_interpretability.InterpretationRecord(
        interpretation_id="int-1",
        system_id="sys-s",
        method=ai_interpretability.MTH_MECHANISTIC,
        finding=ai_interpretability.FND_INTERPRETABLE,
        interpretation_digest="",
        seq=2 ** 53 + 1,
        digest=digest,
    )
    assert tampered.verify(
        "int-1", "sys-s", ai_interpretability.MTH_MECHANISTIC,
        ai_interpretability.FND_INTERPRETABLE, "",
    ) is False
    # and the pin cannot be minted over an out-of-range seq at all
    with pytest.raises(ai_interpretability.AIInterpretabilityError):
        ai_interpretability._pin(
            "interpretation", "int-1", "sys-s",
            ai_interpretability.MTH_MECHANISTIC,
            ai_interpretability.FND_INTERPRETABLE, "", 2 ** 53,
        )


def test_the_safe_range_boundary_is_accepted():
    """The control: the bound must not over-refuse.

    2**53 - 1 is the last integer JCS pins exactly.
    """
    ledger = fresh()
    ledger.interpret("sys-s", 2 ** 53 - 1)
    assert ledger.stats()["interpretations"] == 1


def test_a_pin_refuses_an_integer_outside_the_safe_range():
    """A payload integer that cannot be pinned must be refused.

    The shipped path loses the distinction between 2**53 and
    2**53+1, so a pin over such a payload stops pinning it.
    """
    with pytest.raises(ai_interpretability.AIInterpretabilityError):
        ai_interpretability._canonical([2 ** 53])
    with pytest.raises(ai_interpretability.AIInterpretabilityError):
        ai_interpretability._canonical([2 ** 53 + 1])


def test_a_pin_still_accepts_the_last_safe_integer():
    """The control: the pin refusal must not over-reach."""
    assert ai_interpretability._canonical([2 ** 53 - 1])


def test_verify_answers_false_for_a_record_it_cannot_canonicalize():
    """`verify()` answers a question; a question is not an exception.

    The record's digest cannot be recomputed over a lone surrogate, so
    the answer is "not intact" -- `False`.  It must not raise.
    """
    rec = ai_interpretability.InterpretationRecord(
        interpretation_id="int-1",
        system_id=SURROGATE,
        method=ai_interpretability.MTH_MECHANISTIC,
        finding=ai_interpretability.FND_INTERPRETABLE,
        interpretation_digest="",
        seq=1,
        digest="sha256:" + "0" * 64,
    )
    assert rec.verify(
        "int-1", SURROGATE, ai_interpretability.MTH_MECHANISTIC,
        ai_interpretability.FND_INTERPRETABLE, "",
    ) is False

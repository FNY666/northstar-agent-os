"""Tests for the ai-charter charter-commitment decision ledger, Simulated."""

import ast
import dataclasses
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "ai_charter.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("ai_charter", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["ai_charter"] = module
    spec.loader.exec_module(module)
    return module


ac = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert ac.AI_CHARTER_VERSION == "ai-charter.v1"
    assert ac.SCHEMA_PIN == "northstar.ai-charter.v1"
    assert ac.COMMITMENT_KINDS == (
        "corrigibility",
        "duty-to-humanity",
        "fiduciary-duty",
        "meta-guideline",
        "policy-guideline",
        "operationalization",
        "informational-guideline",
        "virtue",
    )
    assert ac.COMMITMENT_STANCES == ("adopted", "provisional", "suspended", "withdrawn")
    assert ac.VERIFY_VERDICTS == ("verified", "tampered")
    assert ac.POSTURES == (
        "uncommitted",
        "withdrawn",
        "contested",
        "provisional",
        "adopted",
    )
    assert ac.RETIRE_REASONS == ("manual", "superseded", "decommissioned", "false-start")
    assert ac.AUDIT_KINDS == ("declared", "retired", "rejected")


# 2. stdlib-only AST self-check
def test_stdlib_only():
    assert ac.stdlib_only() is True
    tree = ast.parse(MOD.read_text())
    allowed = {
        "hashlib",
        "json",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "ast",
        "pathlib",
        "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                assert node.module.split(".")[0] in allowed


# 3. declare roundtrip + dcl-N minting + verify() + frozen-ness
def test_declare_roundtrip():
    ledger = ac.AICharter()
    rec = ledger.declare(
        "charter-1", 1, commitment_kind="corrigibility", stance="adopted",
        statement_digest=PIN,
    )
    assert rec.declaration_id == "dcl-1"
    assert rec.charter_id == "charter-1"
    assert rec.seq == 1
    assert rec.statement_digest == PIN
    assert rec.verify() is True
    assert rec.digest.startswith("sha256:")
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.stance = "withdrawn"  # type: ignore
    rec2 = ledger.declare("charter-1", 2, commitment_kind="virtue")
    assert rec2.declaration_id == "dcl-2"


# 4. declare bad-input table + seq-burn + rejected-row accounting
def test_declare_bad_inputs_burn_seq():
    ledger = ac.AICharter()
    n0 = len(ledger.audit_log(0))
    bad = [
        lambda: ledger.declare("", 1),
        lambda: ledger.declare("c", 2, commitment_kind="nope"),
        lambda: ledger.declare("c", 3, stance="maybe"),
        lambda: ledger.declare("c", 4, statement_digest="bogus"),
    ]
    for i, fn in enumerate(bad, start=1):
        with pytest.raises(ac.AICharterError):
            fn()
        # each failed mutation consumed its seq (claim-then-burn)
        assert ledger.stats(0)["seq"] == i
    rows = ledger.audit_log(0)
    assert len(rows) - n0 == 4
    assert all(r["kind"] == "rejected" for r in rows[n0:])


# 5. full 8-kind commitment vocabulary acceptance
def test_all_commitment_kinds():
    ledger = ac.AICharter()
    for i, kind in enumerate(ac.COMMITMENT_KINDS, start=1):
        rec = ledger.declare("c", i, commitment_kind=kind)
        assert rec.commitment_kind == kind
        assert rec.verify() is True
    assert ledger.stats(0)["n_declarations"] == len(ac.COMMITMENT_KINDS)


# 6. full 4-stance vocabulary acceptance
def test_all_stances():
    ledger = ac.AICharter()
    for i, stance in enumerate(ac.COMMITMENT_STANCES, start=1):
        rec = ledger.declare(f"c{i}", i, stance=stance)
        assert rec.stance == stance
        assert rec.verify() is True
    assert ledger.stats(0)["n_charters"] == len(ac.COMMITMENT_STANCES)


# 7. verify semantics: roundtrip, tamper-as-data, unknown refusal, read purity
def test_verify_semantics():
    ledger = ac.AICharter()
    rec = ledger.declare("c", 1)
    rep = ledger.verify(rec.declaration_id, 2)
    assert rep.verdict == "verified"
    assert rep.integrity_ok is True
    assert rep.verify() is True
    with pytest.raises(ac.UnknownRecordError):
        ledger.verify("dcl-999", 2)
    # read purity: same read-seq twice, no audit rows, no seq consumption
    n = len(ledger.audit_log(2))
    rep2 = ledger.verify(rec.declaration_id, 2)
    assert rep2.verdict == "verified"
    assert len(ledger.audit_log(2)) == n
    assert ledger.stats(2)["seq"] == 1
    # tamper reported as data, never raised
    object.__setattr__(rec, "stance", "withdrawn")
    rep3 = ledger.verify(rec.declaration_id, 2)
    assert rep3.verdict == "tampered"
    assert rep3.integrity_ok is False
    assert rep3.verify() is True


# 8. evaluate posture math: all 5 postures + precedence
def test_evaluate_postures():
    ledger = ac.AICharter()
    # adopted (all adopted)
    ledger.declare("a", 1, stance="adopted")
    ledger.declare("a", 2, stance="adopted")
    assert ledger.evaluate("a", 3).posture == "adopted"
    # provisional (any provisional, no suspended/withdrawn)
    ledger.declare("p", 4, stance="adopted")
    ledger.declare("p", 5, stance="provisional")
    assert ledger.evaluate("p", 6).posture == "provisional"
    # contested (any suspended outranks provisional)
    ledger.declare("s", 7, stance="provisional")
    ledger.declare("s", 8, stance="suspended")
    assert ledger.evaluate("s", 9).posture == "contested"
    # withdrawn (any withdrawn outranks all)
    ledger.declare("w", 10, stance="adopted")
    ledger.declare("w", 11, stance="suspended")
    ledger.declare("w", 12, stance="withdrawn")
    assert ledger.evaluate("w", 13).posture == "withdrawn"
    # tallies
    rep = ledger.evaluate("w", 13)
    assert rep.n_declarations == 3
    assert rep.n_adopted == 1
    assert rep.n_suspended == 1
    assert rep.n_withdrawn == 1
    assert rep.verify() is True


# 9. evaluate unknown refusal + read purity + integrity flip as data
def test_evaluate_unknown_and_purity():
    ledger = ac.AICharter()
    with pytest.raises(ac.UnknownCharterError):
        ledger.evaluate("ghost", 1)
    ledger.declare("c", 1, stance="adopted")
    n = len(ledger.audit_log(1))
    rep = ledger.evaluate("c", 1)
    assert rep.posture == "adopted"
    assert rep.integrity_ok is True
    assert len(ledger.audit_log(1)) == n  # pure read: no audit rows
    rec = ledger.declaration_record("dcl-1", 1)
    object.__setattr__(rec, "stance", "withdrawn")
    rep2 = ledger.evaluate("c", 1)
    assert rep2.integrity_ok is False
    assert rep2.posture == "withdrawn"  # derived as data from tampered ledger
    assert rep2.verify() is True


# 10. retire terminality: bad reason, unknown, double-retire, id non-recycling
def test_retire_terminality():
    ledger = ac.AICharter()
    with pytest.raises(ac.UnknownCharterError):
        ledger.retire("ghost", 1)
    with pytest.raises(ac.BadReasonError):
        ledger.retire("c", 2, reason="vibes")
    ledger.declare("c", 3)
    ret = ledger.retire("c", 4, reason="superseded")
    assert ret.verify() is True
    assert ledger.retired_ids(4) == ("c",)
    # double retire refused
    with pytest.raises(ac.RetiredCharterError):
        ledger.retire("c", 5)
    # retired id never recycled for new declarations
    with pytest.raises(ac.RetiredCharterError):
        ledger.declare("c", 6)
    # reads still work post-retire
    rep = ledger.evaluate("c", 7)
    assert rep.posture == "adopted"
    assert ledger.declaration_record("dcl-1", 7).charter_id == "c"


# 11. seq discipline: rewind bare, malformed seqs, failed-mutation-consumes-seq
def test_seq_discipline():
    ledger = ac.AICharter()
    with pytest.raises(ac.SeqOrderError):
        ledger.declare("c", 0)  # genesis rewind: bare, zero rows
    assert len(ledger.audit_log(0)) == 0
    ledger.declare("c", 1)
    with pytest.raises(ac.SeqOrderError):
        ledger.declare("c", 1)  # rewind: raises bare, no rejected row
    assert ledger.stats(1)["seq"] == 1
    for bad_seq in (True, 1.5, "2", None):
        with pytest.raises(ac.SeqOrderError):
            ledger.declare("c", bad_seq)  # malformed seq: never burns
    assert ledger.stats(1)["seq"] == 1
    # read seq: negative malformed
    with pytest.raises(ac.SeqOrderError):
        ledger.evaluate("c", -1)


# 12. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    ledger = ac.AICharter()
    rec = ledger.declare("c", 1, commitment_kind="corrigibility", stance="adopted")
    row = ledger.audit_log(1)[0]
    assert row["schema"] == "audit.ndjson/1"
    assert row["module"] == "ai-charter"
    assert row["version"] == "ai-charter.v1"
    assert row["kind"] == "declared"
    assert row["details"]["declaration_id"] == rec.declaration_id
    # pinned vocab values cross the audit boundary as declared data
    assert row["details"]["commitment_kind"] == "corrigibility"
    # raw material keys are banned at the builder level
    for banned in ("charter_text", "statement", "transcript", "weights", "policy"):
        with pytest.raises(ac.AICharterError):
            ac.ai_charter_audit_event("declared", 2, **{banned: "raw"})
    with pytest.raises(ac.AuditKindError):
        ac.ai_charter_audit_event("nope", 2)
    # retired rows
    ledger.retire("c", 2)
    kinds = [r["kind"] for r in ledger.audit_log(2)]
    assert kinds == ["declared", "retired"]
    # rejected rows carry rejected_kind detail
    with pytest.raises(ac.BadStanceError):
        ledger.declare("x", 3, stance="bogus")
    assert ledger.audit_log(3)[-1]["kind"] == "rejected"
    assert ledger.audit_log(3)[-1]["details"]["rejected_kind"] == "BadStanceError"


# 13. cross-instance digest determinism + frozen-ness + 8-thread read smoke
def test_determinism_and_concurrency():
    def build():
        l = ac.AICharter()
        l.declare("c", 1, commitment_kind="fiduciary-duty", stance="provisional",
                  statement_digest=PIN)
        return l

    a, b = build(), build()
    assert a.declaration_record("dcl-1", 0).digest == b.declaration_record("dcl-1", 0).digest
    ledger = build()
    errors = []
    reps = []

    def reader():
        try:
            for _ in range(50):
                reps.append(ledger.evaluate("c", 1).posture)
                reps.append(ledger.verify("dcl-1", 1).verdict)
        except Exception as exc:  # pragma: no cover - must not happen
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert all(r in ("provisional", "verified") for r in reps)
    # frozen records stay frozen
    rec = ledger.declaration_record("dcl-1", 0)
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.digest = "x"  # type: ignore


# 14. views/stats/unknown lookups
def test_views_and_stats():
    ledger = ac.AICharter()
    assert ledger.charter_ids(0) == ()
    assert ledger.declaration_ids(0) == ()
    assert ledger.retired_ids(0) == ()
    assert ledger.declarations_for("ghost", 0) == ()
    with pytest.raises(ac.UnknownDeclarationError):
        ledger.declaration_record("dcl-1", 0)
    s0 = ledger.stats(0)
    assert s0["n_charters"] == 0 and s0["n_declarations"] == 0
    assert s0["n_retired"] == 0 and s0["n_audit_rows"] == 0
    ledger.declare("b", 1, stance="adopted")
    ledger.declare("a", 2, stance="withdrawn")
    assert ledger.charter_ids(2) == ("a", "b")
    assert ledger.declaration_ids(2) == ("dcl-1", "dcl-2")
    assert len(ledger.declarations_for("a", 2)) == 1
    assert ledger.declarations_for("a", 2)[0].stance == "withdrawn"
    s = ledger.stats(2)
    assert s["seq"] == 2
    assert s["n_charters"] == 2 and s["n_declarations"] == 2
    assert s["n_audit_rows"] == 2
    assert ledger.declaration_record("dcl-2", 2).verify() is True


# 15. main() subprocess check
def test_main_subprocess():
    proc = subprocess.run(
        [sys.executable, str(MOD)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0
    assert "ai-charter OK: declare, verify, evaluate, retire, pins, audit" in proc.stdout

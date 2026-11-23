"""Tests for the AI-concept extraction decision ledger, Simulated."""

import ast
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "ai_concept.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32
PIN3 = "sha256:" + "ef" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("ai_concept", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["ai_concept"] = module
    spec.loader.exec_module(module)
    return module


ac = _load()


def _fresh():
    return ac.AIConcept()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert ac.AI_CONCEPT_VERSION == "ai-concept.v1"
    assert ac.SCHEMA_PIN == "northstar.ai-concept.v1"
    assert ac.EXTRACTION_KINDS == (
        "activation-probe",
        "linear-probe",
        "sae-feature",
        "tcav-direction",
        "attention-probe",
        "neuron-cluster",
        "concept-bottleneck",
        "behavioral-probe",
    )
    assert ac.VERDICTS == (
        "concept-present",
        "concept-absent",
        "partial",
        "inconclusive",
        "not-examined",
    )
    assert ac.POSTURES == (
        "unexamined",
        "concept-laden",
        "contested",
        "partial",
        "concept-clean",
    )
    assert ac.RETIRE_REASONS == (
        "manual",
        "superseded",
        "decommissioned",
        "false-start",
    )
    assert set(ac.AUDIT_KINDS) == {
        "extracted",
        "retired",
        "rejected",
    }


# 2. stdlib-only AST check
def test_stdlib_only_ast():
    assert ac.stdlib_only() is True
    tree = ast.parse(MOD.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in {
                    "hashlib",
                    "threading",
                    "dataclasses",
                    "typing",
                    "__future__",
                    "ast",
                    "pathlib",
                    "json",
                    "canonical_json",
                }
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                assert node.module.split(".")[0] in {
                    "hashlib",
                    "threading",
                    "dataclasses",
                    "typing",
                    "__future__",
                    "ast",
                    "pathlib",
                    "json",
                    "canonical_json",
                }


# 3. extract roundtrip / cpt-N minting / verify() / frozen-ness
def test_extract_roundtrip_minting_frozen():
    ledger = _fresh()
    rec = ledger.extract(
        "sys-1",
        1,
        extraction_kind="sae-feature",
        verdict="concept-present",
        strength=77,
        concept_digest=PIN,
    )
    assert rec.extraction_id == "cpt-1"
    assert rec.system_id == "sys-1"
    assert rec.extraction_kind == "sae-feature"
    assert rec.verdict == "concept-present"
    assert rec.strength == 77
    assert rec.concept_digest == PIN
    assert rec.verify() is True
    assert rec.digest.startswith("sha256:")
    with pytest.raises(AttributeError):
        object.__setattr__  # sanity: dataclass is frozen below
        rec.verdict = "concept-absent"
    rec2 = ledger.extract(
        "sys-1", 2, extraction_kind="linear-probe", verdict="concept-absent",
        strength=0, concept_digest=PIN2,
    )
    assert rec2.extraction_id == "cpt-2"
    assert rec2.verify() is True
    assert ledger.extraction_ids(3) == ("cpt-1", "cpt-2")
    assert ledger.system_ids(4) == ("sys-1",)
    # defaults
    rec3 = ledger.extract("sys-2", 5, concept_digest=PIN3)
    assert rec3.extraction_kind == "activation-probe"
    assert rec3.verdict == "inconclusive"
    assert rec3.strength == 0
    assert rec3.verify() is True


# 4. bad-input table + seq-burn + rejected-row accounting + rewind-bare
def test_bad_input_seq_burn_rejected_rows():
    ledger = _fresh()
    good = dict(
        system_id="sys-1", extraction_kind="tcav-direction",
        verdict="concept-present", strength=50, concept_digest=PIN,
    )
    bad_cases = [
        dict(system_id=""),
        dict(system_id=123),
        dict(extraction_kind="no-such-kind"),
        dict(verdict="definitely-present"),
        dict(strength=-1),
        dict(strength=101),
        dict(strength=True),
        dict(strength=1.5),
        dict(concept_digest="not-a-pin"),
        dict(concept_digest="sha256:" + "zz" * 32),
    ]
    for i, bad in enumerate(bad_cases, start=1):
        params = dict(good)
        params.update(bad)
        params["seq"] = i
        with pytest.raises(ac.AIConceptError):
            ledger.extract(**params)
    assert ledger.stats(11)["rejected"] == len(bad_cases)
    # each failed mutation consumed its seq and booked a rejected row
    audit = ledger.audit_log(12)
    rejected = [row for row in audit if row["kind"] == "rejected"]
    assert len(rejected) == len(bad_cases)
    for row in rejected:
        assert row["schema"] == "audit.ndjson/1"
        assert row["details"]["method"] == "extract"
    # rewind raises bare with zero new rows
    before = len(ledger.audit_log(13))
    with pytest.raises(ac.SeqOrderError):
        ledger.extract("sys-1", 1, concept_digest=PIN)
    assert len(ledger.audit_log(14)) == before
    # genesis rewind: fresh ledger, seq 1 used, retry seq 1 bare
    ledger2 = _fresh()
    ledger2.extract("sys-1", 1, concept_digest=PIN)
    before2 = len(ledger2.audit_log(2))
    with pytest.raises(ac.SeqOrderError):
        ledger2.extract("sys-1", 1, concept_digest=PIN)
    assert len(ledger2.audit_log(3)) == before2


# 5. full 8-kind vocabulary
def test_full_extraction_kind_vocabulary():
    ledger = _fresh()
    for i, kind in enumerate(ac.EXTRACTION_KINDS, start=1):
        rec = ledger.extract(
            f"sys-{i}", i, extraction_kind=kind,
            verdict="concept-absent", strength=0, concept_digest=PIN,
        )
        assert rec.extraction_kind == kind
        assert rec.verify() is True
    assert ledger.stats(9)["systems"] == 8


# 6. full 5-verdict vocabulary + strength bounds
def test_full_verdict_vocabulary_and_strength_bounds():
    ledger = _fresh()
    for i, verdict in enumerate(ac.VERDICTS, start=1):
        rec = ledger.extract(
            "sys-1", i, extraction_kind="attention-probe",
            verdict=verdict, strength=0, concept_digest=PIN,
        )
        assert rec.verdict == verdict
    rec0 = ledger.extract("sys-2", 6, verdict="concept-present", strength=0, concept_digest=PIN)
    assert rec0.strength == 0
    rec100 = ledger.extract("sys-3", 7, verdict="concept-present", strength=100, concept_digest=PIN)
    assert rec100.strength == 100
    assert ledger.stats(8)["extractions"] == 7


# 7. verify semantics: verified/tampered-as-data/unknown refusal/read purity
def test_verify_semantics():
    ledger = _fresh()
    rec = ledger.extract(
        "sys-1", 1, extraction_kind="neuron-cluster",
        verdict="concept-present", strength=90, concept_digest=PIN,
    )
    report = ledger.verify("cpt-1", 2)
    assert report.verdict == "verified"
    assert report.extraction_id == "cpt-1"
    assert report.system_id == "sys-1"
    assert report.verify() is True
    # tamper is reported as data, never raised
    object.__setattr__(ledger._extractions["cpt-1"], "strength", 0)
    report2 = ledger.verify("cpt-1", 3)
    assert report2.verdict == "tampered"
    # unknown id refused
    with pytest.raises(ac.UnknownExtractionError):
        ledger.verify("cpt-999", 4)
    # read purity: no seq consumed, no audit row
    before = ledger._seq
    n_rows = len(ledger.audit_log(5))
    ledger.verify("cpt-1", 2)  # stale seq also fine for reads (shape only)
    assert ledger._seq == before
    assert len(ledger.audit_log(6)) == n_rows
    # malformed read seq still shape-checked
    with pytest.raises(ac.SeqOrderError):
        ledger.verify("cpt-1", 0)


# 8. evaluate posture math: all postures + precedence
def test_evaluate_posture_math():
    ledger = _fresh()
    ledger.extract("laden", 1, verdict="concept-absent", strength=0, concept_digest=PIN)
    ledger.extract("laden", 2, verdict="concept-present", strength=60, concept_digest=PIN)
    ev = ledger.evaluate("laden", 3)
    assert ev.posture == "concept-laden"
    assert ev.n_extractions == 2
    assert ev.n_present == 1
    assert ev.n_absent == 1
    assert ev.verify() is True
    assert ev.integrity_ok is True

    ledger.extract("contested", 4, verdict="inconclusive", strength=0, concept_digest=PIN)
    ledger.extract("contested", 5, verdict="partial", strength=10, concept_digest=PIN)
    ev2 = ledger.evaluate("contested", 6)
    assert ev2.posture == "contested"  # inconclusive outranks partial

    ledger.extract("partial", 7, verdict="partial", strength=10, concept_digest=PIN)
    ev3 = ledger.evaluate("partial", 8)
    assert ev3.posture == "partial"

    ledger.extract("partial2", 9, verdict="not-examined", strength=0, concept_digest=PIN)
    ev3b = ledger.evaluate("partial2", 10)
    assert ev3b.posture == "partial"

    ledger.extract("clean", 11, verdict="concept-absent", strength=0, concept_digest=PIN)
    ledger.extract("clean", 12, verdict="concept-absent", strength=0, concept_digest=PIN)
    ev4 = ledger.evaluate("clean", 13)
    assert ev4.posture == "concept-clean"
    assert ev4.n_absent == 2

    # present outranks inconclusive
    ledger.extract("mixed", 14, verdict="inconclusive", strength=0, concept_digest=PIN)
    ledger.extract("mixed", 15, verdict="concept-present", strength=5, concept_digest=PIN)
    ev5 = ledger.evaluate("mixed", 16)
    assert ev5.posture == "concept-laden"

    # tamper flips integrity_ok as data
    object.__setattr__(ledger._extractions["cpt-1"], "strength", 1)
    ev6 = ledger.evaluate("laden", 17)
    assert ev6.integrity_ok is False
    assert ev6.verify() is True


# 9. evaluate read purity + unknown-system refusal
def test_evaluate_read_purity_and_unknown_system():
    ledger = _fresh()
    ledger.extract("sys-1", 1, verdict="concept-absent", strength=0, concept_digest=PIN)
    before = ledger._seq
    n_rows = len(ledger.audit_log(2))
    ev = ledger.evaluate("sys-1", 2)  # same seq twice is fine for reads
    assert ev.posture == "concept-clean"
    ledger.evaluate("sys-1", 2)
    assert ledger._seq == before
    assert len(ledger.audit_log(3)) == n_rows
    with pytest.raises(ac.UnknownSystemError):
        ledger.evaluate("ghost", 4)


# 10. retire terminality + id non-recycling + bad reason + post-retire reads
def test_retire_terminality():
    ledger = _fresh()
    ledger.extract("sys-1", 1, verdict="concept-present", strength=50, concept_digest=PIN)
    with pytest.raises(ac.BadReasonError):
        ledger.retire("sys-1", 2, reason="explode")
    rec = ledger.retire("sys-1", 3, reason="manual")
    assert rec.system_id == "sys-1"
    assert rec.reason == "manual"
    assert rec.verify() is True
    assert ledger.retired_ids(4) == ("sys-1",)
    # double-retire refused, ids never recycled
    with pytest.raises(ac.RetiredSystemError):
        ledger.retire("sys-1", 5, reason="superseded")
    # post-retire mutations refused
    with pytest.raises(ac.RetiredSystemError):
        ledger.extract("sys-1", 6, verdict="concept-absent", strength=0, concept_digest=PIN)
    # post-retire reads still work
    assert ledger.verify("cpt-1", 7).verdict == "verified"
    assert ledger.evaluate("sys-1", 8).posture == "concept-laden"
    assert ledger.extraction_record("cpt-1", 9).verdict == "concept-present"
    # retiring an unknown system refused
    with pytest.raises(ac.UnknownSystemError):
        ledger.retire("ghost", 10, reason="manual")


# 11. seq discipline: malformed seqs, failed-mutation-consumes-seq
def test_seq_discipline():
    ledger = _fresh()
    for bad in (0, -1, 1.5, "2", True, None):
        with pytest.raises(ac.SeqOrderError):
            ledger.extract("sys-1", bad, verdict="concept-absent", strength=0, concept_digest=PIN)
    # failed mutation consumes the seq
    with pytest.raises(ac.BadVerdictError):
        ledger.extract("sys-1", 1, verdict="bogus", strength=0, concept_digest=PIN)
    rec = ledger.extract("sys-1", 2, verdict="concept-absent", strength=0, concept_digest=PIN)
    assert rec.extraction_id == "cpt-1"


# 12. audit shapes + leak ban + bad-kind
def test_audit_shapes_leak_ban_bad_kind():
    ledger = _fresh()
    ledger.extract(
        "sys-1", 1, extraction_kind="behavioral-probe",
        verdict="concept-present", strength=10, concept_digest=PIN,
    )
    ledger.retire("sys-1", 2, reason="superseded")
    with pytest.raises(ac.AIConceptError):
        ledger.extract("sys-1", 3, verdict="concept-absent", strength=0, concept_digest=PIN)
    rows = ledger.audit_log(4)
    kinds = [row["kind"] for row in rows]
    assert kinds == ["extracted", "retired", "rejected"]
    for row in rows:
        assert row["schema"] == "audit.ndjson/1"
        assert isinstance(row["seq"], int)
        assert isinstance(row["details"], dict)
    extracted = rows[0]["details"]
    assert extracted["extraction_id"] == "cpt-1"
    assert extracted["extraction_kind"] == "behavioral-probe"
    assert extracted["verdict"] == "concept-present"
    assert extracted["strength"] == 10
    # pinned vocab values emittable; raw material keys banned
    for banned in (
        "activation", "activations", "weights", "model_weights", "neurons",
        "attention", "concept_vectors", "probe_trace", "transcript",
        "prompt", "evidence", "score", "raw", "secret", "key",
    ):
        with pytest.raises(ac.AuditKindError):
            ac.ai_concept_audit_event("extracted", 9, **{banned: "x"})
    with pytest.raises(ac.AuditKindError):
        ac.ai_concept_audit_event("bogus-kind", 9, system_id="s")
    with pytest.raises(ac.SeqOrderError):
        ac.ai_concept_audit_event("extracted", -1)


# 13. views/stats + unknown lookups
def test_views_stats_unknown_lookups():
    ledger = _fresh()
    assert ledger.stats(1) == {
        "systems": 0,
        "extractions": 0,
        "retired": 0,
        "rejected": 0,
    }
    ledger.extract("a", 1, verdict="concept-present", strength=10, concept_digest=PIN)
    ledger.extract("b", 2, verdict="concept-absent", strength=0, concept_digest=PIN2)
    assert ledger.extractions_for("a", 3) == ("cpt-1",)
    assert ledger.extractions_for("b", 4) == ("cpt-2",)
    assert ledger.system_ids(5) == ("a", "b")
    assert ledger.stats(6)["extractions"] == 2
    with pytest.raises(ac.UnknownExtractionError):
        ledger.extraction_record("cpt-999", 7)
    with pytest.raises(ac.UnknownSystemError):
        ledger.extractions_for("ghost", 8)
    with pytest.raises(ac.BadIdError):
        ledger.extraction_record("", 9)


# 14. cross-instance digest determinism + 8-thread read smoke + frozen-ness
def test_cross_instance_determinism_and_thread_safety():
    l1 = _fresh()
    l2 = _fresh()
    r1 = l1.extract("sys", 1, extraction_kind="sae-feature", verdict="partial",
                    strength=33, concept_digest=PIN)
    r2 = l2.extract("sys", 1, extraction_kind="sae-feature", verdict="partial",
                    strength=33, concept_digest=PIN)
    assert r1.digest == r2.digest
    assert r1.verify() is True
    # frozen record
    with pytest.raises(Exception):
        r1.strength = 99
    # 8-thread concurrent pure reads
    errors = []

    def read_many():
        try:
            for _ in range(200):
                l1.evaluate("sys", 2)
                l1.verify("cpt-1", 3)
                l1.audit_log(4)
                l1.stats(5)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=read_many) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert l1.stats(6)["extractions"] == 1


# 15. main() subprocess self-check
def test_main_subprocess():
    import subprocess

    proc = subprocess.run(
        [sys.executable, str(MOD)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0
    assert "ai-concept OK: extract, verify, evaluate, retire, pins, audit" in proc.stdout

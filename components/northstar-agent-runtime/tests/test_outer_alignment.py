"""Tests for the outer-alignment governance ledger (Simulated)."""

import ast
import dataclasses
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "outer_alignment.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("outer_alignment", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["outer_alignment"] = module
    spec.loader.exec_module(module)
    return module


oa = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert oa.OUTER_ALIGNMENT_VERSION == "outer-alignment.v1"
    assert oa.SCHEMA_PIN == "northstar.outer-alignment.v1"
    assert oa.OBJECTIVE_KINDS == (
        "reward-model",
        "preference-model",
        "hand-coded-reward",
        "demonstration-loss",
        "instruction-following",
        "constrained-optimization",
        "oversight-signal",
        "market-mechanism",
    )
    assert oa.COVERAGE_CLAIMS == ("full", "partial", "unknown")
    assert oa.RETIRE_REASONS == (
        "manual",
        "system-superseded",
        "objective-redesigned",
        "invalidated",
    )
    assert oa.POSTURES == (
        "unspecified",
        "coverage-contested",
        "gap-declared",
        "unknown-coverage",
        "declared-complete",
    )
    assert oa.AUDIT_KINDS == ("specified", "retired", "rejected")


# 2. stdlib-only AST check
def test_stdlib_only():
    tree = ast.parse(MOD.read_text())
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    allowed = {
        "hashlib",
        "json",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "canonical_json",
        "ast",
        "pathlib",
    }
    assert imports <= allowed, imports - allowed
    assert oa.OuterAlignment.stdlib_only()


# 3. specify roundtrip / minting / frozen-ness
def test_specify_roundtrip():
    o = oa.OuterAlignment()
    r1 = o.specify(
        "SYS-1", 1, objective_kind="reward-model", coverage="partial", spec_digest=PIN
    )
    r2 = o.specify(
        "SYS-1",
        2,
        objective_kind="preference-model",
        coverage="full",
        constraint_digest=PIN2,
    )
    assert r1.specification_id == "spc-1"
    assert r2.specification_id == "spc-2"
    assert r1.system_id == "SYS-1" and r2.system_id == "SYS-1"
    assert r1.verify() and r2.verify()
    assert r1.as_dict()["digest"] == r1.digest
    for rec in (r1, r2):
        with pytest.raises(dataclasses.FrozenInstanceError):
            rec.coverage = "full"  # type: ignore
    # records are re-fetchable by id
    assert o.specification_record("spc-1", 0) == r1
    assert o.specifications_for("SYS-1", 0) == ("spc-1", "spc-2")
    # audit rows are digest-pin only
    for row in o.audit_log(0):
        assert row["schema"] == "audit.ndjson/1"
        flat = str(row["details"])
        assert "ab" * 32 not in flat and "cd" * 32 not in flat


# 4. specify bad-input table + seq-burn + rejected-row accounting
def test_specify_bad_inputs():
    o = oa.OuterAlignment()
    o.specify("SYS", 1)
    bad_calls = [
        dict(system_id="", seq=2),
        dict(system_id=None, seq=2),  # type: ignore
        dict(system_id="x" * 129, seq=2),
        dict(system_id="SYS", seq=2, objective_kind="mind-reading"),
        dict(system_id="SYS", seq=2, coverage="total"),
        dict(system_id="SYS", seq=2, spec_digest="nope"),
        dict(system_id="SYS", seq=2, spec_digest="sha256:" + "zz" * 32),
        dict(system_id="SYS", seq=2, spec_digest="sha256:abc"),
        dict(system_id="SYS", seq=2, constraint_digest="sha256:" + "zz" * 32),
    ]
    seq = 2
    for kwargs in bad_calls:
        kwargs["seq"] = seq
        with pytest.raises(oa.OuterAlignmentError):
            o.specify(**kwargs)  # type: ignore
        # claim-then-burn: failed mutation consumed its seq
        assert o.stats(0)["seq"] == seq
        seq += 1
    rejected = [r for r in o.audit_log(0) if r["kind"] == "rejected"]
    assert len(rejected) == len(bad_calls)
    assert all(r["details"]["rejected_kind"] == "specify" for r in rejected)
    assert o.stats(0)["rejected"] == len(bad_calls)
    # the burned seqs cannot be reused by valid calls
    o.specify("SYS", seq)
    assert o.stats(0)["specifications"] == 2


# 5. full objective-kind vocabulary acceptance
def test_objective_kind_vocabulary():
    o = oa.OuterAlignment()
    seq = 0
    for i, kind in enumerate(oa.OBJECTIVE_KINDS):
        seq += 1
        r = o.specify(f"SYS-{i}", seq, objective_kind=kind, coverage="unknown")
        assert r.verify()
        assert r.objective_kind == kind
    assert o.stats(0)["specifications"] == 8
    kinds_in_audit = {
        row["details"]["objective_kind"]
        for row in o.audit_log(0)
        if row["kind"] == "specified"
    }
    assert kinds_in_audit == set(oa.OBJECTIVE_KINDS)


# 6. full coverage vocabulary acceptance
def test_coverage_vocabulary():
    o = oa.OuterAlignment()
    seq = 0
    for i, claim in enumerate(oa.COVERAGE_CLAIMS):
        seq += 1
        r = o.specify("SYS", seq, coverage=claim)
        assert r.verify()
        assert r.coverage == claim
    assert o.evaluate("SYS", 0).coverage_tally == (
        ("full", 1),
        ("partial", 1),
        ("unknown", 1),
    )
    assert o.evaluate("SYS", 0).posture == "coverage-contested"


# 7. verify semantics: roundtrip, tamper-as-data, unknown, read purity
def test_verify_semantics():
    o = oa.OuterAlignment()
    r = o.specify("SYS", 1, coverage="full", spec_digest=PIN)
    v = o.verify("spc-1", 0)
    assert v.verdict == "verified" and v.integrity_ok is True
    assert v.verify() and v.specification_id == "spc-1"
    # tamper is reported as data, never raised
    object.__setattr__(r, "coverage", "partial")
    assert r.verify() is False
    v2 = o.verify("spc-1", 0)
    assert v2.verdict == "tampered" and v2.integrity_ok is False
    assert v2.verify()
    assert o.evaluate("SYS", 0).integrity_ok is False
    # unknown ids raise, pure reads add no audit rows
    before = o.stats(0)["audit_rows"]
    with pytest.raises(oa.UnknownSpecificationError):
        o.verify("spc-999", 0)
    o.verify("spc-1", 0)
    assert o.stats(0)["audit_rows"] == before
    # verify is a pure read: same seq twice, no consumption
    o.verify("spc-1", 5)
    o.verify("spc-1", 5)
    assert o.stats(0)["audit_rows"] == before


# 8. evaluate posture math: all reachable postures + precedence + unknown
def test_evaluate_posture_math():
    o = oa.OuterAlignment()
    o.specify("A", 1, coverage="full")
    assert o.evaluate("A", 0).posture == "declared-complete"
    o.specify("B", 2, coverage="partial")
    assert o.evaluate("B", 0).posture == "gap-declared"
    o.specify("C", 3, coverage="unknown")
    assert o.evaluate("C", 0).posture == "unknown-coverage"
    # full + partial -> contested (contested outranks gap-declared)
    o.specify("D", 4, coverage="full")
    o.specify("D", 5, coverage="partial")
    assert o.evaluate("D", 0).posture == "coverage-contested"
    # full + unknown -> contested
    o.specify("E", 6, coverage="full")
    o.specify("E", 7, coverage="unknown")
    assert o.evaluate("E", 0).posture == "coverage-contested"
    # partial + unknown (no full) -> gap-declared
    o.specify("F", 8, coverage="partial")
    o.specify("F", 9, coverage="unknown")
    assert o.evaluate("F", 0).posture == "gap-declared"
    # all-unknown stays unknown-coverage
    o.specify("G", 10, coverage="unknown")
    o.specify("G", 11, coverage="unknown")
    assert o.evaluate("G", 0).posture == "unknown-coverage"
    # reports are digest-pinned
    assert o.evaluate("A", 0).verify()
    # unknown system raises (pure read, no burn)
    before = o.stats(0)["rejected"]
    with pytest.raises(oa.UnknownSystemError):
        o.evaluate("ZZZ", 0)
    assert o.stats(0)["rejected"] == before


# 9. evaluate read purity
def test_evaluate_read_purity():
    o = oa.OuterAlignment()
    o.specify("SYS", 1, coverage="partial", spec_digest=PIN)
    before = o.stats(0)["audit_rows"]
    e1 = o.evaluate("SYS", 0)
    e2 = o.evaluate("SYS", 0)
    assert e1 == e2
    assert e1.posture == "gap-declared"
    assert e1.n_specifications == 1
    assert o.stats(0)["audit_rows"] == before
    # read seq shape validated but never consumed
    o.evaluate("SYS", 999)
    assert o.stats(0)["seq"] == 1
    with pytest.raises(oa.SeqOrderError):
        o.evaluate("SYS", -1)
    with pytest.raises(oa.SeqOrderError):
        o.evaluate("SYS", True)  # type: ignore


# 10. retire terminality
def test_retire_terminality():
    o = oa.OuterAlignment()
    o.specify("SYS", 1, coverage="full")
    # bad reason burns, unknown system burns
    with pytest.raises(oa.BadReasonError):
        o.retire("SYS", 2, reason="nope")
    with pytest.raises(oa.UnknownSystemError):
        o.retire("GHOST", 3)
    assert o.stats(0)["rejected"] == 2
    rec = o.retire("SYS", 4, reason="objective-redesigned")
    assert rec.verify()
    assert o.retired_ids(0) == ("SYS",)
    # ids are never recycled
    with pytest.raises(oa.RetiredSystemError):
        o.specify("SYS", 5)
    with pytest.raises(oa.RetiredSystemError):
        o.retire("SYS", 6)
    # mint counter never resets: next spec on a live system keeps climbing
    o.specify("SYS2", 7)
    assert o.specify("SYS2", 8).specification_id == "spc-3"
    # reads still work post-retire
    assert o.evaluate("SYS", 0).posture == "declared-complete"
    assert o.specification_record("spc-1", 0).system_id == "SYS"
    assert o.stats(0)["retired"] == 1


# 11. seq discipline
def test_seq_discipline():
    o = oa.OuterAlignment()
    # malformed seqs never claim, never burn
    for bad in (True, 1.5, "3", None, [1], {"a": 1}):
        with pytest.raises(oa.SeqOrderError):
            o.specify("SYS", bad)  # type: ignore
    assert o.stats(0)["seq"] == 0
    assert o.stats(0)["rejected"] == 0
    o.specify("SYS", 1)
    # rewind raises bare with zero audit rows, seq untouched
    rows_before = o.stats(0)["audit_rows"]
    with pytest.raises(oa.SeqOrderError):
        o.specify("SYS", 1)
    with pytest.raises(oa.SeqOrderError):
        o.specify("SYS", 0)
    assert o.stats(0)["audit_rows"] == rows_before
    assert o.stats(0)["seq"] == 1
    # retire also follows claim-then-burn
    with pytest.raises(oa.BadReasonError):
        o.retire("SYS", 2, reason="bogus")
    assert o.stats(0)["seq"] == 2
    assert o.stats(0)["rejected"] == 1


# 12. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    o = oa.OuterAlignment()
    o.specify("SYS", 1, coverage="full", spec_digest=PIN)
    o.retire("SYS", 2)
    rows = o.audit_log(0)
    assert [r["kind"] for r in rows] == ["specified", "retired"]
    for row in rows:
        assert row["schema"] == "audit.ndjson/1"
        assert isinstance(row["seq"], int) and row["seq"] >= 0
        assert isinstance(row["details"], dict)
    # pinned vocabulary values remain emittable as declared data
    assert rows[0]["details"]["objective_kind"] == "reward-model"
    assert rows[0]["details"]["coverage"] == "full"
    # banned raw keys are rejected at the builder for every audit kind
    for key in sorted(oa._BANNED_AUDIT_KEYS):
        for kind in oa.AUDIT_KINDS:
            with pytest.raises(oa.AuditKindError):
                oa.outer_alignment_audit_event(kind, 9, **{key: "x"})
    # unknown audit kind and bad audit seq
    with pytest.raises(oa.AuditKindError):
        oa.outer_alignment_audit_event("nope", 9)
    with pytest.raises(oa.SeqOrderError):
        oa.outer_alignment_audit_event("specified", -1)
    with pytest.raises(oa.SeqOrderError):
        oa.outer_alignment_audit_event("specified", True)  # type: ignore


# 13. determinism + frozen-ness + thread smoke
def test_determinism_tamper_and_thread_smoke():
    def build():
        x = oa.OuterAlignment()
        x.specify("SYS", 1, objective_kind="constrained-optimization", coverage="full", spec_digest=PIN)
        x.specify("SYS", 2, objective_kind="oversight-signal", coverage="full", constraint_digest=PIN2)
        return x

    a, b = build(), build()
    assert a.specification_record("spc-1", 0).digest == b.specification_record("spc-1", 0).digest
    assert a.evaluate("SYS", 0).digest == b.evaluate("SYS", 0).digest
    # tamper breaks verify() as data
    rec = a.specification_record("spc-2", 0)
    object.__setattr__(rec, "constraint_digest", PIN)
    assert rec.verify() is False
    assert a.evaluate("SYS", 0).integrity_ok is False
    # all record types are frozen
    for frozen_rec in (
        rec,
        a.retire("SYS", 3),
        a.evaluate("SYS", 0),
        a.verify("spc-1", 0),
    ):
        with pytest.raises(dataclasses.FrozenInstanceError):
            frozen_rec.seq = -1  # type: ignore
    # 8-thread pure-read smoke
    results = []
    errors = []

    def reader():
        try:
            for _ in range(25):
                results.append(a.evaluate("SYS", 0).posture)
                a.verify("spc-1", 0)
                a.system_ids(0)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert len(results) == 200
    assert all(r == "declared-complete" for r in results)


# 14. views and stats
def test_views_and_stats():
    o = oa.OuterAlignment()
    o.specify("SYS-A", 1, coverage="full")
    o.specify("SYS-B", 2, coverage="partial")
    o.specify("SYS-A", 3, coverage="unknown")
    assert o.system_ids(0) == ("SYS-A", "SYS-B")
    assert o.specification_ids(0) == ("spc-1", "spc-2", "spc-3")
    assert o.specifications_for("SYS-A", 0) == ("spc-1", "spc-3")
    assert o.retired_ids(0) == ()
    st = o.stats(0)
    assert st["systems"] == 2
    assert st["specifications"] == 3
    assert st["retired"] == 0
    assert st["rejected"] == 0
    assert st["audit_rows"] == 3
    assert st["seq"] == 3
    # unknown lookups raise on pure reads
    with pytest.raises(oa.UnknownSystemError):
        o.specifications_for("NOPE", 0)
    with pytest.raises(oa.UnknownSpecificationError):
        o.specification_record("spc-404", 0)
    with pytest.raises(oa.BadIdError):
        o.specification_record("", 0)


# 15. main() self-check via subprocess
def test_main_self_check():
    r = subprocess.run(
        [sys.executable, str(MOD)], capture_output=True, text=True, timeout=60
    )
    assert r.returncode == 0, r.stderr
    assert "outer-alignment OK: specify, evaluate, verify, pins, audit" in r.stdout

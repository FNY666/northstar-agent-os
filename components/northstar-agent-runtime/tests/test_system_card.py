"""Tests for the system-card decision ledger, Simulated."""

import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "system_card.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("system_card", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["system_card"] = module
    spec.loader.exec_module(module)
    return module


sc = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert sc.SYSTEM_CARD_VERSION == "system-card.v1"
    assert sc.SCHEMA_PIN == "northstar.system-card.v1"
    assert sc.DIMENSIONS == (
        "capability-evaluation",
        "red-teaming",
        "alignment-evaluation",
        "safety-evaluation",
        "security-evaluation",
        "benchmark",
    )
    assert sc.OUTCOMES == ("pass", "fail", "conditional", "not-assessed")
    assert sc.CHANNELS == ("internal", "external", "regulatory")
    assert sc.VISIBILITIES == ("internal", "partner", "public")


# 2. stdlib-only AST check
def test_stdlib_only():
    tree = ast.parse(MOD.read_text())
    allowed = {
        "hashlib",
        "json",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "canonical_json",
    }
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    assert imports <= allowed, imports - allowed


# 3. create roundtrip + verify + frozen
def test_create_roundtrip():
    ledger = sc.SystemCard()
    record = ledger.create("card-1", 1, model_digest=PIN, version="v1")
    assert record.card_id == "card-1"
    assert record.model_digest == PIN
    assert record.version == "v1"
    assert record.verify()
    assert record.as_dict()["schema"] == "northstar.system-card.v1"
    assert ledger.card_record(1, "card-1") is record
    with pytest.raises(Exception):
        record.card_id = "nope"


# 4. create bad-input table + duplicate + seq-burn + rejected rows
def test_create_bad_inputs():
    ledger = sc.SystemCard()
    seq = 0
    n_rejected = 0
    for bad_id, kwargs in [
        ("", {}),
        (None, {}),
        ("x" * 129, {}),
        (123, {}),
        ("card-ok", {"model_digest": "nope"}),
        ("card-ok", {"model_digest": "sha256:" + "zz" * 32}),
        ("card-ok", {"model_digest": "sha256:" + "ab" * 31}),
        ("card-ok", {"version": "v" * 65}),
    ]:
        seq += 1
        with pytest.raises(sc.SystemCardError):
            ledger.create(bad_id, seq, **kwargs)
        n_rejected += 1
    ledger.create("card-a", seq + 1, version="v2")
    n_rejected += 0
    seq += 2
    with pytest.raises(sc.DuplicateCardError):
        ledger.create("card-a", seq)
    n_rejected += 1
    rows = ledger.audit_log(seq)
    assert sum(1 for r in rows if r["kind"] == "rejected") == n_rejected
    # failed mutations consumed their seqs
    with pytest.raises(sc.SeqOrderError):
        ledger.create("card-b", seq)


# 5. assess roundtrip + minted ids + verify
def test_assess_roundtrip():
    ledger = sc.SystemCard()
    ledger.create("card-1", 1)
    a1 = ledger.assess("card-1", 2, dimension="red-teaming", outcome="pass",
                       detail_digest=PIN)
    a2 = ledger.assess("card-1", 3, dimension="safety-evaluation",
                       outcome="conditional", detail_digest=PIN2)
    assert a1.assessment_id == "asm-1"
    assert a2.assessment_id == "asm-2"
    assert a1.verify() and a2.verify()
    assert ledger.assessments_for(3, "card-1") == ("asm-1", "asm-2")
    assert ledger.assessment_record(3, "asm-1") is a1


# 6. assess bad-input table + seq-burn
def test_assess_bad_inputs():
    ledger = sc.SystemCard()
    ledger.create("card-1", 1)
    n_rejected = 0
    seq = 1
    for card, kwargs in [
        ("nope", {}),
        ("card-1", {"dimension": "vibes"}),
        ("card-1", {"outcome": "maybe"}),
        ("card-1", {"detail_digest": "junk"}),
        ("", {}),
    ]:
        seq += 1
        with pytest.raises(sc.SystemCardError):
            ledger.assess(card, seq, **kwargs)
        n_rejected += 1
    rows = ledger.audit_log(seq)
    assert sum(1 for r in rows if r["kind"] == "rejected") == n_rejected


# 7. full dimension x outcome vocabulary acceptance
def test_full_dimension_outcome_vocabulary():
    ledger = sc.SystemCard()
    ledger.create("card-1", 1)
    seq = 1
    for dim in sc.DIMENSIONS:
        for out in sc.OUTCOMES:
            seq += 1
            rec = ledger.assess("card-1", seq, dimension=dim, outcome=out)
            assert rec.verify()
    assert ledger.stats(seq)["assessments"] == len(sc.DIMENSIONS) * len(sc.OUTCOMES)


# 8. publish roundtrip + verify + terminality (retired ids never recycled)
def test_publish_terminality():
    ledger = sc.SystemCard()
    ledger.create("card-1", 1)
    ledger.assess("card-1", 2)
    pub = ledger.publish("card-1", 3, channel="external", visibility="public")
    assert pub.publication_id == "pub-1"
    assert pub.verify()
    assert ledger.published_ids(3) == ("card-1",)
    assert ledger.retired_ids(3) == ("card-1",)
    seq = 4
    for op in [
        lambda: ledger.create("card-1", seq),
        lambda: ledger.assess("card-1", seq + 1),
        lambda: ledger.publish("card-1", seq + 2),
    ]:
        with pytest.raises(sc.RetiredCardError):
            op()


# 9. publish refusals
def test_publish_refusals():
    ledger = sc.SystemCard()
    with pytest.raises(sc.UnknownCardError):
        ledger.publish("ghost", 1)
    ledger.create("card-1", 2)
    with pytest.raises(sc.NoAssessmentError):
        ledger.publish("card-1", 3)
    with pytest.raises(sc.BadChannelError):
        ledger.publish("card-1", 4, channel="carrier-pigeon")
    with pytest.raises(sc.BadVisibilityError):
        ledger.publish("card-1", 5, visibility="worldwide")
    ledger.assess("card-1", 6)
    ledger.publish("card-1", 7)
    with pytest.raises(sc.RetiredCardError):
        ledger.publish("card-1", 8)


# 10. seq discipline: rewind bare, malformed seqs, failed-mutation-consumes-seq
def test_seq_discipline():
    ledger = sc.SystemCard()
    ledger.create("card-1", 1)
    # rewind raises bare with no rejected row and no seq consumption
    with pytest.raises(sc.SeqOrderError):
        ledger.create("card-x", 1)
    rows = ledger.audit_log(1)
    assert all(r["kind"] != "rejected" for r in rows)
    for bad in [True, "2", None, -1, 0]:
        with pytest.raises(sc.SeqOrderError):
            ledger.assess("card-1", bad)
    # failed mutation consumes its seq
    with pytest.raises(sc.BadDimensionError):
        ledger.assess("card-1", 2, dimension="vibes")
    with pytest.raises(sc.SeqOrderError):
        ledger.assess("card-1", 2)
    rows = ledger.audit_log(3)
    assert sum(1 for r in rows if r["kind"] == "rejected") == 1


# 11. view read-purity: same-seq reads, no audit rows, no seq consumption
def test_view_read_purity():
    ledger = sc.SystemCard()
    ledger.create("card-1", 1, version="v1")
    ledger.assess("card-1", 2, outcome="pass")
    before = len(ledger.audit_log(2))
    # same seq reused across reads; nothing consumed, no rows written
    assert ledger.card_record(2, "card-1").card_id == "card-1"
    assert ledger.card_ids(2) == ("card-1",)
    assert ledger.assessments_for(2, "card-1") == ("asm-1",)
    assert ledger.stats(2)["cards"] == 1
    report = ledger.status(2)
    assert report.verify()
    assert report.n_cards == 1 and report.n_assessments == 1
    assert report.n_published == 0 and report.integrity_ok
    assert len(ledger.audit_log(2)) == before
    # unknown ids refuse, still no rows
    with pytest.raises(sc.UnknownCardError):
        ledger.card_record(2, "ghost")
    assert len(ledger.audit_log(2)) == before


# 12. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    ledger = sc.SystemCard()
    ledger.create("card-1", 1, model_digest=PIN)
    ledger.assess("card-1", 2, outcome="pass")
    ledger.publish("card-1", 3)
    rows = ledger.audit_log(3)
    kinds = [r["kind"] for r in rows]
    assert kinds == ["created", "assessed", "published"]
    for r in rows:
        assert r["schema"] == "audit.ndjson/1"
        for banned in ("model", "weights", "text", "secret", "prompt",
                       "capability", "score"):
            assert banned not in r["details"]
    with pytest.raises(sc.AuditKindError):
        sc.system_card_audit_event("bogus", 1)
    with pytest.raises(sc.AuditKindError):
        sc.system_card_audit_event("created", 1, weights="raw")


# 13. cross-instance digest determinism + tamper breaks verify
def test_digest_determinism_and_tamper():
    l1, l2 = sc.SystemCard(), sc.SystemCard()
    r1 = l1.create("card-1", 1, model_digest=PIN, version="v1")
    r2 = l2.create("card-1", 1, model_digest=PIN, version="v1")
    assert r1.digest == r2.digest
    a1 = l1.assess("card-1", 2, dimension="benchmark", outcome="pass")
    l2.assess("card-1", 2, dimension="benchmark", outcome="pass")
    assert a1.verify()
    object.__setattr__(a1, "outcome", "fail")
    assert not a1.verify()
    report = l1.status(2)
    # tamper is reported as data: digest still pins integrity_ok=False
    assert not report.integrity_ok
    assert report.verify()


# 14. stats + frozen-ness + thread read smoke
def test_stats_and_concurrency():
    ledger = sc.SystemCard()
    ledger.create("card-1", 1)
    ledger.assess("card-1", 2)
    ledger.assess("card-1", 3)
    ledger.publish("card-1", 4)
    stats = ledger.stats(4)
    assert stats == {"cards": 1, "assessments": 2, "publications": 1,
                     "retired": 1, "rejected": 0}
    rec = ledger.card_record(4, "card-1")
    try:
        rec.version = "v9"
        assert False, "frozen dataclass must refuse assignment"
    except Exception:
        pass

    def read_many():
        for _ in range(50):
            ledger.stats(4)
            ledger.card_ids(4)

    threads = [threading.Thread(target=read_many) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


# 15. main() subprocess check + standalone import
def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, str(MOD)], capture_output=True, text=True, timeout=60,
        cwd=str(MOD.parent),
    )
    assert proc.returncode == 0, proc.stderr
    assert "system-card OK: create, assess, publish, pins, audit" in proc.stdout

"""Tests for the model-card transparency decision ledger, Simulated."""

import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "model_card.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32
PIN3 = "sha256:" + "ef" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("model_card", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["model_card"] = module
    spec.loader.exec_module(module)
    return module


mc = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert mc.MODEL_CARD_VERSION == "model-card.v1"
    assert mc.SCHEMA_PIN == "northstar.model-card.v1"
    assert mc.INTENDED_USES == (
        "classification",
        "generation",
        "recommendation",
        "detection",
        "decision-support",
        "research",
    )
    assert mc.LIMITATIONS == (
        "data-bias",
        "domain-shift",
        "language-limits",
        "adversarial-vulnerability",
        "compute-cost",
        "privacy-risk",
        "label-noise",
        "out-of-scope-use",
    )
    assert set(mc.AUDIT_KINDS) == {"created", "published", "rejected"}


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
    ledger = mc.ModelCard()
    record = ledger.create(
        "card-1", 1, model_id="model-1", intended_use="classification",
        limitations=("data-bias",), metrics=(("accuracy", 0.92),),
        model_digest=PIN, training_digest=PIN2, eval_digest=PIN3,
        version_label="1.0.0",
    )
    assert record.card_id == "card-1"
    assert record.model_id == "model-1"
    assert record.verify()
    assert ledger.card_record(1, "card-1") is record
    assert record.digest.startswith("sha256:")
    with pytest.raises(Exception):
        record.card_id = "card-2"
    assert record.as_dict()["schema"] == "northstar.model-card.v1"


# 4. create bad-input table + seq-burn + rejected rows
def test_create_bad_inputs():
    ledger = mc.ModelCard()
    seq = 0
    n_rejected = 0
    bad_cases = [
        ({"card_id": "", "model_id": "m"}, mc.BadIdError),
        ({"card_id": "c-x", "model_id": ""}, mc.BadIdError),
        ({"card_id": "c-x", "model_id": "m", "intended_use": "bad-use"}, mc.BadUseError),
        ({"card_id": "c-x", "model_id": "m", "limitations": ("nope",)}, mc.BadLimitationError),
        ({"card_id": "c-x", "model_id": "m", "limitations": ["data-bias", "data-bias"]}, mc.BadLimitationError),
        ({"card_id": "c-x", "model_id": "m", "metrics": [("acc", True)]}, mc.BadMetricError),
        ({"card_id": "c-x", "model_id": "m", "metrics": [("acc", float("nan"))]}, mc.BadMetricError),
        ({"card_id": "c-x", "model_id": "m", "metrics": [("acc", float("inf"))]}, mc.BadMetricError),
        ({"card_id": "c-x", "model_id": "m", "metrics": [(("x",), 1.0)]}, mc.BadMetricError),
        ({"card_id": "c-x", "model_id": "m", "metrics": [("acc", 1.0), ("acc", 2.0)]}, mc.BadMetricError),
        ({"card_id": "c-x", "model_id": "m", "metrics": [("acc", 2**54)]}, mc.BadMetricError),
        ({"card_id": "c-x", "model_id": "m", "model_digest": "raw-text"}, mc.BadDigestError),
        ({"card_id": "c-x", "model_id": "m", "model_digest": "sha256:xyz"}, mc.BadDigestError),
        ({"card_id": "c-x", "model_id": "m", "version_label": ""}, mc.BadLabelError),
        ({"card_id": None, "model_id": "m"}, mc.BadIdError),
    ]
    for kwargs, exc in bad_cases:
        seq += 1
        with pytest.raises(exc):
            ledger.create(**kwargs, seq=seq)
        n_rejected += 1
    seq += 1
    ledger.create("card-ok", seq, model_id="model-ok")
    assert ledger._seq == seq
    rejected = [r for r in ledger.audit_log(seq) if r["kind"] == "rejected"]
    assert len(rejected) == n_rejected
    assert ledger.card_ids(seq) == ("card-ok",)


# 5. duplicate create refused
def test_duplicate_create_refused():
    ledger = mc.ModelCard()
    ledger.create("card-1", 1, model_id="model-1")
    with pytest.raises(mc.DuplicateCardError):
        ledger.create("card-1", 2, model_id="model-2")
    with pytest.raises(mc.UnknownCardError):
        ledger.card_record(2, "nope")


# 6. full intended-use vocabulary acceptance
def test_full_use_vocabulary_acceptance():
    ledger = mc.ModelCard()
    seq = 0
    for i, use in enumerate(mc.INTENDED_USES):
        seq += 1
        rec = ledger.create(f"card-{i}", seq, model_id=f"model-{i}",
                            intended_use=use)
        assert rec.intended_use == use
        assert rec.verify()


# 7. publish roundtrip + terminality
def test_publish_roundtrip_and_terminality():
    ledger = mc.ModelCard()
    ledger.create("card-1", 1, model_id="model-1")
    pub = ledger.publish("card-1", 2)
    assert pub.publication_id == "pub-1"
    assert pub.verify()
    assert ledger.is_published(2, "card-1") is True
    assert ledger.is_published(2, "card-1") is True
    with pytest.raises(mc.AlreadyPublishedError):
        ledger.publish("card-1", 3)
    with pytest.raises(mc.UnknownCardError):
        ledger.publish("nope", 4)


# 8. verify report semantics (published + integrity)
def test_verify_report_semantics():
    ledger = mc.ModelCard()
    ledger.create("card-1", 1, model_id="model-1",
                  limitations=("privacy-risk",), metrics=(("f1", 0.81),))
    report = ledger.verify("card-1", 1)
    assert report.published is False
    assert report.integrity_ok is True
    assert report.verify()
    ledger.publish("card-1", 2)
    report2 = ledger.verify("card-1", 2)
    assert report2.published is True
    assert report2.integrity_ok is True
    assert report2.verify()
    # tamper reported as data, never raised
    record = ledger.card_record(2, "card-1")
    object.__setattr__(record, "intended_use", "generation")
    report3 = ledger.verify("card-1", 2)
    assert report3.integrity_ok is False
    assert report3.verify()
    with pytest.raises(mc.UnknownCardError):
        ledger.verify("nope", 2)


# 9. verify read purity (same-seq twice, no audit rows, no seq consumption)
def test_verify_read_purity():
    ledger = mc.ModelCard()
    ledger.create("card-1", 1, model_id="model-1")
    ledger.publish("card-1", 2)
    before = len(ledger.audit_log(2))
    r1 = ledger.verify("card-1", 2)
    r2 = ledger.verify("card-1", 2)
    assert r1.digest == r2.digest
    assert ledger._seq == 2
    assert len(ledger.audit_log(2)) == before


# 10. seq discipline (rewind bare, malformed seqs, view read-purity)
def test_seq_discipline():
    ledger = mc.ModelCard()
    ledger.create("card-1", 1, model_id="model-1")
    with pytest.raises(mc.SeqOrderError):
        ledger.create("card-2", 1, model_id="model-2")
    for bad in (True, "2", 1.5, None, -1, 0):
        with pytest.raises(mc.SeqOrderError):
            ledger.create("card-2", bad, model_id="model-2")
    # rewind raised bare: no rejected rows booked
    rejected = [r for r in ledger.audit_log(1) if r["kind"] == "rejected"]
    assert rejected == []
    assert ledger._seq == 1
    # views validate seq shape only
    with pytest.raises(mc.SeqOrderError):
        ledger.card_ids(-1)
    with pytest.raises(mc.SeqOrderError):
        ledger.verify("card-1", "x")


# 11. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    ledger = mc.ModelCard()
    ledger.create("card-1", 1, model_id="model-1")
    ledger.publish("card-1", 2)
    kinds = [r["kind"] for r in ledger.audit_log(2)]
    assert kinds == ["created", "published"]
    for row in ledger.audit_log(2):
        assert row["schema"] == "audit.ndjson/1"
        for banned in ("text", "content", "description", "name", "author",
                       "weights", "dataset", "summary"):
            assert banned not in row["details"]
    with pytest.raises(mc.AuditKindError):
        mc.model_card_audit_event("nope", 3)
    with pytest.raises(mc.AuditKindError):
        mc.model_card_audit_event("created", 3, description="raw text")


# 12. cross-instance digest determinism + tamper rejection
def test_cross_instance_digest_determinism():
    kwargs = dict(model_id="model-x", intended_use="detection",
                  limitations=("domain-shift",), metrics=(("map", 0.77),),
                  model_digest=PIN)
    a = mc.ModelCard()
    ra = a.create("card-1", 1, **kwargs)
    b = mc.ModelCard()
    rb = b.create("card-1", 1, **kwargs)
    assert ra.digest == rb.digest
    object.__setattr__(rb, "version_label", "9.9.9")
    assert rb.verify() is False
    assert ra.verify() is True


# 13. stats/views + frozen-ness + concurrency smoke
def test_stats_views_frozenness_and_concurrency():
    ledger = mc.ModelCard()
    ledger.create("card-1", 1, model_id="model-1")
    ledger.publish("card-1", 2)
    assert ledger.stats(2) == {
        "n_cards": 1, "n_publications": 1, "n_audit_rows": 2,
    }
    assert ledger.publication_ids(2) == ("pub-1",)
    pub = ledger.publication_record(2, "pub-1")
    assert pub.verify()
    with pytest.raises(Exception):
        pub.card_id = "card-x"
    errors = []

    def _read():
        try:
            for _ in range(50):
                ledger.verify("card-1", 2)
                ledger.stats(2)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=_read) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []


# 14. limitations + metrics edge acceptance
def test_limitations_and_metrics_edges():
    ledger = mc.ModelCard()
    rec = ledger.create(
        "card-1", 1, model_id="model-1",
        limitations=list(mc.LIMITATIONS),
        metrics=[("exact", 2**53), ("neg", -1), ("zero", 0)],
    )
    assert rec.verify()
    assert rec.limitations == mc.LIMITATIONS
    assert rec.metrics[0][0] == "exact"
    # empty digest defaults to the zero pin
    assert rec.model_digest.startswith("sha256:")
    assert len(rec.model_digest) == 71


# 15. main() subprocess check
def test_main_subprocess():
    result = subprocess.run(
        [sys.executable, str(MOD)],
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert "model-card OK: create, publish, verify, pins, audit" in result.stdout

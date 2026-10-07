"""Tests for robust_watermark: embed / survive / extract bookkeeping."""

import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import robust_watermark as rw
from robust_watermark import RobustWatermark

MODULE_PATH = Path(rw.__file__)
GOOD_DIGEST = "sha256:" + "ab" * 32
GOOD_PAYLOAD = "sha256:" + "cd" * 32


def _fresh_embed(**kwargs) -> RobustWatermark:
    ledger = RobustWatermark()
    ledger.embed(GOOD_DIGEST, "lexical-redundancy", 1, **kwargs)
    return ledger


def test_version_and_schema_pins():
    assert rw.ROBUST_WATERMARK_VERSION == "robust-watermark.v1"
    assert rw.ROBUST_WATERMARK_SCHEMA == "northstar.robust-watermark.v1"
    assert rw.AUDIT_SCHEMA == "audit.ndjson/1"
    assert set(rw.CHANNELS) == {
        "lexical-redundancy",
        "syntactic-variation",
        "statistical-bias",
        "semantic-paraphrase",
    }
    assert set(rw.TRANSFORMS) == {
        "paraphrase",
        "crop",
        "compress",
        "translate",
        "summarize",
        "noise-inject",
        "reformat",
    }


def test_stdlib_only():
    tree = ast.parse(MODULE_PATH.read_text())
    allowed = {"hashlib", "threading", "dataclasses", "fractions", "typing",
               "__future__", "canonical_json", "json"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


def test_embed_roundtrip_and_verify():
    ledger = RobustWatermark()
    rec = ledger.embed(GOOD_DIGEST, "statistical-bias", 1,
                       robustness="fragile", payload_digest=GOOD_PAYLOAD)
    assert rec.embed_id == "emb-1"
    assert rec.channel == "statistical-bias"
    assert rec.robustness == "fragile"
    assert rec.content_digest == GOOD_DIGEST
    assert rec.payload_digest == GOOD_PAYLOAD
    assert rec.verify()
    assert ledger.embed_record("emb-1", 2) is rec
    assert ledger.embed_ids(3) == ("emb-1",)
    tampered = rw.EmbedRecord(
        embed_id=rec.embed_id, channel=rec.channel,
        robustness=rec.robustness, content_digest=GOOD_DIGEST,
        payload_digest=GOOD_PAYLOAD, digest="sha256:" + "00" * 32)
    assert not tampered.verify()


def test_embed_bad_inputs_consume_seq_and_book_rejected():
    ledger = RobustWatermark()
    bad = [
        lambda s: ledger.embed("", "lexical-redundancy", s),
        lambda s: ledger.embed("not-a-digest", "lexical-redundancy", s),
        lambda s: ledger.embed(GOOD_DIGEST, "rot13", s),
        lambda s: ledger.embed(GOOD_DIGEST, "lexical-redundancy", s, robustness="indestructible"),
        lambda s: ledger.embed(GOOD_DIGEST, "lexical-redundancy", s, payload_digest="xx"),
    ]
    rows_before = len(ledger.audit_log(1))
    seq = 1
    for fn in bad:
        with pytest.raises(rw.RobustWatermarkError):
            fn(seq)
        seq += 1
    assert len(ledger.audit_log(1)) == rows_before + len(bad)
    kinds = [e["kind"] for e in ledger.audit_log(1)]
    assert set(kinds) == {"robust-watermark.rejected"}
    # seq was claimed: next valid embed must use a higher seq
    with pytest.raises(rw.SeqOrderError):
        ledger.embed(GOOD_DIGEST, "lexical-redundancy", 1)
    rec = ledger.embed(GOOD_DIGEST, "lexical-redundancy", seq)
    assert rec.embed_id == "emb-1"


def test_survive_roundtrip_and_verify():
    ledger = _fresh_embed()
    tr = ledger.survive("emb-1", "paraphrase", 0.35, True, 2)
    assert tr.trial_id == "tr-1"
    assert tr.transform == "paraphrase"
    assert tr.severity == 0.35
    assert tr.survived is True
    assert tr.verify()
    assert ledger.trial_record("tr-1", 3) is tr
    assert ledger.trials_for("emb-1", 4) == ("tr-1",)
    with pytest.raises(rw.UnknownEmbedError):
        ledger.survive("emb-404", "paraphrase", 0.1, True, 5)
    with pytest.raises(rw.BadTransformError):
        ledger.survive("emb-1", "teleport", 0.1, True, 6)


def test_survive_bad_severity_table():
    ledger = _fresh_embed()
    bad_severities = [True, float("nan"), float("inf"), -0.1, 1.1, "0.5", None, [0.5]]
    seq = 2
    for sev in bad_severities:
        with pytest.raises(rw.BadSeverityError):
            ledger.survive("emb-1", "crop", sev, False, seq)
        seq += 1
    # int 0/1 and boundary floats are accepted
    for sev in (0, 1, 0.0, 1.0):
        tr = ledger.survive("emb-1", "crop", sev, False, seq)
        assert tr.severity == float(sev)
        seq += 1


def test_extract_read_purity_and_rate_math():
    ledger = _fresh_embed()
    rep = ledger.extract("emb-1", 2)
    assert rep.verify()
    assert rep.trials == 0 and rep.survived_trials == 0
    assert rep.survival_rate_text == "0/1"
    ledger.survive("emb-1", "paraphrase", 0.2, True, 3)
    ledger.survive("emb-1", "compress", 0.8, False, 4)
    rep = ledger.extract("emb-1", 5)
    assert rep.verify()
    assert (rep.trials, rep.survived_trials) == (2, 1)
    assert rep.survival_rate_text == "1/2"
    # extract is a pure read: same seq twice, no audit rows, no seq consumption
    rows = len(ledger.audit_log(6))
    again = ledger.extract("emb-1", 5)
    assert again.survival_rate_text == "1/2"
    assert len(ledger.audit_log(6)) == rows
    ledger.survive("emb-1", "translate", 0.5, True, 6)  # seq 6 still usable
    with pytest.raises(rw.UnknownEmbedError):
        ledger.extract("emb-404", 7)


def test_seq_discipline():
    ledger = RobustWatermark()
    with pytest.raises(rw.SeqOrderError):
        ledger.embed(GOOD_DIGEST, "lexical-redundancy", 0)
    with pytest.raises(rw.SeqOrderError):
        ledger.embed(GOOD_DIGEST, "lexical-redundancy", True)
    with pytest.raises(rw.SeqOrderError):
        ledger.embed(GOOD_DIGEST, "lexical-redundancy", "1")
    ledger.embed(GOOD_DIGEST, "lexical-redundancy", 1)
    with pytest.raises(rw.SeqOrderError):  # rewind raises bare, consumes nothing
        ledger.embed(GOOD_DIGEST, "lexical-redundancy", 1)
    rows = len(ledger.audit_log(2))
    with pytest.raises(rw.SeqOrderError):
        ledger.embed(GOOD_DIGEST, "lexical-redundancy", 1)
    assert len(ledger.audit_log(2)) == rows  # rewind books no rejected row
    # extract/trial views with bad seq raise SeqOrderError without consuming
    with pytest.raises(rw.SeqOrderError):
        ledger.extract("emb-1", -1)


def test_audit_shapes_and_leak_ban():
    ledger = RobustWatermark()
    rec = ledger.embed(GOOD_DIGEST, "syntactic-variation", 1)
    ledger.survive(rec.embed_id, "summarize", 0.6, False, 2)
    events = ledger.audit_log(3)
    assert [e["kind"] for e in events] == ["watermark-embedded", "robustness-trial"]
    for e in events:
        assert e["schema"] == "audit.ndjson/1"
        assert e["module"] == "robust-watermark"
        joined = str(e["detail"])
        for banned in ("secret-content", "hidden-payload"):
            assert banned not in joined
    # raw content/payload keys are banned from the audit builder
    with pytest.raises(rw.AuditKindError):
        rw.robust_watermark_audit_event("watermark-embedded", 9, content="x")
    with pytest.raises(rw.AuditKindError):
        rw.robust_watermark_audit_event("watermark-embedded", 9, payload="x")
    with pytest.raises(rw.AuditKindError):
        rw.robust_watermark_audit_event("nope", 9)


def test_stats_and_embed_ids_view():
    ledger = RobustWatermark()
    ledger.embed(GOOD_DIGEST, "lexical-redundancy", 1)
    ledger.embed(GOOD_DIGEST, "semantic-paraphrase", 2)
    ledger.survive("emb-1", "paraphrase", 0.1, True, 3)
    ledger.survive("emb-2", "crop", 0.9, False, 4)
    stats = ledger.stats(5)
    assert stats["embeds"] == 2
    assert stats["trials"] == 2
    assert stats["survived"] == 1
    assert stats["by_channel"]["lexical-redundancy"] == 1
    assert stats["by_channel"]["semantic-paraphrase"] == 1
    assert stats["by_transform"]["paraphrase"] == 1
    assert stats["by_transform"]["crop"] == 1
    assert ledger.embed_ids(6) == ("emb-1", "emb-2")
    # read views don't consume seq: seq 6 still usable afterwards
    ledger.survive("emb-1", "reformat", 0.2, True, 6)


def test_cross_instance_digest_determinism():
    a, b = RobustWatermark(), RobustWatermark()
    ra = a.embed(GOOD_DIGEST, "lexical-redundancy", 1, robustness="strong")
    rb = b.embed(GOOD_DIGEST, "lexical-redundancy", 1, robustness="strong")
    assert ra.digest == rb.digest
    ta = a.survive("emb-1", "translate", 0.5, True, 2)
    tb = b.survive("emb-1", "translate", 0.5, True, 2)
    assert ta.digest == tb.digest
    ea = a.extract("emb-1", 3)
    eb = b.extract("emb-1", 3)
    assert ea.digest == eb.digest


def test_survive_unknown_trial_lookup():
    ledger = _fresh_embed()
    with pytest.raises(rw.BadEmbedError):
        ledger.trial_record("tr-404", 2)
    with pytest.raises(rw.UnknownEmbedError):
        ledger.trials_for("emb-404", 2)


def test_frozen_records():
    ledger = _fresh_embed()
    rec = ledger.embed_record("emb-1", 2)
    with pytest.raises(Exception):
        rec.channel = "x"  # frozen dataclass
    tr = ledger.survive("emb-1", "reformat", 0.1, True, 3)
    with pytest.raises(Exception):
        tr.survived = False


def test_concurrency_smoke():
    ledger = _fresh_embed()
    errs = []

    def worker(n):
        try:
            for i in range(10):
                ledger.extract("emb-1", 2)
                ledger.stats(3)
        except Exception as exc:  # pragma: no cover
            errs.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errs


def test_main_subprocess():
    result = subprocess.run(
        [sys.executable, str(MODULE_PATH)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0
    assert "robust-watermark OK: embed, survive, extract, pins, audit" in result.stdout

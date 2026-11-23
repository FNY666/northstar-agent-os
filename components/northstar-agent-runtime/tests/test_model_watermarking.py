"""15 tests for model_watermarking.py (batch spec)."""
import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import model_watermarking
from model_watermarking import (
    ModelWatermarking,
    model_watermarking_audit_event,
    VERSION,
    SCHEMA,
    ModelWatermarkingError,
    BadIdError,
    BadDigestError,
    BadChannelError,
    BadReasonError,
    DuplicateOwnerError,
    UnknownOwnerError,
    RetiredOwnerError,
    DuplicateModelError,
    RetiredModelError,
    UnknownModelError,
    UnknownDetectionError,
    SeqOrderError,
    AuditKindError,
)

HERE = Path(__file__).resolve().parents[1]
MOD = HERE / "model_watermarking.py"
GOOD_DIGEST = "sha256:" + "ab" * 32
OTHER_DIGEST = "sha256:" + "cd" * 32


def fresh() -> ModelWatermarking:
    return ModelWatermarking()


def _reg(mw: ModelWatermarking, oid: str = "owner-1", seq: int = 1):
    return mw.register_owner(oid, seq)


def _emb(mw: ModelWatermarking, mid: str = "model-1",
         oid: str = "owner-1", channel: str = "weight-lsb",
         seq: int = 2, digest: str = GOOD_DIGEST):
    return mw.embed(mid, oid, channel, seq, model_digest=digest)


def _audited(mw: ModelWatermarking, seq: int = 99):
    return mw.audit_log(seq)


# 1. version/schema pins
def test_version_and_schema_pins():
    assert VERSION == "model-watermarking.v1"
    assert SCHEMA == "northstar.model-watermarking.v1"


# 2. stdlib-only AST check
def test_stdlib_only():
    tree = ast.parse(MOD.read_text())
    allowed = {"hashlib", "threading", "dataclasses", "typing", "__future__",
               "re", "json", "canonical_json"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


# 3. register_owner roundtrip + verify
def test_register_owner_roundtrip():
    mw = fresh()
    rec = _reg(mw)
    assert rec.owner_id == "owner-1"
    assert rec.verify()
    assert mw.owner_ids(2) == ("owner-1",)
    assert mw.owner_record("owner-1", 3).owner_id == "owner-1"


# 4. duplicate owner + seq-burn + rejected audit row
def test_duplicate_owner_burns_seq():
    mw = fresh()
    _reg(mw, seq=1)
    with pytest.raises(DuplicateOwnerError):
        mw.register_owner("owner-1", 2)
    kinds = [r["kind"] for r in _audited(mw)]
    assert kinds == ["owner-registered", "rejected"]


# 5. owner bad-input table + seq-burn + unknown-owner view
def test_owner_bad_inputs():
    mw = fresh()
    bad = [None, "", "   ", 123, b"x", "x" * 129, "has space"]
    seq = 1
    for b in bad:
        with pytest.raises(ModelWatermarkingError):
            mw.register_owner(b, seq)
        seq += 1
    assert len(_audited(mw)) == len(bad)
    assert all(r["kind"] == "rejected" for r in _audited(mw))
    with pytest.raises(UnknownOwnerError):
        mw.owner_record("nope", seq)


# 6. embed roundtrip + full channel vocabulary
def test_embed_roundtrip_and_channels():
    mw = fresh()
    _reg(mw, seq=1)
    for i, ch in enumerate(("weight-lsb", "trigger-set", "activation",
                           "dataset", "black-box")):
        rec = mw.embed(f"m-{ch}", "owner-1", ch, 2 + i,
                       model_digest="sha256:%064x" % i)
        assert rec.channel == ch
        assert rec.verify()
    assert len(mw.model_ids(10)) == 5
    assert mw.embed_record("m-dataset", 11).channel == "dataset"


# 7. embed refusals: unknown owner, duplicate, bad channel/digests
def test_embed_refusals():
    mw = fresh()
    _reg(mw, seq=1)
    with pytest.raises(UnknownOwnerError):
        mw.embed("m1", "ghost", "weight-lsb", 2, model_digest=GOOD_DIGEST)
    _emb(mw, seq=3)
    with pytest.raises(DuplicateModelError):
        mw.embed("model-1", "owner-1", "weight-lsb", 4,
                 model_digest=GOOD_DIGEST)
    with pytest.raises(BadChannelError):
        mw.embed("m2", "owner-1", "lorem-ipsum", 5, model_digest=GOOD_DIGEST)
    with pytest.raises(BadDigestError):
        mw.embed("m3", "owner-1", "weight-lsb", 6, model_digest="rawbytes")
    kinds = [r["kind"] for r in _audited(mw)]
    assert kinds.count("rejected") == 4
    assert kinds.count("embedded") == 1


# 8. retire lifecycle: terminal, no recycling, re-retire + bad reason
def test_retire_terminal():
    mw = fresh()
    _reg(mw, seq=1)
    _emb(mw, seq=2)
    r = mw.retire("model-1", 3)
    assert r.verify() and r.reason == "manual"
    _reg(mw, oid="o2", seq=4)
    _emb(mw, mid="m2", oid="o2", seq=5)
    with pytest.raises(BadReasonError):
        mw.retire("m2", 6, reason="bogus")
    with pytest.raises(RetiredModelError):
        mw.retire("model-1", 20)
    with pytest.raises(UnknownModelError):
        mw.retire("ghost", 21)
    with pytest.raises(RetiredModelError):
        mw.embed("model-1", "owner-1", "weight-lsb", 22,
                 model_digest=GOOD_DIGEST)
    with pytest.raises(BadReasonError):
        mw.retire("model-1", 23, reason="bogus")
    with pytest.raises(UnknownModelError):
        mw.verify("model-1", 24)
    assert "model-1" not in mw.model_ids(25)


# 9. retired owner cannot embed, cannot re-register
def test_retired_owner_cannot_embed():
    mw = fresh()
    _reg(mw, seq=1)
    mw.retire_owner("owner-1", 2)
    with pytest.raises(RetiredOwnerError):
        mw.embed("m1", "owner-1", "weight-lsb", 3,
                 model_digest=GOOD_DIGEST)
    with pytest.raises(RetiredOwnerError):
        mw.register_owner("owner-1", 4)
    with pytest.raises(UnknownOwnerError):
        mw.retire_owner("owner-1", 5)
    kinds = [r["kind"] for r in _audited(mw)]
    assert kinds.count("rejected") == 3


# 10. detect: hit, miss, and channel filter
def test_detect_hit_miss_filter():
    mw = fresh()
    _reg(mw, seq=1)
    _emb(mw, mid="m-a", channel="weight-lsb", seq=2, digest=GOOD_DIGEST)
    _emb(mw, mid="m-b", channel="trigger-set", seq=3, digest=OTHER_DIGEST)
    d = mw.detect(GOOD_DIGEST, 4)
    assert d.matched and d.matched_ids == ("m-a",) and d.verify()
    d2 = mw.detect(OTHER_DIGEST, 5, channel="trigger-set")
    assert d2.matched and d2.matched_ids == ("m-b",)
    d3 = mw.detect(OTHER_DIGEST, 6, channel="weight-lsb")
    assert not d3.matched and d3.matched_ids == ()
    d4 = mw.detect("sha256:" + "00" * 32, 7)
    assert not d4.matched and d4.matched_ids == ()
    assert mw.detected_ids(8) == ("det-1", "det-2")
    assert mw.detection_record("det-3", 9).matched is False
    with pytest.raises(UnknownDetectionError):
        mw.detection_record("det-99", 10)
    with pytest.raises(BadDigestError):
        mw.detect("rawbytes", 11)
    with pytest.raises(BadChannelError):
        mw.detect(GOOD_DIGEST, 12, channel="bogus")


# 11. verify roundtrip + tamper-as-data + unknown-model refusal
def test_verify_roundtrip_and_tamper():
    mw = fresh()
    _reg(mw, seq=1)
    rec = _emb(mw, seq=2)
    v = mw.verify("model-1", 3)
    assert v.ok and v.verify()
    object.__setattr__(rec, "channel", "dataset")
    assert rec.verify() is False
    v2 = mw.verify("model-1", 4)
    assert v2.ok is False and v2.verify()
    with pytest.raises(UnknownModelError):
        mw.verify("ghost", 5)


# 12. seq discipline: rewind bare, malformed seqs, view read-purity
def test_seq_discipline():
    mw = fresh()
    _reg(mw, seq=5)
    with pytest.raises(SeqOrderError):
        mw.register_owner("o2", 5)
    with pytest.raises(SeqOrderError):
        mw.register_owner("o2", 3)
    assert tuple(_audited(mw)) == tuple(_audited(mw))
    n = len(_audited(mw))
    assert n == 1  # bare rewinds book nothing
    for bad in (True, -1, "6", None, 2.0):
        with pytest.raises(SeqOrderError):
            mw.register_owner("o-x", bad)
    assert len(_audited(mw)) == n  # bare raises consume nothing
    # views validate seq shape, consume nothing, write no rows
    assert mw.owner_ids(6) == ("owner-1",)
    assert mw.stats(7)["owners"] == 1
    assert len(_audited(mw)) == n
    with pytest.raises(SeqOrderError):
        mw.owner_ids(-1)


# 13. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    mw = fresh()
    _reg(mw, seq=1)
    _emb(mw, seq=2)
    rows = _audited(mw)
    assert [r["kind"] for r in rows] == ["owner-registered", "embedded"]
    for r in rows:
        assert r["schema"] == "audit.ndjson/1"
        assert r["module"] == "model_watermarking"
        assert "digest" in r
    # banned raw-text keys must be refused at the audit boundary
    for banned in ("owner", "secret", "model", "key", "weights", "raw",
                   "trigger", "fingerprint"):
        with pytest.raises(AuditKindError):
            model_watermarking_audit_event("embedded", 3, {banned: "x"})
    with pytest.raises(AuditKindError):
        model_watermarking_audit_event("bogus-kind", 3)


# 14. cross-instance determinism + frozen-ness + concurrency smoke
def test_determinism_frozen_concurrency():
    a, b = fresh(), fresh()
    for mw in (a, b):
        _reg(mw, seq=1)
        rec = _emb(mw, seq=2)
        assert rec.verify()
    assert a.embed_record("model-1", 3).digest == \
        b.embed_record("model-1", 3).digest
    with pytest.raises(Exception):
        a.owner_record("owner-1", 4).owner_id = "hacked"
    errs = []
    def reader():
        try:
            for _ in range(50):
                a.model_ids(5)
                a.stats(6)
        except Exception as e:  # pragma: no cover
            errs.append(e)
    ts = [threading.Thread(target=reader) for _ in range(8)]
    for t in ts: t.start()
    for t in ts: t.join()
    assert not errs
    assert a.stats(7)["embedded"] == 1


# 15. main() subprocess self-check
def test_main_self_check():
    out = subprocess.run([sys.executable, str(MOD)], capture_output=True,
                         text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == ("model-watermarking OK: register, embed, "
                                  "detect, retire, pins, audit")

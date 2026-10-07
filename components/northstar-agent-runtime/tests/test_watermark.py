"""15 tests for watermark.py (batch spec)."""
import ast
import hashlib
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import watermark
from watermark import (
    Watermark,
    watermark_audit_event,
    VERSION,
    SCHEMA,
    WatermarkError,
    BadIdError,
    BadDigestError,
    BadBitsError,
    BadCountsError,
    BadThresholdError,
    DuplicateKeyError,
    UnknownKeyError,
    DuplicateContentError,
    UnknownContentError,
    SeqOrderError,
    AuditKindError,
)

HERE = Path(__file__).resolve().parents[1]
MOD = HERE / "watermark.py"
GOOD_DIGEST = "sha256:" + "ab" * 32


def fresh() -> Watermark:
    return Watermark()


def _reg(wm: Watermark, kid: str = "k1", seq: int = 1):
    return wm.register_key(kid, seq)


# 1. version/schema pins
def test_version_and_schema_pins():
    assert VERSION == "watermark.v1"
    assert SCHEMA == "northstar.watermark.v1"


# 2. stdlib-only AST check
def test_stdlib_only():
    tree = ast.parse(MOD.read_text())
    allowed = {"hashlib", "threading", "dataclasses", "typing", "__future__",
               "re", "math", "json", "canonical_json"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


# 3. register roundtrip + verify
def test_register_roundtrip():
    wm = fresh()
    rec = _reg(wm)
    assert rec.key_id == "k1"
    assert rec.verify()
    assert wm.key_ids(2) == ("k1",)


# 4. duplicate key + seq-burn + rejected audit row
def test_duplicate_key_burns_seq():
    wm = fresh()
    _reg(wm, seq=1)
    with pytest.raises(DuplicateKeyError):
        wm.register_key("k1", 2)
    kinds = [r["kind"] for r in wm.audit_log(3)]
    assert kinds == ["key-registered", "rejected"]
    # seq 2 was consumed by the failed mutation: next use must be > 2
    with pytest.raises(SeqOrderError):
        wm.register_key("k2", 2)
    wm.register_key("k2", 3)


# 5. bad-input table for register
def test_register_bad_inputs():
    wm = fresh()
    for seq, kid in ((1, ""), (2, 123), (3, "  pad  ")):
        with pytest.raises((BadIdError, WatermarkError)):
            wm.register_key(kid, seq)


# 6. embed roundtrip + digest verify
def test_embed_roundtrip():
    wm = fresh()
    _reg(wm, seq=1)
    rec = wm.embed("doc-1", "k1", 2, content_digest=GOOD_DIGEST,
                   bits="1010")
    assert rec.bit_count == 4
    assert rec.verify()
    assert wm.embed_record("doc-1", 3).verify()
    assert wm.content_ids(4) == ("doc-1",)


# 7. embed bad-inputs: unknown key, bad digest, bad bits, duplicate
def test_embed_bad_inputs():
    wm = fresh()
    _reg(wm, seq=1)
    with pytest.raises(UnknownKeyError):
        wm.embed("d", "nope", 2, content_digest=GOOD_DIGEST, bits="1")
    with pytest.raises(BadDigestError):
        wm.embed("d", "k1", 3, content_digest="not-a-digest", bits="1")
    with pytest.raises(BadBitsError):
        wm.embed("d", "k1", 4, content_digest=GOOD_DIGEST, bits="102")
    wm.embed("d", "k1", 5, content_digest=GOOD_DIGEST, bits="1")
    with pytest.raises(DuplicateContentError):
        wm.embed("d", "k1", 6, content_digest=GOOD_DIGEST, bits="1")


# 8. detect verdict math: z-score x1000, threshold crossing as data
def test_detect_verdict_math():
    wm = fresh()
    _reg(wm, seq=1)
    # matches=8, total=10 -> z = 1000*(16-10)/isqrt(10) = 6000//3 = 2000
    d = wm.detect(GOOD_DIGEST, "k1", 2, matches=8, total=10,
                  threshold=1500)
    assert d.z_x1000 == 2000
    assert d.detected is True
    assert d.verify()
    d2 = wm.detect(GOOD_DIGEST, "k1", 3, matches=8, total=10,
                   threshold=2001)
    assert d2.detected is False
    assert wm.detected_ids(4) == ("det-1",)


# 9. detect bad-inputs: bad counts, bad threshold, unknown key, bad digest
def test_detect_bad_inputs():
    wm = fresh()
    _reg(wm, seq=1)
    with pytest.raises(BadCountsError):
        wm.detect(GOOD_DIGEST, "k1", 2, matches=11, total=10)
    with pytest.raises(BadCountsError):
        wm.detect(GOOD_DIGEST, "k1", 3, matches=-1, total=10)
    with pytest.raises(BadThresholdError):
        wm.detect(GOOD_DIGEST, "k1", 4, matches=5, total=10, threshold=0)
    with pytest.raises(UnknownKeyError):
        wm.detect(GOOD_DIGEST, "nope", 5, matches=5, total=10)
    with pytest.raises(BadDigestError):
        wm.detect("raw-text", "k1", 6, matches=5, total=10)


# 10. verify roundtrip + tamper detection via object.__setattr__
def test_verify_and_tamper():
    wm = fresh()
    _reg(wm, seq=1)
    wm.embed("doc-1", "k1", 2, content_digest=GOOD_DIGEST, bits="11")
    rep = wm.verify("doc-1", 3)
    assert rep.ok is True and rep.verify()
    # corrupt the booked record's digest pin: re-walk must flag it
    rec = wm.embed_record("doc-1", 4)
    object.__setattr__(rec, "digest", "sha256:" + "00" * 32)
    rep2 = wm.verify("doc-1", 5)
    assert rep2.ok is False


# 11. seq discipline: rewind bare, malformed seqs
def test_seq_discipline():
    wm = fresh()
    _reg(wm, seq=5)
    with pytest.raises(SeqOrderError):
        wm.register_key("k2", 5)  # rewind: no consumption, no audit row
    assert len(wm.audit_log(6)) == 1
    for bad in (True, -1, "x", 1.5, None):
        with pytest.raises(SeqOrderError):
            wm.register_key("k3", bad)


# 12. view read-purity: same seq twice, no audit rows, no consumption
def test_view_read_purity():
    wm = fresh()
    _reg(wm, seq=1)
    wm.embed("doc-1", "k1", 2, content_digest=GOOD_DIGEST, bits="1")
    before = len(wm.audit_log(3))
    s1 = wm.stats(3)
    s2 = wm.stats(3)
    assert s1 == s2
    assert len(wm.audit_log(3)) == before
    assert s1["keys"] == 1 and s1["embedded"] == 1


# 13. audit shapes + raw-material leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    wm = fresh()
    _reg(wm, seq=1)
    wm.embed("doc-1", "k1", 2, content_digest=GOOD_DIGEST, bits="1010")
    wm.detect(GOOD_DIGEST, "k1", 3, matches=9, total=10)
    rows = wm.audit_log(4)
    assert [r["kind"] for r in rows] == ["key-registered", "embedded",
                                         "detected"]
    for r in rows:
        assert r["schema"] == "audit.ndjson/1"
        for key in r["detail"]:
            assert key not in {"key", "secret", "content", "text", "bits"}
    with pytest.raises(AuditKindError):
        watermark_audit_event("forged", 5)


# 14. cross-instance digest determinism + frozen records
def test_determinism_and_frozen():
    def build():
        wm = fresh()
        _reg(wm, seq=1)
        return wm.embed("doc-1", "k1", 2, content_digest=GOOD_DIGEST,
                        bits="1100")

    a, b = build(), build()
    assert a.digest == b.digest
    import dataclasses
    with pytest.raises(dataclasses.FrozenInstanceError):
        a.content_id = "x"  # type: ignore[misc]
    # object.__setattr__ bypasses frozen-ness (test-side note); ledger
    # tamper checks run through verify(), not attribute writes


# 15. main() subprocess check
def test_main_subprocess():
    r = subprocess.run([sys.executable, str(MOD)], capture_output=True,
                       text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    assert "watermark OK" in r.stdout

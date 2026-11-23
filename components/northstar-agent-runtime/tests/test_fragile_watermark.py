"""15 targeted tests for fragile_watermark.py."""

import ast
import sys
import os

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import fragile_watermark as fw
from fragile_watermark import (
    FRAGILE_WATERMARK_VERSION,
    SCHEMA_PIN,
    DEFAULT_BLOCK_SIZE,
    MIN_BLOCK_SIZE,
    MAX_BLOCK_SIZE,
    FragileWatermark,
    EmbedRecord,
    TamperReport,
    fragile_watermark_audit_event,
    FragileWatermarkError,
    BadKeyError,
    BadCarrierError,
    BadBlockError,
    BadOffsetError,
    BadLengthError,
    BadModeError,
    SeqOrderError,
    AuditKindError,
)

CARRIER = bytes(range(256)) * 2  # 512 bytes, 8 blocks of 64


def _fw():
    return FragileWatermark("test-key-1")


def test_01_version_and_schema_pins():
    assert FRAGILE_WATERMARK_VERSION == "fragile-watermark.v1"
    assert SCHEMA_PIN == "northstar.fragile-watermark.v1"
    assert DEFAULT_BLOCK_SIZE == 64
    assert MIN_BLOCK_SIZE <= DEFAULT_BLOCK_SIZE <= MAX_BLOCK_SIZE


def test_02_stdlib_only():
    tree = ast.parse(open(fw.__file__).read())
    allowed = {
        "hashlib", "hmac", "threading", "dataclasses", "typing",
        "__future__", "canonical_json",
    }
    mods = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            mods.add(node.module.split(".")[0])
    assert mods <= allowed, mods - allowed


def test_03_embed_roundtrip_and_pins():
    f = _fw()
    marked, rec = f.embed(CARRIER, seq=1)
    assert isinstance(rec, EmbedRecord)
    assert len(marked) == len(CARRIER)
    assert marked is not CARRIER
    # only tag bytes (every 64th) may differ
    diffs = [i for i in range(len(CARRIER)) if marked[i] != CARRIER[i]]
    assert diffs == [63, 127, 191, 255, 319, 383, 447, 511], diffs
    assert rec.key_id.startswith("sha256:") and "test-key-1" not in rec.key_id
    assert rec.total_blocks == 8 and rec.block_size == 64
    assert rec.verify(marked)
    assert not rec.verify(bytes([0]) * len(marked))
    d = rec.as_dict()
    assert d["schema"] == SCHEMA_PIN


def test_04_carrier_not_mutated():
    f = _fw()
    before = bytes(CARRIER)
    f.embed(CARRIER, seq=1)
    assert bytes(CARRIER) == before


def test_05_seq_discipline():
    f = _fw()
    f.embed(CARRIER, seq=1)
    with pytest.raises(SeqOrderError):  # rewind raises bare
        f.embed(CARRIER, seq=1)
    with pytest.raises(SeqOrderError):
        f.embed(CARRIER, seq=0)
    for bad in (True, "2", 2.0, None):
        with pytest.raises(SeqOrderError):
            f.embed(CARRIER, seq=bad)
    # failed mutation burns its seq: next valid seq must be 3
    with pytest.raises(BadCarrierError):
        f.embed(b"short", seq=2)
    f.embed(CARRIER, seq=3)  # seq=2 was consumed by the failure
    assert f.stats()["rejected"] == 1


def test_06_bad_inputs_fail_closed():
    f = _fw()
    with pytest.raises(BadKeyError):
        FragileWatermark("")
    with pytest.raises(BadKeyError):
        FragileWatermark(123)
    with pytest.raises(BadCarrierError):
        f.embed("not-bytes", seq=1)
    with pytest.raises(BadCarrierError):
        f.embed(b"", seq=2)
    with pytest.raises(BadCarrierError):
        f.embed(bytes(100), seq=3)  # not a multiple of 64
    with pytest.raises(BadBlockError):
        f.embed(CARRIER, seq=4, block_size=7)
    with pytest.raises(BadBlockError):
        f.embed(CARRIER, seq=5, block_size=True)
    assert f.stats()["rejected"] == 5


def test_07_tamper_flip_single_block():
    f = _fw()
    marked, _ = f.embed(CARRIER, seq=1)
    damaged = FragileWatermark.tamper(marked, 2 * 64 + 10, 1)
    assert damaged is not marked and len(damaged) == len(marked)
    rep = f.locate(damaged, seq=2)
    assert isinstance(rep, TamperReport)
    assert rep.tampered and rep.affected == (2,)
    assert rep.affected_count == 1
    assert rep.first_affected == 2 and rep.last_affected == 2
    assert rep.verify()
    assert rep.as_dict()["schema"] == SCHEMA_PIN


def test_08_tamper_spanning_blocks():
    f = _fw()
    marked, _ = f.embed(CARRIER, seq=1)
    damaged = FragileWatermark.tamper(marked, 63, 2)  # straddles 0/1
    rep = f.locate(damaged, seq=2)
    assert rep.affected == (0, 1)
    # tampering a tag byte alone also fires
    damaged2 = FragileWatermark.tamper(marked, 5 * 64 + 63, 1, mode="zero")
    rep2 = f.locate(damaged2, seq=3)
    assert rep2.affected == (5,)


def test_09_tamper_modes_and_bad_args():
    f = _fw()
    marked, _ = f.embed(CARRIER, seq=1)
    assert FragileWatermark.tamper(marked, 0, 4, mode="zero")[0:4] == b"\x00" * 4
    assert FragileWatermark.tamper(marked, 0, 4, mode="one")[0:4] == b"\xff" * 4
    flipped = FragileWatermark.tamper(marked, 0, 1, mode="flip")
    assert flipped[0] == marked[0] ^ 0xFF
    for kw in (dict(offset=-1, length=1), dict(offset=512, length=1)):
        with pytest.raises(BadOffsetError):
            FragileWatermark.tamper(marked, mode="flip", **kw)
    for kw in (dict(offset=0, length=0), dict(offset=510, length=3)):
        with pytest.raises(BadLengthError):
            FragileWatermark.tamper(marked, mode="flip", **kw)
    with pytest.raises(BadModeError):
        FragileWatermark.tamper(marked, 0, 1, mode="xor")
    with pytest.raises(BadCarrierError):
        FragileWatermark.tamper("nope", 0, 1)


def test_10_clean_carrier_reports_intact():
    f = _fw()
    marked, _ = f.embed(CARRIER, seq=1)
    rep = f.locate(marked, seq=2)
    assert not rep.tampered
    assert rep.affected == () and rep.affected_count == 0
    assert rep.first_affected == -1 and rep.last_affected == -1
    assert rep.verify()


def test_11_wrong_key_flags_everything():
    f = _fw()
    marked, _ = f.embed(CARRIER, seq=1)
    other = FragileWatermark("different-key")
    rep = other.locate(marked, seq=1)
    assert rep.tampered and rep.affected_count == 8
    assert rep.affected == tuple(range(8))


def test_12_report_tamper_evident():
    f = _fw()
    marked, _ = f.embed(CARRIER, seq=1)
    rep = f.locate(marked, seq=2)
    assert rep.verify()
    object.__setattr__(rep, "tampered", True)  # bypass frozen-ness
    assert not rep.verify()
    _, rec = f.embed(CARRIER, seq=3)
    object.__setattr__(rec, "carrier_digest", "sha256:dead")
    assert not rec.verify(marked)


def test_13_audit_shapes_leak_ban_and_bad_kind():
    f = _fw()
    marked, rec = f.embed(CARRIER, seq=1)
    f.locate(marked, seq=2)
    log = f.audit_log()
    assert [r["event"] for r in log] == [
        "fragile-watermark.embedded", "fragile-watermark.located",
    ]
    blob = str(log)
    assert "test-key-1" not in blob and '"key"' not in blob
    for row in log:
        assert row["schema"] == "audit.ndjson/1"
    with pytest.raises(ValueError):
        fragile_watermark_audit_event("embedded", 9, key="secret")
    with pytest.raises(AuditKindError):
        fragile_watermark_audit_event("bogus", 9)


def test_14_cross_instance_determinism():
    m1, r1 = FragileWatermark("k").embed(CARRIER, seq=1)
    m2, r2 = FragileWatermark("k").embed(CARRIER, seq=1)
    assert m1 == m2
    assert r1.carrier_digest == r2.carrier_digest
    assert r1.tag_digest == r2.tag_digest
    # block size pinned by first embed
    f = FragileWatermark("k")
    f.embed(CARRIER, seq=1)
    with pytest.raises(BadBlockError):
        f.embed(bytes(256), seq=2, block_size=32)
    # custom block size works when consistent
    g = FragileWatermark("k")
    marked, rec = g.embed(bytes(256), seq=1, block_size=32)
    assert rec.total_blocks == 8 and rec.block_size == 32
    rep = g.locate(marked, seq=2)
    assert not rep.tampered


def test_15_main_subprocess():
    import subprocess
    out = subprocess.run(
        [sys.executable, fw.__file__],
        capture_output=True, text=True, timeout=60,
    )
    assert out.returncode == 0, out.stderr
    assert "fragile-watermark OK" in out.stdout

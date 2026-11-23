"""Tests for synthetic_media.py — synthetic-content generation/label/disclosure ledger."""

from __future__ import annotations

import ast
import importlib.util
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).resolve().parent.parent / "synthetic_media.py"


def _load():
    spec = importlib.util.spec_from_file_location("synthetic_media", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["synthetic_media"] = module  # frozen dataclasses need this
    spec.loader.exec_module(module)
    return module


sm = _load()
PIN = "sha256:" + "ab" * 32


def test_version_and_schema_pins():
    assert sm.SYNTHETIC_MEDIA_VERSION == "synthetic-media.v1"
    assert sm.SYNTHETIC_MEDIA_SCHEMA == "northstar.synthetic-media.v1"
    assert sm.AUDIT_SCHEMA == "audit.ndjson/1"


def test_stdlib_only():
    tree = ast.parse(MODULE_PATH.read_text())
    allowed = {"hashlib", "threading", "dataclasses", "typing",
               "__future__", "canonical_json", "json"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            assert node.module.split(".")[0] in allowed, node.module


def test_generate_roundtrip_and_verify():
    m = sm.SyntheticMedia()
    rec = m.generate("m-1", "image", 1, prompt_digest=PIN, output_digest=PIN,
                     provenance=("model-a",))
    assert rec.kind == "image"
    assert rec.prompt_digest == PIN
    assert rec.provenance == ("model-a",)
    assert rec.verify()
    assert rec.as_dict()["schema"] == sm.SYNTHETIC_MEDIA_SCHEMA
    assert "m-1" in m.media_ids(1)


def test_generate_bad_inputs_seq_burn():
    m = sm.SyntheticMedia()
    bad = [
        ("", "image", 1),               # empty id
        ("m-x", "hologram", 2),         # bad kind
        ("m-x", "text", 3, "not-a-pin"),  # bad digest
    ]
    for args in bad:
        kwargs = {"prompt_digest": args[3]} if len(args) == 4 else {}
        with pytest.raises(sm.SyntheticMediaError):
            m.generate(args[0], args[1], args[2], **kwargs)
    # duplicates
    m.generate("m-dup", "text", 10)
    with pytest.raises(sm.DuplicateMediaError):
        m.generate("m-dup", "text", 11)
    rows = m.audit_log(11)
    rejected = [r for r in rows if r["kind"] == "rejected"]
    assert len(rejected) == 4  # 3 bad + 1 duplicate; failed mutations burned seqs


def test_label_lifecycle():
    m = sm.SyntheticMedia()
    m.generate("m-1", "video", 1)
    lbl = m.label("m-1", "deepfake", 2)
    assert lbl.label_id == "lbl-1"
    assert lbl.verify()
    labels = m.labels_for("m-1", 2)
    assert len(labels) == 1 and labels[0].label == "deepfake"
    with pytest.raises(sm.BadLabelError):
        m.label("m-1", "probably-fake", 3)
    with pytest.raises(sm.UnknownMediaError):
        m.label("nope", "parody", 4)


def test_disclose_lifecycle():
    m = sm.SyntheticMedia()
    m.generate("m-1", "audio", 1)
    dcl = m.disclose("m-1", "visible-label", 2)
    assert dcl.disclosure_id == "dcl-1"
    assert dcl.verify()
    discs = m.disclosures_for("m-1", 2)
    assert len(discs) == 1 and discs[0].channel == "visible-label"
    with pytest.raises(sm.BadChannelError):
        m.disclose("m-1", "carrier-pigeon", 3)


def test_retire_terminality():
    m = sm.SyntheticMedia()
    m.generate("m-1", "text", 1)
    rec = m.retire("m-1", 2, "superseded")
    assert rec.verify()
    assert "m-1" in m.retired_ids(2)
    for op in (lambda: m.label("m-1", "parody", 3),
               lambda: m.disclose("m-1", "platform-tag", 4),
               lambda: m.retire("m-1", 5)):
        with pytest.raises(sm.RetiredMediaError):
            op()
    with pytest.raises(sm.RetiredMediaError):
        m.generate("m-1", "text", 6)  # ids never recycled


def test_bad_reason_refused():
    m = sm.SyntheticMedia()
    m.generate("m-1", "text", 1)
    with pytest.raises(sm.BadReasonError):
        m.retire("m-1", 2, "oops")


def test_seq_discipline():
    m = sm.SyntheticMedia()
    m.generate("m-1", "text", 1)
    with pytest.raises(sm.SeqOrderError):
        m.generate("m-2", "text", 1)   # rewind raises bare
    with pytest.raises(sm.SeqOrderError):
        m.generate("m-2", "text", True)
    with pytest.raises(sm.SeqOrderError):
        m.generate("m-2", "text", -1)
    # failed mutations consume their seq (claim-then-burn)
    with pytest.raises(sm.SyntheticMediaError):
        m.generate("", "text", 2)
    rec = m.generate("m-2", "text", 3)
    assert rec.seq == 3
    assert m.stats(3)["last_seq"] == 3


def test_view_read_purity():
    m = sm.SyntheticMedia()
    m.generate("m-1", "text", 1)
    before = m.stats(1)["audit_rows"]
    m.generation("m-1", 1)
    m.media_ids(1)
    m.stats(1)
    assert m.stats(1)["audit_rows"] == before  # pure reads write no rows


def test_audit_shapes_and_leak_ban():
    m = sm.SyntheticMedia()
    m.generate("m-1", "image", 1, prompt_digest=PIN)
    m.label("m-1", "watermarked", 2)
    m.disclose("m-1", "embedded-metadata", 3)
    kinds = [r["kind"] for r in m.audit_log(3)]
    assert kinds == ["generated", "labeled", "disclosed"]
    for row in m.audit_log(3):
        assert row["schema"] == "audit.ndjson/1"
        for key in row["detail"]:
            assert key not in sm.BANNED_AUDIT_KEYS, f"audit leak: {key}"
    with pytest.raises(sm.AuditKindError):
        sm.synthetic_media_audit_event("nope", 4)
    ev = sm.synthetic_media_audit_event("generated", 4, prompt="secret")
    assert "prompt" not in ev["detail"]  # banned key filtered


def test_cross_instance_digest_determinism():
    a, b = sm.SyntheticMedia(), sm.SyntheticMedia()
    ra = a.generate("m-1", "image", 1, prompt_digest=PIN)
    rb = b.generate("m-1", "image", 1, prompt_digest=PIN)
    assert ra.digest == rb.digest
    la = a.label("m-1", "ai-generated", 2)
    lb = b.label("m-1", "ai-generated", 2)
    assert la.digest == lb.digest
    # tamper breaks verify
    object.__setattr__(ra, "kind", "video")
    assert not ra.verify()


def test_frozen_records_and_concurrency():
    m = sm.SyntheticMedia()
    rec = m.generate("m-1", "text", 1)
    with pytest.raises(Exception):
        rec.media_id = "changed"  # frozen
    for i in range(2, 10):
        m.generate(f"m-{i}", "text", i)

    def read():
        for _ in range(50):
            m.stats(9)
            m.media_ids(9)

    threads = [threading.Thread(target=read) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert m.stats(9)["generations"] == 9


def test_stats_counts():
    m = sm.SyntheticMedia()
    m.generate("m-1", "text", 1)
    m.label("m-1", "parody", 2)
    m.disclose("m-1", "c2pa-manifest", 3)
    m.generate("m-2", "audio", 4)
    s = m.stats(4)
    assert s["generations"] == 2
    assert s["labels"] == 1
    assert s["disclosures"] == 1
    assert s["retired"] == 0


def test_main_subprocess():
    result = subprocess.run(
        [sys.executable, str(MODULE_PATH)],
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert "synthetic-media OK" in result.stdout

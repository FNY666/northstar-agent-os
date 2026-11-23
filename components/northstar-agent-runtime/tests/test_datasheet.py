"""Tests for the dataset datasheet decision ledger, Simulated."""

import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "datasheet.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("datasheet", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["datasheet"] = module
    spec.loader.exec_module(module)
    return module


ds = _load()


def _full(d, did="ds-1", start=1):
    """Create a datasheet with all required sections; returns next free seq."""
    seq = start
    d.create(did, seq, dataset_digest=PIN, title_digest=PIN)
    for s in ds.REQUIRED_SECTIONS:
        seq += 1
        d.section(did, s, seq, content_digest=PIN)
    return seq + 1


# 1. version/schema pins
def test_version_and_schema_pins():
    assert ds.DATASHEET_VERSION == "datasheet.v1"
    assert ds.SCHEMA_PIN == "northstar.datasheet.v1"
    assert ds.REQUIRED_SECTIONS == (
        "motivation",
        "composition",
        "collection",
        "preprocessing",
        "uses",
        "distribution",
        "maintenance",
    )


# 2. stdlib-only AST check
def test_stdlib_only_ast():
    tree = ast.parse(MOD.read_text())
    allowed = {
        "hashlib", "threading", "dataclasses", "typing", "__future__",
        "canonical_json", "json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


# 3. create roundtrip + verify()
def test_create_roundtrip_and_verify():
    d = ds.Datasheet()
    rec = d.create("ds-1", 1, dataset_digest=PIN, title_digest=PIN2, version="2.0")
    assert rec.datasheet_id == "ds-1"
    assert rec.dataset_pin == PIN
    assert rec.version == "2.0"
    assert rec.verify()
    assert rec.as_dict()["schema"] == ds.SCHEMA_PIN
    assert d.datasheet_record("ds-1", 2) is rec
    assert d.datasheet_ids(3) == ("ds-1",)


# 4. bad-input table + seq-burn + rejected rows
def test_create_bad_input_and_seq_burn():
    d = ds.Datasheet()
    cases = [
        ("", 1, PIN),          # empty id
        (None, 2, PIN),       # non-str id
        ("ds-1", 3, "raw"),   # raw text digest refused
        ("ds-1", 4, "sha256:zz"),  # malformed pin
        ("ds-1", 5, 123),     # non-str digest
    ]
    for did, seq, digest in cases:
        with pytest.raises(ds.DatasheetError):
            d.create(did, seq, dataset_digest=digest)
    assert d.stats(6)["rejected"] == len(cases)
    assert d.datasheet_ids(7) == ()


# 5. duplicate create refused; retired id never recycled
def test_duplicate_create_refused():
    d = ds.Datasheet()
    d.create("ds-1", 1)
    with pytest.raises(ds.DuplicateDatasheetError):
        d.create("ds-1", 2)
    d.retract("ds-1", 3)
    with pytest.raises(ds.RetiredDatasheetError):
        d.create("ds-1", 4)
    assert d.stats(5)["rejected"] == 2


# 6. section roundtrip + minted ids
def test_section_roundtrip_minted_ids():
    d = ds.Datasheet()
    d.create("ds-1", 1)
    r1 = d.section("ds-1", "motivation", 2, content_digest=PIN)
    r2 = d.section("ds-1", "composition", 3, content_digest=PIN)
    assert r1.section_id == "sec-1"
    assert r2.section_id == "sec-2"
    assert r1.verify() and r2.verify()
    assert d.section_record("sec-1", 4) is r1
    assert d.sections_for("ds-1", 5) == ("sec-1", "sec-2")


# 7. section bad-input table + vocabulary
def test_section_bad_input_and_vocabulary():
    d = ds.Datasheet()
    d.create("ds-1", 1)
    cases = [
        ("ds-1", "nonexistent", 2, PIN),   # bad section name
        ("ds-1", "", 3, PIN),              # empty section
        ("ds-1", "motivation", 4, "raw"),  # raw content refused
        ("ds-9", "motivation", 5, PIN),    # unknown datasheet
    ]
    for did, section, seq, digest in cases:
        with pytest.raises(ds.DatasheetError):
            d.section(did, section, seq, content_digest=digest)
    assert d.stats(6)["rejected"] == len(cases)
    for s in ds.REQUIRED_SECTIONS:  # full vocabulary accepted
        d2 = ds.Datasheet()
        d2.create("x", 1)
        d2.section("x", s, 2)


# 8. duplicate section refused; post-publish section refused
def test_duplicate_section_and_post_publish_refused():
    d = ds.Datasheet()
    nxt = _full(d)
    with pytest.raises(ds.DuplicateSectionError):
        d.section("ds-1", "motivation", nxt)
    d.publish("ds-1", nxt + 1)
    with pytest.raises(ds.PublishedDatasheetError):
        d.section("ds-1", "motivation", nxt + 2)
    assert d.stats(nxt + 3)["rejected"] == 2


# 9. verify incomplete -> as data
def test_verify_incomplete_as_data():
    d = ds.Datasheet()
    d.create("ds-1", 1)
    d.section("ds-1", "motivation", 2, content_digest=PIN)
    rep = d.verify("ds-1", 3)
    assert rep.verify()
    assert rep.complete is False
    assert rep.sections_present == ("motivation",)
    assert set(rep.sections_missing) == set(ds.REQUIRED_SECTIONS) - {"motivation"}
    with pytest.raises(ds.UnknownDatasheetError):
        d.verify("ds-9", 4)


# 10. verify complete + read purity (same seq twice, no rows, no consume)
def test_verify_complete_and_read_purity():
    d = ds.Datasheet()
    nxt = _full(d)
    before = len(d.audit_log(nxt))
    rep1 = d.verify("ds-1", nxt)
    rep2 = d.verify("ds-1", nxt)  # same seq reused: read purity
    assert rep1.complete and rep1.integrity_ok
    assert rep1.as_dict()["sections_missing"] == []
    assert rep2 == rep1
    assert len(d.audit_log(nxt + 1)) == before


# 11. publish requires completeness
def test_publish_requires_complete():
    d = ds.Datasheet()
    d.create("ds-1", 1)
    with pytest.raises(ds.DatasheetError):
        d.publish("ds-1", 2)  # incomplete -> refused
    nxt = _full(d, did="ds-2", start=3)
    pub = d.publish("ds-2", nxt)
    assert pub.verify()
    assert d.is_published("ds-2", nxt + 1) is True
    assert d.is_published("ds-1", nxt + 2) is False
    assert d.published_ids(nxt + 3) == ("ds-2",)


# 12. publish terminal; retract terminal + id never recycled
def test_publish_terminality_and_retract():
    d = ds.Datasheet()
    nxt = _full(d)
    d.publish("ds-1", nxt)
    with pytest.raises(ds.PublishedDatasheetError):
        d.publish("ds-1", nxt + 1)
    with pytest.raises(ds.DuplicateDatasheetError):  # published id stays live
        d.create("ds-1", nxt + 2)
    d2 = ds.Datasheet()
    d2.create("ds-x", 1)
    ret = d2.retract("ds-x", 2, reason="superseded")
    assert ret.verify()
    assert d2.stats(3)["retracted"] == 1
    with pytest.raises(ds.RetiredDatasheetError):
        d2.section("ds-x", "motivation", 4)
    with pytest.raises(ds.DatasheetError):
        d2.retract("ds-x", 5, reason="bogus")


# 13. seq discipline: rewind bare, malformed seqs, failed-mutation-consumes-seq
def test_seq_discipline():
    d = ds.Datasheet()
    d.create("ds-1", 1)
    n_rej = d.stats(2)["rejected"]
    with pytest.raises(ds.SeqOrderError):  # rewind raises bare
        d.create("ds-2", 1)
    assert d.stats(3)["rejected"] == n_rej  # no rejected row on bare raise
    for bad in (True, "1", 0, -2, 1.5, None):
        with pytest.raises(ds.SeqOrderError):
            d.datasheet_ids(bad)
    with pytest.raises(ds.DuplicateDatasheetError):  # failed mutation burns seq
        d.create("ds-1", 2)
    assert d.stats(3)["rejected"] == n_rej + 1


# 14. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    d = ds.Datasheet()
    d.create("ds-1", 1)
    d.section("ds-1", "motivation", 2, content_digest=PIN)
    nxt = _full(d, did="ds-2", start=3)
    d.publish("ds-2", nxt)
    log = d.audit_log(nxt + 1)
    kinds = [row["kind"] for row in log]
    assert "datasheet.created" in kinds
    assert "datasheet.section-added" in kinds
    assert "datasheet.published" in kinds
    for row in log:  # no banned key anywhere in the audit trail
        detail = row["detail"]
        for banned in ds.BANNED_AUDIT_KEYS:
            assert banned not in detail, banned
        blob = str(row)
        assert "secret-notes" not in blob
    with pytest.raises(ds.AuditKindError):
        ds.datasheet_audit_event("bogus", {}, 1)
    with pytest.raises(ds.DatasheetError):
        ds.datasheet_audit_event("created", {"title": "raw text"}, 1)


# 15. main() subprocess check + frozen-ness + concurrency smoke
def test_main_subprocess_and_frozen():
    out = subprocess.run(
        [sys.executable, str(MOD)], capture_output=True, text=True
    )
    assert out.returncode == 0
    assert out.stdout.startswith("datasheet OK:")
    d = ds.Datasheet()
    rec = d.create("ds-1", 1)
    with pytest.raises(Exception):
        rec.version = "x"  # frozen dataclass
    errs = []

    def reader():
        try:
            for _ in range(50):
                d.datasheet_ids(2)
                d.stats(3)
        except Exception as e:  # pragma: no cover
            errs.append(e)

    threads = [threading.Thread(target=reader) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errs

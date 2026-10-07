"""Targeted tests for anti_entropy.py (15 tests)."""

import ast
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import anti_entropy
from anti_entropy import (
    ANTI_ENTROPY_VERSION,
    SCHEMA_PIN,
    EMPTY_ROOT,
    AntiEntropy,
    AntiEntropyError,
    AuditKindError,
    BadDigestError,
    BadInventoryError,
    BadKeyError,
    BadValueError,
    SeqOrderError,
    anti_entropy_audit_event,
)


def make(seq_start=0):
    return AntiEntropy("test-replica"), _Seq(seq_start)


class _Seq:
    def __init__(self, start=0):
        self.n = start

    def next(self):
        self.n += 1
        return self.n


def test_version_and_schema_pins():
    assert ANTI_ENTROPY_VERSION == "anti-entropy.v1"
    assert SCHEMA_PIN == "northstar.anti-entropy.v1"
    assert EMPTY_ROOT.startswith("sha256:") and len(EMPTY_ROOT) == 7 + 64


def test_stdlib_only():
    src = Path(anti_entropy.__file__).read_text()
    tree = ast.parse(src)
    allowed = set(sys.stdlib_module_names) | {"merkle_tree"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


def test_put_roundtrip_and_digest():
    rep, s = make()
    rec = rep.put("k1", b"v1", s.next())
    assert rec.key == "k1"
    assert rec.value_digest.startswith("sha256:")
    digest, useq = rep.inventory(s.next())["k1"]
    assert digest == rec.value_digest
    rec2 = rep.put("k1", b"v2", s.next())
    assert rec2.value_digest != rec.value_digest
    assert rep.inventory(s.next())["k1"][0] == rec2.value_digest


def test_put_bad_inputs():
    rep, s = make()
    with pytest.raises(BadKeyError):
        rep.put("", b"v", s.next())
    with pytest.raises(BadKeyError):
        rep.put(123, b"v", s.next())
    with pytest.raises(BadValueError):
        rep.put("k", "not-bytes", s.next())
    with pytest.raises(BadValueError):
        rep.put("k", b"x" * ((1 << 20) + 1), s.next())
    # failed mutations consume their seq: reusing the first bad seq rewinds
    with pytest.raises(SeqOrderError):
        rep.put("k", b"v", 1)


def test_remove_tombstone():
    rep, s = make()
    rep.put("k1", b"v1", s.next())
    rec = rep.remove("k1", s.next())
    assert rec.key == "k1"
    assert "k1" in rep.tombstones(s.next())
    digest, _ = rep.inventory(s.next())["k1"]
    assert digest == anti_entropy.TOMBSTONE_DIGEST
    st = rep.stats(s.next())
    assert st.tombstones == 1 and st.live_keys == 0


def test_remove_unknown_key_books_tombstone():
    rep, s = make()
    rec = rep.remove("ghost", s.next())
    assert rec.key == "ghost"
    assert "ghost" in rep.tombstones(s.next())


def test_digest_deterministic_and_order_independent():
    a, sa = make()
    b, sb = make()
    a.put("k2", b"v2", sa.next())
    a.put("k1", b"v1", sa.next())
    b.put("k1", b"v1", sb.next())
    b.put("k2", b"v2", sb.next())
    da = a.digest(sa.next())
    db = b.digest(sb.next())
    assert da.root == db.root
    assert da.key_count == 2


def test_digest_empty_and_divergence():
    a, sa = make()
    d = a.digest(sa.next())
    assert d.root == EMPTY_ROOT and d.key_count == 0
    a.put("k", b"v", sa.next())
    d2 = a.digest(sa.next())
    assert d2.root != EMPTY_ROOT


def test_compare_equal_and_divergent():
    a, sa = make()
    b, sb = make()
    a.put("k1", b"v1", sa.next())
    a.put("k2", b"v2", sa.next())
    b.put("k1", b"v1-stale", sb.next())
    b.put("k3", b"v3", sb.next())
    da = a.digest(sa.next())
    db = b.digest(sb.next())
    rep = a.compare(db.root, b.inventory(sb.next()), sa.next())
    assert not rep.roots_equal
    assert rep.to_push == ("k2",)
    assert rep.to_pull == ("k3",)
    # identical replicas compare equal
    c, sc = make()
    c.put("k1", b"v1", sc.next())
    c.put("k2", b"v2", sc.next())
    dc = c.digest(sc.next())
    rep2 = a.compare(dc.root, c.inventory(sc.next()), sa.next())
    assert rep2.roots_equal
    assert rep2.to_push == () and rep2.to_pull == () and rep2.conflicts == ()


def test_compare_conflicts_flagged_not_resolved():
    # Both live, different values: the module reports the conflict and
    # refuses to pick a winner — per-replica seqs are not a shared clock.
    a, sa = make()
    b, sb = make()
    a.put("k", b"mine", sa.next())
    b.put("k", b"yours", sb.next())
    db = b.digest(sb.next())
    rep = a.compare(db.root, b.inventory(sb.next()), sa.next())
    assert rep.conflicts == ("k",)
    assert rep.to_push == () and rep.to_pull == ()
    # A symmetric conflict is reported on both sides.
    da = a.digest(sa.next())
    rep_b = b.compare(da.root, a.inventory(sa.next()), sb.next())
    assert rep_b.conflicts == ("k",)


def test_compare_tombstone_pushes_to_peer():
    a, sa = make()
    b, sb = make()
    a.put("k1", b"v1", sa.next())
    b.put("k1", b"v1", sb.next())
    a.remove("k1", sa.next())
    db = b.digest(sb.next())
    rep = a.compare(db.root, b.inventory(sb.next()), sa.next())
    assert not rep.roots_equal
    assert rep.to_push == ("k1",)  # tombstone propagates; no resurrection
    assert rep.to_pull == () and rep.conflicts == ()
    # ... and from the peer's side the tombstone is pulled in.
    da = a.digest(sa.next())
    rep_b = b.compare(da.root, a.inventory(sa.next()), sb.next())
    assert rep_b.to_pull == ("k1",)
    assert rep_b.to_push == () and rep_b.conflicts == ()


def test_compare_bad_inputs():
    rep, s = make()
    good = rep.inventory(s.next())
    with pytest.raises(BadDigestError):
        rep.compare("not-a-pin", good, s.next())
    with pytest.raises(BadInventoryError):
        rep.compare(EMPTY_ROOT, [("k", "v")], s.next())
    with pytest.raises(BadDigestError):
        rep.compare(EMPTY_ROOT, {"k": ("sha256:zzz", 1)}, s.next())
    with pytest.raises(BadInventoryError):
        rep.compare(EMPTY_ROOT, {"k": "sha256:" + "ab" * 32}, s.next())
    with pytest.raises(BadInventoryError):
        rep.compare(EMPTY_ROOT, {"k": ("sha256:" + "ab" * 32, -1)}, s.next())
    with pytest.raises(SeqOrderError):
        rep.compare(EMPTY_ROOT, good, "1")


def test_repair_applies_and_skips_stale():
    a, sa = make()
    b, sb = make()
    a.put("k1", b"v1", sa.next())
    b.put("k1", b"v1", sb.next())
    b.put("k2", b"v2", sb.next())
    rec = a.repair({"k1": b"v1", "k2": b"v2"}, (), sa.next())
    assert rec.applied == 1
    assert rec.skipped_stale == 1  # k1 digest already matched
    assert rec.applied_keys == ("k2",)
    assert a.inventory(sa.next())["k2"][0] == b.inventory(sb.next())["k2"][0]


def test_repair_tombstones():
    a, sa = make()
    b, sb = make()
    a.put("k1", b"v1", sa.next())
    b.put("k1", b"v1", sb.next())
    b.remove("k1", sb.next())
    rec = a.repair({}, ("k1",), sa.next())
    assert rec.tombstoned == 1
    assert "k1" in a.tombstones(sa.next())
    # full convergence: roots match after symmetric repair
    da = a.digest(sa.next())
    db = b.digest(sb.next())
    assert da.root == db.root


def test_seq_ordering_and_rejected_audit():
    rep, s = make()
    rep.put("k", b"v", s.next())
    with pytest.raises(SeqOrderError):
        rep.put("k2", b"v", 1)  # rewind: raises, consumes nothing
    with pytest.raises(SeqOrderError):
        rep.put("k2", b"v", True)  # bool is not an int seq
    # a bad-input failure consumes its seq and books a rejected row
    with pytest.raises(BadKeyError):
        rep.put("", b"v", s.next())
    rows = rep.audit_log()
    assert any(r["kind"] == "anti-entropy.rejected" for r in rows)
    # pure reads validate but never consume: rewind allowed, no audit row
    n = len(rows)
    rep.inventory(0)
    assert len(rep.audit_log()) == n


def test_audit_shapes_and_value_leak_ban():
    rep, s = make()
    rep.put("secret-key", b"super-secret-bytes", s.next())
    rep.remove("secret-key", s.next())
    rep.digest(s.next())
    for row in rep.audit_log():
        assert row["format"] == "audit.ndjson/1"
        assert row["schema"] == SCHEMA_PIN
        blob = str(row)
        assert "super-secret-bytes" not in blob
        assert "secret-key" not in blob or row["kind"] in (
            "anti-entropy.put",
            "anti-entropy.removed",
        )
    with pytest.raises(AuditKindError):
        anti_entropy_audit_event("nope", s.next())
    ev = anti_entropy_audit_event("anti-entropy.digest", s.next(), root=EMPTY_ROOT)
    assert ev["kind"] == "anti-entropy.digest"


def test_main_self_check():
    r = subprocess.run(
        [sys.executable, anti_entropy.__file__],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert r.returncode == 0, r.stderr
    assert "anti-entropy OK" in r.stdout

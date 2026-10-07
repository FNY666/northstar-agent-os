"""Tests for mpc.py: MPC session-orchestration ledger (simulated)."""

import ast
import importlib.util
import subprocess
import sys
import threading
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
MODULE_PATH = HERE.parent / "mpc.py"


def _load():
    spec = importlib.util.spec_from_file_location("mpc", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["mpc"] = module  # frozen dataclasses need a registered module
    spec.loader.exec_module(module)
    return module


mpc = _load()

DIGEST = "sha256:" + "ab" * 32
DIGEST2 = "sha256:" + "cd" * 32


def _fresh():
    return mpc.MPC()


def _run_session(mod=None):
    """Drive one 2-party session to `computed` (before reconstruct)."""
    inst = (mod or _fresh())
    inst.session("s1", 2, 2, 1)
    inst.register_party("s1", "alice", 2)
    inst.register_party("s1", "bob", 3)
    inst.share("s1", "alice", DIGEST, 4)
    inst.share("s1", "bob", DIGEST2, 5)
    inst.compute("s1", DIGEST, 6)
    return inst


# 1. version / schema pins ----------------------------------------------------


def test_version_schema_pins():
    assert mpc.MPC_VERSION == "mpc.v1"
    assert mpc.MPC_SCHEMA == "northstar.mpc.v1"
    assert mpc.AUDIT_SCHEMA == "audit.ndjson/1"
    assert mpc.STATES == ("open", "ready", "committed", "computed", "closed")


# 2. stdlib-only AST check -----------------------------------------------------


def test_stdlib_only():
    tree = ast.parse(MODULE_PATH.read_text())
    allowed = {
        "__future__",
        "hashlib",
        "threading",
        "dataclasses",
        "typing",
        "json",
        "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                assert top in allowed, f"banned import: {alias.name}"
        elif isinstance(node, ast.ImportFrom):
            top = (node.module or "").split(".")[0]
            assert top in allowed, f"banned import: {node.module}"


# 3. session roundtrip / verify -----------------------------------------------


def test_session_roundtrip_verify():
    inst = _fresh()
    rec = inst.session("s1", 3, 2, 1)
    assert rec.session_id == "s1"
    assert rec.n_parties == 3 and rec.threshold == 2
    assert rec.schema == "northstar.mpc.v1" and rec.version == "mpc.v1"
    assert rec.verify()
    assert inst.session_state("s1", 1) == "open"
    looked = inst.session_record("s1", 1)
    assert looked.digest == rec.digest


# 4. session bad-input table + seq-burn + rejected rows ------------------------


def test_session_bad_inputs():
    inst = _fresh()
    bad = [
        ("", 2, 2, mpc.BadSessionError),          # empty id
        ("has space", 2, 2, mpc.BadSessionError),  # whitespace
        ("s1", 1, 2, mpc.BadPartiesError),         # n < 2
        ("s1", True, 2, mpc.BadPartiesError),       # bool n
        ("s1", 3, 1, mpc.BadThresholdError),        # t < 2
        ("s1", 3, 4, mpc.BadThresholdError),        # t > n
        ("s1", 3, True, mpc.BadThresholdError),     # bool t
    ]
    seq = 1
    for sid, n, t, exc in bad:
        seq += 1
        with pytest.raises(exc):
            inst.session(sid, n, t, seq)
    rows = inst.audit_log(999)
    rejected = [r for r in rows if r["kind"] == "mpc.rejected"]
    assert len(rejected) == len(bad)
    assert inst.stats(999)["open_sessions"] == 0


# 5. duplicate session + retired id never recycled ------------------------------


def test_duplicate_and_retired_session():
    inst = _run_session()
    inst.reconstruct("s1", DIGEST, 7)
    assert inst.session_state("s1", 7) == "closed"
    # retired id may never be reused
    with pytest.raises(mpc.RetiredSessionError):
        inst.session("s1", 2, 2, 8)
    with pytest.raises(mpc.RetiredSessionError):
        inst.register_party("s1", "alice", 9)
    inst2 = _fresh()
    inst2.session("s1", 2, 2, 1)
    with pytest.raises(mpc.DuplicateSessionError):
        inst2.session("s1", 2, 2, 2)


# 6. register_party roundtrip + too-many / duplicate ----------------------------


def test_register_party_roundtrip():
    inst = _fresh()
    inst.session("s1", 2, 2, 1)
    r1 = inst.register_party("s1", "alice", 2)
    assert r1.verify()
    assert inst.session_state("s1", 2) == "open"
    inst.register_party("s1", "bob", 3)
    assert inst.session_state("s1", 3) == "ready"
    assert inst.party_ids("s1", 3) == ("alice", "bob")
    # a 3-party session stays open for duplicate / too-many / bad-input cases
    inst.session("s2", 3, 2, 4)
    inst.register_party("s2", "alice", 5)
    with pytest.raises(mpc.DuplicatePartyError):
        inst.register_party("s2", "alice", 6)
    inst.register_party("s2", "bob", 7)
    inst.register_party("s2", "carol", 8)
    assert inst.session_state("s2", 8) == "ready"
    with pytest.raises(mpc.SessionStateError):
        inst.register_party("s2", "dave", 9)
    with pytest.raises(mpc.UnknownSessionError):
        inst.register_party("nope", "alice", 10)
    with pytest.raises(mpc.BadPartyError):
        inst.register_party("s2", "bad id", 11)


# 7. share roundtrip + verify + all-commit transition ----------------------------


def test_share_roundtrip():
    inst = _fresh()
    inst.session("s1", 2, 2, 1)
    inst.register_party("s1", "alice", 2)
    inst.register_party("s1", "bob", 3)
    c1 = inst.share("s1", "alice", DIGEST, 4)
    assert c1.verify()
    assert inst.session_state("s1", 4) == "ready"  # not all committed yet
    c2 = inst.share("s1", "bob", DIGEST2, 5)
    assert c2.verify()
    assert inst.session_state("s1", 5) == "committed"
    looked = inst.commitment("s1", "alice", 5)
    assert looked.input_digest == DIGEST
    assert inst.commitments_for("s1", 5) == ("alice", "bob")


# 8. share bad inputs (wrong phase, unknown party, dup, bad digest) --------------


def test_share_bad_inputs():
    inst = _fresh()
    inst.session("s1", 2, 2, 1)
    # wrong phase: session still open, no parties seated
    with pytest.raises(mpc.SessionStateError):
        inst.share("s1", "alice", DIGEST, 2)
    inst.register_party("s1", "alice", 3)
    inst.register_party("s1", "bob", 4)
    with pytest.raises(mpc.UnknownPartyError):
        inst.share("s1", "carol", DIGEST, 5)
    with pytest.raises(mpc.BadDigestError):
        inst.share("s1", "alice", "not-a-digest", 6)
    inst.share("s1", "alice", DIGEST, 7)
    with pytest.raises(mpc.DuplicateShareError):
        inst.share("s1", "alice", DIGEST, 8)
    rows = inst.audit_log(999)
    rejected = [r for r in rows if r["kind"] == "mpc.rejected"]
    assert len(rejected) == 4


# 9. compute roundtrip + premature compute refusal -------------------------------


def test_compute_roundtrip():
    inst = _fresh()
    inst.session("s1", 2, 2, 1)
    inst.register_party("s1", "alice", 2)
    inst.register_party("s1", "bob", 3)
    # not all inputs committed yet
    inst.share("s1", "alice", DIGEST, 4)
    with pytest.raises(mpc.SessionStateError):
        inst.compute("s1", DIGEST, 5)
    with pytest.raises(mpc.BadDigestError):
        inst.compute("s1", "raw-circuit", 6)
    inst.share("s1", "bob", DIGEST2, 7)
    rec = inst.compute("s1", DIGEST, 8)
    assert rec.verify()
    assert rec.n_inputs == 2
    assert inst.session_state("s1", 8) == "computed"
    # input phase is over: no more shares
    with pytest.raises(mpc.SessionStateError):
        inst.share("s1", "alice", DIGEST, 9)


# 10. reconstruct roundtrip + terminality -----------------------------------------


def test_reconstruct_terminal():
    inst = _run_session()
    # premature: session is computed, but on a fresh one it fails
    inst2 = _fresh()
    inst2.session("s2", 2, 2, 1)
    with pytest.raises(mpc.SessionStateError):
        inst2.reconstruct("s2", DIGEST, 2)
    rec = inst.reconstruct("s1", DIGEST, 7)
    assert rec.verify()
    assert inst.session_state("s1", 7) == "closed"
    # everything after close refuses
    with pytest.raises(mpc.RetiredSessionError):
        inst.register_party("s1", "alice", 8)
    with pytest.raises(mpc.RetiredSessionError):
        inst.share("s1", "alice", DIGEST, 9)
    with pytest.raises(mpc.RetiredSessionError):
        inst.compute("s1", DIGEST, 10)
    with pytest.raises(mpc.RetiredSessionError):
        inst.reconstruct("s1", DIGEST, 11)
    # commitments survive the close as pure reads
    assert inst.commitments_for("s1", 11) == ("alice", "bob")
    stats = inst.stats(11)
    assert stats["closed_sessions"] == 1 and stats["reconstructions"] == 1


# 11. seq discipline ----------------------------------------------------------------


def test_seq_discipline():
    inst = _fresh()
    inst.session("s1", 2, 2, 1)
    # rewind raises bare (no rejected audit row)
    with pytest.raises(mpc.SeqOrderError):
        inst.register_party("s1", "alice", 1)
    for bad in (True, -3, 0, "x", 1.5, None):
        with pytest.raises(mpc.SeqOrderError):
            inst.register_party("s1", "alice", bad)
    rows = inst.audit_log(999)
    assert not [r for r in rows if r["kind"] == "mpc.rejected"]
    # failed mutations consume their seq
    with pytest.raises(mpc.BadPartyError):
        inst.register_party("s1", "bad id", 2)
    with pytest.raises(mpc.SeqOrderError):
        inst.register_party("s1", "alice", 2)  # seq 2 already claimed
    inst.register_party("s1", "alice", 3)  # next fresh seq works
    rejected = [r for r in inst.audit_log(999) if r["kind"] == "mpc.rejected"]
    assert len(rejected) == 1


# 12. audit shapes + leak ban + bad kind --------------------------------------------


def test_audit_shapes_and_leak_ban():
    inst = _run_session()
    inst.reconstruct("s1", DIGEST, 7)
    rows = inst.audit_log(7)
    kinds = [r["kind"] for r in rows]
    assert kinds == [
        "mpc-session-opened",
        "mpc-party-registered",
        "mpc-party-registered",
        "mpc-input-shared",
        "mpc-input-shared",
        "mpc-computed",
        "mpc-reconstructed",
    ]
    for r in rows:
        assert r["schema"] == "audit.ndjson/1"
        assert r["module"] == "mpc"
        assert "digest" in r
    # banned raw keys can never cross the audit boundary
    for bad in ("input", "secret", "share", "value", "output", "circuit", "data"):
        with pytest.raises(mpc.AuditKindError):
            mpc.mpc_audit_event("mpc-computed", 1, **{bad: "x"})
    with pytest.raises(mpc.AuditKindError):
        mpc.mpc_audit_event("nope", 1)
    # raw input text never appears in any audit row
    blob = "\n".join(repr(r) for r in rows)
    assert "super-secret-input" not in blob


# 13. cross-instance determinism + tamper rejection -----------------------------------


def test_determinism_and_tamper():
    a = _run_session()
    b = _run_session()
    ra = a.reconstruct("s1", DIGEST, 7)
    rb = b.reconstruct("s1", DIGEST, 7)
    assert ra.digest == rb.digest
    assert a.session("s2", 2, 2, 8).digest == b.session("s2", 2, 2, 8).digest
    import dataclasses

    tampered = dataclasses.replace(ra, output_digest=DIGEST2)
    assert not tampered.verify()
    assert ra.verify()


# 14. view read-purity + concurrency --------------------------------------------------


def test_read_purity_and_concurrency():
    inst = _run_session()
    before = len(inst.audit_log(6))
    assert inst.session_state("s1", 6) == "computed"
    assert inst.session_state("s1", 6) == "computed"  # same seq twice is fine
    assert inst.session_ids(6) == ("s1",)
    inst.stats(6)
    assert len(inst.audit_log(6)) == before  # reads book nothing

    def reader():
        for _ in range(50):
            inst.session_state("s1", 6)
            inst.stats(6)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


# 15. main() subprocess self-check ------------------------------------------------------


def test_main_subprocess():
    proc = subprocess.run(
        [sys.executable, str(MODULE_PATH)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert "mpc OK: session, register, share, compute, reconstruct, pins, audit" in proc.stdout

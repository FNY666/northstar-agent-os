"""Targeted tests for private_inference."""

import ast
import importlib.util
import subprocess
import sys
import threading
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
MOD = HERE.parent / "private_inference.py"
PIN = "private-inference.v1"
SCHEMA = "northstar.private-inference.v1"


def load():
    spec = importlib.util.spec_from_file_location("private_inference", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["private_inference"] = module
    spec.loader.exec_module(module)
    return module


pi_mod = load()


def make_digest(text="x"):
    return pi_mod._digest_pin({"t": text})


def test_01_version_schema_pins():
    assert pi_mod.PRIVATE_INFERENCE_VERSION == PIN
    assert pi_mod.PRIVATE_INFERENCE_SCHEMA == SCHEMA
    assert set(pi_mod.OUTCOMES) == {"answered", "noise-applied", "refused"}


def test_02_stdlib_only():
    tree = ast.parse(MOD.read_text())
    allowed = {"hashlib", "threading", "dataclasses", "fractions", "math",
               "typing", "__future__", "canonical_json", "json"}
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module.split(".")[0])
    bad = found - allowed
    assert not bad, f"non-stdlib imports: {bad}"


def test_03_register_roundtrip():
    pi = pi_mod.PrivateInference()
    rec = pi.register_model("m1", 1, 5, make_digest("policy"))
    assert rec.model_id == "m1"
    assert rec.query_quota == 5
    assert rec.digest.startswith("sha256:")
    assert rec.as_dict()["schema"] == SCHEMA
    assert pi.model_record("m1") is rec


def test_04_register_bad_inputs_burn_seq():
    pi = pi_mod.PrivateInference()
    before = len(pi.audit_log())
    seq = [0]

    def nxt():
        seq[0] += 1
        return seq[0]

    for bad in ["", "has space", 123, True, "x" * 129]:
        with pytest.raises(pi_mod.PrivateInferenceError):
            pi.register_model(bad, nxt(), 5)
    with pytest.raises(pi_mod.PrivateInferenceError):
        pi.register_model("m", nxt(), 0)
    with pytest.raises(pi_mod.PrivateInferenceError):
        pi.register_model("m", nxt(), True)
    with pytest.raises(pi_mod.PrivateInferenceError):
        pi.register_model("m", nxt(), 5, "not-a-pin")
    rows = pi.audit_log()
    assert len(rows) - before == 8
    assert all(r["kind"] == "private-inference.rejected" for r in rows[before:])
    # duplicate
    pi.register_model("m", nxt(), 1)
    with pytest.raises(pi_mod.DuplicateModelError):
        pi.register_model("m", nxt(), 1)


def test_05_query_roundtrip_and_quota():
    pi = pi_mod.PrivateInference()
    pi.register_model("m1", 1, 2)
    q1 = pi.query("alice", "m1", 2, make_digest("q"))
    assert q1.query_id == "qry-1"
    assert q1.client_id == "alice"
    assert pi.query_record("qry-1") is q1
    pi.query("alice", "m1", 3)
    with pytest.raises(pi_mod.QuotaExhaustedError):
        pi.query("alice", "m1", 4)
    # quota is per-client: bob still has room
    q3 = pi.query("bob", "m1", 5)
    assert q3.query_id == "qry-3"
    with pytest.raises(pi_mod.UnknownModelError):
        pi.query("alice", "nope", 6)
    with pytest.raises(pi_mod.BadClientError):
        pi.query("", "m1", 7)


def test_06_respond_roundtrip_fraction_math():
    pi = pi_mod.PrivateInference()
    pi.register_model("m1", 1, 3)
    q1 = pi.query("alice", "m1", 2)
    r = pi.respond(q1.query_id, 3, "noise-applied", eps_num=2, eps_den=4)
    assert r.eps_text == "1/2"  # reduced
    assert r.outcome == "noise-applied"
    assert r.response_id == "rsp-1"
    with pytest.raises(pi_mod.DuplicateResponseError):
        pi.respond(q1.query_id, 4, "answered")
    with pytest.raises(pi_mod.UnknownQueryError):
        pi.respond("qry-999", 5, "answered")
    with pytest.raises(pi_mod.BadOutcomeError):
        q2 = pi.query("alice", "m1", 6)
        pi.respond(q2.query_id, 7, "maybe")
    with pytest.raises(pi_mod.BadEpsilonError):
        pi.respond(q2.query_id, 8, "refused", eps_num=-1)
    with pytest.raises(pi_mod.BadEpsilonError):
        pi.respond(q2.query_id, 9, "refused", eps_den=0)


def test_07_audit_report_math_and_verify():
    pi = pi_mod.PrivateInference()
    pi.register_model("m1", 1, 4)
    q1 = pi.query("alice", "m1", 2)
    pi.respond(q1.query_id, 3, "noise-applied", eps_num=1, eps_den=2)
    q2 = pi.query("bob", "m1", 4)
    pi.respond(q2.query_id, 5, "answered", eps_num=1, eps_den=4)
    rep = pi.audit(6, "m1")
    assert rep.verify()
    assert rep.total_queries == 2
    assert rep.total_responses == 2
    assert rep.eps_total_text == "3/4"
    assert dict(rep.outcomes)["noise-applied"] == 1
    assert dict(rep.outcomes)["answered"] == 1
    assert dict(rep.outcomes)["refused"] == 0
    assert dict(rep.per_client) == {"alice": 1, "bob": 1}
    assert dict(rep.quota_remaining) == {"alice": 3, "bob": 3}
    assert rep.as_dict()["schema"] == SCHEMA
    # tamper breaks verify
    object.__setattr__(rep, "total_queries", 99)
    assert not rep.verify()


def test_08_retire_terminality():
    pi = pi_mod.PrivateInference()
    pi.register_model("m1", 1, 2)
    pi.query("alice", "m1", 2)
    rec = pi.retire("m1", 3, "policy-violation")
    assert rec.reason == "policy-violation"
    assert pi.retired_ids() == ("m1",)
    with pytest.raises(pi_mod.RetiredModelError):
        pi.query("alice", "m1", 4)
    with pytest.raises(pi_mod.RetiredModelError):
        pi.register_model("m1", 5, 2)
    with pytest.raises(pi_mod.RetiredModelError):
        pi.retire("m1", 6)
    with pytest.raises(pi_mod.RetiredModelError):
        pi.audit(7, "m1")
    with pytest.raises(pi_mod.BadReasonError):
        pi.retire("nope", 8, "vibes")
    with pytest.raises(pi_mod.UnknownModelError):
        pi.retire("nope", 9)


def test_09_seq_discipline():
    pi = pi_mod.PrivateInference()
    pi.register_model("m1", 1, 1)
    # rewind raises bare (no rejected row, no seq consumption)
    before = len(pi.audit_log())
    with pytest.raises(pi_mod.SeqOrderError):
        pi.register_model("m2", 1, 1)
    assert len(pi.audit_log()) == before
    # malformed seqs raise bare
    for bad in [True, "x", 1.5, None, -1]:
        with pytest.raises(pi_mod.SeqOrderError):
            pi.register_model("mx", bad, 1)
    # failed mutation consumes seq: next valid seq must advance
    with pytest.raises(pi_mod.BadModelError):
        pi.register_model("", 2, 1)
    rec = pi.register_model("m2", 3, 1)
    assert rec.seq == 3


def test_10_audit_boundary_leak_ban():
    pi = pi_mod.PrivateInference()
    pi.register_model("m1", 1, 2, make_digest("policy"))
    q = pi.query("alice", "m1", 2, make_digest("secret-query"))
    pi.respond(q.query_id, 3, "answered")
    blob = repr(pi.audit_log())
    assert "secret" not in blob
    assert blob.count("sha256:") >= 2  # pins cross the boundary, not raw text
    with pytest.raises(pi_mod.AuditKindError):
        pi_mod.private_inference_audit_event("nope", 4)
    with pytest.raises(pi_mod.AuditKindError):
        pi_mod.private_inference_audit_event("query-booked", 4,
                                             query="raw-secret")


def test_11_frozen_records():
    pi = pi_mod.PrivateInference()
    rec = pi.register_model("m1", 1, 2)
    import dataclasses
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.model_id = "hacked"  # type: ignore
    q = pi.query("alice", "m1", 2)
    with pytest.raises(dataclasses.FrozenInstanceError):
        q.client_id = "mallory"  # type: ignore


def test_12_stats_and_views():
    pi = pi_mod.PrivateInference()
    pi.register_model("m1", 1, 2)
    pi.register_model("m2", 2, 3)
    q = pi.query("alice", "m1", 3)
    r = pi.respond(q.query_id, 4, "refused")
    assert pi.response_record("rsp-1") is r
    assert pi.model_ids() == ("m1", "m2")
    assert pi.query_ids() == ("qry-1",)
    st = pi.stats()
    assert st == {"models": 2, "retired": 0, "queries": 1,
                  "responses": 1, "audit_rows": 4}
    with pytest.raises(pi_mod.UnknownQueryError):
        pi.query_record("qry-999")


def test_13_cross_instance_digest_determinism():
    a = pi_mod.PrivateInference()
    b = pi_mod.PrivateInference()
    ra = a.register_model("m1", 1, 2, make_digest("p"))
    rb = b.register_model("m1", 1, 2, make_digest("p"))
    assert ra.digest == rb.digest
    qa = a.query("alice", "m1", 2, make_digest("q"))
    qb = b.query("alice", "m1", 2, make_digest("q"))
    assert qa.digest == qb.digest
    assert a.audit(3, "m1").digest == b.audit(3, "m1").digest


def test_14_concurrency_smoke():
    pi = pi_mod.PrivateInference()
    pi.register_model("m1", 1, 100)
    errors = []
    counter = [1]
    clock = threading.Lock()

    def next_seq():
        with clock:
            counter[0] += 1
            return counter[0]

    def worker(i):
        try:
            q = pi.query(f"client-{i}", "m1", next_seq())
            pi.respond(q.query_id, next_seq(), "answered")
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert pi.stats()["queries"] == 8
    assert pi.stats()["responses"] == 8


def test_15_main_subprocess():
    proc = subprocess.run([sys.executable, str(MOD)],
                          capture_output=True, text=True, cwd=str(HERE))
    assert proc.returncode == 0, proc.stderr
    assert "private-inference OK" in proc.stdout

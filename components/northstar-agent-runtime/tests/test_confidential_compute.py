"""Targeted tests for confidential_compute.py (15 tests)."""

import ast
import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

MOD_PATH = Path(__file__).resolve().parent.parent / "confidential_compute.py"


def load():
    name = "confidential_compute_test_mod"
    spec = importlib.util.spec_from_file_location(name, MOD_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


cc_mod = load()

PIN = "sha256:" + "a" * 64
PIN2 = "sha256:" + "b" * 64


def new_session(provider="sev-snp"):
    return cc_mod.ConfidentialCompute(provider)


# 1: version/schema pins
def test_version_schema_pins():
    assert cc_mod.CC_VERSION == "confidential-compute.v1"
    assert cc_mod.SCHEMA_PIN == "northstar.confidential-compute.v1"
    assert set(cc_mod.PROVIDERS) == {"sgx", "sev-snp", "tdx"}
    assert cc_mod.TCB_VERSIONS["sgx"] == 2
    assert cc_mod.TCB_VERSIONS["tdx"] == 1


# 2: stdlib-only AST check
def test_stdlib_only():
    tree = ast.parse(MOD_PATH.read_text())
    allow = {
        "hashlib",
        "hmac",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "json",
        "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allow, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allow, node.module


# 3: run roundtrip + verify
def test_run_roundtrip():
    cc = new_session()
    rec = cc.run("job-1", "inference", 1, input_digest=PIN, output_digest=PIN2)
    assert rec.run_id == "job-1"
    assert rec.provider == "sev-snp"
    assert rec.verify("sev-snp")
    assert rec.as_dict()["schema"] == cc_mod.SCHEMA_PIN
    assert rec.run_id in cc.run_ids()


# 4: duplicate run refused + seq burn + rejected row
def test_duplicate_run_seq_burn():
    cc = new_session()
    cc.run("job-1", "inference", 1)
    with pytest.raises(cc_mod.DuplicateRunError):
        cc.run("job-1", "inference", 2)
    with pytest.raises(cc_mod.SeqOrderError):
        cc.run("job-2", "inference", 2)  # seq 2 consumed by the failed run
    kinds = [e["kind"] for e in cc.audit_log()]
    assert kinds == ["run", "rejected"]
    assert cc.stats()["last_seq"] == 2


# 5: bad-input table
def test_run_bad_inputs():
    bad_workloads = ["", "has space", "x" * 257, 123, None, True]
    for i, bad in enumerate(bad_workloads):
        cc = new_session()
        with pytest.raises(cc_mod.ConfidentialComputeError):
            cc.run("job-%d" % i, bad, 1)
    bad_digests = ["raw-bytes", "sha256:zzz", "md5:" + "a" * 32, 42]
    for bad in bad_digests:
        with pytest.raises(cc_mod.BadDigestError):
            new_session().run("job-d", "inference", 1, input_digest=bad)
        with pytest.raises(cc_mod.BadDigestError):
            new_session().run("job-d2", "inference", 1, output_digest=bad)


# 6: bad provider
def test_bad_provider():
    for bad in ["nope", "", 123, None, True, "SEV-SNP"]:
        with pytest.raises(cc_mod.BadProviderError):
            cc_mod.ConfidentialCompute(bad)
    for p in ("sgx", "sev-snp", "tdx"):
        assert cc_mod.ConfidentialCompute(p).stats()["provider"] == p


# 7: attest roundtrip
def test_attest_roundtrip():
    cc = new_session()
    cc.run("job-1", "inference", 1, input_digest=PIN)
    att = cc.attest("job-1", 2)
    assert att.attest_id == "att-1"
    assert att.tcb_version == cc_mod.TCB_VERSIONS["sev-snp"]
    assert att.enclave_measurement.startswith("sha256:")
    assert att.verify("sev-snp")
    assert cc.attest_record("att-1").run_id == "job-1"


# 8: attest refusals
def test_attest_refusals():
    cc = new_session()
    with pytest.raises(cc_mod.UnknownRunError):
        cc.attest("ghost", 1)
    cc.run("job-1", "inference", 2)
    cc.attest("job-1", 3)
    with pytest.raises(cc_mod.DuplicateAttestError):
        cc.attest("job-1", 4)


# 9: verify ok / attested
def test_verify_ok():
    cc = new_session()
    cc.run("job-1", "inference", 1, input_digest=PIN, output_digest=PIN2)
    rep = cc.verify("job-1", 2)
    assert rep.ok and rep.mac_ok and rep.pin_ok and not rep.attested
    cc.attest("job-1", 3)
    rep2 = cc.verify("job-1", 4, expect_attested=True)
    assert rep2.ok and rep2.attested
    assert rep2.as_dict()["schema"] == cc_mod.SCHEMA_PIN


# 10: verify tamper as data + expect_attested refusal
def test_verify_tamper_as_data():
    cc = new_session()
    cc.run("job-1", "inference", 1, input_digest=PIN)
    run = cc.run_record("job-1")
    object.__setattr__(run, "evidence_mac", "0" * 64)
    rep = cc.verify("job-1", 2)
    assert not rep.ok and not rep.mac_ok
    with pytest.raises(cc_mod.NotAttestedError):
        cc.verify("job-1", 3, expect_attested=True)
    with pytest.raises(cc_mod.UnknownRunError):
        cc.verify("ghost", 3)


# 11: seq discipline
def test_seq_discipline():
    cc = new_session()
    with pytest.raises(cc_mod.SeqOrderError):
        cc.run("job-1", "inference", 0)
    with pytest.raises(cc_mod.SeqOrderError):
        cc.run("job-1", "inference", True)
    with pytest.raises(cc_mod.SeqOrderError):
        cc.run("job-1", "inference", "1")
    cc.run("job-1", "inference", 1)
    with pytest.raises(cc_mod.SeqOrderError):
        cc.run("job-2", "inference", 1)  # rewind raises bare
    assert cc.stats()["last_seq"] == 1
    # verify (pure read) does not consume
    cc.verify("job-1", 1)
    cc.verify("job-1", 1)
    assert cc.stats()["last_seq"] == 1
    with pytest.raises(cc_mod.SeqOrderError):
        cc.verify("job-1", "x")


# 12: view read purity (no audit rows for verify)
def test_verify_read_purity():
    cc = new_session()
    cc.run("job-1", "inference", 1, input_digest=PIN)
    n = len(cc.audit_log())
    cc.verify("job-1", 1)
    cc.verify("job-1", 1)
    assert len(cc.audit_log()) == n
    with pytest.raises(cc_mod.UnknownRunError):
        cc.run_record("ghost")
    with pytest.raises(cc_mod.UnknownRunError):
        cc.attest_record("att-9")
    with pytest.raises(cc_mod.UnknownRunError):
        cc.attest_record(42)


# 13: audit shapes + banned-key ban + bad-kind
def test_audit_shapes_and_bans():
    cc = new_session()
    cc.run("job-1", "inference", 1, input_digest=PIN)
    cc.attest("job-1", 2)
    kinds = [e["kind"] for e in cc.audit_log()]
    assert kinds == ["run", "attested"]
    for e in cc.audit_log():
        assert e["schema"] == "audit.ndjson/1"
        assert e["module"] == "confidential-compute"
        for key in e["details"]:
            assert key not in cc_mod._BANNED_KEYS
    for banned in ("input", "payload", "secret", "key", "raw"):
        with pytest.raises(cc_mod.AuditKindError):
            cc_mod.confidential_compute_audit_event("run", 1, {banned: "x"})
    with pytest.raises(cc_mod.AuditKindError):
        cc_mod.confidential_compute_audit_event("nope", 1, {})
    with pytest.raises(cc_mod.AuditKindError):
        cc_mod.confidential_compute_audit_event("run", "1", {})


# 14: cross-instance digest determinism
def test_cross_instance_determinism():
    a = new_session()
    b = new_session("sev-snp")
    ra = a.run("job-1", "inference", 1, input_digest=PIN, output_digest=PIN2)
    rb = b.run("job-1", "inference", 1, input_digest=PIN, output_digest=PIN2)
    assert ra.digest == rb.digest
    assert ra.evidence_mac == rb.evidence_mac
    aa = a.attest("job-1", 2)
    ab = b.attest("job-1", 2)
    assert aa.digest == ab.digest
    va = a.verify("job-1", 3)
    vb = b.verify("job-1", 3)
    assert va.digest == vb.digest
    # different provider -> different MAC
    c = new_session("tdx")
    rc = c.run("job-1", "inference", 1, input_digest=PIN, output_digest=PIN2)
    assert rc.evidence_mac != ra.evidence_mac
    assert not rc.verify("sev-snp")
    assert rc.verify("tdx")


# 15: main() subprocess self-check
def test_main_subprocess():
    out = subprocess.run(
        [sys.executable, str(MOD_PATH)],
        capture_output=True,
        text=True,
        cwd=str(MOD_PATH.parent),
    )
    assert out.returncode == 0, out.stderr
    assert "confidential-compute OK" in out.stdout

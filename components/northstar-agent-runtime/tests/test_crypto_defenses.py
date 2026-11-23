"""Batch tests for crypto_defense_01..15 (D-CRYPTO-001..015)."""

import importlib.util
import sys
from pathlib import Path

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# ---- 01: Sigstore ----
d01 = _load("crypto_defense_01")


def test_01_sign_verify():
    s = d01.MockSigstore()
    s.register_key("k")
    sig = s.sign(b"data", "k")
    assert s.verify(b"data", sig, "k") is True


def test_01_tamper():
    s = d01.MockSigstore()
    s.register_key("k")
    sig = s.sign(b"data", "k")
    assert s.verify(b"evil", sig, "k") is False


def test_01_unknown_key():
    s = d01.MockSigstore()
    assert s.verify(b"d", b"sig", "nope") is False


def test_01_stdlib():
    assert d01.stdlib_only() is True


# ---- 02: Cosign ----
d02 = _load("crypto_defense_02")


def test_02_verify_identity():
    c = d02.MockCosign()
    c.register_identity("alice")
    sig = c.sign(b"art", "alice")
    assert c.verify(b"art", sig, "alice") is True


def test_02_wrong_identity():
    c = d02.MockCosign()
    c.register_identity("alice")
    c.register_identity("bob")
    sig = c.sign(b"art", "alice")
    assert c.verify(b"art", sig, "bob") is False


def test_02_tamper():
    c = d02.MockCosign()
    c.register_identity("alice")
    sig = c.sign(b"art", "alice")
    assert c.verify(b"bad", sig, "alice") is False


def test_02_stdlib():
    assert d02.stdlib_only() is True


# ---- 03: Rekor ----
d03 = _load("crypto_defense_03")


def test_03_append():
    r = d03.MockRekor()
    assert r.append(b"a") == 0
    assert r.append(b"b") == 1


def test_03_inclusion():
    r = d03.MockRekor()
    r.append(b"a")
    assert r.verify_inclusion(0, b"a") is True
    assert r.verify_inclusion(0, b"x") is False


def test_03_chain():
    r = d03.MockRekor()
    r.append(b"a")
    r.append(b"b")
    assert r.verify_chain() is True


def test_03_stdlib():
    assert d03.stdlib_only() is True


# ---- 04: Fulcio ----
d04 = _load("crypto_defense_04")

import time


def test_04_issue_verify():
    f = d04.MockFulcio()
    cert = f.issue_cert("alice")
    assert f.verify_cert(cert) is True


def test_04_expired():
    f = d04.MockFulcio()
    cert = f.issue_cert("bob", ttl=0.01)
    time.sleep(0.02)
    assert f.verify_cert(cert) is False


def test_04_tampered_identity():
    f = d04.MockFulcio()
    cert = f.issue_cert("alice")
    bad = d04.Certificate(
        cert.cert_id, "eve", cert.issued_at, cert.expires_at, cert.signature
    )
    assert f.verify_cert(bad) is False


def test_04_stdlib():
    assert d04.stdlib_only() is True


# ---- 05: Threshold ----
d05 = _load("crypto_defense_05")


def test_05_split_reconstruct():
    shares = d05.split_secret(b"x" * 16, 3, 2)
    assert d05.reconstruct(shares) == b"x" * 16


def test_05_threshold_sign():
    s = d05.ThresholdSigner(2, 3)
    p = [s.partial_sign(0, b"d"), s.partial_sign(1, b"d")]
    assert s.combine(p, b"d") is True
    assert s.combine(p[:1], b"d") is False


def test_05_bad_params():
    try:
        d05.split_secret(b"", 3, 2)
        assert False
    except d05.ThresholdError:
        pass


def test_05_stdlib():
    assert d05.stdlib_only() is True


# ---- 06: MPC ----
d06 = _load("crypto_defense_06")


def test_06_combine():
    m = d06.MockMpcKey(3, 2)
    p = [m.party_sign(0, b"d"), m.party_sign(1, b"d")]
    c = m.combine_signatures(p, b"d")
    assert m.verify_combined(c, b"d", p) is True


def test_06_insufficient():
    m = d06.MockMpcKey(3, 2)
    try:
        m.combine_signatures([m.party_sign(0, b"d")], b"d")
        assert False
    except d06.MpcError:
        pass


def test_06_bad_party():
    m = d06.MockMpcKey(3, 2)
    try:
        m.party_sign(9, b"d")
        assert False
    except d06.MpcError:
        pass


def test_06_stdlib():
    assert d06.stdlib_only() is True


# ---- 07: HSM ----
d07 = _load("crypto_defense_07")


def test_07_sign_verify():
    h = d07.MockHsm()
    handle = h.generate_key("k")
    sig = h.sign(handle, b"d")
    assert h.verify(handle, b"d", sig) is True


def test_07_tamper():
    h = d07.MockHsm()
    handle = h.generate_key("k")
    sig = h.sign(handle, b"d")
    assert h.verify(handle, b"x", sig) is False


def test_07_delete():
    h = d07.MockHsm()
    handle = h.generate_key("k")
    h.delete_key(handle)
    assert h.key_exists(handle) is False


def test_07_stdlib():
    assert d07.stdlib_only() is True


# ---- 08: Rotation ----
d08 = _load("crypto_defense_08")


def test_08_rotate():
    kr = d08.KeyRotator()
    assert kr.current_version == 1
    kr.rotate()
    assert kr.current_version == 2


def test_08_old_sig_verifies():
    kr = d08.KeyRotator()
    sig = kr.sign(b"d")
    kr.rotate()
    assert kr.verify(b"d", sig) is True


def test_08_tamper():
    kr = d08.KeyRotator()
    sig = kr.sign(b"d")
    assert kr.verify(b"x", sig) is False


def test_08_stdlib():
    assert d08.stdlib_only() is True


# ---- 09: Forward secrecy ----
d09 = _load("crypto_defense_09")

import hashlib


def test_09_session():
    m = d09.ForwardSecrecyManager()
    pub = m.start_session("s")
    assert len(pub) == 32
    assert m.session_active("s") is True


def test_09_close():
    m = d09.ForwardSecrecyManager()
    m.start_session("s")
    m.close_session("s")
    assert m.session_active("s") is False


def test_09_unknown():
    m = d09.ForwardSecrecyManager()
    try:
        m.complete_handshake("nope", b"x" * 32)
        assert False
    except d09.ForwardSecrecyError:
        pass


def test_09_stdlib():
    assert d09.stdlib_only() is True


# ---- 10: PQ KEM ----
d10 = _load("crypto_defense_10")


def test_10_keygen():
    k = d10.MockKyberKem()
    pk, sk = k.keygen()
    assert len(pk) == 32 and len(sk) == 32


def test_10_encaps():
    k = d10.MockKyberKem()
    pk, _ = k.keygen()
    ct, ss = k.encaps(pk)
    assert len(ct) == 32 and len(ss) == 32


def test_10_bad_key():
    k = d10.MockKyberKem()
    try:
        k.encaps(b"short")
        assert False
    except d10.KemError:
        pass


def test_10_stdlib():
    assert d10.stdlib_only() is True


# ---- 11: Hybrid ----
d11 = _load("crypto_defense_11")


def test_11_encaps():
    ct, ss_c, ss_p = d11.hybrid_encaps()
    assert len(ct) == 64


def test_11_kdf():
    ct, ss_c, ss_p = d11.hybrid_encaps()
    out = d11.hybrid_kdf(ss_c, ss_p, b"info")
    assert len(out) == 32


def test_11_kdf_domain_sep():
    ct, ss_c, ss_p = d11.hybrid_encaps()
    a = d11.hybrid_kdf(ss_c, ss_p, b"a")
    b = d11.hybrid_kdf(ss_c, ss_p, b"b")
    assert a != b


def test_11_stdlib():
    assert d11.stdlib_only() is True


# ---- 12: ZK ----
d12 = _load("crypto_defense_12")


def test_12_prove_verify():
    zk = d12.MockZk()
    proof = zk.prove({"c": 1}, {"w": 2})
    assert zk.verify({"c": 1}, proof) is True


def test_12_wrong_stmt():
    zk = d12.MockZk()
    proof = zk.prove({"c": 1}, {"w": 2})
    assert zk.verify({"c": 9}, proof) is False


def test_12_bad_proof():
    zk = d12.MockZk()
    assert zk.verify({"c": 1}, b"bad") is False


def test_12_stdlib():
    assert d12.stdlib_only() is True


# ---- 13: OPRF ----
d13 = _load("crypto_defense_13")


def test_13_blocked():
    s = d13.MockOprfServer(blocklist={b"bad"})
    c = d13.MockOprfClient()
    assert c.screen(b"bad", s) is True


def test_13_clean():
    s = d13.MockOprfServer(blocklist={b"bad"})
    c = d13.MockOprfClient()
    assert c.screen(b"good", s) is False


def test_13_blind_roundtrip():
    s = d13.MockOprfServer()
    c = d13.MockOprfClient()
    b = c.blind(b"x")
    assert c.unblind(s.evaluate(b)) == s.evaluate(b)


def test_13_stdlib():
    assert d13.stdlib_only() is True


# ---- 14: PIR ----
d14 = _load("crypto_defense_14")


def test_14_query():
    s = d14.MockPirServer({0: b"a", 1: b"b"})
    c = d14.MockPirClient()
    assert c.query(1, s) == b"b"


def test_14_missing():
    s = d14.MockPirServer({0: b"a"})
    c = d14.MockPirClient()
    assert c.query(5, s) is None


def test_14_batch():
    s = d14.MockPirServer({0: b"a", 1: b"b"})
    c = d14.MockPirClient()
    assert c.batch_query([0, 1], s) == {0: b"a", 1: b"b"}


def test_14_stdlib():
    assert d14.stdlib_only() is True


# ---- 15: Homomorphic ----
d15 = _load("crypto_defense_15")


def test_15_add():
    he = d15.MockHomomorphic()
    ct = he.add(he.encrypt(10), he.encrypt(20))
    assert he.decrypt(ct) == 30


def test_15_add_plain():
    he = d15.MockHomomorphic()
    ct = he.add_plain(he.encrypt(10), 5)
    assert he.decrypt(ct) == 15


def test_15_roundtrip():
    he = d15.MockHomomorphic()
    assert he.decrypt(he.encrypt(42)) == 42


def test_15_stdlib():
    assert d15.stdlib_only() is True


# ---- version pins ----
def test_version_pins():
    mods = [d01, d02, d03, d04, d05, d06, d07, d08, d09, d10, d11, d12, d13, d14, d15]
    for i, m in enumerate(mods, 1):
        attr = f"CRYPTO_DEFENSE_{i:02d}_VERSION"
        assert getattr(m, attr) == f"crypto-defense-{i:02d}.v1", attr

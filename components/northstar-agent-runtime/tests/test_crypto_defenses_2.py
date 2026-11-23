"""Batch tests for crypto_defense_16..30 (D-CRYPTO-016..030)."""

import importlib.util
import sys
from pathlib import Path

import pytest

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# ---- 16: Secure enclaves ----
d16 = _load("crypto_defense_16")


def test_16_attest_verify():
    e = d16.MockEnclave("enc-1", b"code v1")
    q = e.attest("n1")
    assert d16.verify_quote(q, e.verifier_key(), e.measurement) is True


def test_16_tampered_nonce():
    e = d16.MockEnclave("enc-1", b"code v1")
    q = e.attest("n1")
    bad = d16.AttestationQuote(q.enclave_id, q.measurement, "other", q.mac)
    assert d16.verify_quote(bad, e.verifier_key(), e.measurement) is False


def test_16_wrong_measurement():
    e = d16.MockEnclave("enc-1", b"code v1")
    q = e.attest("n1")
    assert d16.verify_quote(q, e.verifier_key(), "00" * 32) is False


def test_16_stdlib():
    assert d16.stdlib_only() is True


# ---- 17: Remote attestation ----
d17 = _load("crypto_defense_17")


def test_17_handshake():
    p = d17.MockProver("m1")
    v = d17.MockVerifier()
    ch = v.issue_challenge()
    assert v.verify(p.respond(ch), p.verifier_key(), "m1") is True


def test_17_replay():
    p = d17.MockProver("m1")
    v = d17.MockVerifier()
    ch = v.issue_challenge()
    q = p.respond(ch)
    assert v.verify(q, p.verifier_key(), "m1") is True
    assert v.verify(q, p.verifier_key(), "m1") is False


def test_17_wrong_measurement():
    p = d17.MockProver("m1")
    v = d17.MockVerifier()
    q = p.respond(v.issue_challenge())
    assert v.verify(q, p.verifier_key(), "m2") is False


def test_17_stdlib():
    assert d17.stdlib_only() is True


# ---- 18: Measured boot ----
d18 = _load("crypto_defense_18")


def test_18_golden():
    comps = [(0, "fw", b"a"), (1, "bl", b"b")]
    a = d18.MeasuredBoot()
    a.measure_boot(comps)
    b = d18.MeasuredBoot()
    b.measure_boot(comps)
    assert b.verify(a.pcr_state()) is True


def test_18_tamper():
    comps = [(0, "fw", b"a")]
    a = d18.MeasuredBoot()
    a.measure_boot(comps)
    c = d18.MeasuredBoot()
    c.measure_boot([(0, "fw", b"EVIL")])
    assert c.verify(a.pcr_state()) is False


def test_18_extend():
    m = d18.MeasuredBoot()
    assert m.pcr(0) == "00" * 32
    m.extend(0, b"x")
    assert m.pcr(0) != "00" * 32


def test_18_stdlib():
    assert d18.stdlib_only() is True


# ---- 19: TPM ----
d19 = _load("crypto_defense_19")


def test_19_quote():
    t = d19.MockTPM()
    assert t.verify_quote(t.quote("n1")) is True


def test_19_seal_unseal():
    t = d19.MockTPM()
    sealed = t.seal(b"secret", t.pcr_read())
    assert t.unseal(sealed) == b"secret"


def test_19_pcr_change_breaks_unseal():
    t = d19.MockTPM()
    sealed = t.seal(b"secret", t.pcr_read())
    t.extend_pcr(0, b"new bootloader")
    with pytest.raises(d19.TpmError):
        t.unseal(sealed)


def test_19_stdlib():
    assert d19.stdlib_only() is True


# ---- 20: Hardware tokens ----
d20 = _load("crypto_defense_20")


def test_20_sign_verify():
    t = d20.MockHardwareToken("1234")
    assert t.unlock("1234") is True
    sig = t.sign(b"data", user_present=True)
    assert t.verify(b"data", sig) is True


def test_20_no_presence():
    t = d20.MockHardwareToken("1234")
    t.unlock("1234")
    with pytest.raises(d20.TokenError):
        t.sign(b"data", user_present=False)


def test_20_pin_lockout():
    t = d20.MockHardwareToken("9999", max_retries=2)
    t.unlock("0000")
    t.unlock("0000")
    assert t.is_locked is True
    assert t.unlock("9999") is False


def test_20_stdlib():
    assert d20.stdlib_only() is True


# ---- 21: Biometric ----
d21 = _load("crypto_defense_21")


def test_21_genuine():
    b = d21.MockBiometric(threshold=2)
    b.enroll(b"template-001")
    assert b.authenticate(b"template-002", liveness=True) is True


def test_21_impostor():
    b = d21.MockBiometric(threshold=2)
    b.enroll(b"template-001")
    assert b.authenticate(b"someone-else-entirely!", liveness=True) is False


def test_21_no_liveness():
    b = d21.MockBiometric()
    b.enroll(b"template-001")
    with pytest.raises(d21.BiometricError):
        b.authenticate(b"template-001", liveness=False)


def test_21_stdlib():
    assert d21.stdlib_only() is True


# ---- 22: WebAuthn ----
d22 = _load("crypto_defense_22")


def test_22_register_auth():
    rp = d22.MockWebAuthn("example.com", "https://example.com")
    cred = rp.register("alice")
    ch = rp.start_authentication("alice")
    a = rp.make_assertion(cred, ch, "https://example.com")
    assert rp.verify_assertion(a) is True


def test_22_wrong_origin():
    rp = d22.MockWebAuthn("example.com", "https://example.com")
    cred = rp.register("alice")
    ch = rp.start_authentication("alice")
    a = rp.make_assertion(cred, ch, "https://evil.com")
    assert rp.verify_assertion(a) is False


def test_22_replay():
    rp = d22.MockWebAuthn("example.com", "https://example.com")
    cred = rp.register("alice")
    ch = rp.start_authentication("alice")
    a = rp.make_assertion(cred, ch, "https://example.com")
    assert rp.verify_assertion(a) is True
    assert rp.verify_assertion(a) is False


def test_22_stdlib():
    assert d22.stdlib_only() is True


# ---- 23: Passkeys ----
d23 = _load("crypto_defense_23")


def test_23_create_auth():
    m = d23.MockPasskeyManager("example.com")
    pk = m.create_passkey("alice", "phone")
    n = m.challenge(pk.passkey_id)
    a = m.authenticate(pk.passkey_id, "phone", n)
    assert a is not None
    assert m.verify(pk.passkey_id, "phone", n, a) is True


def test_23_second_device():
    m = d23.MockPasskeyManager("example.com")
    pk = m.create_passkey("alice", "phone")
    m.add_device(pk.passkey_id, "laptop")
    n = m.challenge(pk.passkey_id)
    a = m.authenticate(pk.passkey_id, "laptop", n)
    assert a is not None
    assert m.verify(pk.passkey_id, "laptop", n, a) is True


def test_23_revoked():
    m = d23.MockPasskeyManager("example.com")
    pk = m.create_passkey("alice", "phone")
    m.revoke_device(pk.passkey_id, "phone")
    n = m.challenge(pk.passkey_id)
    assert m.authenticate(pk.passkey_id, "phone", n) is None


def test_23_stdlib():
    assert d23.stdlib_only() is True


# ---- 24: OIDC ----
d24 = _load("crypto_defense_24")


def test_24_roundtrip():
    op = d24.MockOIDCProvider("https://idp.example.com")
    tok = op.issue("u1", "client-a", "n-1")
    claims = op.validate(tok, "client-a", "n-1")
    assert claims is not None and claims.sub == "u1"


def test_24_wrong_aud():
    op = d24.MockOIDCProvider("https://idp.example.com")
    tok = op.issue("u1", "client-a", "n-1")
    assert op.validate(tok, "client-b", "n-1") is None


def test_24_expired():
    op = d24.MockOIDCProvider("https://idp.example.com", ttl=-1)
    tok = op.issue("u1", "client-a", "n-1")
    assert op.validate(tok, "client-a", "n-1") is None


def test_24_stdlib():
    assert d24.stdlib_only() is True


# ---- 25: SAML ----
d25 = _load("crypto_defense_25")


def test_25_roundtrip():
    idp = d25.MockSAMLIdP("https://idp.example.com")
    r = idp.issue_response("alice", "sp-1", "https://sp/acs", "req-1")
    a = idp.validate_response(r, "sp-1", "https://sp/acs")
    assert a is not None and a.name_id == "alice"


def test_25_replay():
    idp = d25.MockSAMLIdP("https://idp.example.com")
    r = idp.issue_response("alice", "sp-1", "https://sp/acs", "req-1")
    assert idp.validate_response(r, "sp-1", "https://sp/acs") is not None
    assert idp.validate_response(r, "sp-1", "https://sp/acs") is None


def test_25_wrong_audience():
    idp = d25.MockSAMLIdP("https://idp.example.com")
    r = idp.issue_response("alice", "sp-2", "https://sp/acs", "req-1")
    assert idp.validate_response(r, "sp-1", "https://sp/acs") is None


def test_25_stdlib():
    assert d25.stdlib_only() is True


# ---- 26: OAuth scopes ----
d26 = _load("crypto_defense_26")


def test_26_exact():
    g = d26.parse_scopes("read:files write:files")
    assert d26.has_scope(g, "read:files") is True
    assert d26.has_scope(g, "delete:files") is False


def test_26_wildcard():
    g = d26.parse_scopes("read:*")
    assert d26.has_scope(g, "read:files") is True
    assert d26.has_scope(g, "write:files") is False


def test_26_admin():
    g = d26.parse_scopes("admin")
    assert d26.has_scope(g, "anything:ever") is True
    assert d26.has_all_scopes(g, ["a", "b:c"]) is True


def test_26_stdlib():
    assert d26.stdlib_only() is True


# ---- 27: JWT ----
d27 = _load("crypto_defense_27")


def test_27_roundtrip():
    key = b"k" * 32
    tok = d27.encode({"sub": "u1", "exp": 9999999999}, key)
    assert d27.decode(tok, key).claims["sub"] == "u1"


def test_27_expired():
    key = b"k" * 32
    tok = d27.encode({"sub": "u1", "exp": 1}, key)
    with pytest.raises(d27.JwtError):
        d27.decode(tok, key)


def test_27_alg_none():
    import base64
    import json

    key = b"k" * 32
    h = base64.urlsafe_b64encode(json.dumps({"alg": "none"}).encode()).rstrip(b"=").decode()
    b = base64.urlsafe_b64encode(json.dumps({"sub": "u1"}).encode()).rstrip(b"=").decode()
    with pytest.raises(d27.JwtError):
        d27.decode(f"{h}.{b}.", key)


def test_27_stdlib():
    assert d27.stdlib_only() is True


# ---- 28: Token binding ----
d28 = _load("crypto_defense_28")


def test_28_bind_verify():
    b = d28.TokenBinder()
    bound = b.bind("tok-1", "key-1")
    assert b.verify(bound, "key-1") is True


def test_28_wrong_key():
    b = d28.TokenBinder()
    bound = b.bind("tok-1", "key-1")
    assert b.verify(bound, "key-2") is False


def test_28_tampered():
    b = d28.TokenBinder()
    bound = b.bind("tok-1", "key-1")
    evil = d28.BoundToken("tok-EVIL", bound.key_id, bound.binding)
    assert b.verify(evil, "key-1") is False


def test_28_stdlib():
    assert d28.stdlib_only() is True


# ---- 29: DPoP ----
d29 = _load("crypto_defense_29")


def test_29_valid():
    import secrets

    srv = d29.DPoPServer()
    key = d29.DPoPKey("k1", secrets.token_bytes(32))
    srv.register_key(key)
    p = srv.make_proof(key, "POST", "https://api.example.com/t")
    assert srv.validate(p, "POST", "https://api.example.com/t") is True


def test_29_replay():
    import secrets

    srv = d29.DPoPServer()
    key = d29.DPoPKey("k1", secrets.token_bytes(32))
    srv.register_key(key)
    p = srv.make_proof(key, "POST", "https://api.example.com/t")
    assert srv.validate(p, "POST", "https://api.example.com/t") is True
    assert srv.validate(p, "POST", "https://api.example.com/t") is False


def test_29_wrong_url():
    import secrets

    srv = d29.DPoPServer()
    key = d29.DPoPKey("k1", secrets.token_bytes(32))
    srv.register_key(key)
    p = srv.make_proof(key, "POST", "https://api.example.com/t")
    assert srv.validate(p, "POST", "https://api.example.com/other") is False


def test_29_stdlib():
    assert d29.stdlib_only() is True


# ---- 30: mTLS ----
d30 = _load("crypto_defense_30")


def test_30_handshake():
    import hashlib

    ca = d30.MockCA()
    srv = d30.MockMTLSServer(ca)
    kh = hashlib.sha256(b"k").hexdigest()
    cert = ca.issue("svc", kh)
    assert srv.handshake(cert, kh) is True


def test_30_revoked():
    import hashlib

    ca = d30.MockCA()
    srv = d30.MockMTLSServer(ca)
    kh = hashlib.sha256(b"k").hexdigest()
    cert = ca.issue("svc", kh)
    srv.revoke(cert.serial)
    assert srv.handshake(cert, kh) is False


def test_30_expired():
    import hashlib

    ca = d30.MockCA()
    srv = d30.MockMTLSServer(ca)
    kh = hashlib.sha256(b"k").hexdigest()
    cert = ca.issue("svc", kh, ttl=-1)
    assert srv.handshake(cert, kh) is False


def test_30_stdlib():
    assert d30.stdlib_only() is True


# ---- version pins ----
def test_version_pins():
    mods = [d16, d17, d18, d19, d20, d21, d22, d23, d24, d25, d26, d27, d28, d29, d30]
    for i, m in enumerate(mods, 16):
        attr = f"CRYPTO_DEFENSE_{i:02d}_VERSION"
        assert getattr(m, attr) == f"crypto-defense-{i:02d}.v1", attr

"""Tamper-evident audit feed: hash chain, Ed25519 signatures, CLI verify."""
import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

import cli
import support  # noqa: F401

_CONTRACT_ROOT = Path(__file__).resolve().parents[2] / "northstar-run-contract"
if str(_CONTRACT_ROOT) not in sys.path:
    sys.path.insert(0, str(_CONTRACT_ROOT))
import audit as normative_audit  # noqa: E402

from audit_chain import (
    CHAIN_VERSION,
    CHAIN_VERSION_V2,
    ChainResult,
    _sha256_hex,
    anchor_manifest,
    build_genesis_params,
    canonical_json,
    chain_record,
    chain_records,
    check_anchor,
    generate_keypair,
    genesis_hash,
    jcs_canonical_json,
    sign_record,
    verify_file,
    verify_lines,
    verify_signature,
)
from audit_export import validate_audit_record
from ed25519 import public_key, sign, verify


def sample_audit(seq, event="assistant", **payload):
    return {
        "schema_version": "audit.ndjson/1",
        "component": "northstar-agent-runtime",
        "event": event,
        "seq": seq,
        "ts": f"2026-10-03T10:00:{seq:02d}.000Z",
        "level": "info",
        "payload": dict(payload),
    }


def to_lines(records):
    return [
        json.dumps(r, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        for r in records
    ]


def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class Ed25519VectorTests(unittest.TestCase):
    """RFC 8032 §7.1 TEST 1-3, pinned (two independent sources agree)."""

    VECTORS = [
        (
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ),
        (
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        ),
        (
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "af82",
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
            "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        ),
    ]

    def test_rfc8032_vectors(self):
        for secret_hex, pub_hex, msg_hex, sig_hex in self.VECTORS:
            with self.subTest(msg=msg_hex or "<empty>"):
                sk, msg, sig = (bytes.fromhex(h) for h in (secret_hex, msg_hex, sig_hex))
                self.assertEqual(public_key(sk).hex(), pub_hex)
                self.assertEqual(sign(sk, msg).hex(), sig_hex)
                self.assertTrue(verify(bytes.fromhex(pub_hex), msg, bytes.fromhex(sig_hex)))

    def test_tampered_signature_rejected(self):
        secret_hex, pub_hex, msg_hex, sig_hex = self.VECTORS[0]
        sk, pub, msg, sig = (bytes.fromhex(h) for h in (secret_hex, pub_hex, msg_hex, sig_hex))
        bad = bytearray(sig)
        bad[0] ^= 0x01
        self.assertFalse(verify(pub, msg, bytes(bad)))

    def test_wrong_key_rejected(self):
        secret_hex, pub_hex, msg_hex, _sig_hex = self.VECTORS[0]
        other_secret_hex = self.VECTORS[1][0]
        msg = bytes.fromhex(msg_hex)
        sig = sign(bytes.fromhex(secret_hex), msg)
        self.assertFalse(verify(public_key(bytes.fromhex(other_secret_hex)), msg, sig))
        self.assertTrue(verify(bytes.fromhex(pub_hex), msg, sig))

    def test_malformed_inputs_never_raise(self):
        self.assertFalse(verify(b"short", b"m", b"short"))
        self.assertFalse(verify(bytes(32), b"m", bytes(64)))
        with self.assertRaises(ValueError):
            public_key(b"short")
        with self.assertRaises(ValueError):
            sign(b"short", b"m")


class ChainRoundTripTests(unittest.TestCase):
    def test_chain_then_verify_ok(self):
        records = [sample_audit(i) for i in range(5)]
        chained = chain_records(records, component="northstar-agent-runtime", session_id="s-1")
        result = verify_lines(to_lines(chained))
        self.assertTrue(result.ok)
        self.assertEqual(result.chained, 5)
        self.assertEqual(result.broken_at, None)

    def test_genesis_anchor_is_recomputable(self):
        chained = chain_records([sample_audit(0)], component="c", run_id="r-9")
        first = chained[0]
        self.assertEqual(first["genesis"]["run_id"], "r-9")
        self.assertEqual(genesis_hash(first["genesis"]), first["prev_hash"])

    def test_chain_result_shape(self):
        result = ChainResult(ok=True)
        self.assertIsInstance(result.broken_at, type(None))

    def test_empty_records_chain_to_empty(self):
        self.assertEqual(chain_records([], component="c"), [])


class TamperDetectionTests(unittest.TestCase):
    def setUp(self):
        records = [sample_audit(i, text=f"msg-{i}") for i in range(4)]
        self.chained = chain_records(records, component="northstar-agent-runtime", session_id="s-1")

    def _tampered_lines(self, index, mutate):
        records = [dict(r, payload=dict(r["payload"])) for r in self.chained]
        mutate(records[index])
        return to_lines(records)

    def test_modified_payload_detected_at_exact_line(self):
        lines = self._tampered_lines(2, lambda r: r["payload"].update(text="forged"))
        result = verify_lines(lines)
        self.assertFalse(result.ok)
        self.assertEqual(result.broken_at, 3)

    def test_modified_chain_hash_detected(self):
        lines = self._tampered_lines(1, lambda r: r.update(chain_hash="00" * 32))
        result = verify_lines(lines)
        self.assertFalse(result.ok)
        self.assertEqual(result.broken_at, 2)

    def test_reorder_detected(self):
        records = [self.chained[0], self.chained[2], self.chained[1], self.chained[3]]
        result = verify_lines(to_lines(records))
        self.assertFalse(result.ok)
        self.assertEqual(result.broken_at, 2)

    def test_middle_deletion_detected(self):
        records = [self.chained[0], self.chained[2], self.chained[3]]
        result = verify_lines(to_lines(records))
        self.assertFalse(result.ok)
        self.assertEqual(result.broken_at, 2)

    def test_tail_truncation_is_invisible_to_bare_chain(self):
        # Documented limitation: a bare chain is prefix-valid. The anchor
        # manifest exists exactly for this attack (see AnchorTests).
        lines = to_lines(self.chained[:2])
        result = verify_lines(lines)
        self.assertTrue(result.ok)

    def test_genesis_tamper_detected(self):
        records = [dict(r) for r in self.chained]
        records[0] = dict(records[0], genesis={**records[0]["genesis"], "session_id": "evil"})
        result = verify_lines(to_lines(records))
        self.assertFalse(result.ok)
        self.assertEqual(result.broken_at, 1)


class LegacyFeedTests(unittest.TestCase):
    def test_unprotected_feed_reports_instead_of_crashing(self):
        lines = to_lines([sample_audit(i) for i in range(3)])
        result = verify_lines(lines)
        self.assertFalse(result.ok)
        self.assertTrue(result.unprotected)
        self.assertIsNone(result.broken_at)
        self.assertIn("unprotected", result.reason)

    def test_partially_chained_feed_is_broken(self):
        chained = chain_records([sample_audit(i) for i in range(3)], component="c")
        mixed = to_lines([chained[0], sample_audit(9), chained[2]])
        result = verify_lines(mixed)
        self.assertFalse(result.ok)
        self.assertEqual(result.broken_at, 2)

    def test_empty_feed_is_invalid(self):
        result = verify_lines([])
        self.assertFalse(result.ok)
        self.assertFalse(result.unprotected)

    def test_bad_json_is_invalid_not_crash(self):
        result = verify_lines(['{"not": "closed"'])
        self.assertFalse(result.ok)

    def test_missing_file_reports(self):
        result = verify_file("/tmp/does-not-exist-ns-audit.ndjson")
        self.assertFalse(result.ok)
        self.assertIn("cannot read", result.reason)


class AnchorTests(unittest.TestCase):
    def test_anchor_round_trip(self):
        chained = chain_records([sample_audit(i) for i in range(3)], component="c")
        with tempfile.TemporaryDirectory() as directory:
            feed = Path(directory) / "feed.ndjson"
            feed.write_text("\n".join(to_lines(chained)) + "\n", encoding="utf-8")
            manifest = anchor_manifest(feed)
            self.assertEqual(manifest["records"], 3)
            ok, reason = check_anchor(feed, manifest)
            self.assertTrue(ok, reason)

    def test_truncation_detected_via_anchor(self):
        chained = chain_records([sample_audit(i) for i in range(3)], component="c")
        with tempfile.TemporaryDirectory() as directory:
            feed = Path(directory) / "feed.ndjson"
            feed.write_text("\n".join(to_lines(chained)) + "\n", encoding="utf-8")
            manifest = anchor_manifest(feed)
            feed.write_text("\n".join(to_lines(chained[:2])) + "\n", encoding="utf-8")
            ok, reason = check_anchor(feed, manifest)
            self.assertFalse(ok)
            self.assertIn("differ", reason)

    def test_wholesale_rewrite_detected_via_anchor(self):
        chained = chain_records([sample_audit(i) for i in range(3)], component="c")
        with tempfile.TemporaryDirectory() as directory:
            feed = Path(directory) / "feed.ndjson"
            feed.write_text("\n".join(to_lines(chained)) + "\n", encoding="utf-8")
            manifest = anchor_manifest(feed)
            # Attacker rewrites history with a *fresh valid* chain.
            forged = chain_records(
                [sample_audit(i, text="forged") for i in range(3)], component="c"
            )
            feed.write_text("\n".join(to_lines(forged)) + "\n", encoding="utf-8")
            self.assertTrue(verify_file(feed).ok)  # bare chain cannot see it
            ok, _ = check_anchor(feed, manifest)
            self.assertFalse(ok)


class SignatureTests(unittest.TestCase):
    def test_sign_verify_round_trip(self):
        seed, pubkey = generate_keypair()
        records = chain_records([sample_audit(i) for i in range(3)], component="c", key_id="ops-2026")
        signed = [sign_record(r, seed, key_id="ops-2026") for r in records]
        result = verify_lines(to_lines(signed), public_key=pubkey)
        self.assertTrue(result.ok, result.reason)
        self.assertTrue(verify_signature(signed[0], pubkey))

    def test_signature_tamper_detected(self):
        seed, pubkey = generate_keypair()
        records = chain_records([sample_audit(i) for i in range(3)], component="c", key_id="k")
        signed = [sign_record(r, seed, key_id="k") for r in records]
        signed[1]["signature"] = "ff" * 64
        result = verify_lines(to_lines(signed), public_key=pubkey)
        self.assertFalse(result.ok)
        self.assertEqual(result.broken_at, 2)
        self.assertEqual(result.signature_failures, [2])

    def test_signed_record_without_pubkey_is_broken(self):
        seed, _pubkey = generate_keypair()
        records = chain_records([sample_audit(0)], component="c", key_id="k")
        signed = [sign_record(r, seed, key_id="k") for r in records]
        result = verify_lines(to_lines(signed))
        self.assertFalse(result.ok)

    def test_key_id_after_chain_is_loud(self):
        records = chain_records([sample_audit(0)], component="c")
        seed, _pubkey = generate_keypair()
        with self.assertRaises(ValueError):
            sign_record(records[0], seed, key_id="late")

    def test_wrong_pubkey_rejects(self):
        seed, _pubkey = generate_keypair()
        _seed2, pubkey2 = generate_keypair()
        records = chain_records([sample_audit(0)], component="c", key_id="k")
        signed = [sign_record(r, seed, key_id="k") for r in records]
        result = verify_lines(to_lines(signed), public_key=pubkey2)
        self.assertFalse(result.ok)


class EnvelopeExtensionTests(unittest.TestCase):
    def test_both_validators_accept_chain_fields(self):
        record = sample_audit(0)
        chained = chain_records([record], component="northstar-agent-runtime", session_id="s")[0]
        self.assertEqual(validate_audit_record(chained), ())
        self.assertEqual(normative_audit.validate_record(chained), ())

    def test_both_validators_accept_signature_fields(self):
        seed, _pubkey = generate_keypair()
        record = sample_audit(0)
        signed = sign_record(record, seed, key_id="k")
        self.assertEqual(validate_audit_record(signed), ())
        self.assertEqual(normative_audit.validate_record(signed), ())

    def test_both_validators_reject_malformed_hashes(self):
        for bad_field in ("prev_hash", "chain_hash"):
            record = dict(sample_audit(0))
            record[bad_field] = "xyz"
            self.assertNotEqual(validate_audit_record(record), ())
            self.assertNotEqual(normative_audit.validate_record(record), ())
        record = dict(sample_audit(0))
        record["signature"] = "00" * 32  # 64 hex chars, need 128
        self.assertNotEqual(validate_audit_record(record), ())
        self.assertNotEqual(normative_audit.validate_record(record), ())

    def test_legacy_records_still_validate(self):
        self.assertEqual(validate_audit_record(sample_audit(0)), ())
        self.assertEqual(normative_audit.validate_record(sample_audit(0)), ())


class ProofSpecVectorTests(unittest.TestCase):
    """The fixed vectors in docs/concepts/audit-proof-spec.md §10."""

    VECTORS = [
        '{"chain_hash":"89b21d688c05fb86a9325d3d578d08ded59fabab2d057b1900ff8233ffd2cbf1","component":"northstar-agent-runtime","event":"session_start","genesis":{"chain":"northstar-audit-chain/1","component":"northstar-agent-runtime","schema_version":"audit.ndjson/1","session_id":"ns-vector-fixture","started_ts":"2026-10-03T10:00:00.000Z"},"level":"info","payload":{},"prev_hash":"0223006af268e483502c3c2fe7cc3e9900727a8c73e87cf35f5ab613f8093fc2","schema_version":"audit.ndjson/1","seq":0,"ts":"2026-10-03T10:00:00.000Z"}',
        '{"chain_hash":"8664b5c3cf5742583d793f627d2bc8cc6989dc40d59ed7d6f966d7380cc393d6","component":"northstar-agent-runtime","event":"assistant","level":"info","payload":{"text":"hello"},"prev_hash":"89b21d688c05fb86a9325d3d578d08ded59fabab2d057b1900ff8233ffd2cbf1","schema_version":"audit.ndjson/1","seq":1,"ts":"2026-10-03T10:00:01.000Z"}',
        '{"chain_hash":"9de14bf3d0d0738b86c7c6d0daf983766236119e0bc31beb0050dd180f31ea6a","component":"northstar-agent-runtime","event":"denial","level":"error","payload":{"reason":"read-only","tool":"Write"},"prev_hash":"8664b5c3cf5742583d793f627d2bc8cc6989dc40d59ed7d6f966d7380cc393d6","schema_version":"audit.ndjson/1","seq":2,"ts":"2026-10-03T10:00:02.000Z"}',
    ]

    def test_vectors_verify_ok(self):
        result = verify_lines(self.VECTORS)
        self.assertTrue(result.ok, result.reason)
        self.assertEqual(result.chained, 3)

    def test_vectors_tamper_detected_at_line_3(self):
        tampered = list(self.VECTORS)
        record = json.loads(tampered[1])
        record["payload"] = {"text": "goodbye"}
        tampered[1] = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        result = verify_lines(tampered)
        self.assertFalse(result.ok)
        self.assertEqual(result.broken_at, 2)

    def test_vectors_match_spec_genesis(self):
        first = json.loads(self.VECTORS[0])
        self.assertEqual(
            genesis_hash(first["genesis"]),
            "0223006af268e483502c3c2fe7cc3e9900727a8c73e87cf35f5ab613f8093fc2",
        )
        self.assertEqual(first["prev_hash"], genesis_hash(first["genesis"]))


class JcsCanonicalizationTests(unittest.TestCase):
    """RFC 8785 JSON Canonicalization Scheme vectors."""

    def test_key_order_and_separators(self):
        self.assertEqual(jcs_canonical_json({"b": 1, "a": 2}), b'{"a":2,"b":1}')

    def test_no_short_escapes(self):
        # JCS escapes controls as \u00XX — never \n, \t, etc.
        self.assertEqual(jcs_canonical_json({"a": "\n\t"}), b'{"a":"\\u000a\\u0009"}')
        self.assertEqual(jcs_canonical_json({"a": '"\\'}), b'{"a":"\\"\\\\"}')
        self.assertEqual(jcs_canonical_json({"a": "/"}), b'{"a":"/"}')
        self.assertEqual(jcs_canonical_json({"a": "\u001f"}), b'{"a":"\\u001f"}')

    def test_non_ascii_is_raw_utf8(self):
        self.assertEqual(jcs_canonical_json({"a": "é"}), '{"a":"é"}'.encode("utf-8"))

    def test_utf16_code_unit_key_order(self):
        # U+10000 is the surrogate pair D800 DC00 in UTF-16: it sorts
        # before U+FFFF (a single unit 0xFFFF) although its code point
        # is larger. Legacy sort_keys (code-point order) gets this wrong.
        self.assertEqual(
            jcs_canonical_json({"\uffff": 1, "\U00010000": 2}),
            '{"\U00010000":2,"\uffff":1}'.encode("utf-8"),
        )
        self.assertNotEqual(
            jcs_canonical_json({"\uffff": 1, "\U00010000": 2}),
            canonical_json({"\uffff": 1, "\U00010000": 2}),
            "this is exactly where legacy canonicalization diverges from JCS",
        )

    def test_numbers_follow_ecmascript_to_string(self):
        self.assertEqual(jcs_canonical_json({"n": 1e16}), b'{"n":10000000000000000}')
        self.assertEqual(jcs_canonical_json({"n": 1e-7}), b'{"n":1e-7}')
        self.assertEqual(jcs_canonical_json({"n": 1e-6}), b'{"n":0.000001}')
        self.assertEqual(jcs_canonical_json({"n": 0.1}), b'{"n":0.1}')
        self.assertEqual(jcs_canonical_json({"n": 1e21}), b'{"n":1e+21}')
        self.assertEqual(jcs_canonical_json({"n": -0.0}), b'{"n":0}')  # JCS forbids -0
        self.assertEqual(jcs_canonical_json({"n": 100.0}), b'{"n":100}')
        self.assertEqual(jcs_canonical_json({"n": 2**53}), b'{"n":9007199254740992}')

    def test_non_finite_rejected(self):
        for bad in (float("nan"), float("inf"), float("-inf"), {"a": float("nan")}):
            with self.assertRaises(ValueError, msg=repr(bad)):
                jcs_canonical_json(bad)

    def test_nested_structures(self):
        self.assertEqual(
            jcs_canonical_json({"l": [1, "x", None, True], "d": {}}),
            b'{"d":{},"l":[1,"x",null,true]}',
        )


class ChainV2Tests(unittest.TestCase):
    """northstar-audit-chain/2: JCS canonicalization; v1 keeps verifying."""

    def test_new_chains_default_to_v2(self):
        chained = chain_records([sample_audit(0)], component="c")
        self.assertEqual(chained[0]["genesis"]["chain"], CHAIN_VERSION_V2)
        self.assertEqual(chained[0]["chain"], CHAIN_VERSION_V2)

    def test_v2_round_trip(self):
        chained = chain_records(
            [sample_audit(i, text="héllo\n%d" % i, n=1e16) for i in range(3)],
            component="c",
        )
        result = verify_lines(to_lines(chained))
        self.assertTrue(result.ok, result.reason)
        self.assertEqual(result.chained, 3)

    def test_v1_chain_still_verifies(self):
        # Legacy construction, explicitly requested: verifies forever.
        chained = chain_records(
            [sample_audit(i) for i in range(3)],
            component="c",
            chain_version=CHAIN_VERSION,
        )
        self.assertEqual(chained[0]["genesis"]["chain"], CHAIN_VERSION)
        self.assertNotIn("chain", chained[1])  # v1 records are unstamped (frozen)
        result = verify_lines(to_lines(chained))
        self.assertTrue(result.ok, result.reason)

    def test_v1_and_v2_hashes_differ_on_nontrivial_payload(self):
        recs = [sample_audit(i, text="héllo\nworld", n=1e16) for i in range(2)]
        v1 = chain_records(recs, component="c", chain_version=CHAIN_VERSION)
        v2 = chain_records(recs, component="c", chain_version=CHAIN_VERSION_V2)
        self.assertNotEqual(v1[1]["chain_hash"], v2[1]["chain_hash"])

    def test_v2_tamper_detected(self):
        chained = chain_records([sample_audit(i) for i in range(3)], component="c")
        lines = to_lines(chained)
        rec = json.loads(lines[1])
        rec["payload"] = {"x": 1}
        lines[1] = json.dumps(rec, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        result = verify_lines(lines)
        self.assertFalse(result.ok)
        self.assertEqual(result.broken_at, 2)

    def test_v2_sign_round_trip(self):
        seed, pub = generate_keypair()
        chained = chain_records([sample_audit(i) for i in range(2)], component="c", key_id="k2")
        signed = [sign_record(r, seed, key_id="k2") for r in chained]
        result = verify_lines(to_lines(signed), public_key=pub)
        self.assertTrue(result.ok, result.reason)

    def test_v1_sign_round_trip_unchanged(self):
        seed, pub = generate_keypair()
        chained = chain_records(
            [sample_audit(i) for i in range(2)],
            component="c",
            key_id="k1",
            chain_version=CHAIN_VERSION,
        )
        signed = [sign_record(r, seed, key_id="k1") for r in chained]
        result = verify_lines(to_lines(signed), public_key=pub)
        self.assertTrue(result.ok, result.reason)

    def test_mixed_version_splice_rejected(self):
        # A v2 record spliced into a v1 chain must not verify: the version
        # stamp rides inside the hashed body, so the splice breaks the link.
        v1 = chain_records([sample_audit(i) for i in range(2)], component="c", chain_version=CHAIN_VERSION)
        v2 = chain_records([sample_audit(i) for i in range(2)], component="c", chain_version=CHAIN_VERSION_V2)
        result = verify_lines(to_lines([v1[0], v2[1]]))
        self.assertFalse(result.ok)

    def test_genesis_hash_dispatches_on_version(self):
        v1p = build_genesis_params("c", chain_version=CHAIN_VERSION)
        v2p = build_genesis_params("c", chain_version=CHAIN_VERSION_V2)
        self.assertEqual(genesis_hash(v1p), _sha256_hex(canonical_json(v1p)))
        self.assertEqual(genesis_hash(v2p), _sha256_hex(jcs_canonical_json(v2p)))

    def test_unknown_chain_version_rejected_loudly(self):
        with self.assertRaises(ValueError):
            chain_records([sample_audit(0)], component="c", chain_version="northstar-audit-chain/9")

    def test_historical_v1_feed_file_verifies_via_cli(self):
        # Migration guarantee: feed bytes sealed before the v2 change
        # (legacy canonicalization) still verify, via the real CLI.
        chained = chain_records(
            [sample_audit(i) for i in range(2)], component="c", chain_version=CHAIN_VERSION
        )
        with tempfile.TemporaryDirectory() as directory:
            feed = Path(directory) / "feed.ndjson"
            feed.write_text("\n".join(to_lines(chained)) + "\n", encoding="utf-8")
            code, out, _ = run_cli("audit", "verify", str(feed))
            self.assertEqual(code, 0, out)
            self.assertIn("OK", out)


class ProofSpecV2VectorTests(unittest.TestCase):
    """The fixed v2 vectors in docs/concepts/audit-proof-spec.md §11."""

    VECTORS = [
        '{"chain":"northstar-audit-chain/2","chain_hash":"1508b8f95aa46e9a02bd1b3a03e09ed5712fb0a32d9fdaab61d5bdc1f5321921","component":"northstar-agent-runtime","event":"session_start","genesis":{"chain":"northstar-audit-chain/2","component":"northstar-agent-runtime","schema_version":"audit.ndjson/1","session_id":"ns-vector-fixture-v2","started_ts":"2026-10-03T10:00:00.000Z"},"level":"info","payload":{},"prev_hash":"b50ca8ab0f7039b433351e1051db519fb1eceb71d71f708cf0b53cd0a2442eed","schema_version":"audit.ndjson/1","seq":0,"ts":"2026-10-03T10:00:00.000Z"}',
        '{"chain":"northstar-audit-chain/2","chain_hash":"88e7b1294e3b4aa5d8670c7b75e93b53177faae4b48dbebeed2ef881cfb3beca","component":"northstar-agent-runtime","event":"assistant","level":"info","payload":{"text":"hello"},"prev_hash":"1508b8f95aa46e9a02bd1b3a03e09ed5712fb0a32d9fdaab61d5bdc1f5321921","schema_version":"audit.ndjson/1","seq":1,"ts":"2026-10-03T10:00:01.000Z"}',
    ]

    def test_vectors_verify_ok(self):
        result = verify_lines(self.VECTORS)
        self.assertTrue(result.ok, result.reason)
        self.assertEqual(result.chained, 2)

    def test_vectors_match_spec_genesis(self):
        first = json.loads(self.VECTORS[0])
        self.assertEqual(
            genesis_hash(first["genesis"]),
            "b50ca8ab0f7039b433351e1051db519fb1eceb71d71f708cf0b53cd0a2442eed",
        )
        self.assertEqual(first["prev_hash"], genesis_hash(first["genesis"]))

    def test_vectors_tamper_detected(self):
        tampered = list(self.VECTORS)
        record = json.loads(tampered[1])
        record["payload"] = {"text": "goodbye"}
        tampered[1] = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        result = verify_lines(tampered)
        self.assertFalse(result.ok)
        self.assertEqual(result.broken_at, 2)


class CliAuditTests(unittest.TestCase):
    def _write_feed(self, directory, name, lines):
        feed = Path(directory) / name
        feed.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return feed

    def test_verify_ok_exit_0(self):
        chained = chain_records([sample_audit(i) for i in range(2)], component="c")
        with tempfile.TemporaryDirectory() as directory:
            feed = self._write_feed(directory, "f.ndjson", to_lines(chained))
            code, out, _err = run_cli("audit", "verify", str(feed))
            self.assertEqual(code, 0)
            self.assertIn("OK", out)

    def test_verify_broken_exit_1(self):
        chained = chain_records([sample_audit(i) for i in range(2)], component="c")
        tampered = [dict(r) for r in chained]
        tampered[0]["payload"] = {"x": 1}
        with tempfile.TemporaryDirectory() as directory:
            feed = self._write_feed(directory, "f.ndjson", to_lines(tampered))
            code, out, _err = run_cli("audit", "verify", str(feed))
            self.assertEqual(code, 1)
            self.assertIn("BROKEN", out)

    def test_verify_unprotected_exit_2(self):
        with tempfile.TemporaryDirectory() as directory:
            feed = self._write_feed(directory, "f.ndjson", to_lines([sample_audit(0)]))
            code, out, _err = run_cli("audit", "verify", str(feed))
            self.assertEqual(code, 2)
            self.assertIn("UNPROTECTED", out)

    def test_verify_missing_file_exit_3(self):
        code, _out, _err = run_cli("audit", "verify", "/tmp/does-not-exist-ns-audit.ndjson")
        self.assertEqual(code, 3)

    def test_verify_json_output(self):
        chained = chain_records([sample_audit(i) for i in range(2)], component="c")
        with tempfile.TemporaryDirectory() as directory:
            feed = self._write_feed(directory, "f.ndjson", to_lines(chained))
            code, out, _err = run_cli("audit", "verify", "--json", str(feed))
            self.assertEqual(code, 0)
            payload = json.loads(out)
            self.assertEqual(payload["status"], "OK")
            self.assertEqual(payload["chained"], 2)

    def test_anchor_then_verify_with_anchor(self):
        chained = chain_records([sample_audit(i) for i in range(3)], component="c")
        with tempfile.TemporaryDirectory() as directory:
            feed = self._write_feed(directory, "f.ndjson", to_lines(chained))
            manifest = str(Path(directory) / "anchor.json")
            code, _out, _err = run_cli("audit", "anchor", str(feed), "--out", manifest)
            self.assertEqual(code, 0)
            code, out, _err = run_cli("audit", "verify", "--anchor", manifest, str(feed))
            self.assertEqual(code, 0, out)
            self.assertIn("anchor matches", out)

    def test_truncated_feed_with_anchor_is_broken(self):
        chained = chain_records([sample_audit(i) for i in range(3)], component="c")
        with tempfile.TemporaryDirectory() as directory:
            feed = self._write_feed(directory, "f.ndjson", to_lines(chained))
            manifest = str(Path(directory) / "anchor.json")
            self.assertEqual(run_cli("audit", "anchor", str(feed), "--out", manifest)[0], 0)
            self._write_feed(directory, "f.ndjson", to_lines(chained[:2]))
            code, out, _err = run_cli("audit", "verify", "--anchor", manifest, str(feed))
            self.assertEqual(code, 1)
            self.assertIn("BROKEN", out)

    def test_keygen_emits_pair(self):
        code, out, _err = run_cli("audit", "keygen", "--json")
        self.assertEqual(code, 0)
        pair = json.loads(out)
        self.assertEqual(len(bytes.fromhex(pair["seed_hex"])), 32)
        self.assertEqual(len(bytes.fromhex(pair["pubkey_hex"])), 32)

    def test_verify_with_pubkey(self):
        seed, pubkey = generate_keypair()
        records = chain_records([sample_audit(i) for i in range(2)], component="c", key_id="k")
        signed = [sign_record(r, seed, key_id="k") for r in records]
        with tempfile.TemporaryDirectory() as directory:
            feed = self._write_feed(directory, "f.ndjson", to_lines(signed))
            code, out, _err = run_cli("audit", "verify", "--pubkey", pubkey.hex(), str(feed))
            self.assertEqual(code, 0, out + _err)


if __name__ == "__main__":
    unittest.main()

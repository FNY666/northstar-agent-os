"""External head anchoring via Sigstore Rekor: DSSE entries, hermetic tests.

A fake Rekor v1 server (localhost HTTP) implements the two endpoints the
client uses. The fake *verifies the DSSE signature itself* with the vendored
ed25519 module, so the tests exercise the real crypto path end to end —
only the network hop is fake. One env-gated test (NORTHSTAR_LIVE_REKOR=1)
hits the real public log; it is skipped by default.
"""
import base64
import hashlib
import json
import os
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import support  # noqa: F401

from audit_chain import chain_records
from audit_rekor import (
    ANCHOR_RECORD_VERSION,
    PAYLOAD_TYPE,
    REKOR_V1_DEFAULT,
    RekorError,
    anchor_feed_head,
    anchor_statement,
    build_envelope,
    build_proposal,
    ed25519_spki_pem,
    pae,
    retrieve_by_index,
    submit_entry,
    verify_anchor_in_log,
    verify_anchor_offline,
)
from ed25519 import public_key as ed_public_key
from ed25519 import sign as ed_sign
from ed25519 import verify as ed_verify

_SEED = hashlib.sha256(b"northstar-test-rekor-seed").digest()
_PUBKEY = ed_public_key(_SEED)
_FAKE_UUID = "f" * 80
_FAKE_INDEX = 424242
_FAKE_TIME = 1791023198


def _sample_feed(path: Path, n: int = 3) -> None:
    records = [
        {
            "schema_version": "audit.ndjson/1",
            "component": "northstar-agent-runtime",
            "event": "assistant",
            "seq": i,
            "ts": f"2026-10-03T10:00:{i:02d}.000Z",
            "level": "info",
            "payload": {"i": i},
        }
        for i in range(n)
    ]
    chained = chain_records(records, component="northstar-agent-runtime", session_id="s-1")
    path.write_text(
        "\n".join(json.dumps(r, sort_keys=True, separators=(",", ":")) for r in chained) + "\n",
        encoding="utf-8",
    )


class _FakeRekorHandler(BaseHTTPRequestHandler):
    """Minimal Rekor v1 stub that verifies DSSE signatures for real."""

    server_version = "FakeRekor/1"

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # keep test output clean
        pass

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode())
        except ValueError:
            return self._send(400, {"message": "bad json"})
        if self.path == "/api/v1/log/entries":
            return self._handle_submit(data)
        if self.path == "/api/v1/log/entries/retrieve":
            return self._handle_retrieve(data)
        return self._send(404, {"message": "unknown path"})

    def _handle_submit(self, data):
        try:
            content = data["spec"]["proposedContent"]
            envelope = json.loads(content["envelope"])
            verifiers = content["verifiers"]
            pem = base64.b64decode(verifiers[0]).decode()
            # Re-derive the raw key from the PEM the way the client builds it.
            der = base64.b64decode("".join(pem.splitlines()[1:-1]))
            pubkey = der[-32:]
            payload = base64.b64decode(envelope["payload"])
            sig = base64.b64decode(envelope["signatures"][0]["sig"])
            ok = ed_verify(pubkey, pae(envelope["payloadType"], payload), sig)
        except Exception as error:  # malformed proposal
            return self._send(400, {"message": f"bad proposal: {error}"})
        if not ok:
            return self._send(400, {"message": "signature did not verify"})
        # Remember what was submitted so retrieve can echo it back.
        self.server.submitted = {
            "envelope": envelope,
            "pem": pem,
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
        }
        return self._send(
            201,
            {_FAKE_UUID: {"logIndex": _FAKE_INDEX, "integratedTime": _FAKE_TIME}},
        )

    def _handle_retrieve(self, data):
        indexes = data.get("logIndexes", [])
        if indexes != [_FAKE_INDEX] or not hasattr(self.server, "submitted"):
            return self._send(200, [])
        sub = self.server.submitted
        canonical = {
            "apiVersion": "0.0.1",
            "kind": "dsse",
            "spec": {
                "envelopeHash": {"algorithm": "sha256", "value": "00" * 32},
                "payloadHash": {"algorithm": "sha256", "value": sub["payload_sha256"]},
                "signatures": [
                    {
                        "signature": sub["envelope"]["signatures"][0]["sig"],
                        "verifier": base64.b64encode(sub["pem"].encode()).decode(),
                    }
                ],
            },
        }
        return self._send(
            200,
            [
                {
                    _FAKE_UUID: {
                        "body": base64.b64encode(
                            json.dumps(canonical).encode()
                        ).decode(),
                        "integratedTime": _FAKE_TIME,
                        "logIndex": _FAKE_INDEX,
                        "verification": {},
                    }
                }
            ],
        )


class RekorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _FakeRekorHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.feed = Path(self.tmp.name) / "feed.ndjson"
        _sample_feed(self.feed)

    def tearDown(self):
        self.tmp.cleanup()
        if hasattr(self.server, "submitted"):
            del self.server.submitted

    def test_pae_matches_spec_vector(self):
        # secure-systems-lab/dsse v1.0.0: no trailing signatures section.
        self.assertEqual(pae("t", b"body"), b"DSSEv1 1 t 4 body")

    def test_anchor_round_trip(self):
        record = anchor_feed_head(self.feed, _SEED, rekor_url=self.url)
        self.assertEqual(record["anchor"], ANCHOR_RECORD_VERSION)
        self.assertEqual(record["log_index"], _FAKE_INDEX)
        self.assertEqual(record["uuid"], _FAKE_UUID)
        self.assertEqual(record["integrated_time"], _FAKE_TIME)
        self.assertEqual(record["pubkey"], _PUBKEY.hex())
        self.assertEqual(record["payload"]["records"], 3)

    def test_verify_offline_ok(self):
        record = anchor_feed_head(self.feed, _SEED, rekor_url=self.url)
        from audit_chain import anchor_manifest

        head = anchor_manifest(self.feed)["head_chain_hash"]
        ok, note = verify_anchor_offline(record, head_chain_hash=head)
        self.assertTrue(ok, note)

    def test_verify_offline_detects_rewritten_head(self):
        record = anchor_feed_head(self.feed, _SEED, rekor_url=self.url)
        ok, note = verify_anchor_offline(record, head_chain_hash="0" * 64)
        self.assertFalse(ok)
        self.assertIn("different head", note)

    def test_verify_offline_detects_tampered_anchor_record(self):
        record = anchor_feed_head(self.feed, _SEED, rekor_url=self.url)
        record["payload"]["records"] = 999
        from audit_chain import anchor_manifest

        head = anchor_manifest(self.feed)["head_chain_hash"]
        ok, note = verify_anchor_offline(record, head_chain_hash=head)
        self.assertFalse(ok)
        self.assertIn("payload hash mismatch", note)

    def test_verify_offline_detects_wrong_key(self):
        record = anchor_feed_head(self.feed, _SEED, rekor_url=self.url)
        other = ed_public_key(hashlib.sha256(b"other").digest())
        record["pubkey"] = other.hex()
        from audit_chain import anchor_manifest

        head = anchor_manifest(self.feed)["head_chain_hash"]
        ok, note = verify_anchor_offline(record, head_chain_hash=head)
        self.assertFalse(ok)
        self.assertIn("signature invalid", note)

    def test_verify_in_log_ok(self):
        record = anchor_feed_head(self.feed, _SEED, rekor_url=self.url)
        ok, note = verify_anchor_in_log(record, rekor_url=self.url)
        self.assertTrue(ok, note)
        self.assertIn(str(_FAKE_INDEX), note)

    def test_verify_in_log_detects_replaced_payload(self):
        record = anchor_feed_head(self.feed, _SEED, rekor_url=self.url)
        record["payload_sha256"] = "ab" * 32
        ok, note = verify_anchor_in_log(record, rekor_url=self.url)
        self.assertFalse(ok)
        self.assertIn("differs", note)

    def test_submit_failure_is_loud(self):
        proposal = build_proposal(
            build_envelope(b"x", PAYLOAD_TYPE, ed_sign(_SEED, pae(PAYLOAD_TYPE, b"x"))),
            ed25519_spki_pem(_PUBKEY),
        )
        with self.assertRaises(RekorError):
            submit_entry("http://127.0.0.1:1", proposal, timeout=2)

    def test_unanchored_feed_refuses(self):
        plain = Path(self.tmp.name) / "plain.ndjson"
        plain.write_text('{"a": 1}\n', encoding="utf-8")
        with self.assertRaises(ValueError):
            anchor_feed_head(plain, _SEED, rekor_url=self.url)

    def test_bad_seed_length(self):
        with self.assertRaises(ValueError):
            anchor_feed_head(self.feed, b"short", rekor_url=self.url)

    def test_anchor_statement_is_canonical(self):
        a = anchor_statement(feed_sha256="ab", head_chain_hash="cd", records=1, anchored_at="t")
        b = anchor_statement(records=1, anchored_at="t", head_chain_hash="cd", feed_sha256="ab")
        self.assertEqual(a, b)


@unittest.skipUnless(
    os.environ.get("NORTHSTAR_LIVE_REKOR") == "1", "needs network to the public log"
)
class LiveRekorTests(unittest.TestCase):
    """One real submission against rekor.sigstore.dev. Not run by default."""

    def test_live_submit_and_retrieve(self):
        tmp = tempfile.TemporaryDirectory()
        feed = Path(tmp.name) / "feed.ndjson"
        _sample_feed(feed)
        seed = hashlib.sha256(b"northstar-live-test-never-reused").digest()
        record = anchor_feed_head(feed, seed, rekor_url=REKOR_V1_DEFAULT, timeout=120)
        self.assertEqual(record["rekor_url"], REKOR_V1_DEFAULT)
        from audit_chain import anchor_manifest

        head = anchor_manifest(feed)["head_chain_hash"]
        ok, note = verify_anchor_offline(record, head_chain_hash=head)
        self.assertTrue(ok, note)
        ok, note = verify_anchor_in_log(record, timeout=120)
        self.assertTrue(ok, note)
        tmp.cleanup()


if __name__ == "__main__":
    unittest.main()

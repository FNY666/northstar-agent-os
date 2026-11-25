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
from unittest import mock
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
import audit_rekor
from ed25519 import public_key as ed_public_key
from ed25519 import sign as ed_sign
from ed25519 import verify as ed_verify

_SEED = hashlib.sha256(b"northstar-test-rekor-seed").digest()
_PUBKEY = ed_public_key(_SEED)
_FAKE_UUID = "f" * 80
_FAKE_INDEX = 424242
_FAKE_TIME = 1791023198


class ResponseBoundaryTests(unittest.TestCase):
    def test_rekor_response_is_byte_bounded(self):
        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _size):
                return b"x" * (audit_rekor.MAX_REKOR_RESPONSE_BYTES + 1)

        with mock.patch("audit_rekor.urllib.request.urlopen", return_value=Response()):
            with self.assertRaisesRegex(RekorError, "1 MiB byte cap"):
                audit_rekor._post_json("https://rekor.example", {}, timeout=1)

    def test_a_response_of_exactly_the_cap_is_accepted(self):
        # The byte cap is `len(raw) > MAX`, so a response of EXACTLY
        # ``MAX`` bytes is inside the cap and must be accepted.
        #
        # The test above cannot tell `>` from `>=`: it feeds ``MAX + 1``
        # bytes, which both spellings reject.  Only the boundary input
        # distinguishes them, so it needs its own test -- otherwise the
        # guard's off-by-one is invisible and the mutant ``gt@127``
        # SURVIVES.
        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _size):
                return b"x" * audit_rekor.MAX_REKOR_RESPONSE_BYTES

        with mock.patch("audit_rekor.urllib.request.urlopen", return_value=Response()):
            # The body is not JSON, so it is rejected as a BAD RESPONSE --
            # not as a byte-cap violation.  The distinction is the whole
            # point: the byte cap did NOT fire.
            with self.assertRaisesRegex(RekorError, "bad response") as caught:
                audit_rekor._post_json("https://rekor.example", {}, timeout=1)
        self.assertNotIn("byte cap", str(caught.exception))

    def test_rekor_response_rejects_duplicate_keys_and_nonstandard_constants(self):
        class Response:
            def __init__(self, body):
                self.body = body

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _size):
                return self.body

        for body in (b'{"a":1,"a":2}', b'{"a":NaN}'):
            with self.subTest(body=body), mock.patch(
                "audit_rekor.urllib.request.urlopen", return_value=Response(body)
            ):
                with self.assertRaisesRegex(RekorError, "bad response"):
                    audit_rekor._post_json("https://rekor.example", {}, timeout=1)


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
        cls.server.server_close()

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


class MalformedResponseTests(unittest.TestCase):
    """The client's REJECTION paths, fed the malformed responses they exist for.

    WHY THIS CLASS EXISTS (measured 2026-11-25)
    --------------------------------------------
    The mutant census scores ``audit_rekor.py`` at **0/7**: every one of
    its seven mutants SURVIVES.  That is not a broken instrument -- the
    module's own suite passes (14 passed, 1 skipped) and a hand-planted
    ``or@165`` survives too, so the score is real COVERAGE DEBT.

    The seven survivors are all the same shape: a defensive guard that
    rejects a malformed response, where the guard is an ``or`` (or a
    chain of ``or``s).  The happy-path tests never produce a malformed
    response, so the guard's rejection branch is never taken, and
    mutating ``or`` to ``and`` changes nothing the suite can see.

    The rule this class follows: **a guard needs a CRAFTED INPUT.**  A
    guard that only ever reads a well-formed response is unverifiable,
    and an unverifiable guard is a guard that can be deleted without
    anyone noticing.

    Each test below pins ONE rejection path, and each asserts the
    MESSAGE as well as the type, so a test that passes for the wrong
    reason (some other error being raised) cannot masquerade as a kill.
    """

    class _Response:
        """A urlopen stand-in that returns a fixed JSON body."""

        def __init__(self, body):
            self.body = body

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _size):
            return self.body

    def _post(self, body):
        """``_post_json`` against a stubbed response, returning the body."""
        with mock.patch(
            "audit_rekor.urllib.request.urlopen",
            return_value=self._Response(json.dumps(body).encode("utf-8")),
        ):
            return audit_rekor._post_json("https://rekor.example", {}, timeout=1)

    def test_submit_rejects_a_response_that_is_not_a_dict(self):
        # `not isinstance(response, dict)` -- a list response must be
        # rejected on the TYPE, before the length is ever looked at.
        with self.assertRaisesRegex(RekorError, "unexpected submit response shape"):
            with mock.patch(
                "audit_rekor.urllib.request.urlopen",
                return_value=self._Response(b'["not", "a", "dict"]'),
            ):
                submit_entry("https://rekor.example", {}, timeout=1)

    def test_submit_rejects_a_dict_that_is_not_a_single_entry(self):
        # `len(response) != 1` -- a dict with TWO entries is the shape the
        # guard exists to reject, and the guard is an `or` with the type
        # check.  With a dict, the type check is False, so the length
        # check is the only thing standing between this and a wrong
        # anchor.
        with self.assertRaisesRegex(RekorError, "unexpected submit response shape"):
            with mock.patch(
                "audit_rekor.urllib.request.urlopen",
                return_value=self._Response(b'{"a": {"logIndex": 1}, "b": {"logIndex": 2}}'),
            ):
                submit_entry("https://rekor.example", {}, timeout=1)

    def test_retrieve_rejects_an_empty_entry_list(self):
        # `not response` -- an EMPTY list is a list, so the type check
        # passes and the emptiness check is the one that must fire.
        with self.assertRaisesRegex(RekorError, "rekor returned no entries"):
            with mock.patch(
                "audit_rekor.urllib.request.urlopen",
                return_value=self._Response(b"[]"),
            ):
                retrieve_by_index("https://rekor.example", 1, timeout=1)

    def test_retrieve_rejects_a_first_entry_that_is_not_a_single_item(self):
        # `len(first) != 1` -- same shape as the submit guard: the first
        # element is a dict, so the length check must be the one that
        # fires.
        with self.assertRaisesRegex(RekorError, "unexpected retrieve response shape"):
            with mock.patch(
                "audit_rekor.urllib.request.urlopen",
                return_value=self._Response(b'[{"a": {"body": "x"}, "b": {"body": "y"}}]'),
            ):
                retrieve_by_index("https://rekor.example", 1, timeout=1)

    def test_retrieve_rejects_an_entry_without_a_body(self):
        # `'body' not in entry` -- the entry IS a dict, so the type check
        # passes and the missing-key check must be the one that fires.
        with self.assertRaisesRegex(RekorError, "retrieved entry has no body"):
            with mock.patch(
                "audit_rekor.urllib.request.urlopen",
                return_value=self._Response(b'[{"uuid": {"logIndex": 1}}]'),
            ):
                retrieve_by_index("https://rekor.example", 1, timeout=1)

    def test_anchor_refuses_a_feed_with_no_chained_head(self):
        # `not isinstance(head, str) or not head` -- a manifest whose
        # head_chain_hash is None (an unchained feed) must be refused.
        # The type check is False for a str and True for None; the guard
        # is an `or`, so BOTH halves have to be exercised.
        #
        # The manifest is stubbed rather than produced by a real feed:
        # the sample feed IS chained, so it yields a str head and would
        # not reach this branch at all.
        manifest = {
            "anchor": "northstar-audit-anchor/1",
            "chain": "northstar-audit-chain/1",
            "feed_sha256": "ab" * 32,
            "head_chain_hash": None,
            "records": 3,
        }
        with mock.patch("audit_chain.anchor_manifest", return_value=manifest):
            with self.assertRaisesRegex(ValueError, "no chained head to anchor"):
                anchor_feed_head(self._feed_path(), _SEED, rekor_url="https://rekor.example")

    def test_anchor_refuses_a_feed_whose_head_is_empty(self):
        # The SECOND half of the same guard: a head that is a str but
        # EMPTY.  The type check passes and the emptiness check must
        # fire, so this test is the one that distinguishes the guard
        # from `not isinstance(head, str)`.
        manifest = {
            "anchor": "northstar-audit-anchor/1",
            "chain": "northstar-audit-chain/1",
            "feed_sha256": "ab" * 32,
            "head_chain_hash": "",
            "records": 3,
        }
        with mock.patch("audit_chain.anchor_manifest", return_value=manifest):
            with self.assertRaisesRegex(ValueError, "no chained head to anchor"):
                anchor_feed_head(self._feed_path(), _SEED, rekor_url="https://rekor.example")

    def _feed_path(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "feed.ndjson"
        _sample_feed(path)
        return path

    def test_verify_in_log_falls_back_to_the_default_url(self):
        # `rekor_url or anchor.get("rekor_url") or REKOR_V1_DEFAULT` --
        # the FIRST `or` is what selects the anchor's own recorded URL
        # when the caller passes none, and the SECOND is what falls back
        # to the default when the anchor records none either.
        #
        # With no caller URL and no recorded URL, the default is used.
        # The assertion is on the URL the client actually POSTS to, so
        # the test cannot pass by accident.
        seen = []

        class _Recorder:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _size):
                return b"[]"

        def _urlopen(request, timeout=None):
            seen.append(request.full_url)
            return _Recorder()

        anchor = {"log_index": 7, "pubkey": "00" * 32}
        with mock.patch("audit_rekor.urllib.request.urlopen", side_effect=_urlopen):
            # The stub returns an empty list, so the retrieval refuses --
            # which is the correct behaviour for a log that has no such
            # entry.  The URL is what this test is about.
            with self.assertRaisesRegex(RekorError, "rekor returned no entries"):
                verify_anchor_in_log(anchor)
        self.assertTrue(seen, "the client never opened a connection")
        self.assertTrue(
            seen[0].startswith(REKOR_V1_DEFAULT),
            f"expected the default log url, got {seen[0]}",
        )

    def test_verify_in_log_prefers_the_anchors_recorded_url(self):
        # The OTHER half of the chain: when the anchor records a URL and
        # the caller passes none, the anchor's URL is the one used.
        # Without this test, the `or` chain's FIRST link is unverified.
        seen = []

        class _Recorder:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _size):
                return b"[]"

        def _urlopen(request, timeout=None):
            seen.append(request.full_url)
            return _Recorder()

        anchor = {
            "log_index": 7,
            "pubkey": "00" * 32,
            "rekor_url": "https://log.example/",
        }
        with mock.patch("audit_rekor.urllib.request.urlopen", side_effect=_urlopen):
            with self.assertRaisesRegex(RekorError, "rekor returned no entries"):
                verify_anchor_in_log(anchor)
        self.assertTrue(seen, "the client never opened a connection")
        self.assertTrue(
            seen[0].startswith("https://log.example"),
            f"expected the anchor's own log url, got {seen[0]}",
        )


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

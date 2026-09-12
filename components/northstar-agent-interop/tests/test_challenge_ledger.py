"""Tests for a persistent verifier-scoped challenge ledger."""
from __future__ import annotations

import json
import multiprocessing
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from attestation_freshness import ChallengeBook, seal_attestation
from challenge_ledger import (
    ChallengeLedger,
    LedgerChallenge,
    LedgerError,
    VerifierBoundSeal,
    seal_v2,
    verify_v2,
)
from evidence_proof import ProofAttestation
from proof_signing import ProofSignatureError

SECRET = b"challenge-ledger-test-secret-32bytes"
OTHER_SECRET = b"other-challenge-ledger-secret-32b"
DIGEST = "sha256:" + "a" * 64


def _attestation(route_id="r1"):
    return ProofAttestation(
        "northstar.proof-attestation.v1", "verified", route_id,
        DIGEST, DIGEST, DIGEST, DIGEST,
    )


class Clock:
    def __init__(self, now=1000):
        self.now = now

    def __call__(self):
        return self.now


def _consume_worker(root, challenge_id, verifier_id, result_path):
    try:
        result = ("ok", ChallengeLedger(root, clock=lambda: 1000).consume(
            challenge_id, verifier_id=verifier_id
        ).challenge_id)
    except Exception as exc:
        result = ("error", type(exc).__name__, str(exc))
    Path(result_path).write_text(json.dumps(result), encoding="utf-8")


class LedgerBasics(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="challenge-ledger-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.clock = Clock()
        self.ledger = ChallengeLedger(self.root, clock=self.clock, ttl=60,
                                      nonce_source=lambda n: b"\x01" * n)

    def test_issue_and_consume_round_trip(self):
        challenge = self.ledger.issue(verifier_id="verifier-a", key_id="k1")
        self.assertIsInstance(challenge, LedgerChallenge)
        self.assertEqual(challenge.verifier_id, "verifier-a")
        self.assertEqual(challenge.key_id, "k1")
        consumed = self.ledger.consume(challenge.challenge_id, verifier_id="verifier-a")
        self.assertEqual(consumed, challenge)

    def test_challenge_is_bound_to_verifier_identity(self):
        challenge = self.ledger.issue(verifier_id="verifier-a")
        with self.assertRaises(LedgerError):
            self.ledger.consume(challenge.challenge_id, verifier_id="verifier-b")
        self.assertEqual(
            self.ledger.consume(challenge.challenge_id, verifier_id="verifier-a"),
            challenge,
        )

    def test_unknown_challenge_is_refused(self):
        with self.assertRaises(LedgerError):
            self.ledger.consume("00" * 16, verifier_id="verifier-a")

    def test_repeated_consume_is_refused(self):
        challenge = self.ledger.issue(verifier_id="verifier-a")
        self.ledger.consume(challenge.challenge_id, verifier_id="verifier-a")
        with self.assertRaises(LedgerError):
            self.ledger.consume(challenge.challenge_id, verifier_id="verifier-a")

    def test_expired_challenge_is_refused(self):
        challenge = self.ledger.issue(verifier_id="verifier-a")
        self.clock.now += 61
        with self.assertRaises(LedgerError):
            self.ledger.consume(challenge.challenge_id, verifier_id="verifier-a")

    def test_issue_rejects_bad_verifier_and_key_ids(self):
        for verifier_id, key_id in (("", None), ("bad/id", None), ("verifier-a", "bad/id")):
            with self.assertRaises(LedgerError):
                self.ledger.issue(verifier_id=verifier_id, key_id=key_id)

    def test_issue_persists_only_metadata(self):
        self.ledger.issue(verifier_id="verifier-a", key_id="k1")
        raw = Path(self.root, "ledger.jsonl").read_bytes()
        self.assertNotIn(SECRET, raw)
        self.assertNotIn(SECRET.hex().encode(), raw)
        self.assertIn(b"verifier-a", raw)

    def test_verdict_reports_a_healthy_ledger(self):
        self.ledger.issue(verifier_id="verifier-a")
        self.assertEqual(self.ledger.verdict().state, "replayable")

    def test_new_empty_ledger_is_replayable(self):
        self.assertEqual(self.ledger.verdict().state, "replayable")


class RestartAndIntegrity(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="challenge-ledger-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.clock = Clock()
        self.ledger = ChallengeLedger(self.root, clock=self.clock, ttl=60,
                                      nonce_source=lambda n: b"\x02" * n)

    def test_consumption_survives_restart(self):
        challenge = self.ledger.issue(verifier_id="verifier-a")
        self.ledger.consume(challenge.challenge_id, verifier_id="verifier-a")
        restarted = ChallengeLedger(self.root, clock=self.clock, ttl=60)
        with self.assertRaises(LedgerError):
            restarted.consume(challenge.challenge_id, verifier_id="verifier-a")
        self.assertEqual(restarted.verdict().state, "replayable")

    def test_issued_challenge_survives_restart(self):
        challenge = self.ledger.issue(verifier_id="verifier-a")
        restarted = ChallengeLedger(self.root, clock=self.clock, ttl=60)
        self.assertEqual(
            restarted.consume(challenge.challenge_id, verifier_id="verifier-a"),
            challenge,
        )

    def test_truncated_final_line_is_ignored(self):
        challenge = self.ledger.issue(verifier_id="verifier-a")
        path = Path(self.root, "ledger.jsonl")
        with path.open("ab") as handle:
            handle.write(b'{"schema_version":"northstar.challenge-ledger.v1"')
        restarted = ChallengeLedger(self.root, clock=self.clock, ttl=60)
        self.assertEqual(restarted.verdict().state, "replayable")
        self.assertEqual(
            restarted.consume(challenge.challenge_id, verifier_id="verifier-a"),
            challenge,
        )

    def test_complete_malformed_line_is_unverifiable(self):
        self.ledger.issue(verifier_id="verifier-a")
        with Path(self.root, "ledger.jsonl").open("ab") as handle:
            handle.write(b'{"not":"a ledger record"}\n')
        restarted = ChallengeLedger(self.root, clock=self.clock, ttl=60)
        self.assertEqual(restarted.verdict().state, "unverifiable")
        with self.assertRaises(LedgerError):
            restarted.issue(verifier_id="verifier-a")

    def test_record_tampering_is_unverifiable(self):
        self.ledger.issue(verifier_id="verifier-a")
        path = Path(self.root, "ledger.jsonl")
        value = json.loads(path.read_text().splitlines()[0])
        value["verifier_id"] = "verifier-b"
        path.write_text(json.dumps(value, sort_keys=True) + "\n")
        self.assertEqual(ChallengeLedger(self.root, clock=self.clock).verdict().state,
                         "unverifiable")

    def test_missing_history_is_not_accepted_as_replayable_state(self):
        self.ledger.issue(verifier_id="verifier-a")
        path = Path(self.root, "ledger.jsonl")
        path.unlink()
        restarted = ChallengeLedger(self.root, clock=self.clock)
        self.assertEqual(restarted.verdict().state, "unverifiable")

    def test_chain_record_round_trip(self):
        first = self.ledger.issue(verifier_id="verifier-a")
        self.ledger.consume(first.challenge_id, verifier_id="verifier-a")
        records = self.ledger.records
        self.assertEqual([record["sequence"] for record in records], [1, 2])
        self.assertEqual(records[1]["previous_digest"], records[0]["record_digest"])


class Concurrency(unittest.TestCase):
    def test_concurrent_consumption_succeeds_exactly_once(self):
        root = tempfile.mkdtemp(prefix="challenge-ledger-")
        self.addCleanup(shutil.rmtree, root, True)
        ledger = ChallengeLedger(root, clock=lambda: 1000, ttl=60,
                                nonce_source=lambda n: b"\x03" * n)
        challenge = ledger.issue(verifier_id="verifier-a")
        context = multiprocessing.get_context("fork")
        result_paths = [os.path.join(root, "result-%d.json" % index) for index in range(2)]
        processes = [context.Process(target=_consume_worker,
                                     args=(root, challenge.challenge_id, "verifier-a", result_path))
                     for result_path in result_paths]
        for process in processes:
            process.start()
        for process in processes:
            process.join(10)
        results = [json.loads(Path(path).read_text(encoding="utf-8")) for path in result_paths]
        self.assertEqual(sum(result[0] == "ok" for result in results), 1)
        self.assertEqual(sum(result[0] == "error" for result in results), 1)
        self.assertTrue(all(not process.is_alive() for process in processes))


class SealV2Tests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="challenge-ledger-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.clock = Clock()
        self.ledger = ChallengeLedger(self.root, clock=self.clock, ttl=60,
                                      nonce_source=lambda n: b"\x04" * n)
        self.challenge = self.ledger.issue(verifier_id="verifier-a", key_id="k1")

    def test_v2_seal_binds_verifier_identity(self):
        seal = seal_v2(_attestation(), self.challenge, key_id="k1", secret=SECRET)
        self.assertEqual(seal.schema_version, "northstar.verifier-bound-seal.v2")
        result = verify_v2(
            seal, _attestation(), expected_challenge_id=self.challenge.challenge_id,
            expected_verifier_id="verifier-a", key_resolver=lambda key: SECRET,
        )
        self.assertEqual(result.route_id, "r1")

    def test_v2_seal_rejects_verifier_substitution(self):
        seal = seal_v2(_attestation(), self.challenge, key_id="k1", secret=SECRET)
        with self.assertRaises(ProofSignatureError):
            verify_v2(
                seal, _attestation(), expected_challenge_id=self.challenge.challenge_id,
                expected_verifier_id="verifier-b", key_resolver=lambda key: SECRET,
            )

    def test_v2_seal_rejects_challenge_substitution(self):
        other = self.ledger.issue(verifier_id="verifier-a", key_id="k1")
        seal = seal_v2(_attestation(), self.challenge, key_id="k1", secret=SECRET)
        with self.assertRaises(ProofSignatureError):
            verify_v2(
                seal, _attestation(), expected_challenge_id=other.challenge_id,
                expected_verifier_id="verifier-a", key_resolver=lambda key: SECRET,
            )

    def test_v2_seal_rejects_attestation_tampering(self):
        seal = seal_v2(_attestation(), self.challenge, key_id="k1", secret=SECRET)
        with self.assertRaises(ProofSignatureError):
            verify_v2(
                seal, _attestation("other"), expected_challenge_id=self.challenge.challenge_id,
                expected_verifier_id="verifier-a", key_resolver=lambda key: SECRET,
            )

    def test_v2_wire_form_is_strict_and_round_trips(self):
        seal = seal_v2(_attestation(), self.challenge, key_id="k1", secret=SECRET)
        self.assertEqual(VerifierBoundSeal.from_dict(seal.to_dict()), seal)
        with self.assertRaises(ProofSignatureError):
            VerifierBoundSeal.from_dict({**seal.to_dict(), "extra": True})

    def test_v1_freshness_api_remains_available(self):
        book = ChallengeBook(clock=self.clock, ttl=60, nonce_source=lambda n: b"\x05" * n)
        old_challenge = book.issue()
        old_seal = seal_attestation(_attestation(), key_id="k1", secret=SECRET,
                                    challenge=old_challenge)
        self.assertEqual(old_seal.challenge_id, old_challenge.challenge_id)


if __name__ == "__main__":
    unittest.main()

"""Attestation freshness: challenge-bound sealing that refuses replays."""
import json
import os
import tempfile
import unittest
import shutil
from pathlib import Path

from attestation_freshness import (
    Challenge,
    ChallengeBook,
    FreshnessError,
    SCHEMA,
    SealedAttestation,
    seal_attestation,
    verify_sealed_attestation,
)
from evidence_proof import ProofAttestation
from key_lifecycle import KeyHistory, KeyRing
from proof_signing import ProofSignatureError

SECRET = bytes(range(32))
OTHER_SECRET = bytes(range(1, 33))
ROUTE = "route-1"
PROOF = "sha256:" + "a" * 64
LINEAGE = "sha256:" + "b" * 64
BUNDLE = "sha256:" + "c" * 64
CHECKPOINT = "sha256:" + "d" * 64


def attestation(route=ROUTE):
    return ProofAttestation(
        "northstar.proof-attestation.v1",
        "verified",
        route,
        PROOF,
        LINEAGE,
        BUNDLE,
        CHECKPOINT,
    )


class FakeClock:
    def __init__(self, now=1000):
        self.now = now

    def __call__(self):
        return self.now


def nonces(values):
    stream = iter(values)
    return lambda size: next(stream)


class Fix(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.book = ChallengeBook(clock=self.clock, ttl=60, nonce_source=lambda n: b"\x01" * n)

    def challenge(self):
        return self.book.issue()


class SealingTests(Fix):
    def test_sealed_attestation_verifies_against_its_own_challenge(self):
        challenge = self.challenge()
        sealed = seal_attestation(attestation(), key_id="k1", secret=SECRET, challenge=challenge)
        self.assertEqual(sealed.schema_version, SCHEMA)
        self.assertEqual(sealed.challenge_id, challenge.challenge_id)
        result = verify_sealed_attestation(
            sealed,
            attestation=attestation(),
            expected_challenge_id=challenge.challenge_id,
            key_resolver=lambda key_id: SECRET if key_id == "k1" else None,
        )
        self.assertEqual(result.route_id, ROUTE)

    def test_a_seal_from_an_older_challenge_is_refused(self):
        stale = seal_attestation(attestation(), key_id="k1", secret=SECRET, challenge=self.challenge())
        fresh = self.challenge()
        self.assertNotEqual(stale.challenge_id, fresh.challenge_id)
        with self.assertRaises(FreshnessError):
            verify_sealed_attestation(
                stale,
                attestation=attestation(),
                expected_challenge_id=fresh.challenge_id,
                key_resolver=lambda key_id: SECRET,
            )

    def test_a_seal_does_not_transfer_to_another_attestation(self):
        challenge = self.challenge()
        sealed = seal_attestation(attestation(), key_id="k1", secret=SECRET, challenge=challenge)
        with self.assertRaises(FreshnessError):
            verify_sealed_attestation(
                sealed,
                attestation=attestation(route="route-2"),
                expected_challenge_id=challenge.challenge_id,
                key_resolver=lambda key_id: SECRET,
            )

    def test_a_tampered_challenge_id_breaks_the_seal(self):
        challenge = self.challenge()
        sealed = seal_attestation(attestation(), key_id="k1", secret=SECRET, challenge=challenge)
        forged = SealedAttestation(
            sealed.schema_version,
            b"\x02".hex(),
            sealed.key_id,
            sealed.attestation_digest,
            sealed.signature,
        )
        with self.assertRaises(FreshnessError):
            verify_sealed_attestation(
                forged,
                attestation=attestation(),
                expected_challenge_id=forged.challenge_id,
                key_resolver=lambda key_id: SECRET,
            )

    def test_the_seal_depends_on_the_signing_secret(self):
        challenge = self.challenge()
        sealed = seal_attestation(attestation(), key_id="k1", secret=SECRET, challenge=challenge)
        with self.assertRaises(ProofSignatureError):
            verify_sealed_attestation(
                sealed,
                attestation=attestation(),
                expected_challenge_id=challenge.challenge_id,
                key_resolver=lambda key_id: OTHER_SECRET,
            )

    def test_an_unavailable_key_cannot_verify(self):
        challenge = self.challenge()
        sealed = seal_attestation(attestation(), key_id="k1", secret=SECRET, challenge=challenge)
        with self.assertRaises(ProofSignatureError):
            verify_sealed_attestation(
                sealed,
                attestation=attestation(),
                expected_challenge_id=challenge.challenge_id,
                key_resolver=lambda key_id: None,
            )

    def test_key_identity_can_be_pinned(self):
        challenge = self.challenge()
        sealed = seal_attestation(attestation(), key_id="k1", secret=SECRET, challenge=challenge)
        with self.assertRaises(ProofSignatureError):
            verify_sealed_attestation(
                sealed,
                attestation=attestation(),
                expected_challenge_id=challenge.challenge_id,
                key_resolver=lambda key_id: SECRET,
                expected_key_id="k2",
            )

    def test_an_unverified_attestation_cannot_be_sealed(self):
        challenge = self.challenge()
        broken = ProofAttestation(
            "northstar.proof-attestation.v1", "unknown", ROUTE, PROOF, LINEAGE, BUNDLE, CHECKPOINT
        )
        with self.assertRaises(FreshnessError):
            seal_attestation(broken, key_id="k1", secret=SECRET, challenge=challenge)

    def test_sealed_attestation_round_trips_through_json(self):
        challenge = self.challenge()
        sealed = seal_attestation(attestation(), key_id="k1", secret=SECRET, challenge=challenge)
        restored = SealedAttestation.from_dict(json.loads(json.dumps(sealed.to_dict())))
        self.assertEqual(restored, sealed)

    def test_sealed_attestation_fields_are_validated(self):
        challenge = self.challenge()
        sealed = seal_attestation(attestation(), key_id="k1", secret=SECRET, challenge=challenge)
        for bad in (
            {},
            {**sealed.to_dict(), "schema_version": "northstar.other.v1"},
            {**sealed.to_dict(), "challenge_id": "not-hex"},
            {**sealed.to_dict(), "attestation_digest": "sha256:zz"},
        ):
            with self.assertRaises(FreshnessError):
                SealedAttestation.from_dict(bad)

    def test_the_secret_never_appears_in_the_sealed_record(self):
        challenge = self.challenge()
        sealed = seal_attestation(attestation(), key_id="k1", secret=SECRET, challenge=challenge)
        encoded = json.dumps(sealed.to_dict())
        self.assertNotIn(SECRET.hex(), encoded)
        self.assertNotIn(bytes(SECRET).hex(), encoded)


class ChallengeBookTests(Fix):
    def test_a_consumed_challenge_cannot_be_consumed_again(self):
        challenge = self.challenge()
        self.book.consume(challenge.challenge_id)
        with self.assertRaises(FreshnessError):
            self.book.consume(challenge.challenge_id)

    def test_an_expired_challenge_is_refused(self):
        challenge = self.challenge()
        self.clock.now += 61
        with self.assertRaises(FreshnessError):
            self.book.consume(challenge.challenge_id)

    def test_an_unknown_challenge_is_refused(self):
        with self.assertRaises(FreshnessError):
            self.book.consume("00" * 16)

    def test_challenges_are_single_use_by_construction(self):
        seen = {self.challenge().challenge_id for _ in range(8)}
        self.assertEqual(len(seen), 8)

    def test_expiry_is_relative_to_issue_time(self):
        first = self.challenge()
        self.clock.now += 30
        second = self.challenge()
        self.clock.now += 31
        self.book.consume(second.challenge_id)
        with self.assertRaises(FreshnessError):
            self.book.consume(first.challenge_id)


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="fresh-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.clock = FakeClock()
        self.book = ChallengeBook(clock=self.clock, ttl=60, nonce_source=lambda n: os.urandom(n))
        self.history = KeyHistory(Path(self.dir) / "keys.jsonl")
        self.history.introduce("k1", SECRET)
        self.ring = KeyRing(self.history)
        self.ring.register("k1", SECRET)

    def test_a_revoked_key_cannot_verify_a_fresh_seal(self):
        challenge = self.book.issue()
        sealed = seal_attestation(attestation(), key_id="k1", secret=SECRET, challenge=challenge)
        verify_sealed_attestation(
            sealed,
            attestation=attestation(),
            expected_challenge_id=challenge.challenge_id,
            key_resolver=self.ring.resolver(),
        )
        self.history.revoke("k1")
        with self.assertRaises(ProofSignatureError):
            verify_sealed_attestation(
                sealed,
                attestation=attestation(),
                expected_challenge_id=challenge.challenge_id,
                key_resolver=self.ring.resolver(),
            )

    def test_a_replay_is_refused_end_to_end(self):
        challenge = self.book.issue()
        sealed = seal_attestation(attestation(), key_id="k1", secret=SECRET, challenge=challenge)
        self.book.consume(challenge.challenge_id)
        fresh = self.book.issue()
        with self.assertRaises(FreshnessError):
            verify_sealed_attestation(
                sealed,
                attestation=attestation(),
                expected_challenge_id=fresh.challenge_id,
                key_resolver=self.ring.resolver(),
            )


if __name__ == "__main__":
    unittest.main()

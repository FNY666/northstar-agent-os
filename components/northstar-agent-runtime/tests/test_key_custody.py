"""Tests for key_custody (B173 asinhhc slice).

Covers: the happy path with a stranger verifier, the canonical policy hash,
the policy-tamper refusal, the rollback refusal (the headline: the old
"seal is valid" check lets it through), the cap, the expiry, wrong key and
tampered envelopes, the structured refusal, the monotonic vault version, and
the reuse of the repository's single ed25519 primitive.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from key_custody import (
    SCHEMA_PIN,
    AnchoredState,
    CustodyError,
    CustodyPolicy,
    CustodyRefusal,
    KeyCustody,
    RefusalReason,
    SignatureEnvelope,
    VaultSeal,
    anchor_vault,
    read_anchored,
    seal_is_valid,
    verify_envelope,
)

from forward_seal_ledger import ForwardSealLedger


def _ledger() -> ForwardSealLedger:
    return ForwardSealLedger(initial_key=b"k" * 32, checkpoint_key=b"c" * 32)


def _policy(now: float, **kwargs) -> CustodyPolicy:
    params = dict(
        allowed_ops=("receipt", "attest"),
        max_signatures_per_epoch=2,
        expires_at=now + 3600.0,
        epoch_seconds=3600,
        policy_id="p1",
    )
    params.update(kwargs)
    return CustodyPolicy(**params)


class Clock:
    """A manual clock so expiry and epochs are deterministic."""

    def __init__(self, now: float = 1_000_000.0):
        self.now = now

    def __call__(self) -> float:
        return self.now


class KeyCustodyHappyPathTests(unittest.TestCase):
    def test_seal_anchor_sign_and_stranger_verifies(self):
        """A stranger holding only the public key + anchored hash verifies."""
        ledger = _ledger()
        clock = Clock()
        custody = KeyCustody(
            agent_id="agent-a", ledger=ledger, seed=b"s" * 32, clock=clock
        )
        policy = _policy(clock.now)
        seal = custody.seal_policy(policy, vault_version=1)
        self.assertTrue(seal.verify_self())
        custody.anchor()

        envelope = custody.sign({"receipt_id": "r1", "tool": "write_file"}, op="receipt")

        # The stranger knows only: the public key and the anchored policy hash.
        anchored = read_anchored(ledger)
        self.assertIsNotNone(anchored)
        self.assertTrue(
            verify_envelope(
                envelope,
                custody.public_key,
                anchored_policy_hash=anchored.policy_hash,
            )
        )

    def test_envelope_carries_every_field(self):
        """The envelope is complete: signature, key id + pubkey, hashes, version."""
        ledger = _ledger()
        clock = Clock()
        custody = KeyCustody(
            agent_id="agent-a", ledger=ledger, seed=b"s" * 32, clock=clock
        )
        custody.seal_policy(_policy(clock.now), vault_version=1)
        custody.anchor()
        envelope = custody.sign({"receipt_id": "r1"}, op="receipt")

        self.assertTrue(envelope.signature)
        self.assertTrue(envelope.key_id.startswith("ed25519:"))
        self.assertEqual(envelope.public_key, custody.public_key.hex())
        self.assertEqual(envelope.schema, SCHEMA_PIN)
        self.assertTrue(envelope.policy_hash.startswith("sha256:"))
        self.assertEqual(envelope.vault_version, 1)
        self.assertTrue(envelope.anchored_policy_hash.startswith("sha256:"))
        self.assertEqual(envelope.anchored_vault_version, 1)
        self.assertGreaterEqual(envelope.anchor_seq, 1)
        self.assertTrue(envelope.payload_hash.startswith("sha256:"))
        self.assertEqual(envelope.seq, 1)
        self.assertGreater(envelope.timestamp, 0.0)

    def test_policy_hash_is_canonical(self):
        """Same policy -> same hash; one changed field -> different hash."""
        now = 1_000_000.0
        a = _policy(now)
        b = _policy(now)
        self.assertEqual(a.policy_hash, b.policy_hash)
        # Field order must not matter.
        c = CustodyPolicy(
            policy_id="p1",
            epoch_seconds=3600,
            expires_at=now + 3600.0,
            max_signatures_per_epoch=2,
            allowed_ops=("attest", "receipt"),
        )
        self.assertEqual(a.policy_hash, c.policy_hash)
        # One character changed -> different hash.
        d = _policy(now, policy_id="p2")
        self.assertNotEqual(a.policy_hash, d.policy_hash)

    def test_refusal_is_structured_not_a_bare_exception(self):
        """A refusal carries a reason enum and details; nothing is swallowed."""
        ledger = _ledger()
        clock = Clock()
        custody = KeyCustody(
            agent_id="agent-a", ledger=ledger, seed=b"s" * 32, clock=clock
        )
        custody.seal_policy(_policy(clock.now), vault_version=1)
        custody.anchor()
        with self.assertRaises(CustodyRefusal) as ctx:
            custody.sign({"x": 1}, op="not-a-permitted-op")
        refusal = ctx.exception
        self.assertIs(refusal.reason, RefusalReason.OP_NOT_ALLOWED)
        self.assertEqual(refusal.reason.value, "OP_NOT_ALLOWED")
        self.assertIn("op", refusal.detail)
        self.assertEqual(refusal.to_dict()["reason"], "OP_NOT_ALLOWED")
        self.assertEqual(refusal.to_dict()["schema"], SCHEMA_PIN)


class KeyCustodyRefusalTests(unittest.TestCase):
    def test_policy_tamper_after_seal_is_refused(self):
        """Change the sealed policy -> POLICY_TAMPER, and no signature."""
        ledger = _ledger()
        clock = Clock()
        custody = KeyCustody(
            agent_id="agent-a", ledger=ledger, seed=b"s" * 32, clock=clock
        )
        custody.seal_policy(_policy(clock.now), vault_version=1)
        custody.anchor()

        # The policy changes after sealing (any field): the seal still holds
        # the old hash, the custody object now carries the new one.
        custody._policy = _policy(clock.now, max_signatures_per_epoch=99)
        before = custody.signature_count(custody.policy.epoch_of(clock.now))
        with self.assertRaises(CustodyRefusal) as ctx:
            custody.sign({"x": 1}, op="receipt")
        self.assertIs(ctx.exception.reason, RefusalReason.POLICY_TAMPER)
        self.assertEqual(
            custody.signature_count(custody.policy.epoch_of(clock.now)), before
        )
        self.assertNotEqual(
            ctx.exception.detail["current_policy_hash"],
            ctx.exception.detail["sealed_policy_hash"],
        )

    def test_rollback_to_old_vault_is_refused_though_its_seal_is_valid(self):
        """The headline: a valid seal does NOT survive a rollback."""
        ledger = _ledger()
        clock = Clock()
        policy = _policy(clock.now)

        # Version 1 is anchored.
        first = KeyCustody(
            agent_id="agent-a", ledger=ledger, seed=b"s" * 32, clock=clock
        )
        first.seal_policy(policy, vault_version=1)
        first.anchor()

        # Version 2 is anchored later: the anchored version moved forward.
        second = KeyCustody(
            agent_id="agent-a", ledger=ledger, seed=b"t" * 32, clock=clock
        )
        second.seal_policy(policy, vault_version=2)
        second.anchor()
        anchored = read_anchored(ledger)
        self.assertEqual(anchored.vault_version, 2)

        # Now roll back: an old vault (version 1) with a *looser* policy.
        # Its seal is still self-consistent -- that is exactly the hole the
        # source describes -- but the pre-sign gate compares against the
        # anchored state and refuses.
        looser = _policy(clock.now, max_signatures_per_epoch=999)
        rolled_back = KeyCustody(
            agent_id="agent-a", ledger=ledger, seed=b"r" * 32, clock=clock
        )
        rolled_back.seal_policy(looser, vault_version=1)

        # The old check ("the seal is valid") would let this through.
        self.assertTrue(seal_is_valid(rolled_back.seal))
        self.assertTrue(rolled_back.seal.verify_self())

        # The gate refuses: ROLLBACK, and no signature is produced.
        with self.assertRaises(CustodyRefusal) as ctx:
            rolled_back.sign({"x": 1}, op="receipt")
        self.assertIs(ctx.exception.reason, RefusalReason.ROLLBACK)
        self.assertEqual(ctx.exception.detail["sealed_vault_version"], 1)
        self.assertEqual(ctx.exception.detail["anchored_vault_version"], 2)
        self.assertEqual(rolled_back.signature_count(looser.epoch_of(clock.now)), 0)

    def test_cap_exceeded_is_refused(self):
        """The per-epoch cap is enforced by the gate."""
        ledger = _ledger()
        clock = Clock()
        custody = KeyCustody(
            agent_id="agent-a", ledger=ledger, seed=b"s" * 32, clock=clock
        )
        custody.seal_policy(_policy(clock.now, max_signatures_per_epoch=1), vault_version=1)
        custody.anchor()
        custody.sign({"x": 1}, op="receipt")
        with self.assertRaises(CustodyRefusal) as ctx:
            custody.sign({"x": 2}, op="receipt")
        self.assertIs(ctx.exception.reason, RefusalReason.CAP_EXCEEDED)
        self.assertEqual(ctx.exception.detail["cap"], 1)
        self.assertEqual(ctx.exception.detail["count"], 1)

    def test_expired_policy_is_refused(self):
        """An expired policy refuses to sign."""
        ledger = _ledger()
        clock = Clock()
        custody = KeyCustody(
            agent_id="agent-a", ledger=ledger, seed=b"s" * 32, clock=clock
        )
        custody.seal_policy(_policy(clock.now), vault_version=1)
        custody.anchor()
        clock.now += 7200.0  # past the expiry
        with self.assertRaises(CustodyRefusal) as ctx:
            custody.sign({"x": 1}, op="receipt")
        self.assertIs(ctx.exception.reason, RefusalReason.EXPIRED)
        self.assertEqual(custody.signature_count(0), 0)

    def test_vault_version_is_monotonic(self):
        """The anchored version only grows; an old vault cannot sign."""
        ledger = _ledger()
        clock = Clock()
        policy = _policy(clock.now)
        custody = KeyCustody(
            agent_id="agent-a", ledger=ledger, seed=b"s" * 32, clock=clock
        )
        custody.seal_policy(policy, vault_version=1)
        custody.anchor()
        with self.assertRaises(CustodyError):
            custody.seal_policy(policy, vault_version=1)  # not increasing
        custody.seal_policy(policy, vault_version=2)
        custody.anchor()
        anchored = read_anchored(ledger)
        self.assertEqual(anchored.vault_version, 2)
        with self.assertRaises(CustodyError):
            anchor_vault(ledger, custody.seal)  # re-anchor at the same version

    def test_unsealed_and_unanchored_are_refused(self):
        """Nothing sealed -> NOT_SEALED; sealed but not anchored -> NOT_ANCHORED."""
        ledger = _ledger()
        clock = Clock()
        custody = KeyCustody(
            agent_id="agent-a", ledger=ledger, seed=b"s" * 32, clock=clock
        )
        with self.assertRaises(CustodyRefusal) as ctx:
            custody.sign({"x": 1}, op="receipt")
        self.assertIs(ctx.exception.reason, RefusalReason.NOT_SEALED)
        custody.seal_policy(_policy(clock.now), vault_version=1)
        with self.assertRaises(CustodyRefusal) as ctx:
            custody.sign({"x": 1}, op="receipt")
        self.assertIs(ctx.exception.reason, RefusalReason.NOT_ANCHORED)


class KeyCustodyVerificationTests(unittest.TestCase):
    def _signed(self):
        ledger = _ledger()
        clock = Clock()
        custody = KeyCustody(
            agent_id="agent-a", ledger=ledger, seed=b"s" * 32, clock=clock
        )
        custody.seal_policy(_policy(clock.now), vault_version=1)
        custody.anchor()
        envelope = custody.sign({"receipt_id": "r1"}, op="receipt")
        return ledger, custody, envelope

    def test_wrong_public_key_fails_verification(self):
        """A different public key does not verify the envelope."""
        ledger, custody, envelope = self._signed()
        other = KeyCustody(agent_id="agent-b", ledger=ledger, seed=b"o" * 32)
        self.assertFalse(verify_envelope(envelope, other.public_key))

    def test_tampered_signature_fails_verification(self):
        """Flipping one byte of the signature breaks verification."""
        ledger, custody, envelope = self._signed()
        raw = bytearray(bytes.fromhex(envelope.signature))
        raw[0] ^= 0x01
        broken = SignatureEnvelope.from_dict(
            dict(envelope.to_dict(), signature=bytes(raw).hex())
        )
        self.assertFalse(verify_envelope(broken, custody.public_key))

    def test_tampered_envelope_fields_fail_verification(self):
        """Changing the payload hash, the policy hash or the payload breaks it."""
        ledger, custody, envelope = self._signed()
        broken_hash = SignatureEnvelope.from_dict(
            dict(envelope.to_dict(), payload_hash="sha256:" + "0" * 64)
        )
        self.assertFalse(verify_envelope(broken_hash, custody.public_key))
        broken_policy = SignatureEnvelope.from_dict(
            dict(envelope.to_dict(), policy_hash="sha256:" + "1" * 64)
        )
        self.assertFalse(verify_envelope(broken_policy, custody.public_key))
        broken_payload = SignatureEnvelope.from_dict(
            dict(envelope.to_dict(), payload={"receipt_id": "r2"})
        )
        self.assertFalse(verify_envelope(broken_payload, custody.public_key))

    def test_envelope_round_trips_through_dict(self):
        """The envelope survives a dict round trip and still verifies."""
        ledger, custody, envelope = self._signed()
        again = SignatureEnvelope.from_dict(envelope.to_dict())
        self.assertTrue(verify_envelope(again, custody.public_key))


class KeyCustodyPrimitiveReuseTests(unittest.TestCase):
    def test_module_reuses_the_repository_ed25519_primitive(self):
        """No second signing stack: the vendored ed25519 module is the one used."""
        import key_custody

        source = Path(key_custody.__file__).read_text(encoding="utf-8")
        # The module must not define or import a crypto library of its own.
        self.assertNotIn("from cryptography", source)
        self.assertNotIn("import nacl", source)
        self.assertNotIn("hashlib.sha512", source)
        # It loads the repo's vendored ed25519 module by name.
        self.assertIn('_load_sibling("ed25519")', source)
        # And the primitive it loads is the one message_signing.py uses.
        import message_signing

        signing_source = Path(message_signing.__file__).read_text(encoding="utf-8")
        self.assertIn("from ed25519 import sign", signing_source)
        self.assertIn("from ed25519 import verify", signing_source)
        # The vendored module is the only ed25519 implementation in the repo.
        import ed25519

        self.assertTrue(hasattr(ed25519, "sign") and hasattr(ed25519, "verify"))

    def test_signature_is_verifiable_with_the_vendored_primitive(self):
        """The envelope signature checks out under the repo's ed25519 alone."""
        import ed25519

        ledger = _ledger()
        clock = Clock()
        custody = KeyCustody(
            agent_id="agent-a", ledger=ledger, seed=b"s" * 32, clock=clock
        )
        custody.seal_policy(_policy(clock.now), vault_version=1)
        custody.anchor()
        envelope = custody.sign({"receipt_id": "r1"}, op="receipt")
        self.assertTrue(
            ed25519.verify(
                custody.public_key, envelope.signing_body(), bytes.fromhex(envelope.signature)
            )
        )


class KeyCustodyEndToEndTests(unittest.TestCase):
    def test_full_driven_path(self):
        """The whole path: seal -> anchor -> sign -> stranger verify -> refuse."""
        ledger = _ledger()
        clock = Clock()
        custody = KeyCustody(
            agent_id="agent-a", ledger=ledger, seed=b"s" * 32, clock=clock
        )
        policy = _policy(clock.now)
        custody.seal_policy(policy, vault_version=1)
        custody.anchor()
        envelope = custody.sign({"receipt_id": "r1"}, op="receipt")
        anchored = read_anchored(ledger)
        self.assertTrue(
            verify_envelope(
                envelope, custody.public_key, anchored_policy_hash=anchored.policy_hash
            )
        )
        # The anchor really landed in the append-only ledger.
        record = ledger.record(anchored.seq)
        self.assertEqual(record.seq, anchored.seq)
        self.assertIn("vault_version=1", dict(record.event)["authorization"])

    def test_anchor_is_readable_from_the_ledger_afterwards(self):
        """The anchored state survives outside the vault: it is in the ledger."""
        ledger = _ledger()
        clock = Clock()
        custody = KeyCustody(
            agent_id="agent-a", ledger=ledger, seed=b"s" * 32, clock=clock
        )
        custody.seal_policy(_policy(clock.now), vault_version=4)
        anchored = custody.anchor()
        self.assertIsInstance(anchored, AnchoredState)
        self.assertEqual(anchored.vault_version, 4)
        again = read_anchored(ledger)
        self.assertEqual(again.policy_hash, anchored.policy_hash)
        self.assertEqual(again.seq, anchored.seq)
        self.assertEqual(again.anchor_digest, anchored.anchor_digest)

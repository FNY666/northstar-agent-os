"""Tests for key_custody (B173 asinhhc slice).

Covers: the happy path with a stranger verifier, the canonical policy hash,
the policy-tamper refusal, the rollback refusal (the headline: the old
"seal is valid" check lets it through), the cap, the expiry, wrong key and
tampered envelopes, the structured refusal, the monotonic vault version, and
the reuse of the repository's single ed25519 primitive.

The ``KeyCustodyDoubleGuardTests`` class at the end is the B173
``mutant-lift-asinhhc`` addition: it drives the SECOND half of every
double-guard in ``key_custody.py`` (the half the original suite never
reached), so each planted fault is killed by the slice's OWN tests.
"""

import importlib.util
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import key_custody
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


def _seal(vault_version: int = 1) -> VaultSeal:
    """A standalone, self-consistent seal (no custody object needed)."""
    return VaultSeal.create(
        vault_version=vault_version,
        policy_hash="sha256:" + "0" * 64,
        sealed_at=1_000_000.0,
        key_id="ed25519:test",
    )


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


class KeyCustodyDoubleGuardTests(unittest.TestCase):
    """The SECOND half of every double-guard in ``key_custody.py``.

    B173 ``mutant-lift-asinhhc``: the original suite drove only ONE half of
    each guard (usually the TYPE half), so flipping the connective of a
    double-guard left the suite green.  Every test here drives the OTHER
    half, so each planted fault is killed by the slice's own tests.
    """

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

    # -- lt@193: `if self.max_signatures_per_epoch < 0:` ---------------
    #
    # The guard is reached only after the two TYPE guards above it
    # (``isinstance(..., bool)`` and ``not isinstance(..., int)``) have
    # passed, so feeding a NEGATIVE int reaches the bound check itself.
    # The fault `lt@193` is `< -> <=`: with the fault, a cap of exactly 0
    # is refused, without it, a cap of 0 is legal.
    def test_a_negative_cap_is_refused(self):
        """A negative cap is refused by the bound guard (its first half)."""
        with self.assertRaises(CustodyError) as ctx:
            CustodyPolicy(max_signatures_per_epoch=-1)
        self.assertIn("non-negative", str(ctx.exception))

    def test_a_cap_of_exactly_zero_is_legal_and_its_boundary_is_exact(self):
        """0 is the exact limit: legal.  -1 is the limit - 1: refused.

        ``lt@193`` mutated to ``<=`` would refuse a cap of exactly 0, so
        this test dies with the fault applied.
        """
        policy = CustodyPolicy(max_signatures_per_epoch=0)
        self.assertEqual(policy.max_signatures_per_epoch, 0)
        self.assertEqual(policy.canonical_form()["max_signatures_per_epoch"], 0)
        # The limit + 1 is legal too.
        policy1 = CustodyPolicy(max_signatures_per_epoch=1)
        self.assertEqual(policy1.max_signatures_per_epoch, 1)
        with self.assertRaises(CustodyError):
            CustodyPolicy(max_signatures_per_epoch=-1)

    def test_a_zero_cap_blocks_the_first_signature(self):
        """A cap of exactly 0 refuses at the gate (cap 0 is the boundary)."""
        ledger = _ledger()
        clock = Clock()
        custody = KeyCustody(
            agent_id="agent-a", ledger=ledger, seed=b"s" * 32, clock=clock
        )
        custody.seal_policy(
            _policy(clock.now, max_signatures_per_epoch=0), vault_version=1
        )
        custody.anchor()
        with self.assertRaises(CustodyRefusal) as ctx:
            custody.sign({"x": 1}, op="receipt")
        self.assertIs(ctx.exception.reason, RefusalReason.CAP_EXCEEDED)
        self.assertEqual(ctx.exception.detail["cap"], 0)
        self.assertEqual(ctx.exception.detail["count"], 0)

    # -- lt@631: `if vault_version < 1:` -------------------------------
    #
    # The exact limit is 1; 0 is the limit - 1.  ``lt@631`` mutated to
    # ``<=`` refuses a version of exactly 1.
    def test_a_vault_version_below_one_is_refused(self):
        """vault_version 0 is refused (the limit - 1)."""
        ledger = _ledger()
        clock = Clock()
        custody = KeyCustody(
            agent_id="agent-a", ledger=ledger, seed=b"s" * 32, clock=clock
        )
        with self.assertRaises(CustodyError) as ctx:
            custody.seal_policy(_policy(clock.now), vault_version=0)
        self.assertIn(">= 1", str(ctx.exception))

    def test_a_vault_version_of_exactly_one_is_accepted(self):
        """vault_version 1 is the exact limit: accepted."""
        ledger = _ledger()
        clock = Clock()
        custody = KeyCustody(
            agent_id="agent-a", ledger=ledger, seed=b"s" * 32, clock=clock
        )
        seal = custody.seal_policy(_policy(clock.now), vault_version=1)
        self.assertEqual(seal.vault_version, 1)
        self.assertTrue(seal.verify_self())

    # -- lt@688: `if self._seal.vault_version < anchored.vault_version:`
    #
    # The exact limit is the ANCHORED version: equal is NOT a rollback
    # (a rollback is strictly older).  ``lt@688`` mutated to ``<=`` would
    # refuse an EQUAL version -- i.e. the ordinary re-seal-at-the-same-
    # version case, which the suite never drove.
    def test_an_equal_vault_version_is_not_a_rollback(self):
        """A vault at exactly the anchored version is NOT a rollback.

        The exact limit (equal) passes; the limit - 1 (older) is a
        rollback.
        """
        ledger = _ledger()
        clock = Clock()
        policy = _policy(clock.now)
        custody = KeyCustody(
            agent_id="agent-a", ledger=ledger, seed=b"s" * 32, clock=clock
        )
        custody.seal_policy(policy, vault_version=2)
        custody.anchor()
        anchored = read_anchored(ledger)
        self.assertEqual(anchored.vault_version, 2)

        # A SECOND vault at exactly the anchored version: equal, not older.
        equal = KeyCustody(
            agent_id="agent-a", ledger=ledger, seed=b"e" * 32, clock=clock
        )
        equal.seal_policy(policy, vault_version=2)
        envelope = equal.sign({"x": 1}, op="receipt")
        self.assertEqual(envelope.vault_version, 2)
        self.assertEqual(envelope.anchored_vault_version, 2)

    def test_a_vault_one_version_older_than_the_anchor_is_a_rollback(self):
        """The limit - 1 (one version older) IS a rollback."""
        ledger = _ledger()
        clock = Clock()
        policy = _policy(clock.now)
        first = KeyCustody(
            agent_id="agent-a", ledger=ledger, seed=b"s" * 32, clock=clock
        )
        first.seal_policy(policy, vault_version=1)
        first.anchor()
        second = KeyCustody(
            agent_id="agent-a", ledger=ledger, seed=b"t" * 32, clock=clock
        )
        second.seal_policy(policy, vault_version=2)
        second.anchor()

        rolled_back = KeyCustody(
            agent_id="agent-a", ledger=ledger, seed=b"r" * 32, clock=clock
        )
        rolled_back.seal_policy(policy, vault_version=1)
        with self.assertRaises(CustodyRefusal) as ctx:
            rolled_back.sign({"x": 1}, op="receipt")
        self.assertIs(ctx.exception.reason, RefusalReason.ROLLBACK)

    # -- eq@286: `return expected == self.seal` -----------------------
    #
    # ``eq`` needs BOTH sides: the seal that re-derives (True) and the one
    # that does not (False).  The original suite only drove the True side.
    def test_a_seal_that_does_not_re_derive_is_not_valid(self):
        """A tampered seal digest does NOT verify (the False side of eq)."""
        ledger = _ledger()
        clock = Clock()
        custody = KeyCustody(
            agent_id="agent-a", ledger=ledger, seed=b"s" * 32, clock=clock
        )
        seal = custody.seal_policy(_policy(clock.now), vault_version=1)
        self.assertTrue(seal.verify_self())
        # Flip one hex digit of the seal: it no longer re-derives.
        broken_digest = ("f" if seal.seal[7] != "f" else "0") + seal.seal[8:]
        broken = VaultSeal(
            vault_version=seal.vault_version,
            policy_hash=seal.policy_hash,
            sealed_at=seal.sealed_at,
            key_id=seal.key_id,
            seal=broken_digest,
        )
        self.assertFalse(broken.verify_self())
        self.assertFalse(seal_is_valid(broken))
        # And the True side still holds.
        self.assertTrue(seal_is_valid(seal))

    # -- or@336: `if not isinstance(value, str) or ";" not in value:`
    #
    # The first half fires on a NON-STR, the second on a str WITHOUT a
    # ";".  The original suite drove neither, so both were unmeasured.
    def test_a_non_string_anchor_authorization_is_not_parsed(self):
        """A non-str authorization parses to None (the type half)."""
        self.assertIsNone(key_custody._parse_anchor_authorization(None))
        self.assertIsNone(key_custody._parse_anchor_authorization(123))
        self.assertIsNone(key_custody._parse_anchor_authorization(["a"]))

    def test_a_string_anchor_authorization_without_a_semicolon_is_not_parsed(self):
        """A str WITHOUT ";" parses to None (the emptiness half)."""
        self.assertIsNone(key_custody._parse_anchor_authorization(""))
        self.assertIsNone(key_custody._parse_anchor_authorization("vault_version=1"))
        # And the well-formed one DOES parse (the True side).
        parsed = key_custody._parse_anchor_authorization(
            "vault_version=7;policy_hash=sha256:abc"
        )
        self.assertEqual(parsed, (7, "sha256:abc"))

    # -- or@348: `if version is None or not policy_hash:` --------------
    #
    # The first half fires when the version is MISSING, the second when
    # the policy hash is EMPTY.  Both are needed.
    def test_an_anchor_authorization_without_a_version_is_not_parsed(self):
        """A missing version parses to None (the first half)."""
        self.assertIsNone(
            key_custody._parse_anchor_authorization("policy_hash=sha256:abc")
        )

    def test_an_anchor_authorization_with_an_empty_policy_hash_is_not_parsed(self):
        """An EMPTY policy hash parses to None (the second half)."""
        self.assertIsNone(
            key_custody._parse_anchor_authorization("vault_version=1;policy_hash=")
        )
        self.assertIsNone(
            key_custody._parse_anchor_authorization("vault_version=1;")
        )

    # -- or@392: `if ledger is None or not callable(getattr(ledger, "append", None)):`
    #
    # The first half is a None ledger, the second is a ledger WITHOUT an
    # append().  Both must be refused.
    def test_a_ledger_without_an_append_method_is_refused(self):
        """A ledger without append() is refused (the second half)."""

        class NoAppend:
            pass

        with self.assertRaises(CustodyError) as ctx:
            anchor_vault(NoAppend(), _seal())
        self.assertIn("append()", str(ctx.exception))

    def test_a_none_ledger_is_refused(self):
        """A None ledger is refused (the first half)."""
        with self.assertRaises(CustodyError) as ctx:
            anchor_vault(None, _seal())
        self.assertIn("append()", str(ctx.exception))

    # -- or@521: `if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != 32:`
    #
    # The first half is a NON-BYTES public key, the second is a bytes
    # public key of the WRONG LENGTH.  Both must be refused.
    def test_a_non_bytes_public_key_does_not_verify(self):
        """A public key that is not bytes does not verify (first half)."""
        ledger, custody, envelope = self._signed()
        self.assertFalse(verify_envelope(envelope, "not-bytes"))
        self.assertFalse(verify_envelope(envelope, None))
        self.assertFalse(verify_envelope(envelope, 12345))

    def test_a_public_key_of_the_wrong_length_does_not_verify(self):
        """A 31-byte public key does not verify (second half)."""
        ledger, custody, envelope = self._signed()
        self.assertFalse(verify_envelope(envelope, custody.public_key[:-1]))
        self.assertFalse(verify_envelope(envelope, custody.public_key + b"\x00"))
        # The exact length (32) does verify.
        self.assertTrue(verify_envelope(envelope, custody.public_key))

    # -- retF@522 / retF@525 / retF@527 / retF@530 / retF@532 / retF@535
    #    / retT@536 / retF@538 -----------------------------------------
    #
    # These are the ``return False`` / ``return True`` constants of
    # ``verify_envelope``.  Each one needs the branch it guards to be
    # REACHED, and the returned constant to be the thing observed.
    def test_a_signature_of_the_wrong_length_does_not_verify(self):
        """A signature that is not 64 bytes does not verify (retF@525)."""
        ledger, custody, envelope = self._signed()
        short = SignatureEnvelope.from_dict(
            dict(envelope.to_dict(), signature=bytes.fromhex(envelope.signature)[:-1].hex())
        )
        self.assertFalse(verify_envelope(short, custody.public_key))
        long = SignatureEnvelope.from_dict(
            dict(envelope.to_dict(), signature=bytes.fromhex(envelope.signature) + b"\x00" and (bytes.fromhex(envelope.signature) + b"\x00").hex())
        )
        self.assertFalse(verify_envelope(long, custody.public_key))

    def test_a_signature_that_is_not_hex_does_not_verify(self):
        """A non-hex signature does not verify (the except branch, retF@538)."""
        ledger, custody, envelope = self._signed()
        broken = SignatureEnvelope.from_dict(
            dict(envelope.to_dict(), signature="zz" * 64)
        )
        self.assertFalse(verify_envelope(broken, custody.public_key))

    def test_a_malformed_public_key_does_not_verify(self):
        """A 32-byte but off-curve public key does not verify (retF@527)."""
        ledger, custody, envelope = self._signed()
        self.assertFalse(verify_envelope(envelope, b"\xff" * 32))
        self.assertFalse(verify_envelope(envelope, b"\x00" * 32))

    def test_a_mismatched_anchored_policy_hash_does_not_verify(self):
        """A wrong anchored policy hash does not verify (retF@530/532)."""
        ledger, custody, envelope = self._signed()
        self.assertFalse(
            verify_envelope(
                envelope, custody.public_key, anchored_policy_hash="sha256:" + "0" * 64
            )
        )
        # The envelope's own anchored_policy_hash is checked too.
        broken_anchored = SignatureEnvelope.from_dict(
            dict(envelope.to_dict(), anchored_policy_hash="sha256:" + "1" * 64)
        )
        self.assertFalse(
            verify_envelope(broken_anchored, custody.public_key)
        )
        # The correct anchored hash verifies (retT@536).
        anchored = read_anchored(ledger)
        self.assertTrue(
            verify_envelope(
                envelope,
                custody.public_key,
                anchored_policy_hash=anchored.policy_hash,
            )
        )

    def test_a_wrong_payload_hash_does_not_verify(self):
        """A payload hash that does not match the payload does not verify."""
        ledger, custody, envelope = self._signed()
        broken = SignatureEnvelope.from_dict(
            dict(envelope.to_dict(), payload_hash="sha256:" + "2" * 64)
        )
        self.assertFalse(verify_envelope(broken, custody.public_key))

    # -- or@521 / retF@532 / retF@535 ---------------------------------
    #
    # These three need the fault to be OBSERVABLE, i.e. the mutant has to
    # change the RESULT of ``verify_envelope`` from False to True.  Each
    # test therefore builds an envelope that is VALID in every respect
    # except the one field under test, and RE-SIGNS it with the seed the
    # custody object was built from -- otherwise the signature check
    # would refuse first and the later check would never be observed.
    def _resign(self, envelope: SignatureEnvelope, seed: bytes) -> SignatureEnvelope:
        """Re-sign an edited envelope so only the edited field is wrong."""
        import ed25519

        signature = ed25519.sign(seed, envelope.signing_body()).hex()
        return SignatureEnvelope.from_dict(
            dict(envelope.to_dict(), signature=signature)
        )

    def test_a_public_key_of_the_wrong_type_is_refused_even_at_length_32(self):
        """A non-bytes public key of exactly 32 units is refused (or@521).

        The guard is a TYPE guard: a list of 32 ints is not a public key.
        With the fault (``or -> and``) the length half would swallow it,
        and ``bytes(list)`` would then rebuild the very same 32 bytes --
        so the envelope would VERIFY.  It must not.
        """
        ledger, custody, envelope = self._signed()
        as_list = list(custody.public_key)
        self.assertEqual(len(as_list), 32)
        self.assertNotIsInstance(as_list, (bytes, bytearray))
        self.assertFalse(verify_envelope(envelope, as_list))

    def test_a_wrong_anchored_policy_hash_is_refused_even_with_a_valid_signature(self):
        """A wrong ``anchored_policy_hash`` is refused (retF@532).

        The signature is re-signed over the tampered body, so the ONLY
        thing wrong with the envelope is the anchored policy hash.  The
        envelope's own ``policy_hash`` still matches the supplied anchor,
        so the FIRST of the two anchored checks passes and the SECOND is
        the one under test.
        """
        ledger, custody, envelope = self._signed()
        anchored = read_anchored(ledger)
        self.assertIsNotNone(anchored)
        tampered = SignatureEnvelope.from_dict(
            dict(envelope.to_dict(), anchored_policy_hash="sha256:" + "3" * 64)
        )
        resigned = self._resign(tampered, b"s" * 32)
        # The signature itself is now valid: the only defect is the hash.
        self.assertFalse(
            verify_envelope(
                resigned, custody.public_key, anchored_policy_hash=anchored.policy_hash
            )
        )

    def test_a_wrong_payload_hash_is_refused_even_with_a_valid_signature(self):
        """A wrong ``payload_hash`` is refused (retF@535).

        The signature is re-signed over the tampered body, so the ONLY
        thing wrong with the envelope is the payload hash -- which is
        exactly the check that must refuse it.
        """
        ledger, custody, envelope = self._signed()
        tampered = SignatureEnvelope.from_dict(
            dict(envelope.to_dict(), payload_hash="sha256:" + "4" * 64)
        )
        resigned = self._resign(tampered, b"s" * 32)
        self.assertFalse(verify_envelope(resigned, custody.public_key))

    # -- or@565: `if not isinstance(agent_id, str) or not agent_id:` ----
    #
    # The first half is a NON-STR agent id, the second is an EMPTY str.
    def test_a_non_string_agent_id_is_refused(self):
        """A non-str agent id is refused (first half)."""
        with self.assertRaises(CustodyError):
            KeyCustody(agent_id=123, seed=b"s" * 32)
        with self.assertRaises(CustodyError):
            KeyCustody(agent_id=None, seed=b"s" * 32)

    def test_an_empty_agent_id_is_refused(self):
        """An EMPTY agent id is refused (second half)."""
        with self.assertRaises(CustodyError):
            KeyCustody(agent_id="", seed=b"s" * 32)

    # -- or@573: `if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:`
    #
    # The first half is a NON-BYTES seed, the second is a wrong-LENGTH
    # seed.
    def test_a_non_bytes_seed_is_refused(self):
        """A non-bytes seed is refused (first half)."""
        with self.assertRaises(CustodyError):
            KeyCustody(agent_id="agent-a", seed="not-bytes")
        with self.assertRaises(CustodyError):
            KeyCustody(agent_id="agent-a", seed=12345)

    def test_a_seed_of_the_wrong_length_is_refused(self):
        """A 31-byte seed is refused (second half); 32 bytes is accepted."""
        with self.assertRaises(CustodyError) as ctx:
            KeyCustody(agent_id="agent-a", seed=b"s" * 31)
        self.assertIn("32-byte", str(ctx.exception))
        with self.assertRaises(CustodyError):
            KeyCustody(agent_id="agent-a", seed=b"s" * 33)
        accepted = KeyCustody(agent_id="agent-a", seed=b"s" * 32)
        self.assertEqual(len(accepted.public_key), 32)

    # -- or@629: `if isinstance(vault_version, bool) or not isinstance(vault_version, int):`
    #
    # The first half is a BOOL, the second a non-int.  Both refused.
    def test_a_boolean_vault_version_is_refused(self):
        """A bool vault_version is refused (first half)."""
        ledger = _ledger()
        clock = Clock()
        custody = KeyCustody(
            agent_id="agent-a", ledger=ledger, seed=b"s" * 32, clock=clock
        )
        with self.assertRaises(CustodyError) as ctx:
            custody.seal_policy(_policy(clock.now), vault_version=True)
        self.assertIn("must be an int", str(ctx.exception))
        with self.assertRaises(CustodyError):
            custody.seal_policy(_policy(clock.now), vault_version=False)

    def test_a_non_integer_vault_version_is_refused(self):
        """A non-int vault_version is refused (second half)."""
        ledger = _ledger()
        clock = Clock()
        custody = KeyCustody(
            agent_id="agent-a", ledger=ledger, seed=b"s" * 32, clock=clock
        )
        with self.assertRaises(CustodyError):
            custody.seal_policy(_policy(clock.now), vault_version=1.0)
        with self.assertRaises(CustodyError):
            custody.seal_policy(_policy(clock.now), vault_version="1")

    # -- and@633: `if self._seal is not None and vault_version <= self._seal.vault_version:`
    #
    # ``and -> or`` weakens it: with the fault, the FIRST seal (no seal
    # yet) would be refused.  So the "first seal is accepted" case is the
    # one that dies with the fault.
    def test_the_first_seal_of_a_fresh_custody_object_is_accepted(self):
        """A fresh custody object with NO seal accepts its first version.

        ``and@633`` mutated to ``or`` would refuse this.
        """
        ledger = _ledger()
        clock = Clock()
        custody = KeyCustody(
            agent_id="agent-a", ledger=ledger, seed=b"s" * 32, clock=clock
        )
        self.assertIsNone(custody.seal)
        seal = custody.seal_policy(_policy(clock.now), vault_version=1)
        self.assertEqual(seal.vault_version, 1)

    # -- or@678: `if self._seal is None or self._policy is None:` ------
    #
    # The first half is a missing SEAL, the second a missing POLICY.
    # The second half is only reachable when the seal exists but the
    # policy does not.
    def test_a_custody_object_with_a_seal_but_no_policy_is_not_sealed(self):
        """A seal without a policy is still NOT_SEALED (second half)."""
        ledger = _ledger()
        clock = Clock()
        custody = KeyCustody(
            agent_id="agent-a", ledger=ledger, seed=b"s" * 32, clock=clock
        )
        custody.seal_policy(_policy(clock.now), vault_version=1)
        # The policy is dropped: the gate must still refuse as NOT_SEALED.
        custody._policy = None
        with self.assertRaises(CustodyRefusal) as ctx:
            custody.sign({"x": 1}, op="receipt")
        self.assertIs(ctx.exception.reason, RefusalReason.NOT_SEALED)

    # -- and@750: `assert self._seal is not None and self._policy is not None`
    #
    # ``and -> or`` weakens the assertion: with the fault, a custody
    # object with NO seal at all would pass the assertion instead of
    # raising AssertionError.  So the "no seal -> AssertionError" case
    # is the one that dies with the fault.
    def test_signing_without_a_seal_asserts(self):
        """Signing with no seal raises AssertionError, not a silent pass.

        ``and@750`` mutated to ``or`` would let the assertion pass (and
        the sign then die further down with an AttributeError instead).
        """
        ledger = _ledger()
        clock = Clock()
        custody = KeyCustody(
            agent_id="agent-a", ledger=ledger, seed=b"s" * 32, clock=clock
        )
        # The gate is stubbed out so the ASSERT is the thing under test:
        # the seal is gone but the policy is not.
        custody._seal = None
        custody._policy = _policy(clock.now)
        custody.pre_sign_gate = lambda op, now=None: AnchoredState(
            vault_version=1,
            policy_hash=custody._policy.policy_hash,
            seq=1,
            record_hash="sha256:" + "0" * 64,
            anchor_digest="sha256:" + "0" * 64,
            anchored_at=clock.now,
        )
        with self.assertRaises(AssertionError):
            custody.sign({"x": 1}, op="receipt")

    # -- and@395: `if current is not None and seal.vault_version <= current.vault_version:`
    #
    # The first half is "there IS a current anchor".  With the fault
    # (``and -> or``), the FIRST anchor into an EMPTY ledger would be
    # refused -- because ``current is None`` is False, but the ``or``
    # would then evaluate the second half with ``current`` being None.
    def test_the_first_anchor_into_an_empty_ledger_is_accepted(self):
        """Anchoring into an EMPTY ledger succeeds (the first half)."""
        ledger = _ledger()
        seal = _seal()
        state = anchor_vault(ledger, seal)
        self.assertEqual(state.vault_version, seal.vault_version)
        self.assertEqual(read_anchored(ledger).vault_version, seal.vault_version)

    # -- retF@814 / retF@817 / retT@818 / and@816 ----------------------
    #
    # ``stdlib_only`` reads its OWN source, so its branches can only be
    # driven by a COPY of the module with a foreign import injected.
    def _load_module_copy(self, extra_import: str):
        """Load a COPY of key_custody.py with ``extra_import`` injected.

        The copy is written to a temp dir; the module is loaded from
        there by path, so its ``stdlib_only()`` reads the COPY's source
        (its own ``__file__``), not the original's.
        """
        original = Path(key_custody.__file__).read_text(encoding="utf-8")
        marker = "from __future__ import annotations\n"
        self.assertIn(marker, original)
        mutated = original.replace(marker, marker + extra_import + "\n", 1)
        tmpdir = tempfile.mkdtemp(prefix="kc-copy-")
        self.addCleanup(shutil.rmtree, tmpdir, True)
        path = Path(tmpdir) / "key_custody_copy.py"
        path.write_text(mutated, encoding="utf-8")
        spec = importlib.util.spec_from_file_location(
            "key_custody_copy_" + Path(tmpdir).name, str(path)
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        try:
            spec.loader.exec_module(module)
        finally:
            sys.modules.pop(spec.name, None)
        return module

    def test_stdlib_only_is_false_for_a_module_with_a_foreign_import(self):
        """A foreign ``import`` makes stdlib_only False (retF@814)."""
        module = self._load_module_copy("import requests")
        self.assertFalse(module.stdlib_only())

    def test_stdlib_only_is_false_for_a_module_with_a_foreign_from_import(self):
        """A foreign ``from ... import`` makes stdlib_only False (retF@817)."""
        module = self._load_module_copy("from requests import get")
        self.assertFalse(module.stdlib_only())

    def test_stdlib_only_is_true_for_the_module_as_it_ships(self):
        """The shipped module is stdlib-only (retT@818, and@816)."""
        self.assertTrue(key_custody.stdlib_only())
        # A copy with only an ALLOWED import is still stdlib-only.
        module = self._load_module_copy("import json")
        self.assertTrue(module.stdlib_only())

    # -- eq@875: `if __name__ == "__main__": main()` -------------------
    #
    # The self-check is only evidence if it actually RUNS.
    def test_running_the_module_as_a_script_runs_its_self_check(self):
        """The module run as a SCRIPT runs its own self-check (eq@875)."""
        script = Path(key_custody.__file__)
        result = subprocess.run(
            [sys.executable, str(script)],
            cwd=str(script.parent),
            capture_output=True,
            text=True,
            timeout=180,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("key-custody OK", result.stdout)
        self.assertIn("stdlib only", result.stdout)

    def test_the_modules_self_check_passes_in_process(self):
        """The self-check passes when main() is called in-process."""
        key_custody.main()

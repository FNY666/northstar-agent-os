"""Tests for inter-agent message signing."""

import unittest

from message_signing import (
    NonceTracker,
    SignedMessage,
    sign_message,
    verify_message,
)


def _keys():
    from ed25519 import public_key as ed_pubkey

    seed = bytes(32)
    return seed, ed_pubkey(seed)


class MessageSigningTests(unittest.TestCase):
    def test_sign_verify_roundtrip(self):
        seed, pubkey = _keys()
        msg = sign_message("did:example:alice", seed, "did:example:bob", {"text": "hello"})
        self.assertTrue(verify_message(msg, pubkey))

    def test_tampered_payload_fails(self):
        seed, pubkey = _keys()
        msg = sign_message("did:example:alice", seed, "did:example:bob", {"text": "hello"})
        tampered = SignedMessage(
            sender_id=msg.sender_id,
            recipient_id=msg.recipient_id,
            payload={"text": "goodbye"},
            timestamp=msg.timestamp,
            nonce=msg.nonce,
            signature=msg.signature,
        )
        self.assertFalse(verify_message(tampered, pubkey))

    def test_tampered_sender_fails(self):
        seed, pubkey = _keys()
        msg = sign_message("did:example:alice", seed, "did:example:bob", {"text": "hello"})
        tampered = SignedMessage(
            sender_id="did:example:mallory",
            recipient_id=msg.recipient_id,
            payload=msg.payload,
            timestamp=msg.timestamp,
            nonce=msg.nonce,
            signature=msg.signature,
        )
        self.assertFalse(verify_message(tampered, pubkey))

    def test_expired_timestamp_fails(self):
        seed, pubkey = _keys()
        msg = sign_message(
            "did:example:alice", seed, "did:example:bob", {"text": "hello"},
            timestamp=1000.0,
        )
        self.assertFalse(
            verify_message(msg, pubkey, max_age_seconds=300.0, now=2000.0)
        )
        # Within the window: passes.
        self.assertTrue(
            verify_message(msg, pubkey, max_age_seconds=300.0, now=1100.0)
        )

    def test_replayed_nonce_fails(self):
        seed, pubkey = _keys()
        tracker = NonceTracker(max_age_seconds=300.0)
        msg = sign_message("did:example:alice", seed, "did:example:bob", {"text": "hello"})
        self.assertTrue(verify_message(msg, pubkey, nonce_tracker=tracker))
        # Same message again: replay.
        self.assertFalse(verify_message(msg, pubkey, nonce_tracker=tracker))
        # A different message (fresh nonce) still passes.
        msg2 = sign_message("did:example:alice", seed, "did:example:bob", {"text": "again"})
        self.assertTrue(verify_message(msg2, pubkey, nonce_tracker=tracker))

    def test_wrong_sender_key_fails(self):
        from ed25519 import public_key as ed_pubkey

        seed, _ = _keys()
        other_pubkey = ed_pubkey(bytes([1] * 32))
        msg = sign_message("did:example:alice", seed, "did:example:bob", {"text": "hello"})
        self.assertFalse(verify_message(msg, other_pubkey))

    def test_nonce_tracker_expiry(self):
        tracker = NonceTracker(max_age_seconds=60.0)
        self.assertTrue(tracker.check("n1", now=1000.0))
        self.assertFalse(tracker.check("n1", now=1010.0))  # replay within window
        self.assertTrue(tracker.check("n1", now=1100.0))  # expired: fresh again

    def test_benign_control(self):
        # Ordinary signed traffic between two honest agents verifies.
        from ed25519 import public_key as ed_pubkey

        seed_a = bytes(32)
        pub_a = ed_pubkey(seed_a)
        seed_b = bytes([2] * 32)
        pub_b = ed_pubkey(seed_b)
        m1 = sign_message("did:example:alice", seed_a, "did:example:bob", {"task": "summarize"})
        m2 = sign_message("did:example:bob", seed_b, "did:example:alice", {"result": "done"})
        self.assertTrue(verify_message(m1, pub_a))
        self.assertTrue(verify_message(m2, pub_b))
        # Cross-check: alice's key does not verify bob's message.
        self.assertFalse(verify_message(m2, pub_a))

    def test_serialization_roundtrip(self):
        seed, pubkey = _keys()
        msg = sign_message("did:example:alice", seed, "did:example:bob", {"n": 42})
        restored = SignedMessage.from_dict(msg.as_dict())
        self.assertEqual(restored, msg)
        self.assertTrue(verify_message(restored, pubkey))


if __name__ == "__main__":
    unittest.main()

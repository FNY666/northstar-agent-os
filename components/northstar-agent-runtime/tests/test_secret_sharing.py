"""Tests for secret_sharing: Shamir (t, n) byte-string key backup (simulated)."""

import dataclasses
import unittest

from secret_sharing import (
    EVENT_RECOVERED,
    EVENT_REJECTED,
    EVENT_SPLIT,
    FIELD_PRIME,
    SECRET_SHARING_SCHEMA,
    SECRET_SHARING_VERSION,
    BackupShare,
    BackupValidationError,
    RecoveryError,
    SecretSharing,
    SecretSharingError,
    secret_sharing_audit_event,
)


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(SECRET_SHARING_VERSION, "secret-sharing.v1")

    def test_schema_pin(self):
        self.assertEqual(SECRET_SHARING_SCHEMA, "northstar.secret-sharing.v1")

    def test_field_prime_is_mersenne(self):
        self.assertEqual(FIELD_PRIME, (1 << 61) - 1)
        self.assertEqual(SecretSharing.field_prime, FIELD_PRIME)


class TestSplitRecover(unittest.TestCase):
    def setUp(self):
        self.ss = SecretSharing()
        self.key = b"northstar-backup-key-42"

    def test_split_happy_path(self):
        shares = self.ss.split(self.key, n=5, t=3)
        self.assertEqual(len(shares), 5)
        self.assertEqual([s.share_id for s in shares], [1, 2, 3, 4, 5])
        for s in shares:
            self.assertEqual(s.n, 5)
            self.assertEqual(s.threshold, 3)
            self.assertEqual(s.secret_len, len(self.key))

    def test_recover_exactly_t_non_prefix(self):
        shares = self.ss.split(self.key, n=5, t=3)
        self.assertEqual(self.ss.recover(shares[:3]), self.key)
        self.assertEqual(self.ss.recover(shares[2:]), self.key)
        self.assertEqual(self.ss.recover((shares[0], shares[2], shares[4])), self.key)

    def test_recover_more_than_t(self):
        shares = self.ss.split(self.key, n=5, t=3)
        self.assertEqual(self.ss.recover(shares), self.key)

    def test_recover_fewer_than_t_raises(self):
        shares = self.ss.split(self.key, n=5, t=3)
        with self.assertRaises(RecoveryError):
            self.ss.recover(shares[:2])
        with self.assertRaises(RecoveryError):
            self.ss.recover(shares[:1])

    def test_byte_exactness_leading_zeros(self):
        tricky = b"\x00\x00\x01key\xff"
        shares = self.ss.split(tricky, n=3, t=2)
        self.assertEqual(self.ss.recover(shares[:2]), tricky)

    def test_odd_length_secret(self):
        odd = bytes(range(1, 20))  # 19 bytes -> 3 chunks
        shares = self.ss.split(odd, n=4, t=2)
        self.assertEqual(self.ss.recover(shares[:2]), odd)

    def test_single_byte_secret(self):
        shares = self.ss.split(b"\x00", n=3, t=2)
        self.assertEqual(self.ss.recover(shares[:2]), b"\x00")

    def test_multi_chunk_long_secret(self):
        long_key = bytes((i * 37 + 11) % 256 for i in range(300))
        shares = self.ss.split(long_key, n=5, t=3)
        self.assertEqual(self.ss.recover((shares[1], shares[3], shares[4])), long_key)

    def test_threshold_one(self):
        shares = self.ss.split(self.key, n=3, t=1)
        self.assertEqual(self.ss.recover(shares[:1]), self.key)

    def test_single_custodian(self):
        shares = self.ss.split(self.key, n=1, t=1)
        self.assertEqual(len(shares), 1)
        self.assertEqual(self.ss.recover(shares), self.key)

    def test_all_shares_required(self):
        shares = self.ss.split(self.key, n=4, t=4)
        with self.assertRaises(RecoveryError):
            self.ss.recover(shares[:3])
        self.assertEqual(self.ss.recover(shares), self.key)

    def test_deterministic_split(self):
        a = self.ss.split(self.key, n=5, t=3)
        b = self.ss.split(self.key, n=5, t=3)
        self.assertEqual(a, b)

    def test_distinct_secrets_distinct_shares(self):
        a = self.ss.split(b"key-one-secret", n=5, t=3)
        b = self.ss.split(b"key-two-secret", n=5, t=3)
        self.assertNotEqual(a[0].words, b[0].words)

    def test_params_change_shares(self):
        a = self.ss.split(self.key, n=5, t=3)
        b = self.ss.split(self.key, n=5, t=2)
        self.assertNotEqual(a[0].words, b[0].words)

    def test_words_in_field(self):
        shares = self.ss.split(self.key, n=5, t=3)
        for s in shares:
            for w in s.words:
                self.assertGreaterEqual(w, 0)
                self.assertLess(w, FIELD_PRIME)


class TestSplitValidation(unittest.TestCase):
    def setUp(self):
        self.ss = SecretSharing()

    def test_non_bytes_secret_rejected(self):
        with self.assertRaises(TypeError):
            self.ss.split("not-bytes", n=3, t=2)
        with self.assertRaises(TypeError):
            self.ss.split(123, n=3, t=2)
        with self.assertRaises(TypeError):
            self.ss.split(None, n=3, t=2)

    def test_empty_secret_rejected(self):
        with self.assertRaises(ValueError):
            self.ss.split(b"", n=3, t=2)

    def test_bad_n(self):
        with self.assertRaises(ValueError):
            self.ss.split(b"key", n=0, t=1)

    def test_threshold_above_n(self):
        with self.assertRaises(ValueError):
            self.ss.split(b"key", n=3, t=4)

    def test_threshold_zero(self):
        with self.assertRaises(ValueError):
            self.ss.split(b"key", n=3, t=0)

    def test_bool_params_rejected(self):
        with self.assertRaises(TypeError):
            self.ss.split(b"key", n=True, t=2)
        with self.assertRaises(TypeError):
            self.ss.split(b"key", n=3, t=False)

    def test_str_params_rejected(self):
        with self.assertRaises(TypeError):
            self.ss.split(b"key", n="3", t=2)


class TestRecoverValidation(unittest.TestCase):
    def setUp(self):
        self.ss = SecretSharing()
        self.shares = self.ss.split(b"recover-me", n=5, t=3)

    def test_empty_share_list(self):
        with self.assertRaises(RecoveryError):
            self.ss.recover([])

    def test_duplicate_share_ids(self):
        with self.assertRaises(RecoveryError):
            self.ss.recover([self.shares[0], self.shares[0], self.shares[1]])

    def test_mixed_thresholds(self):
        other = self.ss.split(b"recover-me", n=5, t=2)
        with self.assertRaises(RecoveryError):
            self.ss.recover([self.shares[0], self.shares[1], other[0]])

    def test_mixed_n(self):
        other = self.ss.split(b"recover-me", n=4, t=3)
        with self.assertRaises(RecoveryError):
            self.ss.recover([self.shares[0], self.shares[1], other[0]])

    def test_mixed_secret_lengths(self):
        other = self.ss.split(b"recover-me-too", n=5, t=3)
        with self.assertRaises(RecoveryError):
            self.ss.recover([self.shares[0], self.shares[1], other[0]])

    def test_non_share_records(self):
        with self.assertRaises(TypeError):
            self.ss.recover([self.shares[0], "not-a-share", self.shares[2]])

    def test_share_id_out_of_range(self):
        with self.assertRaises(BackupValidationError):
            BackupShare(share_id=9, words=(1,), secret_len=1, n=5, threshold=3)

    def test_share_word_out_of_field(self):
        with self.assertRaises(BackupValidationError):
            BackupShare(
                share_id=1,
                words=(FIELD_PRIME,),
                secret_len=1,
                n=5,
                threshold=3,
            )

    def test_share_words_not_tuple(self):
        with self.assertRaises(TypeError):
            BackupShare(
                share_id=1, words=[1], secret_len=1, n=5, threshold=3
            )

    def test_share_frozen(self):
        share = self.shares[0]
        with self.assertRaises(dataclasses.FrozenInstanceError):
            share.share_id = 99  # type: ignore[misc]

    def test_as_dict_shape(self):
        d = self.shares[0].as_dict()
        self.assertEqual(d["schema"], SECRET_SHARING_SCHEMA)
        self.assertEqual(d["share_id"], 1)
        self.assertEqual(d["n"], 5)
        self.assertEqual(d["threshold"], 3)
        self.assertEqual(d["field_prime"], FIELD_PRIME)
        self.assertEqual(len(d["words"]), len(self.shares[0].words))

    def test_error_hierarchy(self):
        self.assertTrue(issubclass(BackupValidationError, SecretSharingError))
        self.assertTrue(issubclass(RecoveryError, SecretSharingError))


class TestDigestAndAudit(unittest.TestCase):
    def setUp(self):
        self.ss = SecretSharing()
        self.key = b"digest-key"

    def test_share_digest_deterministic(self):
        a = self.ss.split(self.key, n=5, t=3)
        b = self.ss.split(self.key, n=5, t=3)
        self.assertEqual(self.ss.share_digest(a), self.ss.share_digest(b))

    def test_share_digest_distinguishes_secrets(self):
        a = self.ss.split(self.key, n=5, t=3)
        b = self.ss.split(b"other-key!!", n=5, t=3)
        self.assertNotEqual(self.ss.share_digest(a), self.ss.share_digest(b))

    def test_share_digest_prefix(self):
        shares = self.ss.split(self.key, n=5, t=3)
        self.assertTrue(self.ss.share_digest(shares).startswith("sha256:"))

    def test_share_digest_rejects_non_shares(self):
        with self.assertRaises(TypeError):
            self.ss.share_digest(["x"])

    def test_audit_event_shapes(self):
        ev = secret_sharing_audit_event(EVENT_SPLIT, 1, n=5, threshold=3)
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["module"], SECRET_SHARING_SCHEMA)
        self.assertEqual(ev["kind"], EVENT_SPLIT)
        self.assertEqual(ev["audit_seq"], 1)
        ev2 = secret_sharing_audit_event(EVENT_RECOVERED, 2)
        self.assertEqual(ev2["kind"], EVENT_RECOVERED)
        ev3 = secret_sharing_audit_event(EVENT_REJECTED, 3, reason="too-few")
        self.assertEqual(ev3["kind"], EVENT_REJECTED)
        self.assertEqual(ev3["reason"], "too-few")

    def test_audit_event_bad_kind(self):
        with self.assertRaises(ValueError):
            secret_sharing_audit_event("bogus", 1)

    def test_audit_event_bad_seq(self):
        with self.assertRaises(ValueError):
            secret_sharing_audit_event(EVENT_SPLIT, -1)
        with self.assertRaises(TypeError):
            secret_sharing_audit_event(EVENT_SPLIT, True)
        with self.assertRaises(TypeError):
            secret_sharing_audit_event(EVENT_SPLIT, "1")

    def test_main_self_check(self):
        import secret_sharing

        secret_sharing.main()


if __name__ == "__main__":
    unittest.main()

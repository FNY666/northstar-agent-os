"""Targeted tests for encryption_at_rest.py."""

import unittest

from encryption_at_rest import (
    EncryptionAtRest,
    StoreRecord,
    EncryptedBlock,
    RotationRecord,
    RevocationRecord,
    EncryptionAtRestError,
    BadInputError,
    UnknownStoreError,
    DuplicateStoreError,
    UnknownBlockError,
    AlreadyEncryptedError,
    IntegrityError,
    StoreRevokedError,
    SeqOrderError,
    encryption_at_rest_audit_event,
    __version__,
    __schema__,
)


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(__version__, "encryption-at-rest.v1")

    def test_schema_pin(self):
        self.assertEqual(__schema__, "northstar.encryption-at-rest.v1")


class TestCreateStore(unittest.TestCase):
    def test_happy_path(self):
        ear = EncryptionAtRest()
        rec = ear.create_store("vault", 1)
        self.assertEqual(rec.store_id, "vault")
        self.assertEqual(rec.generation, 1)
        self.assertEqual(rec.state, "active")
        self.assertEqual(rec.created_seq, 1)

    def test_duplicate_refused(self):
        ear = EncryptionAtRest()
        ear.create_store("vault", 1)
        with self.assertRaises(DuplicateStoreError):
            ear.create_store("vault", 2)

    def test_bad_inputs(self):
        ear = EncryptionAtRest()
        seq = 1
        for bad in ("", 123, None, b"vault"):
            with self.assertRaises(BadInputError):
                ear.create_store(bad, seq)  # type: ignore[arg-type]
            seq += 1  # failed mutations consume their seq
        with self.assertRaises(BadInputError):
            ear.create_store("vault", -1)
        with self.assertRaises(BadInputError):
            ear.create_store("vault", True)  # bool seq refused

    def test_unknown_store_lookup(self):
        ear = EncryptionAtRest()
        with self.assertRaises(UnknownStoreError):
            ear.store("nope")


class TestEncryptDecrypt(unittest.TestCase):
    def test_roundtrip(self):
        ear = EncryptionAtRest()
        ear.create_store("vault", 1)
        block = ear.encrypt("vault", "row-1", b"secret-bytes", 2)
        self.assertEqual(block.generation, 1)
        self.assertTrue(block.dek_pin.startswith("sha256:"))
        self.assertEqual(ear.decrypt("vault", "row-1", 3), b"secret-bytes")

    def test_empty_plaintext(self):
        ear = EncryptionAtRest()
        ear.create_store("vault", 1)
        ear.encrypt("vault", "row-1", b"", 2)
        self.assertEqual(ear.decrypt("vault", "row-1", 3), b"")

    def test_deterministic_across_instances(self):
        a = EncryptionAtRest()
        b = EncryptionAtRest()
        a.create_store("vault", 1)
        b.create_store("vault", 1)
        ba = a.encrypt("vault", "row-1", b"same", 2)
        bb = b.encrypt("vault", "row-1", b"same", 2)
        self.assertEqual(ba.ciphertext, bb.ciphertext)
        self.assertEqual(ba.tag, bb.tag)

    def test_encrypt_unknown_store(self):
        ear = EncryptionAtRest()
        with self.assertRaises(UnknownStoreError):
            ear.encrypt("nope", "row-1", b"x", 1)

    def test_duplicate_data_id_refused(self):
        ear = EncryptionAtRest()
        ear.create_store("vault", 1)
        ear.encrypt("vault", "row-1", b"a", 2)
        with self.assertRaises(AlreadyEncryptedError):
            ear.encrypt("vault", "row-1", b"b", 3)

    def test_decrypt_unknown_block(self):
        ear = EncryptionAtRest()
        ear.create_store("vault", 1)
        with self.assertRaises(UnknownBlockError):
            ear.decrypt("vault", "row-1", 2)

    def test_oversize_plaintext_refused(self):
        ear = EncryptionAtRest()
        ear.create_store("vault", 1)
        with self.assertRaises(BadInputError):
            ear.encrypt("vault", "row-1", b"x" * ((1 << 20) + 1), 2)

    def test_tampered_ciphertext_refused(self):
        ear = EncryptionAtRest()
        ear.create_store("vault", 1)
        block = ear.encrypt("vault", "row-1", b"secret", 2)
        tampered = EncryptedBlock(
            store_id=block.store_id, data_id=block.data_id,
            generation=block.generation, nonce=block.nonce,
            ciphertext=b"X" + block.ciphertext[1:], tag=block.tag,
            dek_pin=block.dek_pin, seq=3)
        ear._blocks[("vault", "row-1")] = tampered
        with self.assertRaises(IntegrityError):
            ear.decrypt("vault", "row-1", 4)

    def test_tampered_tag_refused(self):
        ear = EncryptionAtRest()
        ear.create_store("vault", 1)
        block = ear.encrypt("vault", "row-1", b"secret", 2)
        tampered = EncryptedBlock(
            store_id=block.store_id, data_id=block.data_id,
            generation=block.generation, nonce=block.nonce,
            ciphertext=block.ciphertext, tag=b"\x00" * 32,
            dek_pin=block.dek_pin, seq=3)
        ear._blocks[("vault", "row-1")] = tampered
        with self.assertRaises(IntegrityError):
            ear.decrypt("vault", "row-1", 4)

    def test_key_material_never_in_records(self):
        ear = EncryptionAtRest()
        ear.create_store("vault", 1)
        block = ear.encrypt("vault", "row-1", b"secret-bytes", 2)
        d = block.as_dict()
        self.assertNotIn(b"secret-bytes", str(d).encode())
        for ev in ear.audit_log():
            self.assertNotIn("secret-bytes", str(ev))


class TestRotate(unittest.TestCase):
    def test_rotation_advances_generation(self):
        ear = EncryptionAtRest()
        ear.create_store("vault", 1)
        rec = ear.rotate("vault", 2)
        self.assertEqual((rec.old_generation, rec.new_generation), (1, 2))
        self.assertEqual(ear.store("vault").generation, 2)

    def test_new_encrypts_use_current_generation(self):
        ear = EncryptionAtRest()
        ear.create_store("vault", 1)
        ear.encrypt("vault", "old", b"a", 2)
        ear.rotate("vault", 3)
        block = ear.encrypt("vault", "new", b"b", 4)
        self.assertEqual(block.generation, 2)

    def test_old_blocks_still_decrypt(self):
        ear = EncryptionAtRest()
        ear.create_store("vault", 1)
        ear.encrypt("vault", "old", b"pre-rotation", 2)
        ear.rotate("vault", 3)
        ear.rotate("vault", 4)
        self.assertEqual(ear.decrypt("vault", "old", 5), b"pre-rotation")

    def test_rotate_unknown_store(self):
        ear = EncryptionAtRest()
        with self.assertRaises(UnknownStoreError):
            ear.rotate("nope", 1)


class TestReencrypt(unittest.TestCase):
    def test_migrates_to_current_generation(self):
        ear = EncryptionAtRest()
        ear.create_store("vault", 1)
        ear.encrypt("vault", "row-1", b"migrate-me", 2)
        ear.rotate("vault", 3)
        new = ear.reencrypt("vault", "row-1", 4)
        self.assertEqual(new.generation, 2)
        self.assertEqual(ear.decrypt("vault", "row-1", 5), b"migrate-me")

    def test_reencrypt_unknown_block(self):
        ear = EncryptionAtRest()
        ear.create_store("vault", 1)
        with self.assertRaises(UnknownBlockError):
            ear.reencrypt("vault", "row-1", 2)

    def test_reencrypt_already_current(self):
        ear = EncryptionAtRest()
        ear.create_store("vault", 1)
        ear.encrypt("vault", "row-1", b"x", 2)
        new = ear.reencrypt("vault", "row-1", 3)
        self.assertEqual(new.generation, 1)
        self.assertEqual(ear.decrypt("vault", "row-1", 4), b"x")


class TestRevoke(unittest.TestCase):
    def test_revoke_is_terminal(self):
        ear = EncryptionAtRest()
        ear.create_store("vault", 1)
        ear.encrypt("vault", "row-1", b"x", 2)
        rec = ear.revoke("vault", 3)
        self.assertEqual(rec.store_id, "vault")
        self.assertEqual(ear.store("vault").state, "revoked")
        with self.assertRaises(StoreRevokedError):
            ear.encrypt("vault", "row-2", b"y", 4)
        with self.assertRaises(StoreRevokedError):
            ear.decrypt("vault", "row-1", 5)
        with self.assertRaises(StoreRevokedError):
            ear.rotate("vault", 6)
        with self.assertRaises(StoreRevokedError):
            ear.reencrypt("vault", "row-1", 7)


class TestSeqDiscipline(unittest.TestCase):
    def test_rewind_refused(self):
        ear = EncryptionAtRest()
        ear.create_store("vault", 5)
        with self.assertRaises(SeqOrderError):
            ear.rotate("vault", 5)
        with self.assertRaises(SeqOrderError):
            ear.rotate("vault", 2)

    def test_failed_mutation_consumes_seq(self):
        ear = EncryptionAtRest()
        ear.create_store("vault", 1)
        with self.assertRaises(UnknownStoreError):
            ear.encrypt("nope", "row-1", b"x", 2)
        # seq 2 is consumed; next mutation must use 3+
        with self.assertRaises(SeqOrderError):
            ear.encrypt("vault", "row-1", b"x", 2)
        block = ear.encrypt("vault", "row-1", b"x", 3)
        self.assertEqual(block.seq, 3)


class TestViews(unittest.TestCase):
    def test_store_and_block_ids(self):
        ear = EncryptionAtRest()
        ear.create_store("b-store", 1)
        ear.create_store("a-store", 2)
        self.assertEqual(ear.store_ids(), ["a-store", "b-store"])
        ear.encrypt("a-store", "row-2", b"y", 3)
        ear.encrypt("a-store", "row-1", b"x", 4)
        self.assertEqual(ear.block_ids("a-store"), ["row-1", "row-2"])
        self.assertEqual(ear.block_ids("b-store"), [])

    def test_stats(self):
        ear = EncryptionAtRest()
        ear.create_store("vault", 1)
        ear.encrypt("vault", "row-1", b"x", 2)
        ear.revoke("vault", 3)
        stats = ear.stats()
        self.assertEqual(stats, {"stores": 1, "blocks": 1, "revoked": 1})


class TestAudit(unittest.TestCase):
    def test_event_shapes(self):
        ev = encryption_at_rest_audit_event("encrypted", 7,
                                            store_id="vault", data_id="row-1")
        self.assertEqual(ev["event"], "encryption-at-rest")
        self.assertEqual(ev["kind"], "encrypted")
        self.assertEqual(ev["audit_seq"], 7)
        self.assertEqual(ev["schema"], "audit.ndjson/1")

    def test_bad_kind_refused(self):
        with self.assertRaises(ValueError):
            encryption_at_rest_audit_event("nonsense", 0)

    def test_bad_seq_refused(self):
        with self.assertRaises(ValueError):
            encryption_at_rest_audit_event("encrypted", -1)
        with self.assertRaises(ValueError):
            encryption_at_rest_audit_event("encrypted", True)

    def test_all_kinds(self):
        for kind in ("store-created", "store-rotated", "store-revoked",
                     "encrypted", "reencrypted", "decrypted", "rejected"):
            ev = encryption_at_rest_audit_event(kind, 0)
            self.assertEqual(ev["kind"], kind)

    def test_plaintext_banned_from_audit(self):
        ear = EncryptionAtRest()
        ear.create_store("vault", 1)
        ear.encrypt("vault", "row-1", b"top-secret-value", 2)
        blob = str(ear.audit_log())
        self.assertNotIn("top-secret-value", blob)


class TestConcurrency(unittest.TestCase):
    def test_thread_smoke(self):
        import threading
        ear = EncryptionAtRest()
        ear.create_store("vault", 1)
        errors = []

        def work(i):
            try:
                ear.encrypt("vault", f"row-{i}", f"v{i}".encode(), 2 + i)
            except EncryptionAtRestError as e:  # noqa: BLE001
                errors.append(e)

        threads = [threading.Thread(target=work, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(ear.block_ids("vault")), 8)


class TestStdlibOnly(unittest.TestCase):
    def test_no_third_party_imports(self):
        import ast
        import pathlib
        src = pathlib.Path(__file__).resolve().parent.parent / \
            "encryption_at_rest.py"
        tree = ast.parse(src.read_text())
        allowed = {"__future__", "hashlib", "hmac", "threading",
                   "dataclasses", "typing"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], allowed,
                                  alias.name)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed,
                              node.module)


class TestMain(unittest.TestCase):
    def test_main_self_check(self):
        import encryption_at_rest
        encryption_at_rest.main()


if __name__ == "__main__":
    unittest.main()

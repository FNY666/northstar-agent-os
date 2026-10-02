import unittest

from evidence_chain import EvidenceChain, verify_chain
from evidence_contract import EvidenceEntry, EvidenceRef


class EvidenceChainTests(unittest.TestCase):
    def setUp(self):
        self.chain = EvidenceChain("run-001")

    def append_two(self):
        first = self.chain.append(
            source="host",
            kind="authorization.verified",
            occurred_at=1_800_000_000,
            subject={"actor_id": "actor-1", "policy_revision": "policy-9"},
            source_id="grant-event-1",
        )
        second = self.chain.append(
            source="durable",
            kind="step.finished",
            occurred_at=1_800_000_001,
            subject=b"canonical source bytes",
            refs=(EvidenceRef("authorization", "grant-1", first.subject_digest),),
            source_id="event-2",
        )
        return first, second

    def test_entries_form_a_contiguous_previous_digest_chain(self):
        first, second = self.append_two()
        self.assertEqual(first.sequence, 1)
        self.assertIsNone(first.previous_entry_digest)
        self.assertEqual(second.sequence, 2)
        self.assertEqual(second.previous_entry_digest, first.entry_digest)
        self.assertEqual(self.chain.head_digest, second.entry_digest)
        report = self.chain.verify()
        self.assertTrue(report.ok, report.errors)
        self.assertEqual(report.entries_checked, 2)
        self.assertEqual(report.run_id, "run-001")
        self.assertEqual(report.head_digest, second.entry_digest)

    def test_canonical_entries_verify_after_json_round_trip(self):
        self.append_two()
        rows = [entry.to_dict() for entry in self.chain.entries]
        report = verify_chain(rows, expected_run_id="run-001")
        self.assertTrue(report.ok, report.errors)
        self.assertEqual(report.head_digest, self.chain.head_digest)

    def test_frozen_entry_mutation_is_revalidated_and_chain_returns_copies(self):
        returned = self.chain.append(
            source="runtime",
            kind="session.started",
            occurred_at=1_800_000_000,
            subject={"session_id": "s1"},
            source_id="start-1",
        )
        object.__setattr__(returned, "kind", "session.ended")
        report = verify_chain([returned], expected_run_id="run-001")
        self.assertFalse(report.ok)
        self.assertIn("entry_digest", " ".join(report.errors))
        with self.assertRaisesRegex(ValueError, "entry_digest"):
            EvidenceChain("run-001", entries=[returned])

        visible = self.chain.entries[0]
        object.__setattr__(visible, "kind", "session.ended")
        self.assertTrue(self.chain.verify().ok)

    def test_wrong_expected_run_id_is_reported(self):
        self.append_two()
        report = verify_chain(self.chain.entries, expected_run_id="another-run")
        self.assertFalse(report.ok)
        self.assertIn("run_id does not match", " ".join(report.errors))

    def test_reordered_or_removed_entry_breaks_sequence_and_link(self):
        first, second = self.append_two()
        reordered = verify_chain([second, first], expected_run_id="run-001")
        self.assertFalse(reordered.ok)
        self.assertTrue(any("sequence" in error for error in reordered.errors))
        self.assertTrue(any("previous_entry_digest" in error for error in reordered.errors))
        removed = verify_chain([second], expected_run_id="run-001")
        self.assertFalse(removed.ok)
        self.assertTrue(any("sequence" in error for error in removed.errors))
        self.assertTrue(any("previous_entry_digest" in error for error in removed.errors))

    def test_malformed_row_is_not_silently_skipped(self):
        first, _ = self.append_two()
        report = verify_chain([first.to_dict(), {"sequence": 2}], expected_run_id="run-001")
        self.assertFalse(report.ok)
        self.assertEqual(report.entries_checked, 1)
        self.assertIn("entry #2", " ".join(report.errors))

    def test_chain_append_rejects_other_run_or_invalid_extension(self):
        first, _ = self.append_two()
        other = EvidenceEntry.create(
            run_id="run-002",
            sequence=2,
            source="runtime",
            kind="session.ended",
            occurred_at=1_800_000_002,
            subject_digest=first.subject_digest,
            previous_entry_digest=first.entry_digest,
        )
        with self.assertRaisesRegex(ValueError, "run_id"):
            self.chain.append_entry(other)
        broken = EvidenceEntry.create(
            run_id="run-001",
            sequence=4,
            source="runtime",
            kind="session.ended",
            occurred_at=1_800_000_002,
            subject_digest=first.subject_digest,
            previous_entry_digest=first.entry_digest,
        )
        with self.assertRaisesRegex(ValueError, "sequence"):
            self.chain.append_entry(broken)
        wrong_link = EvidenceEntry.create(
            run_id="run-001",
            sequence=3,
            source="runtime",
            kind="session.ended",
            occurred_at=1_800_000_002,
            subject_digest=first.subject_digest,
            previous_entry_digest=first.entry_digest,
        )
        with self.assertRaisesRegex(ValueError, "previous_entry_digest"):
            self.chain.append_entry(wrong_link)

    def test_source_id_retry_is_idempotent_but_conflicts_are_rejected(self):
        first = self.chain.append(
            source="runtime",
            kind="session.started",
            occurred_at=1_800_000_000,
            subject={"session_id": "s1"},
            source_id="start-1",
        )
        retry = self.chain.append(
            source="runtime",
            kind="session.started",
            occurred_at=1_800_000_000,
            subject={"session_id": "s1"},
            source_id="start-1",
        )
        self.assertEqual(retry, first)
        self.assertIsNot(retry, first)
        self.assertEqual(len(self.chain.entries), 1)
        with self.assertRaisesRegex(ValueError, "conflicts"):
            self.chain.append(
                source="runtime",
                kind="session.started",
                occurred_at=1_800_000_000,
                subject={"session_id": "different"},
                source_id="start-1",
            )

    def test_idempotent_retry_does_not_coerce_bool_timestamp_to_int(self):
        self.chain.append(
            source="runtime",
            kind="session.started",
            occurred_at=1,
            subject={"session_id": "s1"},
            source_id="start-1",
        )
        with self.assertRaisesRegex(ValueError, "occurred_at must be an integer"):
            self.chain.append(
                source="runtime",
                kind="session.started",
                occurred_at=True,
                subject={"session_id": "s1"},
                source_id="start-1",
            )

    def test_reversed_refs_do_not_break_idempotent_retry(self):
        ref_a = EvidenceRef("artifact", "a", "sha256:" + "a" * 64)
        ref_b = EvidenceRef("session", "b", "sha256:" + "b" * 64)
        first = self.chain.append(
            source="runtime", kind="session.started", occurred_at=1_800_000_000,
            subject={"session_id": "s1"}, refs=(ref_a, ref_b), source_id="start-refs",
        )
        retry = self.chain.append(
            source="runtime", kind="session.started", occurred_at=1_800_000_000,
            subject={"session_id": "s1"}, refs=(ref_b, ref_a), source_id="start-refs",
        )
        self.assertEqual(retry, first)
        self.assertEqual(len(self.chain.entries), 1)

    def test_duplicate_source_ids_in_imported_chain_are_rejected(self):
        first, second = self.append_two()
        duplicate = EvidenceEntry.create(
            run_id="run-001",
            sequence=3,
            source="runtime",
            kind="session.ended",
            occurred_at=1_800_000_002,
            subject_digest=first.subject_digest,
            previous_entry_digest=second.entry_digest,
            source_id="grant-event-1",
        )
        report = verify_chain([first, second, duplicate])
        self.assertFalse(report.ok)
        self.assertTrue(any("duplicate source_id" in error for error in report.errors))

    def test_empty_chain_is_structurally_valid_but_has_no_head(self):
        report = verify_chain([], expected_run_id="run-001")
        self.assertTrue(report.ok)
        self.assertIsNone(report.head_digest)
        self.assertEqual(report.entries_checked, 0)


if __name__ == "__main__":
    unittest.main()

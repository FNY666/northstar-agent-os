import unittest

from evidence_contract import (
    EVIDENCE_ENTRY_SCHEMA_VERSION,
    EvidenceEntry,
    EvidenceRef,
    canonical_json,
    digest_subject,
)


class CanonicalJsonTests(unittest.TestCase):
    def test_mapping_key_order_does_not_change_bytes_or_digest(self):
        left = {"outer": {"z": 1, "a": True}, "items": ["é", 2]}
        right = {"items": ["é", 2], "outer": {"a": True, "z": 1}}
        self.assertEqual(canonical_json(left), canonical_json(right))
        self.assertEqual(digest_subject(left), digest_subject(right))
        self.assertEqual(canonical_json(left), '{"items":["é",2],"outer":{"a":true,"z":1}}'.encode())

    def test_subject_bytes_are_hashed_exactly_and_domain_separated(self):
        self.assertEqual(digest_subject(b"same bytes"), digest_subject(b"same bytes"))
        self.assertNotEqual(digest_subject(b"same bytes"), digest_subject({"value": "same bytes"}))
        self.assertNotEqual(digest_subject(b"same bytes"), digest_subject(b"same bytes\n"))

    def test_values_outside_the_interoperable_json_subset_are_rejected(self):
        for value in (
            {"bad": float("nan")},
            {"bad": float("inf")},
            {"bad": 1.25},
            {"bad": 1 << 53},
            {"é": "non-ascii key"},
            {1: "non-string key"},
            {"set": {1, 2}},
        ):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    digest_subject(value)

    def test_oversized_subject_is_rejected(self):
        from evidence_contract import MAX_SUBJECT_BYTES

        with self.assertRaisesRegex(ValueError, "exceeds"):
            digest_subject(b"x" * (MAX_SUBJECT_BYTES + 1))


class EvidenceRefTests(unittest.TestCase):
    def test_round_trip(self):
        ref = EvidenceRef("session", "ns-001", "sha256:" + "a" * 64)
        self.assertEqual(EvidenceRef.from_dict(ref.to_dict()), ref)

    def test_rejects_unknown_fields_and_unsafe_ids(self):
        valid = {"kind": "artifact", "ref_id": "output-1", "digest": "sha256:" + "0" * 64}
        with self.assertRaisesRegex(ValueError, "unknown fields"):
            EvidenceRef.from_dict({**valid, "path": "../../secret"})
        with self.assertRaisesRegex(ValueError, "must not contain"):
            EvidenceRef("artifact", "../secret", "sha256:" + "0" * 64)
        with self.assertRaisesRegex(ValueError, "lowercase identifier"):
            EvidenceRef("Artifact", "output-1", "sha256:" + "0" * 64)


class EvidenceEntryTests(unittest.TestCase):
    def setUp(self):
        self.entry = EvidenceEntry.create(
            run_id="run-001",
            sequence=1,
            source="runtime",
            kind="session.started",
            occurred_at=1_800_000_000,
            subject_digest=digest_subject({"session_id": "session-001"}),
            refs=(),
            previous_entry_digest=None,
            source_id="source-001",
        )

    def test_created_entry_round_trips_with_canonical_digest(self):
        self.assertEqual(self.entry.schema_version, EVIDENCE_ENTRY_SCHEMA_VERSION)
        loaded = EvidenceEntry.from_dict(self.entry.to_dict())
        self.assertEqual(loaded, self.entry)
        self.assertEqual(loaded.canonical_json(), canonical_json(loaded.to_dict()))

    def test_tampered_body_or_digest_is_rejected(self):
        changed = self.entry.to_dict()
        changed["kind"] = "session.ended"
        with self.assertRaisesRegex(ValueError, "entry_digest"):
            EvidenceEntry.from_dict(changed)
        changed = self.entry.to_dict()
        changed["entry_digest"] = "sha256:" + "f" * 64
        with self.assertRaisesRegex(ValueError, "entry_digest"):
            EvidenceEntry.from_dict(changed)

    def test_unknown_and_missing_fields_fail_closed(self):
        unknown = {**self.entry.to_dict(), "unreviewed": True}
        with self.assertRaisesRegex(ValueError, "unknown fields"):
            EvidenceEntry.from_dict(unknown)
        missing = self.entry.to_dict()
        del missing["source"]
        with self.assertRaisesRegex(ValueError, "missing fields"):
            EvidenceEntry.from_dict(missing)

    def test_sequence_and_timestamp_reject_bool(self):
        for field in ("sequence", "occurred_at"):
            with self.subTest(field=field):
                value = self.entry.to_dict()
                value[field] = True
                # The entry digest must match first, so validate the primitive directly
                # by attempting to construct with a freshly recomputed digest.
                value[field] = 1
                value["entry_digest"] = EvidenceEntry.create(
                    run_id=value["run_id"],
                    sequence=value["sequence"],
                    source=value["source"],
                    kind=value["kind"],
                    occurred_at=value["occurred_at"],
                    subject_digest=value["subject_digest"],
                    refs=tuple(EvidenceRef.from_dict(ref) for ref in value["refs"]),
                    previous_entry_digest=value["previous_entry_digest"],
                    source_id=value["source_id"],
                ).entry_digest
                value[field] = True
                with self.assertRaisesRegex(ValueError, "must be an integer"):
                    EvidenceEntry.from_dict(value)

    def test_sequence_greater_than_one_requires_previous_digest(self):
        with self.assertRaisesRegex(ValueError, "previous_entry_digest"):
            EvidenceEntry.create(
                run_id="run-001",
                sequence=2,
                source="runtime",
                kind="session.started",
                occurred_at=1_800_000_000,
                subject_digest=digest_subject({}),
            )

    def test_duplicate_refs_are_rejected(self):
        ref = EvidenceRef("session", "s1", "sha256:" + "a" * 64)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            EvidenceEntry.create(
                run_id="run-001",
                sequence=1,
                source="runtime",
                kind="session.started",
                occurred_at=1_800_000_000,
                subject_digest=digest_subject({}),
                refs=(ref, ref),
            )

    def test_refs_are_canonicalized_and_unsorted_wire_data_is_rejected(self):
        ref_a = EvidenceRef("artifact", "a", "sha256:" + "a" * 64)
        ref_b = EvidenceRef("session", "b", "sha256:" + "b" * 64)
        reverse = EvidenceEntry.create(
            run_id="run-001", sequence=1, source="runtime", kind="session.started",
            occurred_at=1_800_000_000, subject_digest=digest_subject({}), refs=(ref_b, ref_a),
        )
        ordered = EvidenceEntry.create(
            run_id="run-001", sequence=1, source="runtime", kind="session.started",
            occurred_at=1_800_000_000, subject_digest=digest_subject({}), refs=(ref_a, ref_b),
        )
        self.assertEqual(reverse, ordered)
        self.assertEqual(reverse.refs, (ref_a, ref_b))
        wire = ordered.to_dict()
        wire["refs"].reverse()
        with self.assertRaisesRegex(ValueError, "refs must be sorted"):
            EvidenceEntry.from_dict(wire)

    def test_factory_requires_immutable_ref_tuple(self):
        with self.assertRaisesRegex(ValueError, "refs must be a tuple"):
            EvidenceEntry.create(
                run_id="run-001",
                sequence=1,
                source="runtime",
                kind="session.started",
                occurred_at=1_800_000_000,
                subject_digest=digest_subject({}),
                refs=[],
            )


if __name__ == "__main__":
    unittest.main()

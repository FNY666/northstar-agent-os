"""Tests for append-only preservation of contradictory admission witnesses."""
from __future__ import annotations

import json
import multiprocessing
import shutil
import tempfile
import unittest
from pathlib import Path

from admission_witness import AdmissionWitness
from evidence_conflict_ledger import (
    ConflictLedgerError,
    ConflictLedgerVerdict,
    ConflictObservation,
    EvidenceConflictLedger,
)
from test_admission_witness import WitnessFixture


def alternate_witness(witness, *, evidence_root=None, claimed_evidence_state=None,
                      claim_digest=None, package_digest=None):
    unsigned = AdmissionWitness(
        witness.schema_version,
        witness.policy,
        witness.policy_digest,
        witness.package_digest if package_digest is None else package_digest,
        witness.claim_digest if claim_digest is None else claim_digest,
        witness.evidence_root if evidence_root is None else evidence_root,
        witness.claimed_evidence_state if claimed_evidence_state is None else claimed_evidence_state,
        witness.admission_state,
        witness.reasons,
        witness.unverified,
        "",
    )
    return AdmissionWitness(
        unsigned.schema_version,
        unsigned.policy,
        unsigned.policy_digest,
        unsigned.package_digest,
        unsigned.claim_digest,
        unsigned.evidence_root,
        unsigned.claimed_evidence_state,
        unsigned.admission_state,
        unsigned.reasons,
        unsigned.unverified,
        unsigned.computed_digest,
    )


def record_worker(root, left, right, result_path):
    try:
        ledger = EvidenceConflictLedger(root)
        observation = ledger.record_conflict(
            AdmissionWitness.from_dict(left), AdmissionWitness.from_dict(right)
        )
        result = ("ok", observation.conflict_id)
    except Exception as exc:
        result = ("error", type(exc).__name__, str(exc))
    Path(result_path).write_text(json.dumps(result), encoding="utf-8")


class ConflictLedgerTests(WitnessFixture):
    def setUp(self):
        super().setUp()
        self.ledger_root = Path(self.root) / "conflicts"
        self.ledger = EvidenceConflictLedger(self.ledger_root)
        self.left = self.witness()
        self.right_root = alternate_witness(
            self.left,
            evidence_root="sha256:" + "f" * 64,
            package_digest="sha256:" + "e" * 64,
        )

    def test_same_claim_different_root_is_persisted_as_conflict(self):
        observation = self.ledger.record_conflict(self.left, self.right_root)
        self.assertIsInstance(observation, ConflictObservation)
        self.assertEqual(observation.claim_digest, self.left.claim_digest)
        self.assertIn("evidence_root_mismatch", observation.reasons)
        self.assertEqual(observation.sequence, 1)
        self.assertEqual(observation.previous_digest, "sha256:" + "0" * 64)
        self.assertLessEqual(observation.witness_a_digest, observation.witness_b_digest)

    def test_same_claim_different_claimed_state_is_persisted_as_conflict(self):
        right = alternate_witness(
            self.left,
            claimed_evidence_state="verified-unpinned",
            package_digest="sha256:" + "d" * 64,
        )
        observation = self.ledger.record_conflict(self.left, right)
        self.assertIn("claimed_evidence_state_mismatch", observation.reasons)

    def test_reversed_pair_is_idempotent_not_a_winner_selection(self):
        first = self.ledger.record_conflict(self.left, self.right_root)
        second = self.ledger.record_conflict(self.right_root, self.left)
        self.assertEqual(first, second)
        self.assertEqual(len(self.ledger.records), 1)
        self.assertEqual(first.witness_a_digest, min(self.left.witness_digest, self.right_root.witness_digest))

    def test_same_evidence_is_not_a_conflict(self):
        with self.assertRaises(ConflictLedgerError):
            self.ledger.record_conflict(self.left, self.left)

    def test_different_claims_are_not_a_conflict(self):
        other = alternate_witness(
            self.left,
            claim_digest="sha256:" + "a" * 64,
            package_digest="sha256:" + "b" * 64,
        )
        with self.assertRaises(ConflictLedgerError):
            self.ledger.record_conflict(self.left, other)

    def test_restart_recovers_conflicts(self):
        first = self.ledger.record_conflict(self.left, self.right_root)
        restored = EvidenceConflictLedger(self.ledger_root)
        self.assertEqual(restored.records, [first])
        self.assertEqual(restored.verify().state, "replayable")

    def test_truncated_final_line_is_ignored(self):
        first = self.ledger.record_conflict(self.left, self.right_root)
        with (self.ledger_root / "conflicts.jsonl").open("ab") as handle:
            handle.write(b'{"schema_version":"northstar.evidence-conflict-ledger.v1"')
        restored = EvidenceConflictLedger(self.ledger_root)
        self.assertEqual(restored.records, [first])
        self.assertEqual(restored.verify().state, "replayable")

    def test_complete_malformed_tampered_and_missing_history_fail_closed(self):
        self.ledger.record_conflict(self.left, self.right_root)
        path = self.ledger_root / "conflicts.jsonl"
        with path.open("ab") as handle:
            handle.write(b'{"not":"a conflict record"}\n')
        restored = EvidenceConflictLedger(self.ledger_root)
        self.assertEqual(restored.verify().state, "unverifiable")
        with self.assertRaises(ConflictLedgerError):
            restored.record_conflict(self.left, self.right_root)

        clean_root = Path(self.root) / "missing"
        clean = EvidenceConflictLedger(clean_root)
        clean.record_conflict(self.left, self.right_root)
        (clean_root / "conflicts.jsonl").unlink()
        self.assertEqual(EvidenceConflictLedger(clean_root).verify().state, "unverifiable")

    def test_tampering_and_reordering_fail_closed(self):
        first = self.ledger.record_conflict(self.left, self.right_root)
        state_conflict = alternate_witness(
            self.left,
            claimed_evidence_state="verified-unpinned",
            package_digest="sha256:" + "d" * 64,
        )
        self.ledger.record_conflict(self.left, state_conflict)
        path = self.ledger_root / "conflicts.jsonl"
        lines = path.read_text(encoding="utf-8").splitlines()
        value = json.loads(lines[0])
        value["claim_digest"] = "sha256:" + "1" * 64
        lines[0] = json.dumps(value, sort_keys=True, separators=(",", ":"))
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.assertEqual(EvidenceConflictLedger(self.ledger_root).verify().state, "unverifiable")

        reordered_root = Path(self.root) / "reordered"
        reordered = EvidenceConflictLedger(reordered_root)
        reordered.record_conflict(self.left, self.right_root)
        reordered.record_conflict(self.left, state_conflict)
        lines = (reordered_root / "conflicts.jsonl").read_text(encoding="utf-8").splitlines()
        (reordered_root / "conflicts.jsonl").write_text("\n".join(reversed(lines)) + "\n", encoding="utf-8")
        self.assertEqual(EvidenceConflictLedger(reordered_root).verify().state, "unverifiable")

    def test_persisted_ledger_has_no_raw_event_prompt_or_secret(self):
        self.ledger.record_conflict(self.left, self.right_root)
        raw = (self.ledger_root / "conflicts.jsonl").read_text(encoding="utf-8")
        for forbidden in ("event_id", "prompt", "raw_output", "secret", "historical-key-material"):
            self.assertNotIn(forbidden, raw)

    def test_same_host_concurrent_duplicate_recording_writes_once(self):
        root = Path(self.root) / "concurrent"
        context = multiprocessing.get_context("fork")
        paths = [root / ("result-%d.json" % number) for number in range(2)]
        processes = [context.Process(
            target=record_worker,
            args=(str(root), self.left.to_dict(), self.right_root.to_dict(), str(path)),
        ) for path in paths]
        for process in processes:
            process.start()
        for process in processes:
            process.join(10)
        results = [json.loads(path.read_text(encoding="utf-8")) for path in paths]
        self.assertEqual(sum(result[0] == "ok" for result in results), 2)
        self.assertTrue(all(not process.is_alive() for process in processes))
        ledger = EvidenceConflictLedger(root)
        self.assertEqual(len(ledger.records), 1)
        self.assertEqual(ledger.verify().state, "replayable")


if __name__ == "__main__":
    unittest.main()

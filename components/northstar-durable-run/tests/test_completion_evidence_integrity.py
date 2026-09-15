"""Fault injection for the archived evidence journal's hash chain."""
from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

import completion_batch_replay as batch
from completion_batch_replay import default_context, load_spec
from completion_replay import _evidence_status, verify_evidence_chain

ROOT = Path(__file__).resolve().parent.parent
RUN = "2026-09-11-action-failure-recovery"
EVIDENCE = "evidence/round-2.evidence.jsonl"


def _load(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _dump(path, events):
    text = "\n".join(
        json.dumps(event, sort_keys=True, separators=(",", ":")) for event in events
    )
    path.write_text(text + "\n", encoding="utf-8")


def _archived_journals():
    return sorted(ARCHIVE_ROOT.glob("*/evidence/*.evidence.jsonl")) + sorted(
        ARCHIVE_ROOT.glob("*/evidence/*/*.evidence.jsonl")
    )


class EvidenceChainTest(unittest.TestCase):
    def test_every_archived_journal_verifies_intact(self):
        journals = _archived_journals()
        self.assertGreaterEqual(len(journals), 10)
        for path in journals:
            with self.subTest(journal=str(path.relative_to(ARCHIVE_ROOT))):
                self.assertIsNone(verify_evidence_chain(_load(path)))

    def test_partial_last_line_is_rejected(self):
        # A process killed mid-append leaves bytes that cannot be parsed, which
        # is a different failure from a cleanly shortened journal.
        path = _archived_journals()[0]
        with tempfile.TemporaryDirectory() as temporary:
            torn = Path(temporary) / "torn.evidence.jsonl"
            torn.write_bytes(path.read_bytes()[:-40])
            self.assertEqual(_evidence_status(torn), "")

    def test_dropping_the_final_event_leaves_a_valid_shorter_chain(self):
        # Honest boundary: the chain alone cannot prove nothing was appended to
        # an earlier point in history, only that what remains is self-consistent.
        path = _archived_journals()[0]
        events = _load(path)
        self.assertIsNone(verify_evidence_chain(events[:-1]))
        self.assertEqual(_evidence_status(path), "finished")

    def test_deleted_middle_event_is_rejected(self):
        path = _archived_journals()[0]
        events = _load(path)
        del events[2]
        self.assertEqual(verify_evidence_chain(events), "evidence_sequence_gap")

    def test_edited_event_content_is_rejected(self):
        path = _archived_journals()[0]
        events = _load(path)
        events[2]["injected_field"] = "x"
        self.assertEqual(verify_evidence_chain(events), "evidence_digest_mismatch")

    def test_inserted_duplicate_is_rejected_even_when_renumbered(self):
        path = _archived_journals()[0]
        events = _load(path)
        events.insert(2, dict(events[2]))
        for index, event in enumerate(events, start=1):
            event["sequence"] = index
        self.assertEqual(verify_evidence_chain(events), "evidence_chain_broken")

    def test_missing_chain_fields_are_rejected(self):
        path = _archived_journals()[0]
        events = _load(path)
        events[0].pop("event_digest")
        self.assertEqual(verify_evidence_chain(events), "evidence_digest_mismatch")


def _rechain(events):
    """Rebuild a journal so every digest and link is self-consistent."""
    previous = None
    rebuilt = []
    for index, event in enumerate(events, start=1):
        body = {key: value for key, value in event.items() if key != "event_digest"}
        body["sequence"] = index
        body["prev_event_digest"] = previous
        form = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        digest = "sha256:" + hashlib.sha256(form.encode("utf-8")).hexdigest()
        body["event_digest"] = digest
        previous = digest
        rebuilt.append(body)
    return rebuilt


def _edit(events, index, key, value):
    copy = json.loads(json.dumps(events))
    copy[index][key] = value
    return copy


ARCHIVE_ROOT = Path("/var/minis/shared/northstar-live-runs")
SPEC = Path(__file__).resolve().parents[1] / "replay" / "archive-replay-spec.json"
EVALUATOR = Path(__file__).resolve().parents[1] / "completion_contract_v2.py"
RECOVERY_RUN = "2026-09-11-action-failure-recovery"
RECOVERY_TASK = "live-transient-write-recovery-v1"


class EvidenceFaultInjectionTest(unittest.TestCase):
    def _outcome_for(self, root, task_id=RECOVERY_TASK):
        context = replace(default_context(root, EVALUATOR), archive_root=root)
        for outcome in batch.replay_archive(context, load_spec(SPEC), modes=("digest",)):
            if outcome.task_id == task_id:
                return outcome.verdict
        raise AssertionError("task was not replayed")

    def _tampered_run(self, temporary, mutate):
        root = Path(temporary) / "archive"
        shutil.copytree(ARCHIVE_ROOT / RECOVERY_RUN, root / RECOVERY_RUN)
        evidence = root / RECOVERY_RUN / "evidence" / "round-2.evidence.jsonl"
        _dump(evidence, mutate(_load(evidence)))
        return root

    def test_untampered_archive_still_verifies(self):
        self.assertEqual(self._outcome_for(ARCHIVE_ROOT), "verified")

    def test_edited_middle_event_turns_verified_into_unknown(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self._tampered_run(
                temporary, lambda events: _edit(events, 2, "injected_field", "x")
            )
            self.assertEqual(self._outcome_for(root), "unknown")

    def test_dropped_terminal_event_turns_verified_into_unknown(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self._tampered_run(temporary, lambda events: events[:-1])
            self.assertEqual(self._outcome_for(root), "unknown")

    def test_deleted_middle_event_turns_verified_into_unknown(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self._tampered_run(temporary, lambda events: events[:2] + events[3:])
            self.assertEqual(self._outcome_for(root), "unknown")

    def test_full_rewrite_is_undetectable_without_external_anchor(self):
        # Honest boundary: an actor who rewrites the file and recomputes the
        # whole chain produces a journal that is internally consistent, so the
        # chain alone cannot prove the contents were never rewritten. Detecting
        # that needs an anchor held outside the journal.
        events = _load(ARCHIVE_ROOT / RECOVERY_RUN / "evidence" / "round-2.evidence.jsonl")
        events[2]["injected_field"] = "x"
        self.assertIsNone(verify_evidence_chain(_rechain(events)))

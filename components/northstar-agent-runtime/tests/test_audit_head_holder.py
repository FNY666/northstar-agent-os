"""Independent audit-head holder: second holder, sealed head, tail check.

Moltbook B173 (audit-head independence slice).  The gap this closes: the
reader's head lived nowhere outside the writer's domain, so a shortened
chain read clean to every reader that only ever saw the shortened chain.

What these tests pin:

* (a) a record is not sealed without an anchor receipt (C15,
  anchor-before-acknowledge), and an anchor for a *different* head cannot
  seal this one;
* (b) a shortened chain is caught by the tail-sampling check against the
  independent head (C51);
* (c) a re-minted chain with a new head is reported as a mismatch on
  fresh start (C46/48);
* (d) the seal commits to the observed seq range ``[1..N]`` (C21).
"""

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ahh = _load("audit_head_holder")

HEAD_A = "sha256:" + "aa" * 32
HEAD_B = "sha256:" + "bb" * 32
HEAD_C = "sha256:" + "cc" * 32
GENESIS = "sha256:" + "dd" * 32


def _pin(head=HEAD_A, seq=3, records=3, first=1, last=None, prev=""):
    if last is None:
        last = seq
    return ahh.HeadPin(
        head_hash=head,
        seq=seq,
        records_sealed=records,
        genesis=GENESIS,
        seq_first=first,
        seq_last=last,
        prev_head=prev,
    )


def _receipt(pin=None, independent=True, anchor_id="a1", head=None, records=None, rng=None):
    """A receipt that commits to ``pin`` (the honest case)."""
    pin = pin if pin is not None else _pin()
    return ahh.AnchorReceipt(
        anchor="northstar-audit-anchor/1",
        anchor_id=anchor_id,
        independent=independent,
        head_hash=head if head is not None else pin.head_hash,
        records_sealed=records if records is not None else pin.records_sealed,
        seq_range=rng if rng is not None else pin.seq_range,
    )


def _cli_args(command, **overrides):
    import argparse

    args = argparse.Namespace(
        audit_command=command,
        store="",
        head_hash="",
        seq=0,
        genesis="",
        records=-1,
        seq_first=1,
        seq_last=-1,
        anchor_manifest="",
        independent=False,
        allow_same_domain=False,
        json=False,
    )
    for key, value in overrides.items():
        setattr(args, key, value)
    return args


class _HolderCase(unittest.TestCase):
    """Base: a temp directory per test."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)

    def holder(self, name="heads.ndjson", **kw):
        return ahh.HeadHolder(self.tmp / name, **kw)


class TestSealRequiresAnAnchor(_HolderCase):
    """(a) a record is not sealed without an anchor receipt (C15)."""

    def test_publish_without_a_receipt_is_refused(self):
        """No anchor receipt -> no publish -> the head is not sealed."""
        holder = self.holder()
        with self.assertRaises(ahh.HeadHolderError):
            holder.publish_head(_pin(), receipt=None)
        # Nothing was written: the store does not exist at all.
        self.assertFalse((self.tmp / "heads.ndjson").exists())
        self.assertEqual(holder.receipts(), ())

    def test_seal_without_an_anchor_fails_closed(self):
        """The holder's write-path dependency: no anchorer, no receipt, no seal."""
        holder = self.holder()
        with self.assertRaises(ahh.HeadHolderError):
            holder.seal(_pin())
        self.assertEqual(holder.receipts(), ())

    def test_a_record_is_not_sealed_before_the_anchor_returns(self):
        """The anchor round-trip happens before anything is published."""
        seen = []

        def failing_anchorer(pin):
            seen.append(pin.head_hash)
            raise ahh.HeadHolderError("anchor unreachable")

        holder = self.holder(anchorer=failing_anchorer)
        with self.assertRaises(ahh.HeadHolderError):
            holder.seal(_pin())
        # The anchor was asked, and the failure left no head behind.
        self.assertEqual(seen, [HEAD_A])
        self.assertEqual(holder.receipts(), ())
        self.assertFalse((self.tmp / "heads.ndjson").exists())

    def test_an_anchor_for_another_head_cannot_seal_this_one(self):
        """The receipt must commit to the head being sealed."""
        holder = self.holder()
        with self.assertRaises(ahh.HeadHolderError):
            holder.publish_head(_pin(head=HEAD_A), receipt=_receipt(head=HEAD_B))
        self.assertEqual(holder.receipts(), ())

    def test_an_anchor_with_a_mismatched_record_count_is_refused(self):
        holder = self.holder()
        with self.assertRaises(ahh.HeadHolderError):
            holder.publish_head(_pin(records=3), receipt=_receipt(records=99))
        self.assertEqual(holder.receipts(), ())

    def test_an_anchor_with_a_mismatched_seq_range_is_refused(self):
        holder = self.holder()
        with self.assertRaises(ahh.HeadHolderError):
            holder.publish_head(_pin(seq=3, first=1, last=3), receipt=_receipt(rng=(1, 7)))
        self.assertEqual(holder.receipts(), ())

    def test_a_receipt_naming_no_head_cannot_seal(self):
        """An anchor that commits to nothing seals nothing."""
        holder = self.holder()
        receipt = ahh.AnchorReceipt(anchor="a", anchor_id="a1")
        with self.assertRaises(ahh.HeadHolderError):
            holder.publish_head(_pin(), receipt=receipt)
        self.assertEqual(holder.receipts(), ())


class TestTailSamplingCheck(_HolderCase):
    """(b) a shortened chain is caught by the tail check (C51)."""

    def test_tail_check_passes_when_the_held_head_agrees(self):
        holder = self.holder()
        pin = _pin()
        holder.publish_head(pin, receipt=_receipt(pin))
        report = holder.tail_check(pin, writer_rows=3)
        self.assertTrue(report.ok)
        self.assertTrue(report.independent_head_present)
        self.assertTrue(report.independent)
        self.assertEqual(report.writer_rows, 3)
        self.assertEqual(report.independent_rows, 3)

    def test_the_same_head_at_a_different_seq_is_a_mismatch(self):
        """The head hash alone is not the comparison.

        A writer that reuses the *same* head hash at a different position
        in the chain must not pass: the held head's seq is compared too.
        (The record count and seq range are compared as well, but a
        ``HeadPin`` already forces ``records_sealed == seq_last`` and
        ``seq_first == 1``, so the seq comparison is the one that can
        actually differ.)
        """
        holder = self.holder()
        held = _pin(seq=3, records=3)
        holder.publish_head(held, receipt=_receipt(held))
        # The same head hash, claimed at seq 99.
        writer = _pin(seq=99, records=99)
        report = holder.tail_check(writer, writer_rows=3)
        self.assertFalse(report.ok)
        self.assertIn("seq", report.reason)

    def _pin_with_forced_fields(self, **overrides):
        """A pin with fields set behind the dataclass's own validation.

        The pin's invariants already force ``records_sealed == seq_last``
        and ``seq_first == 1``, so the tail check's record-count and
        seq-range comparisons can only be reached by a pin that skipped
        them.  This builds one, so those comparisons are exercised.
        """
        fields = dict(
            head_hash=HEAD_A,
            seq=3,
            records_sealed=3,
            genesis=GENESIS,
            seq_first=1,
            seq_last=3,
            prev_head="",
        )
        fields.update(overrides)
        pin = object.__new__(ahh.HeadPin)
        for key, value in fields.items():
            object.__setattr__(pin, key, value)
        return pin

    def test_a_pin_with_a_different_record_count_is_a_mismatch(self):
        """The record count is compared, not just the head hash."""
        holder = self.holder()
        held = _pin(seq=3, records=3)
        holder.publish_head(held, receipt=_receipt(held))
        writer = self._pin_with_forced_fields(records_sealed=99)
        report = holder.tail_check(writer, writer_rows=3)
        self.assertFalse(report.ok)
        self.assertIn("row-count mismatch", report.reason)

    def test_a_pin_with_a_different_seq_range_is_a_mismatch(self):
        """The seq range is compared, not just the head hash."""
        holder = self.holder()
        held = _pin(seq=3, records=3)
        holder.publish_head(held, receipt=_receipt(held))
        writer = self._pin_with_forced_fields(seq_first=2)
        report = holder.tail_check(writer, writer_rows=3)
        self.assertFalse(report.ok)
        self.assertIn("range", report.reason)

    def test_a_shortened_chain_is_caught_by_the_tail_check(self):
        holder = self.holder()
        pin = _pin(seq=5, records=5)
        holder.publish_head(pin, receipt=_receipt(pin))
        # The writer now holds fewer rows than the holder anchored.
        report = holder.tail_check(pin, writer_rows=2)
        self.assertFalse(report.ok)
        self.assertIn("shortened", report.reason)
        self.assertEqual(report.writer_rows, 2)
        self.assertEqual(report.independent_rows, 5)

    def test_an_extended_chain_is_caught_by_the_tail_check(self):
        """The row-count comparison is two-sided, not one."""
        holder = self.holder()
        pin = _pin(seq=3, records=3)
        holder.publish_head(pin, receipt=_receipt(pin))
        report = holder.tail_check(pin, writer_rows=9)
        self.assertFalse(report.ok)
        self.assertIn("extended", report.reason)
        self.assertEqual(report.independent_rows, 3)

    def test_a_re_minted_head_is_caught_by_the_tail_check(self):
        """A rewritten chain has a different head hash."""
        holder = self.holder()
        pin = _pin(head=HEAD_A)
        holder.publish_head(pin, receipt=_receipt(pin))
        reminted = _pin(head=HEAD_B)
        report = holder.tail_check(reminted, writer_rows=3)
        self.assertFalse(report.ok)
        self.assertIn("head mismatch", report.reason)

    def test_a_missing_independent_head_fails_closed(self):
        """Nobody outside the writer holds the head -> the check fails."""
        holder = self.holder()
        report = holder.tail_check(_pin(), writer_rows=3)
        self.assertFalse(report.ok)
        self.assertFalse(report.independent_head_present)
        self.assertIn("no independent head held", report.reason)

    def test_a_corrupt_head_store_fails_closed(self):
        """A corrupt store must not raise out of the check."""
        path = self.tmp / "heads.ndjson"
        path.write_bytes(b"\xff\xfe not utf-8 \x00")
        holder = ahh.HeadHolder(path)
        report = holder.tail_check(_pin(), writer_rows=3)
        self.assertFalse(report.ok)
        self.assertFalse(report.independent_head_present)
        self.assertIn("unreadable", report.reason)

    def test_a_same_domain_anchor_fails_the_strict_check(self):
        """An offline manifest in the writer's own directory is not independent."""
        holder = self.holder(require_independent=False)
        pin = _pin()
        holder.publish_head(pin, receipt=_receipt(pin, independent=False))
        # The store accepted it, but the strict check refuses to call it independent.
        report = holder.tail_check(pin, writer_rows=3, require_independent=True)
        self.assertFalse(report.ok)
        self.assertFalse(report.independent)
        self.assertIn("independent holder is required", report.reason)

    def test_the_strict_check_refuses_a_non_independent_publish(self):
        holder = self.holder()
        with self.assertRaises(ahh.HeadHolderError):
            holder.publish_head(_pin(), receipt=_receipt(independent=False))
        self.assertEqual(holder.receipts(), ())


class TestFreshStartCarriesTheOldHead(_HolderCase):
    """(c) a re-mint is a mismatch, not a clean start (C46/48)."""

    def test_a_fresh_start_with_no_previous_head_cannot_claim_a_seq(self):
        """A clean start has sealed nothing, so it claims no seq.

        Without a previous head there is nothing to carry, and a seq
        would be a claim the fresh start cannot back.  The count is
        passed explicitly here so that the pin's own
        ``records_sealed == seq_last`` rule cannot be what refuses it:
        this test is about the fresh-start rule itself.
        """
        with self.assertRaises(ahh.HeadHolderError) as caught:
            ahh.fresh_start_pin(
                None, genesis=GENESIS, head_hash=HEAD_A, seq=3, records_sealed=3
            )
        self.assertIn("no previous head", str(caught.exception))

    def test_a_clean_fresh_start_claims_no_seq(self):
        """A genuinely clean start seals nothing, so it is [1..0]."""
        pin = ahh.fresh_start_pin(None, genesis=GENESIS, head_hash=HEAD_A)
        self.assertEqual(pin.seq, 0)
        self.assertEqual(pin.records_sealed, 0)
        self.assertEqual(pin.seq_range, (1, 0))
        self.assertEqual(pin.prev_head, "")

    def test_a_re_mint_is_reported_as_a_mismatch_on_fresh_start(self):
        """A new head carried over the old one is not a clean start."""
        old = _pin(head=HEAD_A, seq=3, records=3)
        # The independent holder still holds the old head.
        independent = old
        # The writer re-minted the chain: same records, new head.
        reminted = ahh.fresh_start_pin(
            old, genesis=GENESIS, head_hash=HEAD_B, seq=3, records_sealed=3
        )
        ok, note = ahh.check_fresh_start(reminted, independent)
        self.assertFalse(ok)
        self.assertIn("mismatch", note)
        # The note says it is a re-mint, not just any disagreement.
        self.assertIn("re-minted", note)

    def test_the_fresh_start_carries_the_old_head_hash(self):
        """The re-mint is linked to the history it replaces."""
        old = _pin(head=HEAD_A, seq=3, records=3)
        reminted = ahh.fresh_start_pin(
            old, genesis=GENESIS, head_hash=HEAD_B, seq=3, records_sealed=3
        )
        self.assertEqual(reminted.prev_head, HEAD_A)
        self.assertEqual(reminted.head_hash, HEAD_B)

    def test_the_holder_fresh_start_carries_the_old_head(self):
        holder = self.holder()
        old = _pin(head=HEAD_A, seq=3, records=3)
        carried = holder.fresh_start_head(old, head_hash=HEAD_B)
        self.assertEqual(carried.prev_head, HEAD_A)
        # The carried head is the *new* one: a fresh start that kept the
        # old hash would be no re-mint at all.
        self.assertEqual(carried.head_hash, HEAD_B)

    def test_a_fresh_start_without_the_old_head_is_refused(self):
        """No previous head means a re-mint is indistinguishable from a clean start."""
        holder = self.holder()
        with self.assertRaises(ahh.HeadHolderError):
            holder.fresh_start_head(None, head_hash=HEAD_B)
        with self.assertRaises(ahh.HeadHolderError):
            ahh.fresh_start_pin(None, genesis=GENESIS, head_hash=HEAD_A, seq=3)

    def test_a_fresh_start_keeping_the_old_hash_is_refused(self):
        """A re-mint that keeps the old hash is not a re-mint."""
        holder = self.holder()
        old = _pin(head=HEAD_A, seq=3, records=3)
        with self.assertRaises(ahh.HeadHolderError):
            holder.fresh_start_head(old, head_hash=HEAD_A)

    def test_a_fresh_start_with_nobody_holding_a_head_fails_closed(self):
        """Nobody outside the writer holds a head -> not a clean start."""
        ok, note = ahh.check_fresh_start(_pin(), None)
        self.assertFalse(ok)
        self.assertIn("no independent head held", note)

    def test_a_fresh_start_that_drops_the_old_head_is_a_mismatch(self):
        """The holder holds a head; the fresh start carried none -> a re-mint."""
        ok, note = ahh.check_fresh_start(None, _pin(head=HEAD_A))
        self.assertFalse(ok)
        self.assertIn("re-mint", note)

    def test_a_fresh_start_continuing_the_held_head_is_ok(self):
        """The carried head is the head the holder still holds."""
        held = _pin(head=HEAD_A, seq=3, records=3)
        ok, note = ahh.check_fresh_start(held, held)
        self.assertTrue(ok)
        self.assertIn("continues", note)


class TestSealCommitsToTheSeqRange(_HolderCase):
    """(d) the seal commits to the observed seq range [1..N] (C21)."""

    def test_the_range_must_start_at_one(self):
        """A range of [2..N] is not the committed range [1..N].

        A pin that starts at 2 commits to a range that omits the first
        record, so it is refused rather than sealed.
        """
        with self.assertRaises(ahh.HeadHolderError):
            _pin(seq=3, records=3, first=2, last=3)

    def test_the_seal_commits_to_the_observed_seq_range(self):
        """The held receipt carries the seq range the seal commits to."""
        holder = self.holder()
        pin = _pin(seq=4, records=4, first=1, last=4)
        holder.publish_head(pin, receipt=_receipt(pin))
        held = holder.latest()
        self.assertEqual(held.pin.seq_range, (1, 4))
        self.assertEqual(held.pin.as_dict()["seq_range"], [1, 4])

    def test_a_mismatched_seq_range_fails_the_tail_check(self):
        """A pin whose range differs from the anchored one is refused."""
        holder = self.holder()
        pin = _pin(seq=4, records=4, first=1, last=4)
        holder.publish_head(pin, receipt=_receipt(pin))
        # The writer claims a different observed range: the pin refuses
        # to be built at all, so it can never be sealed.
        with self.assertRaises(ahh.HeadHolderError):
            ahh.HeadPin(
                head_hash=pin.head_hash,
                seq=4,
                records_sealed=4,
                genesis=GENESIS,
                seq_first=1,
                seq_last=9,
            )
        # And the seal itself refuses a receipt whose range disagrees.
        with self.assertRaises(ahh.HeadHolderError):
            holder.publish_head(pin, receipt=_receipt(pin, rng=(1, 9)))

    def test_a_pin_whose_seq_and_range_disagree_is_refused(self):
        """The seal commits to one consistent range [1..N] (C21)."""
        with self.assertRaises(ahh.HeadHolderError):
            ahh.HeadPin(
                head_hash=HEAD_A,
                seq=5,
                records_sealed=5,
                genesis=GENESIS,
                seq_first=1,
                seq_last=0,
            )
        with self.assertRaises(ahh.HeadHolderError):
            ahh.HeadPin(
                head_hash=HEAD_A,
                seq=3,
                records_sealed=99,
                genesis=GENESIS,
                seq_first=1,
                seq_last=3,
            )

    def test_the_pin_rejects_an_inverted_seq_range(self):
        with self.assertRaises(ahh.HeadHolderError):
            ahh.HeadPin(
                head_hash=HEAD_A,
                seq=3,
                records_sealed=3,
                genesis=GENESIS,
                seq_first=5,
                seq_last=2,
            )

    def test_an_empty_seq_range_is_legitimate(self):
        """A chain that has sealed nothing yet: [1..0] is not an inversion."""
        pin = ahh.HeadPin(head_hash=HEAD_A, seq=0, records_sealed=0, genesis=GENESIS)
        self.assertEqual(pin.seq_range, (1, 0))


class TestAnchorMachineryAndLedger(_HolderCase):
    """Integration with the real anchor machinery and the real ledger."""

    def _ledger(self, count=3):
        fsl = _load("forward_seal_ledger")
        ledger = fsl.ForwardSealLedger(b"k" * 32, b"c" * 32)
        pin_value = "sha256:" + "ab" * 32
        for i in range(count):
            ledger.append(
                intent=f"i-{i}",
                action="a",
                subject="s",
                authorization="auth",
                inputs_digest=pin_value,
                logic_digest=pin_value,
                execution_digest=pin_value,
                outcome="o",
            )
        return ledger

    def test_the_offline_anchorer_produces_a_receipt_that_commits_to_the_head(self):
        """The offline anchor path writes a real manifest and seals the head."""
        holder = ahh.HeadHolder(
            self.tmp / "heads.ndjson",
            require_independent=False,
            anchorer=ahh.offline_head_anchorer(
                self.tmp / "anchor.json", anchor_id="offline-1"
            ),
        )
        pin = _pin(seq=3, records=3)
        entry = holder.seal(pin)
        self.assertEqual(entry.pin.head_hash, pin.head_hash)
        self.assertEqual(entry.receipt.head_hash, pin.head_hash)
        self.assertEqual(entry.receipt.records_sealed, 3)
        self.assertEqual(entry.receipt.seq_range, (1, 3))
        # The manifest is on disk and pins the head.
        manifest = (self.tmp / "anchor.json").read_text(encoding="utf-8")
        self.assertIn("head_chain_hash", manifest)
        self.assertIn("northstar-audit-head-anchor/1", manifest)

    def test_the_anchor_count_is_the_sealed_count_not_the_head_feed_count(self):
        """The anchor observes the sealed records, not the head feed's rows.

        The head anchor manifest is a manifest over a one-record head
        feed, so its ``records`` is 1.  The count the receipt commits to
        is the number of *sealed ledger records* the head covers -- 3
        here.  Reading the wrong one would have the tail check compare
        the writer against 1 row instead of 3.
        """
        manifest = {
            "anchor": "northstar-audit-anchor/1",
            "chain": "sha256:" + "ab" * 32,
            "feed_sha256": "sha256:" + "cd" * 32,
            "head_chain_hash": HEAD_A,
            "records": 1,
            "records_sealed": 3,
            "seq_range": [1, 3],
            "anchored_at": "2026-11-12T00:00:00Z",
        }
        receipt = ahh.offline_anchor_receipt(anchor_id="a1", manifest=manifest)
        self.assertEqual(receipt.records_sealed, 3)
        self.assertEqual(receipt.seq_range, (1, 3))
        self.assertEqual(receipt.head_hash, HEAD_A)

    def test_the_ledger_head_pin_commits_to_the_sealed_range(self):
        """The pin built from a real forward-seal ledger."""
        ledger = self._ledger(3)
        pin = ahh.ledger_head_pin(ledger)
        self.assertEqual(pin.seq, 3)
        self.assertEqual(pin.records_sealed, 3)
        self.assertEqual(pin.seq_range, (1, 3))
        self.assertEqual(pin.head_hash, ledger.record(3).record_hash)
        self.assertEqual(pin.genesis, ledger.genesis)

    def test_the_tail_check_agrees_with_the_real_ledger(self):
        """The writer's row count is the ledger's length."""
        ledger = self._ledger(3)
        holder = self.holder()
        pin = ahh.ledger_head_pin(ledger)
        holder.publish_head(pin, receipt=_receipt(pin))
        report = holder.tail_check(pin, writer_rows=len(ledger))
        self.assertTrue(report.ok)
        # Now the writer drops records: the tail check must catch it.
        shortened = holder.tail_check(pin, writer_rows=len(ledger) - 1)
        self.assertFalse(shortened.ok)

    def test_the_store_is_append_only_across_publishes(self):
        """Two heads, two receipts, both readable in order."""
        holder = self.holder()
        first = _pin(head=HEAD_A, seq=1, records=1, first=1, last=1)
        second = _pin(head=HEAD_B, seq=2, records=2, first=1, last=2)
        holder.publish_head(first, receipt=_receipt(first))
        holder.publish_head(second, receipt=_receipt(second))
        receipts = holder.receipts()
        self.assertEqual(len(receipts), 2)
        self.assertEqual(receipts[0].pin.head_hash, HEAD_A)
        self.assertEqual(receipts[1].pin.head_hash, HEAD_B)
        self.assertEqual(holder.latest().pin.head_hash, HEAD_B)
        ok, note = holder.verify_store()
        self.assertTrue(ok, note)

    def test_a_missing_store_is_not_intact(self):
        """Fails closed: a missing store is a missing independent holder."""
        holder = self.holder()
        ok, note = holder.verify_store()
        self.assertFalse(ok)
        self.assertIn("no independent head store", note)

    def test_the_module_self_check_runs(self):
        """``python3 audit_head_holder.py`` -- the module's own gate."""
        result = subprocess.run(
            [sys.executable, str(RUNTIME / "audit_head_holder.py")],
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("audit-head-holder OK", result.stdout)


class TestHostileStore(_HolderCase):
    """The store must not be rewritable by the writer that owns it."""

    def _store(self, pins):
        holder = self.holder()
        for pin in pins:
            holder.publish_head(pin, receipt=_receipt(pin))
        return holder

    def test_a_truncated_store_is_detected(self):
        """Cutting the store short is caught by the row-count comparison."""
        first = _pin(head=HEAD_A, seq=1, records=1, last=1)
        second = _pin(head=HEAD_B, seq=2, records=2, last=2)
        holder = self._store([first, second])
        path = self.tmp / "heads.ndjson"
        lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
        path.write_text("".join(lines[:1]), encoding="utf-8")
        holder2 = ahh.HeadHolder(path)
        # The store now holds one head and reads clean on its own: a
        # truncated *tail* is not a broken chain link.
        self.assertEqual(len(holder2.receipts()), 1)
        # The writer still holds 2 rows, but the holder now counts 1:
        # the row-count comparison catches the truncation.
        report = holder2.tail_check(_pin(head=HEAD_A, seq=1, records=1, last=1), writer_rows=2)
        self.assertFalse(report.ok)
        self.assertIn("extended", report.reason)

    def test_an_edited_store_entry_is_detected(self):
        """Editing an entry breaks its digest."""
        holder = self._store([_pin(head=HEAD_A, seq=1, records=1, last=1)])
        path = self.tmp / "heads.ndjson"
        record = json.loads(path.read_text(encoding="utf-8").strip())
        record["records_sealed"] = 999
        path.write_text(json.dumps(record) + "\n", encoding="utf-8")
        with self.assertRaises(ahh.HeadHolderError):
            ahh.HeadHolder(path).receipts()

    def test_an_edited_genesis_is_caught_by_the_digest(self):
        """The digest catches an edit the pin's own rules cannot see.

        ``genesis`` is not constrained by ``HeadPin``, so editing it is
        caught *only* by the entry digest.  Without that check a
        whole-store rewrite that swaps the chain's genesis would read
        clean.
        """
        holder = self._store([_pin(head=HEAD_A, seq=1, records=1, last=1)])
        path = self.tmp / "heads.ndjson"
        record = json.loads(path.read_text(encoding="utf-8").strip())
        record["genesis"] = "sha256:" + "ee" * 32
        path.write_text(json.dumps(record) + "\n", encoding="utf-8")
        with self.assertRaises(ahh.HeadHolderError) as caught:
            ahh.HeadHolder(path).receipts()
        # The *entry* digest is the load-bearing check: it covers the
        # whole entry, so it fires first.  The head digest covers the pin
        # and the receipt digest covers the anchor; both are
        # defence-in-depth behind it.
        self.assertIn("entry digest mismatch", str(caught.exception))

    def test_an_edited_anchor_detail_is_caught_by_the_digest(self):
        """The receipt digest covers the anchor's own detail field."""
        holder = self._store([_pin(head=HEAD_A, seq=1, records=1, last=1)])
        path = self.tmp / "heads.ndjson"
        record = json.loads(path.read_text(encoding="utf-8").strip())
        record["anchor"]["detail"]["feed_sha256"] = "sha256:" + "ff" * 32
        path.write_text(json.dumps(record) + "\n", encoding="utf-8")
        with self.assertRaises(ahh.HeadHolderError) as caught:
            ahh.HeadHolder(path).receipts()
        self.assertIn("entry digest mismatch", str(caught.exception))

    def _rewrite_with_recomputed_entry_digest(self, path, mutate):
        """Edit a store entry *and* fix its entry digest.

        This is what an attacker who can rewrite the whole store would
        do.  The entry digest is then not the check that fires -- the
        head digest and the receipt digest are the layers behind it.
        """
        record = json.loads(path.read_text(encoding="utf-8").strip())
        mutate(record)
        body = {key: value for key, value in record.items() if key != "entry_digest"}
        record["entry_digest"] = ahh._entry_digest(body)
        path.write_text(json.dumps(record) + "\n", encoding="utf-8")

    def test_a_rewritten_genesis_is_caught_by_the_head_digest(self):
        """Behind the entry digest, the head digest catches a rewritten pin."""
        holder = self._store([_pin(head=HEAD_A, seq=1, records=1, last=1)])
        path = self.tmp / "heads.ndjson"

        def rewrite(record):
            record["genesis"] = "sha256:" + "ee" * 32

        self._rewrite_with_recomputed_entry_digest(path, rewrite)
        with self.assertRaises(ahh.HeadHolderError) as caught:
            ahh.HeadHolder(path).receipts()
        self.assertIn("head digest mismatch", str(caught.exception))

    def test_a_rewritten_anchor_is_caught_by_the_receipt_digest(self):
        """Behind the entry digest, the receipt digest catches a rewritten anchor."""
        holder = self._store([_pin(head=HEAD_A, seq=1, records=1, last=1)])
        path = self.tmp / "heads.ndjson"

        def rewrite(record):
            record["anchor"]["detail"]["feed_sha256"] = "sha256:" + "ff" * 32

        self._rewrite_with_recomputed_entry_digest(path, rewrite)
        with self.assertRaises(ahh.HeadHolderError) as caught:
            ahh.HeadHolder(path).receipts()
        self.assertIn("receipt digest mismatch", str(caught.exception))

    def test_a_removed_middle_entry_is_detected(self):
        """Removing an entry from the middle breaks the chain link."""
        first = _pin(head=HEAD_A, seq=1, records=1, last=1)
        second = _pin(head=HEAD_B, seq=2, records=2, last=2)
        third = _pin(head=HEAD_C, seq=3, records=3, last=3)
        holder = self._store([first, second, third])
        path = self.tmp / "heads.ndjson"
        lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
        path.write_text("".join(lines[:1] + lines[2:]), encoding="utf-8")
        with self.assertRaises(ahh.HeadHolderError):
            ahh.HeadHolder(path).receipts()

    def test_a_rollback_to_a_lower_seq_is_refused(self):
        """The store is monotonic: a head cannot go backwards."""
        holder = self._store([_pin(head=HEAD_A, seq=5, records=5, last=5)])
        lower = _pin(head=HEAD_B, seq=2, records=2, last=2)
        with self.assertRaises(ahh.HeadHolderError):
            holder.publish_head(lower, receipt=_receipt(lower))

    def test_a_store_line_whose_anchor_names_another_head_is_refused(self):
        """The read path re-checks that the receipt commits to the head."""
        holder = self._store([_pin(head=HEAD_A, seq=1, records=1, last=1)])
        path = self.tmp / "heads.ndjson"
        record = json.loads(path.read_text(encoding="utf-8").strip())
        record["anchor"]["head_hash"] = HEAD_C
        path.write_text(json.dumps(record) + "\n", encoding="utf-8")
        with self.assertRaises(ahh.HeadHolderError):
            ahh.HeadHolder(path).receipts()

    def test_a_store_line_whose_anchor_is_not_a_dict_is_refused(self):
        """A malformed anchor must fail closed, not raise out of the read."""
        holder = self._store([_pin(head=HEAD_A, seq=1, records=1, last=1)])
        path = self.tmp / "heads.ndjson"
        record = json.loads(path.read_text(encoding="utf-8").strip())
        record["anchor"] = ["not", "a", "dict"]
        path.write_text(json.dumps(record) + "\n", encoding="utf-8")
        with self.assertRaises(ahh.HeadHolderError):
            ahh.HeadHolder(path).receipts()

    def test_an_unwritable_store_fails_closed(self):
        """An I/O error must not escape the fail-closed API."""
        blocker = self.tmp / "blocked"
        blocker.write_text("not a directory", encoding="utf-8")
        holder = ahh.HeadHolder(blocker / "heads.ndjson")
        with self.assertRaises(ahh.HeadHolderError):
            holder.publish_head(_pin(), receipt=_receipt(_pin()))

    def test_a_receipt_with_no_observed_count_cannot_seal(self):
        """The seal must commit to the count the anchor observed."""
        holder = self.holder()
        receipt = ahh.AnchorReceipt(
            anchor="a",
            anchor_id="a1",
            head_hash=HEAD_A,
            records_sealed=None,
            seq_range=(1, 3),
        )
        with self.assertRaises(ahh.HeadHolderError):
            holder.publish_head(_pin(), receipt=receipt)
        self.assertEqual(holder.receipts(), ())

    def test_a_receipt_with_no_observed_range_cannot_seal(self):
        holder = self.holder()
        receipt = ahh.AnchorReceipt(
            anchor="a",
            anchor_id="a1",
            head_hash=HEAD_A,
            records_sealed=3,
            seq_range=None,
        )
        with self.assertRaises(ahh.HeadHolderError):
            holder.publish_head(_pin(), receipt=receipt)
        self.assertEqual(holder.receipts(), ())

    def test_a_fork_at_the_same_seq_is_refused(self):
        """Two heads claiming the same position is a fork, not a continuation.

        The store is the outside holder's record of *one* chain.  If a
        second, different head could be published at the same seq, the
        tail check would compare the writer against whichever head
        happened to be written last, and a fork would read clean.
        """
        holder = self._store([_pin(head=HEAD_A, seq=5, records=5, last=5)])
        forked = _pin(head=HEAD_B, seq=5, records=5, last=5)
        with self.assertRaises(ahh.HeadHolderError):
            holder.publish_head(forked, receipt=_receipt(forked))
        self.assertEqual(holder.latest().pin.head_hash, HEAD_A)

    def test_a_store_that_already_forks_is_refused_on_read(self):
        """A fork already in the store is a corrupt store, not a clean read.

        The write path refuses to create one; the read path must refuse
        to read one, or the tail check would compare the writer against
        whichever head happened to be written last.
        """
        holder = self._store([_pin(head=HEAD_A, seq=5, records=5, last=5)])
        path = self.tmp / "heads.ndjson"
        prev_digest = holder.receipts()[-1].entry_digest
        # Build the forked entry by hand, chaining it correctly so the
        # fork is the only thing wrong with the store.
        forked = _pin(head=HEAD_B, seq=5, records=5, last=5)
        receipt = _receipt(forked)
        body = {
            "schema": ahh.HEAD_RECEIPT_SCHEMA,
            **forked.as_dict(),
            "anchor": receipt.as_dict(),
            "head_digest": ahh._digest(forked.as_dict()),
            "receipt_digest": ahh._digest(receipt.as_dict()),
            "prev_digest": prev_digest,
        }
        entry = dict(body)
        entry["entry_digest"] = ahh._entry_digest(body)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry) + "\n")
        with self.assertRaises(ahh.HeadHolderError):
            ahh.HeadHolder(path).receipts()

    def test_a_republish_of_the_same_head_is_allowed(self):
        """Re-sealing the same head is idempotent, not a fork."""
        pin = _pin(head=HEAD_A, seq=5, records=5, last=5)
        holder = self._store([pin])
        holder.publish_head(pin, receipt=_receipt(pin))
        self.assertEqual(holder.latest().pin.head_hash, HEAD_A)
        self.assertEqual(len(holder.receipts()), 2)

    def test_a_store_line_whose_anchor_observed_no_count_is_refused(self):
        """The read path applies the same commitments as the write path.

        A store line whose anchor carries no observed count cannot have
        been sealed -- the write path refuses to publish one -- so the read
        path treats it as a corrupt store rather than a sealed head.
        """
        holder = self._store([_pin(head=HEAD_A, seq=1, records=1, last=1)])
        path = self.tmp / "heads.ndjson"
        record = json.loads(path.read_text(encoding="utf-8").strip())
        record["anchor"]["records_sealed"] = None
        path.write_text(json.dumps(record) + "\n", encoding="utf-8")
        with self.assertRaises(ahh.HeadHolderError):
            ahh.HeadHolder(path).receipts()

    def test_a_store_line_whose_anchor_observed_no_range_is_refused(self):
        holder = self._store([_pin(head=HEAD_A, seq=1, records=1, last=1)])
        path = self.tmp / "heads.ndjson"
        record = json.loads(path.read_text(encoding="utf-8").strip())
        record["anchor"]["seq_range"] = None
        path.write_text(json.dumps(record) + "\n", encoding="utf-8")
        with self.assertRaises(ahh.HeadHolderError):
            ahh.HeadHolder(path).receipts()

    def test_a_store_line_whose_anchor_names_no_head_is_refused(self):
        holder = self._store([_pin(head=HEAD_A, seq=1, records=1, last=1)])
        path = self.tmp / "heads.ndjson"
        record = json.loads(path.read_text(encoding="utf-8").strip())
        record["anchor"]["head_hash"] = ""
        path.write_text(json.dumps(record) + "\n", encoding="utf-8")
        with self.assertRaises(ahh.HeadHolderError):
            ahh.HeadHolder(path).receipts()

    def test_a_store_line_with_an_uncannonicalisable_field_fails_closed(self):
        """A digest recompute must not raise out of the read path."""
        holder = self._store([_pin(head=HEAD_A, seq=1, records=1, last=1)])
        path = self.tmp / "heads.ndjson"
        # NaN is accepted by ``json.loads`` but is not valid canonical
        # JSON, so the digest recompute must fail closed rather than
        # raise out of the read path.
        path.write_text(
            '{"schema": %r, "head_hash": %r, "seq": 1, "records_sealed": 1,'
            ' "genesis": %r, "seq_range": [1, 1], "prev_head": "",'
            ' "anchor": {"anchor": "a", "anchor_id": "a1", "independent": true,'
            ' "detail": {"bad": NaN}, "head_hash": %r, "records_sealed": 1,'
            ' "seq_range": [1, 1]}, "head_digest": "x", "receipt_digest": "y",'
            ' "prev_digest": "", "entry_digest": "z"}\n'
            % (
                ahh.HEAD_RECEIPT_SCHEMA,
                HEAD_A,
                GENESIS,
                HEAD_A,
            ),
            encoding="utf-8",
        )
        with self.assertRaises(ahh.HeadHolderError):
            ahh.HeadHolder(path).receipts()


class TestCliSurface(_HolderCase):
    """The ``northstar audit seal-head`` / ``check-head`` commands."""

    def test_the_cli_seals_a_head_into_the_independent_store(self):
        from audit_cli import run_audit

        store = self.tmp / "heads.ndjson"
        manifest = self.tmp / "anchor.json"
        rc = run_audit(
            _cli_args(
                "seal-head",
                store=str(store),
                head_hash=HEAD_A,
                seq=3,
                genesis=GENESIS,
                anchor_manifest=str(manifest),
                independent=True,
            )
        )
        self.assertEqual(rc, 0)
        self.assertTrue(store.exists())
        self.assertTrue(manifest.exists())
        holder = ahh.HeadHolder(store)
        self.assertEqual(holder.latest().pin.head_hash, HEAD_A)
        self.assertEqual(holder.latest().pin.seq_range, (1, 3))

    def test_the_cli_refuses_to_seal_without_an_anchor(self):
        """Anchor-before-acknowledge, at the CLI surface."""
        from audit_cli import run_audit

        store = self.tmp / "heads.ndjson"
        rc = run_audit(
            _cli_args(
                "seal-head",
                store=str(store),
                head_hash=HEAD_A,
                seq=3,
                genesis=GENESIS,
            )
        )
        self.assertEqual(rc, 3)
        self.assertFalse(store.exists())

    def test_the_cli_refuses_a_record_count_that_disagrees_with_the_seq(self):
        """``--records`` is honoured, not ignored.

        The seal commits to one range [1..N], so a record count that
        disagrees with the seq cannot be sealed.  The flag must not be
        silently dropped.
        """
        from audit_cli import run_audit

        store = self.tmp / "heads.ndjson"
        manifest = self.tmp / "anchor.json"
        rc = run_audit(
            _cli_args(
                "seal-head",
                store=str(store),
                head_hash=HEAD_A,
                seq=3,
                genesis=GENESIS,
                records=99,
                anchor_manifest=str(manifest),
                independent=True,
            )
        )
        self.assertEqual(rc, 3)
        self.assertFalse(store.exists())

    def test_the_cli_tail_check_passes_on_agreement(self):
        from audit_cli import run_audit

        store = self.tmp / "heads.ndjson"
        manifest = self.tmp / "anchor.json"
        seal = dict(
            store=str(store),
            head_hash=HEAD_A,
            seq=3,
            genesis=GENESIS,
            anchor_manifest=str(manifest),
            independent=True,
        )
        self.assertEqual(run_audit(_cli_args("seal-head", **seal)), 0)
        rc = run_audit(
            _cli_args("check-head", store=str(store), head_hash=HEAD_A, seq=3, genesis=GENESIS)
        )
        self.assertEqual(rc, 0)

    def test_the_cli_tail_check_catches_a_shortened_chain(self):
        from audit_cli import run_audit

        store = self.tmp / "heads.ndjson"
        manifest = self.tmp / "anchor.json"
        self.assertEqual(
            run_audit(
                _cli_args(
                    "seal-head",
                    store=str(store),
                    head_hash=HEAD_A,
                    seq=5,
                    genesis=GENESIS,
                    anchor_manifest=str(manifest),
                    independent=True,
                )
            ),
            0,
        )
        rc = run_audit(
            _cli_args("check-head", store=str(store), head_hash=HEAD_A, seq=5, genesis=GENESIS)
        )
        self.assertEqual(rc, 0)
        # The writer now holds fewer rows than the holder observed.
        rc = run_audit(
            _cli_args(
                "check-head",
                store=str(store),
                head_hash=HEAD_A,
                seq=5,
                genesis=GENESIS,
                records=2,
            )
        )
        self.assertEqual(rc, 1)

    def test_the_cli_tail_check_fails_closed_with_no_independent_head(self):
        from audit_cli import run_audit

        rc = run_audit(
            _cli_args(
                "check-head",
                store=str(self.tmp / "missing.ndjson"),
                head_hash=HEAD_A,
                seq=3,
                genesis=GENESIS,
            )
        )
        self.assertEqual(rc, 3)

    def test_the_cli_json_output_is_valid_json(self):
        """Every --json path emits one parseable object."""
        import io
        from contextlib import redirect_stdout

        from audit_cli import run_audit

        store = self.tmp / "heads.ndjson"
        manifest = self.tmp / "anchor.json"
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            rc = run_audit(
                _cli_args(
                    "seal-head",
                    store=str(store),
                    head_hash=HEAD_A,
                    seq=3,
                    genesis=GENESIS,
                    anchor_manifest=str(manifest),
                    independent=True,
                    json=True,
                )
            )
        self.assertEqual(rc, 0)
        payload = json.loads(buffer.getvalue())
        self.assertEqual(payload["status"], "OK")
        self.assertEqual(payload["head_hash"], HEAD_A)
        self.assertEqual(payload["seq_range"], [1, 3])
        self.assertEqual(payload["store"], str(store))

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            rc = run_audit(
                _cli_args(
                    "check-head",
                    store=str(store),
                    head_hash=HEAD_A,
                    seq=3,
                    genesis=GENESIS,
                    json=True,
                )
            )
        self.assertEqual(rc, 0)
        payload = json.loads(buffer.getvalue())
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["status"], "OK")

    def test_the_cli_json_emits_json_on_the_error_paths(self):
        """Every --json path emits one parseable object -- errors too.

        A ``--json`` consumer that gets an empty string on the error path
        cannot tell "no head held" from "the tool crashed", so the error
        paths emit JSON too.
        """
        import io
        from contextlib import redirect_stdout

        from audit_cli import run_audit

        cases = [
            # (command, kwargs, expected status)
            (
                "seal-head",
                dict(store=str(self.tmp / "h.ndjson"), head_hash=HEAD_A, seq=3, genesis=GENESIS),
                "INVALID",
            ),
            (
                "seal-head",
                dict(
                    store=str(self.tmp / "h.ndjson"),
                    head_hash=HEAD_A,
                    seq=3,
                    genesis=GENESIS,
                    anchor_manifest=str(self.tmp / "m.json"),
                ),
                "INVALID",
            ),
            (
                "check-head",
                dict(store="", head_hash=HEAD_A, seq=3, genesis=GENESIS),
                "INVALID",
            ),
            (
                "check-head",
                dict(
                    store=str(self.tmp / "missing.ndjson"),
                    head_hash=HEAD_A,
                    seq=3,
                    genesis=GENESIS,
                ),
                "MISMATCH",
            ),
        ]
        for command, kwargs, status in cases:
            with self.subTest(command=command, status=status):
                buffer = io.StringIO()
                with redirect_stdout(buffer):
                    rc = run_audit(_cli_args(command, json=True, **kwargs))
                self.assertEqual(rc, 3)
                payload = json.loads(buffer.getvalue())
                self.assertEqual(payload["status"], status)
                self.assertTrue(payload["reason"])

    def test_the_cli_refuses_an_unwritable_anchor_manifest(self):
        """An I/O failure must be a clean error, not a traceback."""
        from audit_cli import run_audit

        rc = run_audit(
            _cli_args(
                "seal-head",
                store=str(self.tmp / "h.ndjson"),
                head_hash=HEAD_A,
                seq=3,
                genesis=GENESIS,
                anchor_manifest="/proc/nope/a.json",
                independent=True,
            )
        )
        self.assertEqual(rc, 3)
        self.assertFalse((self.tmp / "h.ndjson").exists())

    def test_the_cli_check_head_refuses_an_unusable_store_path(self):
        """An empty store path is a failure to check, not agreement."""
        from audit_cli import run_audit

        rc = run_audit(
            _cli_args("check-head", store="", head_hash=HEAD_A, seq=3, genesis=GENESIS)
        )
        self.assertEqual(rc, 3)


if __name__ == "__main__":
    unittest.main()

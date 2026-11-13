"""Tests for ledger_concurrency: gapless seq, idempotent update, Infra flag.

Covers the ageOfAgents absorption:
  * concurrent append under a sidecar lock -> gapless, monotonic sequence
  * torn-tail repair (a half-written trailing line is never a crash)
  * transactional check-then-append (idempotent under concurrent callers)
  * the Infra flag (a gate that never ran is not the executor's failure)
"""

from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _load():
    spec = importlib.util.spec_from_file_location(
        "ledger_concurrency", ROOT / "ledger_concurrency.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["ledger_concurrency"] = module
    spec.loader.exec_module(module)
    return module


lc = _load()


class LedgerConcurrencyTestCase(unittest.TestCase):
    """Shared temp-log fixture."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.log_path = self.dir / "decisions.jsonl"
        self.log = lc.ConcurrentLedger(self.log_path)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _write_raw(self, text: str) -> None:
        self.log_path.write_text(text, encoding="utf-8")


class AppendSequenceTests(LedgerConcurrencyTestCase):
    """Rule: sequence numbers start at 1, monotonic, gapless, no duplicates."""

    def test_first_append_takes_seq_one(self):
        event = self.log.append("first")
        self.assertEqual(event.seq, 1)
        self.assertEqual(self.log.next_seq(), 2)

    def test_sequence_is_monotonic_and_gapless(self):
        for i in range(5):
            self.log.append(f"e-{i}")
        seqs = [event.seq for event in self.log.read_events()]
        self.assertEqual(seqs, [1, 2, 3, 4, 5])

    def test_two_concurrent_writers_keep_the_sequence_gapless(self):
        """Two writers, N appends each: 1..2N, no gap, no duplicate."""
        n = 12
        errors = []

        def worker(tag):
            try:
                for i in range(n):
                    self.log.append(f"{tag}-{i}")
            except BaseException as error:  # pragma: no cover - failure path
                errors.append(error)

        threads = [threading.Thread(target=worker, args=(tag,)) for tag in ("a", "b")]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        seqs = [event.seq for event in self.log.read_events()]
        self.assertEqual(seqs, list(range(1, 2 * n + 1)))
        self.assertEqual(len(set(seqs)), len(seqs), "no duplicate sequence numbers")
        self.assertEqual(len(seqs), 2 * n, "no event was lost")

    def test_two_concurrent_writers_lose_no_payload(self):
        n = 8
        errors = []

        def worker(tag):
            try:
                for i in range(n):
                    self.log.append(f"{tag}-{i}")
            except BaseException as error:  # pragma: no cover - failure path
                errors.append(error)

        threads = [threading.Thread(target=worker, args=(tag,)) for tag in ("x", "y")]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        payloads = [event.payload for event in self.log.read_events()]
        self.assertEqual(sorted(payloads), sorted([f"{t}-{i}" for t in ("x", "y") for i in range(n)]))


class TornTailTests(LedgerConcurrencyTestCase):
    """Rule: a half-written trailing line is repaired, never a crash."""

    def test_a_torn_tail_is_not_counted_as_an_event(self):
        self.log.append("whole")
        with open(self.log_path, "a", encoding="utf-8") as handle:
            handle.write('{"seq": 2, "payload": "half-writ')
        events = self.log.read_events()
        self.assertEqual([event.payload for event in events], ["whole"])
        self.assertEqual(len(events), 1, "a torn tail is not an event")

    def test_repair_tail_drops_the_fragment_and_keeps_the_events(self):
        self.log.append("one")
        self.log.append("two")
        with open(self.log_path, "a", encoding="utf-8") as handle:
            handle.write('{"seq": 3, "payload": "torn')
        fragment = self.log.repair_tail()
        self.assertIsNotNone(fragment)
        self.assertIn("torn", fragment)
        events = self.log.read_events()
        self.assertEqual([event.payload for event in events], ["one", "two"])

    def test_the_next_append_after_a_torn_tail_continues_the_sequence(self):
        self.log.append("one")
        with open(self.log_path, "a", encoding="utf-8") as handle:
            handle.write('{"seq": 2, "pay')
        event = self.log.append("two")
        self.assertEqual(event.seq, 2, "the torn tail took no sequence number")
        events = self.log.read_events()
        self.assertEqual([e.payload for e in events], ["one", "two"])
        self.assertEqual([e.seq for e in events], [1, 2])

    def test_a_torn_tail_never_raises_a_corruption_error(self):
        self.log.append("one")
        with open(self.log_path, "a", encoding="utf-8") as handle:
            handle.write('{"seq": 2, "payload": "x"')
        # The reader must not raise: a half-written tail is not corruption.
        self.assertEqual(len(self.log.read_events()), 1)

    def test_a_corrupt_middle_line_still_raises(self):
        self.log.append("one")
        self.log.append("two")
        self._write_raw(
            '{"seq":1,"payload":"one","idempotency_key":"","record_hash":"x"}\n'
            "not json at all\n"
            '{"seq":3,"payload":"three","idempotency_key":"","record_hash":"y"}\n'
        )
        with self.assertRaises(lc.LogCorruptError):
            self.log.read_events()


class SidecarLockTests(LedgerConcurrencyTestCase):
    """Rule: the lock is on the sidecar file; readers stay lock-free."""

    def test_the_lock_lives_on_a_sidecar_file_not_on_the_log(self):
        self.assertEqual(self.log.lock_path, Path(str(self.log_path) + ".lock"))
        self.assertNotEqual(self.log.lock_path, self.log_path)
        self.assertEqual(lc.SidecarLock.SUFFIX, ".lock")

    def test_the_lock_file_is_created_on_the_sidecar(self):
        self.log.append("one")
        self.assertTrue(Path(str(self.log_path) + ".lock").exists())
        self.assertFalse(
            any(name.startswith("decisions.jsonl.") and name != "decisions.jsonl.lock"
                for name in os.listdir(self.dir)),
            "no lock file is placed next to the log other than the sidecar",
        )

    def test_a_reader_reads_the_log_while_the_writer_holds_the_lock(self):
        self.log.append("one")
        lock = lc.SidecarLock(self.log_path)
        lock.acquire()
        try:
            # The writer holds the sidecar lock; the reader is not blocked.
            events = self.log.read_events()
            self.assertEqual([event.payload for event in events], ["one"])
        finally:
            lock.release()

    def test_two_locks_on_the_same_path_are_mutually_exclusive(self):
        first = lc.SidecarLock(self.log_path)
        second = lc.SidecarLock(self.log_path)
        first.acquire()
        acquired = []

        def grab():
            try:
                second.acquire(timeout=0.2)
                acquired.append(True)
                second.release()
            except lc.LedgerConcurrencyError:
                acquired.append(False)

        thread = threading.Thread(target=grab)
        thread.start()
        thread.join()
        first.release()
        self.assertEqual(acquired, [False], "the second writer must wait")


class CheckThenAppendTests(LedgerConcurrencyTestCase):
    """Rule: read-decide-append is one transaction; repeats land one event."""

    def test_a_repeated_decision_lands_only_one_event(self):
        first, landed = self.log.update(
            key="ticket-1",
            check=lambda events: True,
            decide=lambda events: {"decision": "approved"},
            payload_of=lambda decision: "ticket-1 approved",
        )
        self.assertTrue(landed)
        second, landed_again = self.log.update(
            key="ticket-1",
            check=lambda events: True,
            decide=lambda events: {"decision": "approved"},
            payload_of=lambda decision: "ticket-1 approved",
        )
        self.assertFalse(landed_again, "the second caller must not append again")
        self.assertEqual(second.seq, first.seq)
        self.assertEqual(len(self.log.read_events()), 1)

    def test_two_concurrent_callers_racing_one_decision_land_one_event(self):
        results = []
        errors = []
        barrier = threading.Barrier(2)

        def decide_once():
            try:
                barrier.wait(timeout=5)
                outcome = self.log.update(
                    key="ticket-42",
                    check=lambda events: True,
                    decide=lambda events: {"decision": "approved"},
                    payload_of=lambda decision: "ticket-42 approved",
                )
                results.append(outcome)
            except BaseException as error:  # pragma: no cover - failure path
                errors.append(error)

        threads = [threading.Thread(target=decide_once) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 2)
        landed = [flag for _, flag in results]
        self.assertEqual(sorted(landed), [False, True], "exactly one caller lands it")
        events = self.log.read_events()
        self.assertEqual(len(events), 1, "the racing decision lands one event")
        self.assertEqual(events[0].idempotency_key, "ticket-42")

    def test_the_check_sees_the_events_as_they_are_inside_the_lock(self):
        self.log.append("prior")
        seen = {}

        def check(events):
            seen["count"] = len(events)
            return True

        self.log.update(
            key="k",
            check=check,
            decide=lambda events: {"n": len(events)},
            payload_of=lambda decision: "n",
        )
        self.assertEqual(seen["count"], 1, "the check saw the prior event")

    def test_a_check_that_no_longer_holds_writes_no_event(self):
        self.log.update(
            key="ticket-7",
            check=lambda events: True,
            decide=lambda events: {"d": "approved"},
            payload_of=lambda decision: "ticket-7 approved",
        )
        with self.assertRaises(lc.LedgerConcurrencyError):
            self.log.update(
                key="ticket-8",
                check=lambda events: False,
                decide=lambda events: {"d": "approved"},
                payload_of=lambda decision: "ticket-8 approved",
            )
        self.assertEqual(len(self.log.read_events()), 1, "no event was written")

    def test_a_decision_waits_for_a_ticket_still_awaiting_approval(self):
        """The Northstar-shaped check: 'is this ticket still awaiting approval?'"""
        state = {"awaiting": True}

        def check(events):
            return state["awaiting"]

        def decide(events):
            return {"decision": "approved"}

        event, landed = self.log.update(
            key="ticket-9",
            check=check,
            decide=decide,
            payload_of=lambda d: "ticket-9 approved",
        )
        self.assertTrue(landed)
        state["awaiting"] = False
        with self.assertRaises(lc.LedgerConcurrencyError):
            self.log.update(
                key="ticket-10",
                check=check,
                decide=decide,
                payload_of=lambda d: "ticket-10 approved",
            )
        self.assertEqual(len(self.log.read_events()), 1)

    def test_find_by_key_returns_the_landed_event(self):
        event, _ = self.log.update(
            key="k1",
            check=lambda events: True,
            decide=lambda events: {},
            payload_of=lambda d: "body",
        )
        found = self.log.find_by_key("k1")
        self.assertIsNotNone(found)
        self.assertEqual(found.seq, event.seq)
        self.assertIsNone(self.log.find_by_key("nope"))


class InfraFlagTests(unittest.TestCase):
    """Rule: a gate that never ran is Infra -- never the executor's failure."""

    def test_an_infra_signal_is_classified_infra(self):
        result = lc.classify_verification(signals=("sandbox_unreachable",))
        self.assertEqual(result.outcome, lc.OUTCOME_INFRA)
        self.assertTrue(result.infra)
        self.assertFalse(result.failed)

    def test_infra_is_never_counted_as_a_failure(self):
        results = (
            lc.classify_verification(signals=("sandbox_unreachable",)),
            lc.classify_verification(signals=("relay_unavailable",)),
            lc.classify_verification(exit_code=1, signals=("test_failed",)),
        )
        counts = lc.tally(results)
        self.assertEqual(counts["infra"], 2)
        self.assertEqual(counts["failed"], 1)
        self.assertEqual(counts["passed"], 0)

    def test_a_relay_http_status_is_infra(self):
        for status in (403, 429, 502):
            result = lc.classify_verification(http_status=status)
            self.assertEqual(result.outcome, lc.OUTCOME_INFRA, status)
            self.assertFalse(result.failed)

    def test_a_genuine_failure_is_classified_failed(self):
        result = lc.classify_verification(exit_code=1, signals=("test_failed",))
        self.assertEqual(result.outcome, lc.OUTCOME_FAILED)
        self.assertTrue(result.failed)
        self.assertFalse(result.infra)

    def test_a_nonzero_exit_without_an_infra_signal_is_the_executors_failure(self):
        result = lc.classify_verification(exit_code=2)
        self.assertEqual(result.outcome, lc.OUTCOME_FAILED)
        self.assertIn("executor", result.detail)

    def test_a_clean_run_is_passed(self):
        result = lc.classify_verification(exit_code=0)
        self.assertEqual(result.outcome, lc.OUTCOME_PASSED)
        self.assertTrue(result.passed)

    def test_the_source_docker_codes_are_kept_verbatim_and_are_not_northstars_own(self):
        """The source's 125/126/127 are Docker-specific; Northstar has its own list."""
        self.assertEqual(lc.SOURCE_DOCKER_INFRA_EXIT_CODES, (125, 126, 127))
        for code in lc.SOURCE_DOCKER_INFRA_EXIT_CODES:
            self.assertNotIn(code, lc.NORTHSTAR_INFRA_HTTP_STATUS)
        # The Northstar signal list is explicit and disjoint from the
        # agent-failure list.
        self.assertFalse(
            set(lc.NORTHSTAR_INFRA_SIGNALS) & set(lc.NORTHSTAR_AGENT_FAILURE_SIGNALS)
        )
        self.assertIn("sandbox_unreachable", lc.NORTHSTAR_INFRA_SIGNALS)
        self.assertIn("test_failed", lc.NORTHSTAR_AGENT_FAILURE_SIGNALS)

    def test_an_unknown_signal_is_not_silently_treated_as_infra(self):
        result = lc.classify_verification(exit_code=1, signals=("mystery_signal",))
        self.assertEqual(result.outcome, lc.OUTCOME_FAILED)


class DrivenPathTests(LedgerConcurrencyTestCase):
    """The full path, driven end to end: append, decide, verify, tally."""

    def test_the_whole_path_runs(self):
        # (a) two concurrent writers, gapless sequence.
        errors = []

        def writer(tag):
            try:
                for i in range(5):
                    self.log.append(f"{tag}-{i}")
            except BaseException as error:  # pragma: no cover
                errors.append(error)

        threads = [threading.Thread(target=writer, args=(t,)) for t in ("w1", "w2")]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertEqual([e.seq for e in self.log.read_events()], list(range(1, 11)))

        # (b) a torn tail is repaired, never a crash.
        with open(self.log_path, "a", encoding="utf-8") as handle:
            handle.write('{"seq": 11, "payload": "half')
        self.assertEqual(len(self.log.read_events()), 10)
        self.log.repair_tail()

        # (c) two writers race one approval decision: one event lands.
        outcomes = []
        barrier = threading.Barrier(2)

        def racer():
            barrier.wait(timeout=5)
            outcomes.append(
                self.log.update(
                    key="approval-1",
                    check=lambda events: True,
                    decide=lambda events: {"decision": "approved"},
                    payload_of=lambda d: "approval-1 approved",
                )
            )

        racers = [threading.Thread(target=racer) for _ in range(2)]
        for thread in racers:
            thread.start()
        for thread in racers:
            thread.join()
        self.assertEqual(sorted(flag for _, flag in outcomes), [False, True])

        # (d) a gate that never ran is Infra, and is not a rejection.
        infra = lc.classify_verification(signals=("relay_unavailable",))
        counts = lc.tally((infra,))
        self.assertEqual(counts["failed"], 0)
        self.assertEqual(counts["infra"], 1)

        # The log ends with exactly one event per append and one per decision.
        events = self.log.read_events()
        self.assertEqual(len(events), 11)
        self.assertEqual(
            [e.seq for e in events], list(range(1, 12)), "still gapless end to end"
        )
        self.assertEqual(
            sum(1 for e in events if e.idempotency_key == "approval-1"), 1
        )


class ModuleShapeTests(unittest.TestCase):
    """Rule: the module keeps the repo's house shape."""

    def test_version_and_schema_pins(self):
        self.assertEqual(lc.LEDGER_CONCURRENCY_VERSION, "ledger-concurrency.v1")
        self.assertEqual(lc.SCHEMA_PIN, "northstar.ledger-concurrency.v1")

    def test_the_module_is_stdlib_only(self):
        self.assertTrue(lc.stdlib_only())

    def test_the_three_outcomes_are_distinct(self):
        self.assertEqual(len(set(lc.OUTCOMES)), 3)
        self.assertEqual(lc.OUTCOMES, ("passed", "failed", "infra"))


if __name__ == "__main__":
    unittest.main()

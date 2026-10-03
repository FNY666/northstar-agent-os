"""Hybrid Logical Clock (HLC) for audit timestamps: pure clock rules,
producer stamping, export mapping, and the verify-side causality check."""
import sys
import unittest
from pathlib import Path

import support  # noqa: F401

_CONTRACT_ROOT = Path(__file__).resolve().parents[2] / "northstar-run-contract"
if str(_CONTRACT_ROOT) not in sys.path:
    sys.path.insert(0, str(_CONTRACT_ROOT))
import audit as normative_audit  # noqa: E402

from hlc import (
    C_MAX,
    L_MAX,
    HLCClock,
    pack,
    receive,
    tick,
    unpack,
)
from audit_chain import chain_records, verify_lines
from audit_export import record_to_audit, validate_audit_record
from sessions import SessionStore


def _stamp(l, c):
    return pack(l, c)


class TickRules(unittest.TestCase):
    def test_same_physical_time_advances_counter(self):
        l, c = tick((1000, 0), pt_ms=1000)
        self.assertEqual((l, c), (1000, 1))
        l, c = tick((l, c), pt_ms=1000)
        self.assertEqual((l, c), (1000, 2))

    def test_physical_time_advance_resets_counter(self):
        self.assertEqual(tick((1000, 7), pt_ms=1005), (1005, 0))

    def test_clock_behind_keeps_logical_time(self):
        # l already ahead of the physical clock: l' = max(l, pt) = l.
        self.assertEqual(tick((2000, 3), pt_ms=1000), (2000, 4))

    def test_repeated_ticks_are_strictly_increasing(self):
        state = (0, 0)
        prev = None
        for _ in range(50):
            state = tick(state, pt_ms=1000)
            self.assertTrue(prev is None or prev < state)
            prev = state

    def test_counter_overflow_advances_l_not_c(self):
        # Documented deviation: c never overflows the 16-bit field; l
        # advances by one millisecond instead, keeping the stamp greater.
        self.assertEqual(tick((1000, C_MAX), pt_ms=1000), (1001, 0))
        self.assertEqual(receive((1000, 0), 1000, C_MAX, pt_ms=1000), (1001, 0))


class ReceiveRules(unittest.TestCase):
    def test_merge_future_message(self):
        # l' ties the message: c' = c_msg + 1, strictly after the message.
        self.assertEqual(receive((0, 0), 1000, 5, pt_ms=100), (1000, 6))

    def test_merge_ties_both(self):
        # l' == l == l_msg: c' = max(c, c_msg) + 1.
        self.assertEqual(receive((1000, 7), 1000, 3, pt_ms=100), (1000, 8))
        self.assertEqual(receive((1000, 2), 1000, 9, pt_ms=100), (1000, 10))

    def test_merge_own_time_dominates(self):
        # l' == l > l_msg: c' = c + 1.
        self.assertEqual(receive((2000, 4), 1000, 9, pt_ms=100), (2000, 5))

    def test_physical_time_dominates_both(self):
        self.assertEqual(receive((1000, 4), 1000, 9, pt_ms=1500), (1500, 0))


class WireFormat(unittest.TestCase):
    def test_pack_unpack_roundtrip(self):
        self.assertEqual(unpack(pack(1727865600000, 3)), (1727865600000, 3))
        self.assertEqual(unpack(pack(0, 0)), (0, 0))
        self.assertEqual(unpack(pack(L_MAX, C_MAX)), (L_MAX, C_MAX))

    def test_unpack_rejects_garbage(self):
        for bad in ("", "abc", "1:2:3", ":3", "1:", "-1:2", "1:-2",
                    "1.5:2", " 1:2", "1:2 ", None, 12, (1, 2),
                    f"{L_MAX + 1}:0", f"0:{C_MAX + 1}"):
            self.assertIsNone(unpack(bad), f"unpack({bad!r}) should be None")

    def test_pack_rejects_out_of_range(self):
        for l, c in ((-1, 0), (0, -1), (L_MAX + 1, 0), (0, C_MAX + 1)):
            with self.assertRaises(ValueError):
                pack(l, c)


class TwoWriterSkewedClocks(unittest.TestCase):
    """The money test: two writers with skewed clocks, causally ordered.

    Writer A is 100ms *ahead* of writer B (B's wall clock lags). A's event
    causally precedes B's (B read A's record before appending). Wall-clock
    order inverts; HLC order does not.
    """

    def test_causality_survives_clock_skew(self):
        # A ticks at its physical time 1000.
        a_state = tick((0, 0), pt_ms=1000)
        stamp_a = pack(*a_state)
        # B's physical clock reads 900 for the same instant. B merges A's
        # stamp (the receive rule) before stamping its own event.
        b_state = receive((0, 0), a_state[0], a_state[1], pt_ms=900)
        stamp_b = pack(*b_state)
        # HLC: B's stamp is strictly after A's — causality preserved.
        self.assertLess(unpack(stamp_a), unpack(stamp_b))
        # Wall clock: B's physical reading (900) is *before* A's (1000) —
        # the inversion HLC exists to fix.
        self.assertLess(900, 1000)
        # And the chain continues: A later observes B's stamp.
        a2 = receive(a_state, b_state[0], b_state[1], pt_ms=1010)
        self.assertLess(unpack(stamp_b), a2)

    def test_hlc_clock_class(self):
        clock = HLCClock()
        first = clock.tick(pt_ms=500)
        second = clock.tick(pt_ms=500)
        self.assertLess(unpack(first), unpack(second))
        self.assertTrue(clock.receive("999:0", pt_ms=500))
        third = clock.tick(pt_ms=500)
        self.assertLess(unpack(second), unpack(third))
        # Malformed input never corrupts the clock.
        before = clock.state
        self.assertFalse(clock.receive("garbage"))
        self.assertEqual(clock.state, before)


class ProducerStamping(unittest.TestCase):
    def test_appends_carry_nondecreasing_hlc(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            store = SessionStore(directory=tmp, session_id="hlc-test")
            stamps = []
            for _ in range(5):
                record = store.append("informational", {"note": "x"})
                stamps.append(unpack(record["hlc"]))
            for earlier, later in zip(stamps, stamps[1:]):
                self.assertLessEqual(earlier, later)

    def test_merge_hlc_advances_later_stamps(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            store = SessionStore(directory=tmp, session_id="hlc-merge")
            first = store.append("informational")["hlc"]
            # Another writer's stamp far in the "future".
            self.assertTrue(store.merge_hlc(_stamp(9_999_999_999_999, 0)))
            second = store.append("informational")["hlc"]
            self.assertLess(unpack(first), unpack(second))
            self.assertLessEqual((9_999_999_999_999, 0), unpack(second))
            self.assertFalse(store.merge_hlc("not-a-stamp"))


class ExportMapping(unittest.TestCase):
    def _transcript_record(self, **overrides):
        record = {
            "index": 0,
            "ts": "2026-10-03T10:00:00.000Z",
            "session_id": "s1",
            "type": "informational",
        }
        record.update(overrides)
        return record

    def test_hlc_maps_to_top_level_not_payload(self):
        audit = record_to_audit(self._transcript_record(hlc="1727865600000:3"))
        self.assertEqual(audit["hlc"], "1727865600000:3")
        self.assertNotIn("hlc", audit["payload"])

    def test_missing_hlc_stays_missing(self):
        audit = record_to_audit(self._transcript_record())
        self.assertNotIn("hlc", audit)
        self.assertEqual(validate_audit_record(audit), ())

    def test_malformed_hlc_fails_export_loudly(self):
        with self.assertRaises(ValueError):
            record_to_audit(self._transcript_record(hlc="bogus"))

    def test_validator_accepts_good_rejects_bad(self):
        good = record_to_audit(self._transcript_record(hlc="1:0"))
        self.assertEqual(validate_audit_record(good), ())
        for bad in ("1:2:3", "-1:0", f"{L_MAX + 1}:0", f"0:{C_MAX + 1}"):
            rec = dict(good)
            rec["hlc"] = bad
            self.assertTrue(validate_audit_record(rec), f"{bad} should fail")

    def test_contract_parity_on_hlc(self):
        """The normative validator must agree with the mirror on hlc."""
        for stamp in ("1727865600000:3", "0:0", "1:2:3", "bogus"):
            rec = record_to_audit(self._transcript_record())
            rec["hlc"] = stamp
            mirror = validate_audit_record(rec)
            normative = normative_audit.validate_record(rec)
            self.assertEqual(bool(mirror), bool(normative),
                             f"parity break on hlc={stamp!r}: {mirror} vs {normative}")


def _chained_feed(hlc_stamps):
    """Build a chained feed; hlc_stamps[i] is the stamp for record i
    (None = record carries no hlc)."""
    records = []
    for i, stamp in enumerate(hlc_stamps):
        record = {
            "schema_version": "audit.ndjson/1",
            "component": "northstar-agent-runtime",
            "event": "informational",
            "seq": i,
            "ts": f"2026-10-03T10:00:{i:02d}.000Z",
            "level": "info",
            "payload": {},
        }
        if stamp is not None:
            record["hlc"] = stamp
        records.append(record)
    chained = chain_records(records, component="northstar-agent-runtime",
                            session_id="hlc-verify")
    import json
    return [json.dumps(r, sort_keys=True) for r in chained]


class VerifyCausality(unittest.TestCase):
    def test_ordered_stamps_verify(self):
        lines = _chained_feed([_stamp(1000, 0), _stamp(1000, 1), _stamp(1001, 0)])
        result = verify_lines(lines)
        self.assertTrue(result.ok, result.reason)
        self.assertEqual(result.causality_violation, "")

    def test_inverted_stamps_fail_with_causality_violation(self):
        lines = _chained_feed([_stamp(1000, 5), _stamp(1000, 2), _stamp(1001, 0)])
        result = verify_lines(lines)
        self.assertFalse(result.ok)
        self.assertEqual(result.causality_violation, "causality-inversion")
        self.assertEqual(result.broken_at, 2)  # 1-based physical line number
        self.assertIn("causality inversion", result.reason)

    def test_legacy_feed_without_hlc_verifies_unchanged(self):
        lines = _chained_feed([None, None, None])
        result = verify_lines(lines)
        self.assertTrue(result.ok, result.reason)

    def test_mixed_feed_skips_unstamped_pairs(self):
        lines = _chained_feed([_stamp(1000, 0), None, _stamp(1001, 0)])
        result = verify_lines(lines)
        self.assertTrue(result.ok, result.reason)

    def test_unparseable_stamp_is_skipped_not_fatal(self):
        lines = _chained_feed([_stamp(1000, 0), "garbage", _stamp(1001, 0)])
        result = verify_lines(lines)
        self.assertTrue(result.ok, result.reason)

    def test_equal_stamps_are_not_an_inversion(self):
        # Non-decreasing is the enforced invariant; equality can arise when
        # a producer appends without merging (offline re-seal).
        lines = _chained_feed([_stamp(1000, 0), _stamp(1000, 0)])
        result = verify_lines(lines)
        self.assertTrue(result.ok, result.reason)


if __name__ == "__main__":
    unittest.main()

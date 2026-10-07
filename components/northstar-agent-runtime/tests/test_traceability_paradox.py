"""Tests for traceability_paradox: GAP, REORDER, HASH_BREAK detection."""

import hashlib
import unittest

from traceability_paradox import (
    SCHEMA_PIN,
    TRACEABILITY_PARADOX_VERSION,
    ParadoxFinding,
    ParadoxType,
    TraceabilityParadoxError,
    classify_paradox,
    detect_paradox,
    jcs_canonical_json,
    paradox_audit_event,
    scan_paradoxes,
)

_SEAL = ("prev_hash", "chain_hash", "signature")
_GENESIS = "00" * 32


def _seal(body, prev_hash):
    clean = {k: v for k, v in body.items() if k not in _SEAL}
    chain_hash = hashlib.sha256(
        bytes.fromhex(prev_hash) + jcs_canonical_json(clean)
    ).hexdigest()
    return {**clean, "prev_hash": prev_hash, "chain_hash": chain_hash}


def _chained_log(n=3):
    records = []
    prev = _GENESIS
    for i in range(1, n + 1):
        rec = _seal(
            {
                "seq": i,
                "ts": f"2026-10-07T20:00:0{i}",
                "action": f"action-{i}",
            },
            prev,
        )
        records.append(rec)
        prev = rec["chain_hash"]
    return records


class VersionPinTests(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(TRACEABILITY_PARADOX_VERSION, "traceability-paradox.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.traceability-paradox.v1")


class CleanLogTests(unittest.TestCase):
    def test_clean_chained_log_is_silent(self):
        self.assertFalse(detect_paradox(_chained_log()))
        self.assertEqual(scan_paradoxes(_chained_log()), [])

    def test_unchained_log_is_silent(self):
        log = [
            {"seq": 1, "ts": "2026-10-07T20:00:00"},
            {"seq": 2, "ts": "2026-10-07T20:00:01"},
        ]
        self.assertFalse(detect_paradox(log))

    def test_empty_log_is_silent(self):
        self.assertFalse(detect_paradox([]))
        self.assertIsNone(classify_paradox([]))

    def test_no_seq_no_ts_log_is_silent(self):
        self.assertFalse(detect_paradox([{"a": 1}, {"b": 2}]))


class GapTests(unittest.TestCase):
    def test_seq_gap_fires(self):
        log = _chained_log(4)
        # delete record 3 but keep the chain consistent: reseal from record 4
        kept = [log[0], log[1], log[3]]
        resealed = []
        prev = _GENESIS
        for rec in kept:
            resealed.append(_seal(
                {"seq": rec["seq"], "ts": rec["ts"], "action": rec["action"]},
                prev,
            ))
            prev = resealed[-1]["chain_hash"]
        findings = scan_paradoxes(resealed)
        self.assertTrue(any(f.paradox_type is ParadoxType.GAP for f in findings))
        # chain itself still verifies - only the gap fires
        self.assertFalse(any(f.paradox_type is ParadoxType.HASH_BREAK for f in findings))

    def test_duplicate_seq_fires(self):
        log = _chained_log(2)
        dup = dict(log[1])
        dup["seq"] = 1
        findings = scan_paradoxes(log[:1] + [dup])
        self.assertTrue(any(f.paradox_type is ParadoxType.GAP for f in findings))

    def test_seq_not_required_on_any_record(self):
        log = [{"ts": "2026-10-07T20:00:00"}, {"ts": "2026-10-07T20:00:01"}]
        self.assertFalse(detect_paradox(log))

    def test_non_integer_seq_raises(self):
        with self.assertRaises(TraceabilityParadoxError):
            scan_paradoxes([{"seq": "1"}, {"seq": "2"}])


class ReorderTests(unittest.TestCase):
    def test_ts_out_of_order_fires(self):
        log = [
            {"seq": 1, "ts": "2026-10-07T20:00:02"},
            {"seq": 2, "ts": "2026-10-07T20:00:01"},
        ]
        findings = scan_paradoxes(log)
        self.assertTrue(
            any(f.paradox_type is ParadoxType.REORDER for f in findings)
        )

    def test_numeric_ts_out_of_order_fires(self):
        log = [{"seq": 1, "ts": 200}, {"seq": 2, "ts": 100}]
        findings = scan_paradoxes(log)
        self.assertTrue(
            any(f.paradox_type is ParadoxType.REORDER for f in findings)
        )

    def test_equal_ts_is_not_reorder(self):
        log = [
            {"seq": 1, "ts": "2026-10-07T20:00:00"},
            {"seq": 2, "ts": "2026-10-07T20:00:00"},
        ]
        self.assertFalse(detect_paradox(log))

    def test_missing_ts_skips_reorder_check(self):
        log = [{"seq": 1, "ts": 200}, {"seq": 2}]
        self.assertFalse(detect_paradox(log))


class HashBreakTests(unittest.TestCase):
    def test_tampered_body_breaks_chain(self):
        log = _chained_log(2)
        log[1] = dict(log[1])
        log[1]["action"] = "malicious-action"
        findings = scan_paradoxes(log)
        self.assertTrue(
            any(f.paradox_type is ParadoxType.HASH_BREAK for f in findings)
        )

    def test_swapped_records_break_chain(self):
        log = _chained_log(2)
        findings = scan_paradoxes([log[1], log[0]])
        self.assertTrue(
            any(f.paradox_type is ParadoxType.HASH_BREAK for f in findings)
        )

    def test_partial_seal_breaks(self):
        log = [{"seq": 1, "prev_hash": _GENESIS}]
        findings = scan_paradoxes(log)
        self.assertTrue(
            any(f.paradox_type is ParadoxType.HASH_BREAK for f in findings)
        )

    def test_bad_prev_hash_format_breaks(self):
        log = [
            {"seq": 1, "prev_hash": "not-hex", "chain_hash": "00" * 32},
        ]
        findings = scan_paradoxes(log)
        self.assertTrue(
            any(f.paradox_type is ParadoxType.HASH_BREAK for f in findings)
        )


class ClassifyTests(unittest.TestCase):
    def test_classify_returns_most_severe(self):
        log = _chained_log(2)
        log[1] = dict(log[1])
        log[1]["action"] = "evil"
        log[1]["seq"] = 99  # gap + hash break
        self.assertEqual(classify_paradox(log), ParadoxType.HASH_BREAK)

    def test_classify_gap_when_only_gap(self):
        log = _chained_log(3)
        # reseal with a gap so only GAP fires
        resealed = []
        prev = _GENESIS
        for rec in (log[0], log[2]):
            resealed.append(_seal(
                {"seq": rec["seq"], "ts": rec["ts"], "action": rec["action"]},
                prev,
            ))
            prev = resealed[-1]["chain_hash"]
        self.assertEqual(classify_paradox(resealed), ParadoxType.GAP)

    def test_classify_none_on_clean(self):
        self.assertIsNone(classify_paradox(_chained_log()))


class InputValidationTests(unittest.TestCase):
    def test_non_mapping_record_raises(self):
        with self.assertRaises(TypeError):
            scan_paradoxes([{"seq": 1}, "not-a-record"])

    def test_non_sequence_log_raises(self):
        with self.assertRaises(TypeError):
            scan_paradoxes({"seq": 1})

    def test_finding_validation(self):
        with self.assertRaises(ValueError):
            ParadoxFinding(index=-1, paradox_type=ParadoxType.GAP, detail="x")
        with self.assertRaises(TypeError):
            ParadoxFinding(index=0, paradox_type="gap", detail="x")
        with self.assertRaises(ValueError):
            ParadoxFinding(index=0, paradox_type=ParadoxType.GAP, detail="")
        with self.assertRaises(TypeError):
            ParadoxFinding(index=True, paradox_type=ParadoxType.GAP, detail="x")

    def test_findings_are_frozen(self):
        f = ParadoxFinding(index=0, paradox_type=ParadoxType.GAP, detail="x")
        with self.assertRaises(Exception):
            f.index = 5  # type: ignore[misc]


class AuditEventTests(unittest.TestCase):
    def test_audit_event_shape(self):
        findings = scan_paradoxes([{"seq": 1, "prev_hash": _GENESIS}])
        event = paradox_audit_event(findings, 7)
        self.assertEqual(event["schema"], SCHEMA_PIN)
        self.assertEqual(event["seq"], 7)
        self.assertTrue(event["paradox_found"])
        self.assertEqual(event["findings"][0]["type"], "hash-break")

    def test_audit_event_clean(self):
        event = paradox_audit_event([], 0)
        self.assertFalse(event["paradox_found"])
        self.assertEqual(event["findings"], [])

    def test_audit_event_bad_seq_raises(self):
        with self.assertRaises(TraceabilityParadoxError):
            paradox_audit_event([], -1)


if __name__ == "__main__":
    unittest.main()

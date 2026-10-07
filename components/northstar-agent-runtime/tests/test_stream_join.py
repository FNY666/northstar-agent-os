"""Tests for stream_join."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from stream_join import (  # noqa: E402
    AUDIT_FORMAT,
    SCHEMA_PIN,
    STREAM_JOIN_VERSION,
    JoinedPair,
    StreamEvent,
    StreamJoin,
    stream_join_audit_event,
)


def _event(event_id, key="k", timestamp=1, payload=None):
    return StreamEvent(
        event_id=event_id, key=key, timestamp=timestamp,
        payload={} if payload is None else payload,
    )


class TestVersionPin(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(STREAM_JOIN_VERSION, "stream-join.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.stream-join.v1")
        self.assertEqual(AUDIT_FORMAT, "audit.ndjson/1")


class TestEventValidation(unittest.TestCase):
    def test_bool_timestamp_rejected(self):
        with self.assertRaises(TypeError):
            _event("e", timestamp=True)

    def test_negative_timestamp_rejected(self):
        with self.assertRaises(ValueError):
            _event("e", timestamp=-1)

    def test_str_timestamp_rejected(self):
        with self.assertRaises(TypeError):
            _event("e", timestamp="10")  # type: ignore[arg-type]

    def test_empty_id_rejected(self):
        with self.assertRaises(ValueError):
            _event("")

    def test_bool_id_rejected(self):
        with self.assertRaises(TypeError):
            _event(True)  # type: ignore[arg-type]

    def test_empty_key_rejected(self):
        with self.assertRaises(ValueError):
            _event("e", key="")

    def test_bool_key_rejected(self):
        with self.assertRaises(TypeError):
            _event("e", key=True)  # type: ignore[arg-type]

    def test_non_mapping_payload_rejected(self):
        with self.assertRaises(TypeError):
            StreamEvent(event_id="e", key="k", timestamp=1, payload=[("a", 1)])  # type: ignore[arg-type]

    def test_non_str_payload_key_rejected(self):
        with self.assertRaises(TypeError):
            _event("e", payload={1: "x"})  # type: ignore[dict-item]

    def test_payload_copied(self):
        src = {"v": 1}
        ev = _event("e", payload=src)
        src["v"] = 99
        self.assertEqual(dict(ev.payload), {"v": 1})

    def test_frozen(self):
        ev = _event("e")
        with self.assertRaises(Exception):
            ev.timestamp = 5  # type: ignore[misc]

    def test_as_dict(self):
        d = _event("e", key="k", timestamp=7, payload={"v": 1}).as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["event_id"], "e")
        self.assertEqual(d["timestamp"], 7)


class TestIngest(unittest.TestCase):
    def test_duplicate_left_id_rejected(self):
        sj = StreamJoin()
        sj.add_left(_event("e"))
        with self.assertRaises(ValueError):
            sj.add_left(_event("e"))

    def test_duplicate_right_id_rejected(self):
        sj = StreamJoin()
        sj.add_right(_event("e"))
        with self.assertRaises(ValueError):
            sj.add_right(_event("e"))

    def test_same_id_both_sides_allowed(self):
        sj = StreamJoin()
        sj.add_left(_event("e"))
        sj.add_right(_event("e"))
        self.assertEqual(len(sj.left()), 1)
        self.assertEqual(len(sj.right()), 1)

    def test_non_event_rejected(self):
        sj = StreamJoin()
        with self.assertRaises(TypeError):
            sj.add_left({"event_id": "e"})  # type: ignore[arg-type]


class TestExactJoin(unittest.TestCase):
    def test_exact_match(self):
        sj = StreamJoin()
        sj.add_left(_event("l", timestamp=5))
        sj.add_right(_event("r", timestamp=5))
        pairs = sj.join()
        self.assertEqual(len(pairs), 1)
        self.assertEqual((pairs[0].left_id, pairs[0].right_id), ("l", "r"))

    def test_key_mismatch_no_pair(self):
        sj = StreamJoin()
        sj.add_left(_event("l", key="a", timestamp=5))
        sj.add_right(_event("r", key="b", timestamp=5))
        self.assertEqual(sj.join(), ())

    def test_timestamp_mismatch_no_pair(self):
        sj = StreamJoin()
        sj.add_left(_event("l", timestamp=5))
        sj.add_right(_event("r", timestamp=6))
        self.assertEqual(sj.join(), ())

    def test_empty_streams(self):
        self.assertEqual(StreamJoin().join(), ())

    def test_deterministic_order(self):
        sj = StreamJoin()
        sj.add_left(_event("l2", timestamp=5))
        sj.add_left(_event("l1", timestamp=5))
        sj.add_right(_event("r2", timestamp=5))
        sj.add_right(_event("r1", timestamp=5))
        ids = [(p.left_id, p.right_id) for p in sj.join()]
        self.assertEqual(ids, [("l1", "r1"), ("l1", "r2"), ("l2", "r1"), ("l2", "r2")])

    def test_pair_digest_deterministic(self):
        sj = StreamJoin()
        sj.add_left(_event("l", timestamp=5, payload={"x": 1}))
        sj.add_right(_event("r", timestamp=5, payload={"y": 2}))
        a = sj.join()[0].digest
        sj2 = StreamJoin()
        sj2.add_left(_event("l", timestamp=5, payload={"x": 999}))
        sj2.add_right(_event("r", timestamp=5, payload={"y": -1}))
        b = sj2.join()[0].digest
        self.assertEqual(a, b, "digest must bind identity, not payload")
        self.assertTrue(a.startswith("sha256:"))

    def test_pair_verify(self):
        l, r = _event("l", timestamp=5), _event("r", timestamp=5)
        sj = StreamJoin()
        sj.add_left(l)
        sj.add_right(r)
        pair = sj.join()[0]
        self.assertTrue(pair.verify(l, r))
        self.assertFalse(pair.verify(r, l))
        self.assertFalse(pair.verify(_event("l", timestamp=6), r))

    def test_pair_verify_key_mismatch(self):
        l, r = _event("l", key="a", timestamp=5), _event("r", key="a", timestamp=5)
        sj = StreamJoin()
        sj.add_left(l)
        sj.add_right(r)
        pair = sj.join()[0]
        self.assertFalse(pair.verify(_event("l", key="b", timestamp=5), r))

    def test_pair_record_frozen(self):
        pair = JoinedPair(
            left_id="l", right_id="r", key="k",
            left_timestamp=1, right_timestamp=2, digest="sha256:abc",
        )
        with self.assertRaises(Exception):
            pair.left_id = "x"  # type: ignore[misc]


class TestWindowedJoin(unittest.TestCase):
    def _two_windows(self):
        sj = StreamJoin()
        sj.add_left(_event("l1", timestamp=10))
        sj.add_left(_event("l2", timestamp=25))
        sj.add_right(_event("r1", timestamp=15))
        sj.add_right(_event("r2", timestamp=29))
        return sj

    def test_same_window_pairs(self):
        sj = self._two_windows()
        ids = {(p.left_id, p.right_id) for p in sj.windowed_join(10)}
        self.assertEqual(ids, {("l1", "r1"), ("l2", "r2")})

    def test_boundary_assignment(self):
        sj = StreamJoin()
        sj.add_left(_event("l", timestamp=10))
        sj.add_right(_event("r", timestamp=19))
        sj.add_right(_event("r2", timestamp=20))
        self.assertEqual(len(sj.windowed_join(10)), 1)

    def test_key_still_required(self):
        sj = StreamJoin()
        sj.add_left(_event("l", key="a", timestamp=10))
        sj.add_right(_event("r", key="b", timestamp=12))
        self.assertEqual(sj.windowed_join(10), ())

    def test_zero_window_rejected(self):
        with self.assertRaises(ValueError):
            StreamJoin().windowed_join(0)

    def test_negative_window_rejected(self):
        with self.assertRaises(ValueError):
            StreamJoin().windowed_join(-3)

    def test_bool_window_rejected(self):
        with self.assertRaises(TypeError):
            StreamJoin().windowed_join(True)  # type: ignore[arg-type]

    def test_str_window_rejected(self):
        with self.assertRaises(TypeError):
            StreamJoin().windowed_join("10")  # type: ignore[arg-type]

    def test_wide_window_matches_all(self):
        sj = self._two_windows()
        self.assertEqual(len(sj.windowed_join(1000)), 4)


class TestIntervalJoin(unittest.TestCase):
    def _setup(self):
        sj = StreamJoin()
        sj.add_left(_event("l", timestamp=10))
        sj.add_right(_event("r0", timestamp=4))   # below lower bound -5
        sj.add_right(_event("r1", timestamp=5))   # on lower bound
        sj.add_right(_event("r2", timestamp=15))  # on upper bound
        sj.add_right(_event("r3", timestamp=16))  # above upper bound
        return sj

    def test_within_bounds_pairs(self):
        ids = {(p.left_id, p.right_id) for p in self._setup().interval_join(-5, 5)}
        self.assertEqual(ids, {("l", "r1"), ("l", "r2")})

    def test_asymmetric_bounds(self):
        ids = {(p.left_id, p.right_id) for p in self._setup().interval_join(0, 100)}
        self.assertEqual(ids, {("l", "r2"), ("l", "r3")})

    def test_negative_bounds_only(self):
        sj = StreamJoin()
        sj.add_left(_event("l", timestamp=10))
        sj.add_right(_event("r1", timestamp=5))
        sj.add_right(_event("r2", timestamp=12))
        ids = {(p.left_id, p.right_id) for p in sj.interval_join(-10, -1)}
        self.assertEqual(ids, {("l", "r1")})

    def test_lower_above_upper_rejected(self):
        with self.assertRaises(ValueError):
            StreamJoin().interval_join(5, 4)

    def test_bool_bound_rejected(self):
        with self.assertRaises(TypeError):
            StreamJoin().interval_join(True, 5)  # type: ignore[arg-type]

    def test_key_still_required(self):
        sj = StreamJoin()
        sj.add_left(_event("l", key="a", timestamp=10))
        sj.add_right(_event("r", key="b", timestamp=12))
        self.assertEqual(sj.interval_join(-5, 5), ())


class TestAuditEvent(unittest.TestCase):
    def test_shape(self):
        ev = stream_join_audit_event("joined", 3, count=2)
        self.assertEqual(ev["format"], "audit.ndjson/1")
        self.assertEqual(ev["schema"], SCHEMA_PIN)
        self.assertEqual(ev["kind"], "joined")
        self.assertEqual(ev["count"], 2)
        self.assertEqual(ev["seq"], 3)

    def test_default_count_zero(self):
        self.assertEqual(stream_join_audit_event("joined", 0)["count"], 0)

    def test_all_kinds(self):
        for kind in ("left-ingested", "right-ingested", "joined",
                     "windowed-joined", "interval-joined"):
            self.assertEqual(stream_join_audit_event(kind, 0)["kind"], kind)

    def test_bad_kind_rejected(self):
        with self.assertRaises(ValueError):
            stream_join_audit_event("bogus", 0)

    def test_bad_seq_rejected(self):
        with self.assertRaises(TypeError):
            stream_join_audit_event("joined", True)

    def test_negative_count_rejected(self):
        with self.assertRaises(ValueError):
            stream_join_audit_event("joined", 0, count=-1)

    def test_bool_count_rejected(self):
        with self.assertRaises(TypeError):
            stream_join_audit_event("joined", 0, count=True)


class TestMain(unittest.TestCase):
    def test_main_runs(self):
        import stream_join

        stream_join.main()


if __name__ == "__main__":
    unittest.main()

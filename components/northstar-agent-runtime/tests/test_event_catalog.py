"""Tests for event_catalog (AsyncAPI-shaped event schema ledger)."""

import threading
import unittest

import event_catalog
from event_catalog import EventCatalog


def fresh() -> EventCatalog:
    return EventCatalog()


GOOD_DEF = {
    "type": "object",
    "properties": {
        "user_id": {"type": "string"},
        "age": {"type": "integer"},
        "score": {"type": "number"},
        "active": {"type": "boolean"},
        "tags": {"type": "array"},
        "meta": {"type": "object"},
        "note": {"type": "null"},
    },
    "required": ["user_id"],
}


def register_user(cat: EventCatalog, seq: int, eid: str = "user.created.v1"):
    return cat.schema(eid, "UserCreated", "user/created", GOOD_DEF, seq)


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(event_catalog.EVENT_CATALOG_VERSION, "event-catalog.v1")
        self.assertEqual(
            event_catalog.EVENT_CATALOG_SCHEMA, "northstar.event-catalog.v1"
        )
        self.assertEqual(event_catalog.AUDIT_SCHEMA, "audit.ndjson/1")

    def test_stdlib_only(self):
        self.assertTrue(
            event_catalog._stdlib_only(event_catalog.__file__)
        )

    def test_main(self):
        event_catalog.main()


class TestSchema(unittest.TestCase):
    def test_schema_roundtrip(self):
        cat = fresh()
        rec = register_user(cat, 1)
        self.assertTrue(rec.verify())
        self.assertEqual(rec.topic, "user/created")
        self.assertEqual(cat.event("user.created.v1"), rec)
        self.assertEqual(cat.event_ids(), ("user.created.v1",))

    def test_schema_duplicate_refused(self):
        cat = fresh()
        register_user(cat, 1)
        with self.assertRaises(event_catalog.DuplicateEventError):
            register_user(cat, 2)
        # failed mutation consumed its seq
        register_user(cat, 3, eid="order.placed.v1")

    def test_schema_bad_inputs(self):
        cat = fresh()
        bad_defs = [
            ("not-a-mapping",),
            ({"type": "array"},),  # root type unsupported
            ({"type": "object", "properties": {"x": {"type": "uuid"}}},),  # unpinned
            ({"type": "object", "properties": "nope"},),
            ({"type": "object", "required": ["missing"]},),
        ]
        seq = 1
        for (d,) in bad_defs:
            seq += 1
            with self.assertRaises(event_catalog.BadSchemaError):
                cat.schema("e.bad", "Bad", "bad/topic", d, seq)
        seq += 1
        with self.assertRaises(event_catalog.BadEventError):
            cat.schema("has space", "Bad", "bad/topic", GOOD_DEF, seq)
        seq += 1
        with self.assertRaises(event_catalog.BadEventError):
            cat.schema("e.bad2", "Bad", "bad topic", GOOD_DEF, seq)


class TestDiscover(unittest.TestCase):
    def test_discover_topic_prefix_and_name(self):
        cat = fresh()
        register_user(cat, 1)
        cat.schema("order.placed.v1", "OrderPlaced", "order/placed", GOOD_DEF, 2)
        r = cat.discover("user/", 1)
        self.assertTrue(r.verify())
        self.assertEqual(r.event_ids, ("user.created.v1",))
        r2 = cat.discover("orderplaced", 1)
        self.assertEqual(r2.event_ids, ("order.placed.v1",))

    def test_discover_no_match_is_data(self):
        cat = fresh()
        register_user(cat, 1)
        r = cat.discover("billing/", 1)
        self.assertTrue(r.verify())
        self.assertEqual(r.event_ids, ())

    def test_discover_read_view_seq_not_consumed(self):
        cat = fresh()
        register_user(cat, 1)
        cat.discover("user/", 1)  # read view: smaller seq fine
        self.assertEqual(cat.stats()["last_seq"], 1)


class TestValidate(unittest.TestCase):
    def test_validate_valid_payload(self):
        cat = fresh()
        register_user(cat, 1)
        r = cat.validate(
            "user.created.v1",
            {"user_id": "u-1", "age": 30, "score": 1.5, "active": True,
             "tags": [], "meta": {}, "note": None},
            2,
        )
        self.assertTrue(r.valid)
        self.assertEqual(r.violations, ())
        self.assertTrue(r.verify())

    def test_validate_violations_are_data(self):
        cat = fresh()
        register_user(cat, 1)
        r = cat.validate(
            "user.created.v1", {"age": "thirty", "active": "yes"}, 2
        )
        self.assertFalse(r.valid)
        self.assertEqual(len(r.violations), 3)  # missing user_id + 2 type errs
        self.assertTrue(r.verify())

    def test_validate_unknown_event_and_bad_payload(self):
        cat = fresh()
        with self.assertRaises(event_catalog.UnknownEventError):
            cat.validate("nope.v1", {}, 1)
        register_user(cat, 2)
        with self.assertRaises(event_catalog.BadPayloadError):
            cat.validate("user.created.v1", ["not", "a", "mapping"], 3)


class TestSeqDiscipline(unittest.TestCase):
    def test_seq_rewind_and_bool_refused(self):
        cat = fresh()
        register_user(cat, 1)
        for bad in (1, True, -5, 1.5, "2"):
            with self.assertRaises(event_catalog.SeqOrderError):
                cat.validate("user.created.v1", {}, bad)

    def test_failed_mutation_consumes_seq(self):
        cat = fresh()
        register_user(cat, 1)
        with self.assertRaises(event_catalog.DuplicateEventError):
            register_user(cat, 2)  # burns 2
        rec = register_user(cat, 3, eid="order.placed.v1")  # 3 is fine
        self.assertTrue(rec.verify())


class TestAudit(unittest.TestCase):
    def test_audit_shapes_and_boundary(self):
        cat = fresh()
        register_user(cat, 1)
        r = cat.validate("user.created.v1", {"user_id": "u-1"}, 2)
        rows = cat.audit_log()
        kinds = [row["kind"] for row in rows]
        self.assertIn("event-registered", kinds)
        self.assertIn("event-validated", kinds)
        for row in rows:
            self.assertEqual(row["schema"], event_catalog.AUDIT_SCHEMA)
            # schema definitions and payload bytes never cross the boundary
            blob = repr(row)
            self.assertNotIn("u-1", blob)
            self.assertNotIn("properties", blob)
        ev = event_catalog.event_catalog_audit_event("rejected", 9, "e1")
        self.assertEqual(ev["kind"], "rejected")
        with self.assertRaises(event_catalog.AuditKindError):
            event_catalog.event_catalog_audit_event("bogus", 9)

    def test_concurrency_smoke(self):
        cat = fresh()
        register_user(cat, 1)
        errors = []

        def worker(i: int):
            try:
                cat.validate("user.created.v1", {"user_id": f"u-{i}"}, 2 + i * 100)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()

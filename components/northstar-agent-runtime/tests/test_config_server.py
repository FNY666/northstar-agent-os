"""Targeted tests for config_server.py."""

import unittest

from config_server import (
    AUDIT_FORMAT,
    CONFIG_SERVER_VERSION,
    SCHEMA_PIN,
    ConfigServer,
    ConfigServerError,
    DigestConflictError,
    PropertyRecord,
    RefreshReport,
    ResolvedValue,
    UnknownApplicationError,
    UnknownKeyError,
    config_server_audit_event,
)


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(CONFIG_SERVER_VERSION, "config-server.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.config-server.v1")

    def test_audit_format(self):
        self.assertEqual(AUDIT_FORMAT, "audit.ndjson/1")


class TestSetGet(unittest.TestCase):
    def setUp(self):
        self.server = ConfigServer()

    def test_set_returns_frozen_record(self):
        record = self.server.set("app", "default", "k", "v", seq=1)
        self.assertIsInstance(record, PropertyRecord)
        with self.assertRaises(Exception):
            record.key = "other"  # frozen
        self.assertTrue(record.value_digest.startswith("sha256:"))

    def test_get_roundtrip(self):
        self.server.set("app", "default", "k", "v", seq=1)
        got = self.server.get("app", "default", "k", seq=2)
        self.assertIsInstance(got, ResolvedValue)
        self.assertEqual(got.value, "v")

    def test_profile_precedence(self):
        self.server.set("app", "default", "timeout", 3000, seq=1)
        self.server.set("app", "prod", "timeout", 1500, seq=2)
        got = self.server.get("app", "prod", "timeout", seq=3)
        self.assertEqual(got.value, 1500)
        self.assertEqual(got.source, "app+profile+label")

    def test_profile_falls_back_to_default(self):
        self.server.set("app", "default", "timeout", 3000, seq=1)
        got = self.server.get("app", "staging", "timeout", seq=2)
        self.assertEqual(got.value, 3000)
        self.assertEqual(got.source, "app+default-profile+label")

    def test_label_falls_back_to_main(self):
        self.server.set("app", "default", "timeout", 3000, seq=1)
        got = self.server.get("app", "default", "timeout", seq=2, label="feature-x")
        self.assertEqual(got.value, 3000)
        self.assertEqual(got.source, "app+default-profile+main")

    def test_label_profile_wins(self):
        self.server.set("app", "prod", "k", "main-val", seq=1)
        self.server.set("app", "prod", "k", "feature-val", seq=2, label="feature-x")
        got = self.server.get("app", "prod", "k", seq=3, label="feature-x")
        self.assertEqual(got.value, "feature-val")
        self.assertEqual(got.source, "app+profile+label")

    def test_record_digest_determinism(self):
        self.server.set("app", "default", "k", "v", seq=1)
        a = self.server.get("app", "default", "k", seq=2)
        b = self.server.get("app", "default", "k", seq=3)
        self.assertEqual(a.record_digest, b.record_digest)
        self.assertEqual(a.value_digest, b.value_digest)

    def test_overwrite_bumps_version(self):
        r1 = self.server.set("app", "default", "k", "v1", seq=1)
        r2 = self.server.set("app", "default", "k", "v2", seq=2)
        self.assertEqual(r2.version, r1.version + 1)
        self.assertEqual(self.server.get("app", "default", "k", seq=3).value, "v2")

    def test_bool_value_ok_but_bool_key_refused(self):
        self.server.set("app", "default", "flag", True, seq=1)
        self.assertTrue(self.server.get("app", "default", "flag", seq=2).value)
        with self.assertRaises(TypeError):
            self.server.set("app", "default", True, "v", seq=3)

    def test_expected_digest_match(self):
        r = self.server.set("app", "default", "k", "v", seq=1)
        self.server.set("app", "default", "k", "v2", seq=2, expected_digest=r.value_digest)

    def test_expected_digest_conflict(self):
        self.server.set("app", "default", "k", "v", seq=1)
        with self.assertRaises(DigestConflictError):
            self.server.set(
                "app", "default", "k", "v2", seq=2,
                expected_digest="sha256:deadbeef",
            )

    def test_unknown_app_on_get(self):
        with self.assertRaises(UnknownApplicationError):
            self.server.get("nope", "default", "k", seq=1)

    def test_unknown_key(self):
        self.server.set("app", "default", "k", "v", seq=1)
        with self.assertRaises(UnknownKeyError):
            self.server.get("app", "default", "missing", seq=2)

    def test_bad_inputs(self):
        with self.assertRaises(TypeError):
            self.server.set("app", "default", "k", "v", seq=True)
        with self.assertRaises(ValueError):
            self.server.set("app", "default", "k", "v", seq=-1)
        with self.assertRaises(ValueError):
            self.server.set("app", "default", "", "v", seq=1)
        with self.assertRaises(ValueError):
            self.server.set("app", "default", "k", float("nan"), seq=1)
        with self.assertRaises(TypeError):
            self.server.get("app", "default", 123, seq=1)


class TestDelete(unittest.TestCase):
    def setUp(self):
        self.server = ConfigServer()

    def test_delete_hides_key(self):
        self.server.set("app", "default", "k", "v", seq=1)
        self.server.delete("app", "default", "k", seq=2)
        with self.assertRaises(UnknownKeyError):
            self.server.get("app", "default", "k", seq=3)

    def test_delete_unknown_refused(self):
        with self.assertRaises(UnknownKeyError):
            self.server.delete("app", "default", "k", seq=1)

    def test_delete_bumps_version(self):
        v1 = self.server.version("app")
        self.server.set("app", "default", "k", "v", seq=1)
        v2 = self.server.version("app")
        self.server.delete("app", "default", "k", seq=2)
        self.assertGreater(self.server.version("app"), v2)
        self.assertGreater(v2, v1)


class TestRefresh(unittest.TestCase):
    def setUp(self):
        self.server = ConfigServer()
        self.server.set("app", "default", "a", 1, seq=1)
        self.server.set("app", "default", "b", 2, seq=2)

    def test_refresh_reports_all_changes_first_time(self):
        report = self.server.refresh("app", seq=10)
        self.assertIsInstance(report, RefreshReport)
        self.assertEqual(report.from_version, 0)
        self.assertEqual(report.to_version, 2)
        self.assertEqual(set(report.changed_keys), {"a", "b"})
        self.assertTrue(report.report_digest.startswith("sha256:"))

    def test_second_refresh_empty(self):
        self.server.refresh("app", seq=10)
        report = self.server.refresh("app", seq=11)
        self.assertEqual(report.changed_keys, ())
        self.assertEqual(report.from_version, report.to_version)

    def test_refresh_after_mutation(self):
        self.server.refresh("app", seq=10)
        self.server.set("app", "default", "c", 3, seq=11)
        report = self.server.refresh("app", seq=12)
        self.assertEqual(report.changed_keys, ("c",))
        self.assertEqual(report.from_version, 2)
        self.assertEqual(report.to_version, 3)

    def test_refresh_unknown_app(self):
        with self.assertRaises(UnknownApplicationError):
            self.server.refresh("nope", seq=1)

    def test_refresh_label_isolation(self):
        self.server.refresh("app", seq=10)
        self.server.set("app", "default", "c", 3, seq=11, label="feature-x")
        main = self.server.refresh("app", seq=12)
        self.assertEqual(main.changed_keys, ())
        feat = self.server.refresh("app", seq=13, label="feature-x")
        self.assertEqual(feat.changed_keys, ("c",))

    def test_report_digest_determinism(self):
        r1 = self.server.refresh("app", seq=10)
        self.server._refreshed_at[("app", "main")] = 0  # reset view, not versions
        r2 = self.server.refresh("app", seq=11)
        self.assertEqual(r1.report_digest, r2.report_digest)

    def test_refresh_bad_seq(self):
        with self.assertRaises((TypeError, ValueError)):
            self.server.refresh("app", seq=-1)


class TestViews(unittest.TestCase):
    def setUp(self):
        self.server = ConfigServer()
        self.server.set("app", "default", "b", 1, seq=1)
        self.server.set("app", "default", "a", 2, seq=2)

    def test_keys_sorted(self):
        self.assertEqual(self.server.keys("app", "default"), ("a", "b"))

    def test_keys_exact_profile_only(self):
        self.server.set("app", "prod", "c", 3, seq=3)
        self.assertEqual(self.server.keys("app", "prod"), ("c",))
        self.assertEqual(self.server.keys("app", "default"), ("a", "b"))

    def test_version_starts_zero(self):
        self.assertEqual(self.server.version("fresh"), 0)


class TestAudit(unittest.TestCase):
    def test_all_kinds(self):
        for kind in ("property-set", "property-read", "property-deleted",
                     "refreshed", "rejected"):
            rec = config_server_audit_event(kind, seq=1)
            self.assertEqual(rec["kind"], kind)
            self.assertEqual(rec["format"], "audit.ndjson/1")
            self.assertEqual(rec["schema"], SCHEMA_PIN)

    def test_bad_kind(self):
        with self.assertRaises(ValueError):
            config_server_audit_event("bogus", seq=1)

    def test_bad_seq(self):
        with self.assertRaises((TypeError, ValueError)):
            config_server_audit_event("refreshed", seq=-1)


class TestMain(unittest.TestCase):
    def test_main_runs(self):
        from config_server import main
        main()


if __name__ == "__main__":
    unittest.main()

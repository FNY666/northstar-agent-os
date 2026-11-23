"""Targeted tests for feature_flags.py."""

import unittest

from feature_flags import (
    BUCKETS,
    FEATURE_FLAGS_VERSION,
    SCHEMA_PIN,
    FeatureFlag,
    FlagManager,
    is_enabled,
)


def make_flag(**kwargs):
    args = {"name": "test-flag", "enabled": True, "rollout_pct": 50}
    args.update(kwargs)
    return FeatureFlag(**args)


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(FEATURE_FLAGS_VERSION, "feature-flags.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.feature-flags.v1")
        self.assertEqual(make_flag().schema, SCHEMA_PIN)


class TestFeatureFlagValidation(unittest.TestCase):
    def test_frozen(self):
        flag = make_flag()
        with self.assertRaises(Exception):
            flag.enabled = False

    def test_empty_name_rejected(self):
        with self.assertRaises(ValueError):
            make_flag(name="")

    def test_non_str_name_rejected(self):
        with self.assertRaises(TypeError):
            make_flag(name=123)

    def test_nul_name_rejected(self):
        with self.assertRaises(ValueError):
            make_flag(name="a\x00b")

    def test_non_bool_enabled_rejected(self):
        with self.assertRaises(TypeError):
            make_flag(enabled=1)
        with self.assertRaises(TypeError):
            make_flag(enabled="yes")

    def test_bool_rollout_rejected(self):
        with self.assertRaises(TypeError):
            make_flag(rollout_pct=True)

    def test_negative_rollout_rejected(self):
        with self.assertRaises(ValueError):
            make_flag(rollout_pct=-1)

    def test_over_100_rollout_rejected(self):
        with self.assertRaises(ValueError):
            make_flag(rollout_pct=100.1)

    def test_nan_inf_rollout_rejected(self):
        with self.assertRaises(ValueError):
            make_flag(rollout_pct=float("nan"))
        with self.assertRaises(ValueError):
            make_flag(rollout_pct=float("inf"))

    def test_int_rollout_normalized_to_float(self):
        self.assertEqual(make_flag(rollout_pct=50).rollout_pct, 50.0)
        self.assertIsInstance(make_flag(rollout_pct=50).rollout_pct, float)

    def test_non_str_description_rejected(self):
        with self.assertRaises(TypeError):
            make_flag(description=42)

    def test_wrong_schema_rejected(self):
        with self.assertRaises(ValueError):
            FeatureFlag(
                name="x", enabled=True, rollout_pct=10, schema="bogus"
            )

    def test_as_dict(self):
        d = FeatureFlag(
            name="f", enabled=False, rollout_pct=12.5, description="d"
        ).as_dict()
        self.assertEqual(
            d,
            {
                "name": "f",
                "enabled": False,
                "rollout_pct": 12.5,
                "description": "d",
                "schema": SCHEMA_PIN,
            },
        )


class TestIsEnabled(unittest.TestCase):
    def test_disabled_flag_off_for_everyone(self):
        flag = make_flag(enabled=False, rollout_pct=100)
        for i in range(200):
            self.assertFalse(is_enabled(flag, f"user-{i}"))

    def test_zero_pct_off_for_everyone(self):
        flag = make_flag(rollout_pct=0)
        for i in range(200):
            self.assertFalse(is_enabled(flag, f"user-{i}"))

    def test_hundred_pct_on_for_everyone(self):
        flag = make_flag(rollout_pct=100)
        for i in range(200):
            self.assertTrue(is_enabled(flag, f"user-{i}"))

    def test_deterministic(self):
        flag = make_flag(rollout_pct=33.3)
        for i in range(100):
            sid = f"subject-{i}"
            self.assertEqual(is_enabled(flag, sid), is_enabled(flag, sid))

    def test_both_outcomes_occur_at_50(self):
        flag = make_flag(rollout_pct=50)
        outcomes = {is_enabled(flag, f"user-{i}") for i in range(2000)}
        self.assertEqual(outcomes, {True, False})

    def test_half_rollout_roughly_half(self):
        flag = make_flag(rollout_pct=50)
        on = sum(is_enabled(flag, f"user-{i}") for i in range(4000))
        self.assertGreater(on, 1600)
        self.assertLess(on, 2400)

    def test_different_flags_differ(self):
        a = make_flag(name="flag-a", rollout_pct=50)
        b = make_flag(name="flag-b", rollout_pct=50)
        diffs = sum(
            is_enabled(a, f"user-{i}") != is_enabled(b, f"user-{i}")
            for i in range(500)
        )
        self.assertGreater(diffs, 0)

    def test_non_flag_rejected(self):
        with self.assertRaises(TypeError):
            is_enabled("not-a-flag", "user-1")

    def test_non_str_subject_rejected(self):
        with self.assertRaises(TypeError):
            is_enabled(make_flag(), 123)

    def test_empty_subject_rejected(self):
        with self.assertRaises(ValueError):
            is_enabled(make_flag(), "")


class TestFlagManager(unittest.TestCase):
    def make_mgr(self):
        mgr = FlagManager()
        mgr.register(FeatureFlag(name="beta", enabled=True, rollout_pct=100))
        mgr.register(FeatureFlag(name="alpha", enabled=True, rollout_pct=0))
        return mgr

    def test_register_and_get(self):
        mgr = self.make_mgr()
        self.assertEqual(mgr.get("beta").name, "beta")

    def test_duplicate_register_rejected(self):
        mgr = self.make_mgr()
        with self.assertRaises(ValueError):
            mgr.register(FeatureFlag(name="beta", enabled=True, rollout_pct=10))

    def test_get_unknown_keyerror(self):
        with self.assertRaises(KeyError):
            self.make_mgr().get("nope")

    def test_set_enabled(self):
        mgr = self.make_mgr()
        new = mgr.set_enabled("beta", False)
        self.assertFalse(new.enabled)
        self.assertFalse(mgr.get("beta").enabled)
        self.assertFalse(mgr.is_enabled("beta", "user-1"))

    def test_set_enabled_bad_type(self):
        with self.assertRaises(TypeError):
            self.make_mgr().set_enabled("beta", 1)

    def test_set_rollout(self):
        mgr = self.make_mgr()
        new = mgr.set_rollout("alpha", 100)
        self.assertEqual(new.rollout_pct, 100.0)
        self.assertTrue(mgr.is_enabled("alpha", "user-1"))

    def test_set_rollout_bad_value(self):
        with self.assertRaises(ValueError):
            self.make_mgr().set_rollout("alpha", 101)

    def test_set_rollout_unknown_keyerror(self):
        with self.assertRaises(KeyError):
            self.make_mgr().set_rollout("nope", 10)

    def test_remove(self):
        mgr = self.make_mgr()
        mgr.remove("beta")
        with self.assertRaises(KeyError):
            mgr.get("beta")

    def test_remove_unknown_keyerror(self):
        with self.assertRaises(KeyError):
            self.make_mgr().remove("nope")

    def test_flag_names_sorted(self):
        mgr = FlagManager()
        mgr.register(FeatureFlag(name="zeta", enabled=True, rollout_pct=10))
        mgr.register(FeatureFlag(name="mid", enabled=True, rollout_pct=10))
        mgr.register(FeatureFlag(name="abc", enabled=True, rollout_pct=10))
        self.assertEqual(mgr.flag_names(), ("abc", "mid", "zeta"))

    def test_snapshot_order(self):
        mgr = self.make_mgr()
        snap = mgr.snapshot()
        self.assertEqual([f.name for f in snap], ["alpha", "beta"])

    def test_evaluate_all(self):
        mgr = self.make_mgr()
        result = mgr.evaluate_all("user-1")
        self.assertEqual(result, {"alpha": False, "beta": True})

    def test_evaluate_all_bad_subject(self):
        with self.assertRaises(TypeError):
            self.make_mgr().evaluate_all(7)

    def test_audit_event(self):
        mgr = self.make_mgr()
        flag = mgr.get("beta")
        ev = mgr.flag_audit_event("disabled", flag, seq=3)
        self.assertEqual(ev["type"], "feature-flag")
        self.assertEqual(ev["kind"], "disabled")
        self.assertEqual(ev["audit_seq"], 3)
        self.assertEqual(ev["schema"], SCHEMA_PIN)
        self.assertEqual(ev["flag"]["name"], "beta")

    def test_audit_event_bad_kind(self):
        mgr = self.make_mgr()
        with self.assertRaises(ValueError):
            mgr.flag_audit_event("nonsense", mgr.get("beta"), seq=0)

    def test_audit_event_bad_seq(self):
        mgr = self.make_mgr()
        with self.assertRaises(TypeError):
            mgr.flag_audit_event("registered", mgr.get("beta"), seq=True)
        with self.assertRaises(ValueError):
            mgr.flag_audit_event("registered", mgr.get("beta"), seq=-1)

    def test_main_self_check(self):
        import feature_flags

        feature_flags.main()


if __name__ == "__main__":
    unittest.main()

"""Tests for load_generator: Locust-style user-population bookkeeping."""

import threading
import unittest

from load_generator import (
    AUDIT_KINDS,
    LOAD_GENERATOR_VERSION,
    MAX_RAMP_STAGES,
    MAX_USERS_PER_SPAWN,
    MAX_WAIT_MS,
    SCHEMA_PIN,
    WAIT_DISTRIBUTIONS,
    BadStageError,
    BadWaitError,
    BadWeightError,
    DuplicateScenarioError,
    DuplicateUserClassError,
    LoadGenerator,
    LoadGeneratorError,
    RampPlan,
    RampStage,
    ScenarioPlan,
    SeqOrderError,
    SpawnLimitError,
    SpawnReport,
    UnknownRampError,
    UnknownScenarioError,
    UnknownSpawnError,
    UnknownUserClassError,
    UserClass,
    load_generator_audit_event,
    main,
)


def _gen_with_shop():
    gen = LoadGenerator()
    gen.define_user_class(
        "browse", 3, 0, wait_min_ms=1000, wait_max_ms=3000,
        wait_dist="uniform",
    )
    gen.define_user_class("checkout", 1, 1)
    gen.scenario(
        "shop",
        [("browse", 3), ("checkout", 1)],
        [("view", 5), ("buy", 1)],
        2,
    )
    return gen


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(LOAD_GENERATOR_VERSION, "load-generator.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.load-generator.v1")

    def test_wait_distributions(self):
        self.assertEqual(
            WAIT_DISTRIBUTIONS, ("constant", "uniform", "exponential")
        )

    def test_audit_kinds(self):
        self.assertIn("users-spawned", AUDIT_KINDS)
        self.assertIn("ramp-defined", AUDIT_KINDS)
        self.assertIn("rejected", AUDIT_KINDS)


class TestUserClass(unittest.TestCase):
    def test_define_roundtrip(self):
        gen = LoadGenerator()
        record = gen.define_user_class("api", 2, 0)
        self.assertIsInstance(record, UserClass)
        self.assertEqual(record.class_id, "api")
        self.assertEqual(record.weight, 2)
        self.assertEqual(record.wait_dist, "constant")
        self.assertTrue(record.digest.startswith("sha256:"))
        self.assertIs(gen.user_class("api"), record)
        self.assertEqual(gen.user_class_ids(), ("api",))

    def test_duplicate_refused(self):
        gen = LoadGenerator()
        gen.define_user_class("api", 2, 0)
        with self.assertRaises(DuplicateUserClassError):
            gen.define_user_class("api", 2, 1)

    def test_zero_weight_refused(self):
        gen = LoadGenerator()
        with self.assertRaises(BadWeightError):
            gen.define_user_class("api", 0, 0)

    def test_bool_weight_refused(self):
        gen = LoadGenerator()
        with self.assertRaises(BadWeightError):
            gen.define_user_class("api", True, 0)

    def test_inverted_wait_refused(self):
        gen = LoadGenerator()
        with self.assertRaises(BadWaitError):
            gen.define_user_class(
                "api", 1, 0, wait_min_ms=500, wait_max_ms=100
            )

    def test_unknown_dist_refused(self):
        gen = LoadGenerator()
        with self.assertRaises(BadWaitError):
            gen.define_user_class("api", 1, 0, wait_dist="weibull")

    def test_constant_requires_equal_window(self):
        gen = LoadGenerator()
        with self.assertRaises(BadWaitError):
            gen.define_user_class(
                "api", 1, 0, wait_min_ms=100, wait_max_ms=200
            )
        ok = gen.define_user_class(
            "api", 1, 1, wait_min_ms=150, wait_max_ms=150
        )
        self.assertEqual(ok.wait_min_ms, ok.wait_max_ms)

    def test_wait_ceiling_refused(self):
        gen = LoadGenerator()
        with self.assertRaises(BadWaitError):
            gen.define_user_class(
                "api", 1, 0, wait_min_ms=0,
                wait_max_ms=MAX_WAIT_MS + 1, wait_dist="uniform",
            )

    def test_unknown_class_lookup(self):
        gen = LoadGenerator()
        with self.assertRaises(UnknownUserClassError):
            gen.user_class("ghost")


class TestScenario(unittest.TestCase):
    def test_scenario_roundtrip(self):
        gen = _gen_with_shop()
        plan = gen.scenario_plan("shop")
        self.assertIsInstance(plan, ScenarioPlan)
        self.assertEqual(
            plan.user_classes, (("browse", 3), ("checkout", 1))
        )
        self.assertEqual(
            [(t.name, t.weight) for t in plan.tasks],
            [("view", 5), ("buy", 1)],
        )
        self.assertTrue(plan.digest.startswith("sha256:"))
        self.assertEqual(gen.scenario_ids(), ("shop",))

    def test_duplicate_scenario_refused(self):
        gen = _gen_with_shop()
        with self.assertRaises(DuplicateScenarioError):
            gen.scenario(
                "shop", [("browse", 1)], [("view", 1)], 3
            )

    def test_unknown_class_in_mix_refused(self):
        gen = LoadGenerator()
        gen.define_user_class("api", 1, 0)
        with self.assertRaises(UnknownUserClassError):
            gen.scenario(
                "s", [("ghost", 1)], [("view", 1)], 1
            )

    def test_empty_tasks_refused(self):
        gen = LoadGenerator()
        gen.define_user_class("api", 1, 0)
        with self.assertRaises(LoadGeneratorError):
            gen.scenario("s", [("api", 1)], [], 1)

    def test_duplicate_task_name_refused(self):
        gen = LoadGenerator()
        gen.define_user_class("api", 1, 0)
        with self.assertRaises(LoadGeneratorError):
            gen.scenario(
                "s", [("api", 1)],
                [("view", 1), ("view", 2)], 1,
            )

    def test_unknown_scenario_lookup(self):
        gen = LoadGenerator()
        with self.assertRaises(UnknownScenarioError):
            gen.scenario_plan("ghost")


class TestSpawn(unittest.TestCase):
    def test_spawn_split(self):
        gen = _gen_with_shop()
        report = gen.spawn("shop", 40, 3)
        self.assertIsInstance(report, SpawnReport)
        self.assertEqual(report.spawn_id, "spawn-1")
        self.assertEqual(len(report.users), 40)
        counts = {}
        for user in report.users:
            counts[user.class_id] = counts.get(user.class_id, 0) + 1
        self.assertEqual(counts, {"browse": 30, "checkout": 10})

    def test_user_ids_monotonic(self):
        gen = _gen_with_shop()
        report = gen.spawn("shop", 5, 3)
        self.assertEqual(
            [u.user_id for u in report.users],
            ["user-1", "user-2", "user-3", "user-4", "user-5"],
        )

    def test_wait_bounds(self):
        gen = _gen_with_shop()
        report = gen.spawn("shop", 40, 3)
        for user in report.users:
            if user.class_id == "checkout":
                self.assertEqual(user.wait_ms, 0)
            else:
                self.assertGreaterEqual(user.wait_ms, 1000)
                self.assertLessEqual(user.wait_ms, 3000)

    def test_deterministic_replay(self):
        first = _gen_with_shop().spawn("shop", 25, 3)
        second = _gen_with_shop().spawn("shop", 25, 3)
        self.assertEqual(
            [u.wait_ms for u in first.users],
            [u.wait_ms for u in second.users],
        )
        self.assertEqual(
            [u.digest for u in first.users],
            [u.digest for u in second.users],
        )

    def test_spawn_ceiling_refused(self):
        gen = _gen_with_shop()
        with self.assertRaises(SpawnLimitError):
            gen.spawn("shop", MAX_USERS_PER_SPAWN + 1, 3)

    def test_zero_count_refused(self):
        gen = _gen_with_shop()
        with self.assertRaises(SpawnLimitError):
            gen.spawn("shop", 0, 3)

    def test_unknown_scenario_refused(self):
        gen = _gen_with_shop()
        with self.assertRaises(UnknownScenarioError):
            gen.spawn("ghost", 10, 3)

    def test_unknown_spawn_lookup(self):
        gen = LoadGenerator()
        with self.assertRaises(UnknownSpawnError):
            gen.spawn_report("spawn-9")


class TestRamp(unittest.TestCase):
    def test_ramp_roundtrip(self):
        gen = _gen_with_shop()
        plan = gen.ramp("shop", [(10, 20), (10, 40)], 3)
        self.assertIsInstance(plan, RampPlan)
        self.assertEqual(plan.ramp_id, "ramp-1")
        self.assertEqual(plan.peak_users, 40)
        self.assertEqual(plan.total_spawn_deltas, 40)
        self.assertTrue(plan.digest.startswith("sha256:"))
        self.assertIs(gen.ramp_plan("ramp-1"), plan)

    def test_users_at_interpolation(self):
        gen = _gen_with_shop()
        gen.ramp("shop", [(10, 20), (10, 40)], 3)
        self.assertEqual(gen.users_at("ramp-1", 0), 0)
        self.assertEqual(gen.users_at("ramp-1", 5), 10)
        self.assertEqual(gen.users_at("ramp-1", 10), 20)
        self.assertEqual(gen.users_at("ramp-1", 15), 30)
        self.assertEqual(gen.users_at("ramp-1", 20), 40)
        self.assertEqual(gen.users_at("ramp-1", 1000), 40)

    def test_ramp_down_interpolation(self):
        gen = _gen_with_shop()
        gen.ramp("shop", [(10, 40), (10, 0)], 3)
        self.assertEqual(gen.users_at("ramp-1", 15), 20)

    def test_empty_stages_refused(self):
        gen = _gen_with_shop()
        with self.assertRaises(BadStageError):
            gen.ramp("shop", [], 3)

    def test_negative_target_refused(self):
        gen = _gen_with_shop()
        with self.assertRaises(BadStageError):
            gen.ramp("shop", [(10, -5)], 3)

    def test_target_ceiling_refused(self):
        gen = _gen_with_shop()
        with self.assertRaises(BadStageError):
            gen.ramp("shop", [(10, MAX_USERS_PER_SPAWN + 1)], 3)

    def test_negative_tick_refused(self):
        gen = _gen_with_shop()
        gen.ramp("shop", [(10, 20)], 3)
        with self.assertRaises(LoadGeneratorError):
            gen.users_at("ramp-1", -1)

    def test_unknown_ramp_refused(self):
        gen = LoadGenerator()
        with self.assertRaises(UnknownRampError):
            gen.users_at("ramp-9", 0)

    def test_ramp_stage_records(self):
        stage = RampStage(10, 25)
        self.assertEqual(
            stage.as_dict(),
            {"duration_seqs": 10, "target_users": 25},
        )
        with self.assertRaises(BadStageError):
            RampStage(-1, 5)
        with self.assertRaises(BadStageError):
            RampStage(10, True)


class TestSeqAndAudit(unittest.TestCase):
    def test_seq_rewind_refused(self):
        gen = LoadGenerator()
        gen.define_user_class("api", 1, 5)
        with self.assertRaises(SeqOrderError):
            gen.define_user_class("api2", 1, 4)

    def test_bool_seq_refused(self):
        gen = LoadGenerator()
        with self.assertRaises(LoadGeneratorError):
            gen.define_user_class("api", 1, True)

    def test_audit_event_shape(self):
        event = load_generator_audit_event(
            "users-spawned", 3, {"spawn_id": "spawn-1"}
        )
        self.assertEqual(event["schema"], "northstar.audit.ndjson/1")
        self.assertEqual(event["module"], "load-generator.v1")
        self.assertEqual(event["event"], "users-spawned")
        self.assertEqual(event["audit_seq"], 3)
        self.assertEqual(event["spawn_id"], "spawn-1")

    def test_unknown_audit_kind_refused(self):
        with self.assertRaises(LoadGeneratorError):
            load_generator_audit_event("bogus", 0, {})

    def test_thread_safety(self):
        gen = LoadGenerator()
        gen.define_user_class("api", 1, 0)
        gen.scenario("s", [("api", 1)], [("t", 1)], 1)
        errors = []
        turn = {"next": 0}
        turn_lock = threading.Lock()
        turn_event = threading.Condition(turn_lock)

        def worker(n):
            try:
                with turn_event:
                    while turn["next"] != n:
                        turn_event.wait()
                    gen.spawn("s", 4, 2 + n)
                    turn["next"] += 1
                    turn_event.notify_all()
            except LoadGeneratorError as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        user_ids = []
        for spawn_id in ("spawn-1", "spawn-2", "spawn-3", "spawn-4"):
            report = gen.spawn_report(spawn_id)
            user_ids.extend(u.user_id for u in report.users)
        self.assertEqual(len(set(user_ids)), 16)

    def test_main_self_check(self):
        main()


if __name__ == "__main__":
    unittest.main()

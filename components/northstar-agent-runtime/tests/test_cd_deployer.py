"""Tests for cd_deployer: progressive-delivery orchestration state machine."""

import unittest

from cd_deployer import (
    AUDIT_KINDS,
    CD_DEPLOYER_VERSION,
    DEFAULT_CANARY_STEPS,
    SCHEMA_PIN,
    STRATEGIES,
    AdvanceReport,
    CDDeployer,
    CDDeployerError,
    DeploymentInProgressError,
    DeploymentRecord,
    DeploymentStatus,
    NoLiveDeploymentError,
    RollbackReport,
    RolloutStep,
    ServiceRecord,
    UnknownServiceError,
    cd_deployer_audit_event,
    main,
)


class VersionPinTests(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(CD_DEPLOYER_VERSION, "cd-deployer.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.cd-deployer.v1")

    def test_strategies_closed(self):
        self.assertEqual(STRATEGIES, ("canary", "blue_green", "rolling", "recreate"))


class RegisterServiceTests(unittest.TestCase):
    def setUp(self):
        self.deployer = CDDeployer()

    def test_register_happy_path(self):
        record = self.deployer.register_service("svc", "v1.0.0", seq=0)
        self.assertIsInstance(record, ServiceRecord)
        self.assertEqual(record.service, "svc")
        self.assertEqual(record.stable_version, "v1.0.0")
        self.assertTrue(record.digest.startswith("sha256:"))

    def test_register_duplicate(self):
        self.deployer.register_service("svc", "v1.0.0", seq=0)
        with self.assertRaises(CDDeployerError):
            self.deployer.register_service("svc", "v1.0.0", seq=1)

    def test_register_bad_inputs(self):
        with self.assertRaises(TypeError):
            self.deployer.register_service("", "v1.0.0", seq=0)
        with self.assertRaises(TypeError):
            self.deployer.register_service("svc", "", seq=0)
        with self.assertRaises(TypeError):
            self.deployer.register_service("svc", "v1.0.0", seq=True)
        with self.assertRaises(TypeError):
            self.deployer.register_service("svc", "v1.0.0", seq=-1)

    def test_service_record_frozen(self):
        record = self.deployer.register_service("svc", "v1.0.0", seq=0)
        with self.assertRaises(Exception):
            record.service = "other"  # type: ignore[misc]


class DeployTests(unittest.TestCase):
    def setUp(self):
        self.deployer = CDDeployer()
        self.deployer.register_service("svc", "v1.0.0", seq=0)

    def test_deploy_canary_default_ladder(self):
        record = self.deployer.deploy("svc", "v1.1.0", "canary", seq=1)
        self.assertIsInstance(record, DeploymentRecord)
        self.assertEqual(record.strategy, "canary")
        self.assertEqual([s.target_pct for s in record.steps],
                         [1.0, 5.0, 25.0, 50.0, 100.0])
        self.assertTrue(record.digest.startswith("sha256:"))

    def test_deploy_unknown_service(self):
        with self.assertRaises(UnknownServiceError):
            self.deployer.deploy("nope", "v1.1.0", "canary", seq=1)

    def test_deploy_unknown_strategy(self):
        with self.assertRaises(CDDeployerError):
            self.deployer.deploy("svc", "v1.1.0", "teleport", seq=1)

    def test_deploy_same_version_as_stable(self):
        with self.assertRaises(CDDeployerError):
            self.deployer.deploy("svc", "v1.0.0", "canary", seq=1)

    def test_deploy_while_in_progress(self):
        self.deployer.deploy("svc", "v1.1.0", "canary", seq=1)
        with self.assertRaises(DeploymentInProgressError):
            self.deployer.deploy("svc", "v1.2.0", "rolling", seq=2)

    def test_deploy_bad_inputs(self):
        with self.assertRaises(TypeError):
            self.deployer.deploy("", "v1.1.0", "canary", seq=1)
        with self.assertRaises(TypeError):
            self.deployer.deploy("svc", "v1.1.0", "canary", seq=True)

    def test_blue_green_steps(self):
        record = self.deployer.deploy("svc", "v1.1.0", "blue_green", seq=1)
        names = [s.name for s in record.steps]
        self.assertEqual(names, ["provision-green", "verify-green", "cutover"])
        pcts = [s.target_pct for s in record.steps]
        self.assertEqual(pcts, [0.0, 0.0, 100.0])

    def test_rolling_and_recreate_steps(self):
        record = self.deployer.deploy("svc", "v1.1.0", "rolling", seq=1)
        self.assertEqual(len(record.steps), 4)
        self.assertEqual(record.steps[-1].target_pct, 100.0)
        self.deployer.rollback("svc", seq=2)
        record = self.deployer.deploy("svc", "v1.1.0", "recreate", seq=3)
        self.assertEqual(len(record.steps), 1)
        self.assertEqual(record.steps[0].name, "replace-all")


class CanaryStepsTests(unittest.TestCase):
    def setUp(self):
        self.deployer = CDDeployer()
        self.deployer.register_service("svc", "v1.0.0", seq=0)

    def test_canary_explicit_steps(self):
        record = self.deployer.canary("svc", "v1.1.0", (10.0, 50.0, 100.0), seq=1)
        self.assertEqual([s.target_pct for s in record.steps], [10.0, 50.0, 100.0])

    def test_canary_steps_validation(self):
        with self.assertRaises(TypeError):  # empty
            self.deployer.canary("svc", "v1.1.0", (), seq=1)
        with self.assertRaises(ValueError):  # not strictly increasing
            self.deployer.canary("svc", "v1.1.0", (10.0, 10.0, 100.0), seq=1)
        with self.assertRaises(ValueError):  # not ending at 100
            self.deployer.canary("svc", "v1.1.0", (10.0, 50.0), seq=1)
        with self.assertRaises(TypeError):  # bool pct
            self.deployer.canary("svc", "v1.1.0", (10.0, True, 100.0), seq=1)
        with self.assertRaises(ValueError):  # zero pct
            self.deployer.canary("svc", "v1.1.0", (0.0, 100.0), seq=1)
        with self.assertRaises(ValueError):  # NaN
            self.deployer.canary("svc", "v1.1.0", (10.0, float("nan"), 100.0), seq=1)
        with self.assertRaises(ValueError):  # > 100
            self.deployer.canary("svc", "v1.1.0", (10.0, 150.0), seq=1)
        with self.assertRaises(UnknownServiceError):
            self.deployer.canary("nope", "v1.1.0", (100.0,), seq=1)


class AdvanceTests(unittest.TestCase):
    def setUp(self):
        self.deployer = CDDeployer()
        self.deployer.register_service("svc", "v1.0.0", seq=0)

    def test_advance_canary_to_completion(self):
        self.deployer.canary("svc", "v1.1.0", (25.0, 100.0), seq=1)
        first = self.deployer.advance("svc", seq=2)
        self.assertIsInstance(first, AdvanceReport)
        self.assertFalse(first.completed)
        self.assertEqual(first.current_traffic_pct, 25.0)
        self.assertEqual(first.remaining_steps, 1)
        self.assertEqual(first.stable_version, "v1.0.0")  # not promoted yet
        final = self.deployer.advance("svc", seq=3)
        self.assertTrue(final.completed)
        self.assertEqual(final.current_traffic_pct, 100.0)
        self.assertEqual(final.stable_version, "v1.1.0")
        status = self.deployer.status("svc")
        self.assertFalse(status.live)
        self.assertEqual(status.stable_version, "v1.1.0")

    def test_advance_no_live(self):
        with self.assertRaises(NoLiveDeploymentError):
            self.deployer.advance("svc", seq=1)
        with self.assertRaises(UnknownServiceError):
            self.deployer.advance("nope", seq=1)

    def test_blue_green_traffic_stays_zero_until_cutover(self):
        self.deployer.deploy("svc", "v1.1.0", "blue_green", seq=1)
        self.deployer.advance("svc", seq=2)
        self.assertEqual(self.deployer.status("svc").current_traffic_pct, 0.0)
        self.deployer.advance("svc", seq=3)
        self.assertEqual(self.deployer.status("svc").current_traffic_pct, 0.0)
        final = self.deployer.advance("svc", seq=4)
        self.assertTrue(final.completed)
        self.assertEqual(final.current_traffic_pct, 100.0)


class PauseResumeTests(unittest.TestCase):
    def setUp(self):
        self.deployer = CDDeployer()
        self.deployer.register_service("svc", "v1.0.0", seq=0)
        self.deployer.deploy("svc", "v1.1.0", "rolling", seq=1)

    def test_pause_blocks_advance(self):
        self.deployer.pause("svc", seq=2)
        self.assertTrue(self.deployer.status("svc").paused)
        with self.assertRaises(CDDeployerError):
            self.deployer.advance("svc", seq=3)
        self.deployer.resume("svc", seq=4)
        self.assertFalse(self.deployer.status("svc").paused)
        self.deployer.advance("svc", seq=5)  # works again

    def test_double_pause_and_resume_without_pause(self):
        self.deployer.pause("svc", seq=2)
        with self.assertRaises(CDDeployerError):
            self.deployer.pause("svc", seq=3)
        self.deployer.resume("svc", seq=4)
        with self.assertRaises(CDDeployerError):
            self.deployer.resume("svc", seq=5)

    def test_pause_no_live(self):
        other = CDDeployer()
        other.register_service("other", "v9.0.0", seq=0)
        with self.assertRaises(NoLiveDeploymentError):
            other.pause("other", seq=1)
        with self.assertRaises(NoLiveDeploymentError):
            other.resume("other", seq=1)


class RollbackTests(unittest.TestCase):
    def setUp(self):
        self.deployer = CDDeployer()
        self.deployer.register_service("svc", "v1.0.0", seq=0)

    def test_rollback_mid_rollout(self):
        self.deployer.deploy("svc", "v1.1.0", "canary", seq=1)
        self.deployer.advance("svc", seq=2)
        report = self.deployer.rollback("svc", seq=3)
        self.assertIsInstance(report, RollbackReport)
        self.assertEqual(report.dropped_version, "v1.1.0")
        self.assertEqual(report.restored_stable, "v1.0.0")
        self.assertEqual(report.completed_steps, 1)
        self.assertTrue(report.digest.startswith("sha256:"))
        status = self.deployer.status("svc")
        self.assertFalse(status.live)
        self.assertEqual(status.stable_version, "v1.0.0")

    def test_rollback_no_live(self):
        with self.assertRaises(NoLiveDeploymentError):
            self.deployer.rollback("svc", seq=1)
        with self.assertRaises(UnknownServiceError):
            self.deployer.rollback("nope", seq=1)

    def test_rollback_then_redeploy(self):
        self.deployer.deploy("svc", "v1.1.0", "canary", seq=1)
        self.deployer.rollback("svc", seq=2)
        record = self.deployer.deploy("svc", "v1.2.0", "recreate", seq=3)
        self.assertEqual(record.version, "v1.2.0")


class StatusViewTests(unittest.TestCase):
    def test_status_idle_and_live(self):
        deployer = CDDeployer()
        deployer.register_service("a", "v1.0.0", seq=0)
        deployer.register_service("b", "v2.0.0", seq=0)
        self.assertEqual(deployer.services(), ("a", "b"))
        idle = deployer.status("a")
        self.assertIsInstance(idle, DeploymentStatus)
        self.assertFalse(idle.live)
        self.assertIsNone(idle.strategy)
        deployer.deploy("a", "v1.1.0", "rolling", seq=1)
        live = deployer.status("a")
        self.assertTrue(live.live)
        self.assertEqual(live.strategy, "rolling")
        self.assertEqual(live.target_version, "v1.1.0")
        self.assertEqual(live.completed_steps, 0)
        self.assertEqual(live.total_steps, 4)
        # service b untouched
        self.assertFalse(deployer.status("b").live)

    def test_status_unknown_service(self):
        deployer = CDDeployer()
        with self.assertRaises(UnknownServiceError):
            deployer.status("nope")


class RolloutStepTests(unittest.TestCase):
    def test_step_frozen(self):
        step = RolloutStep(index=0, name="canary-1%", target_pct=1.0)
        with self.assertRaises(Exception):
            step.name = "x"  # type: ignore[misc]

    def test_step_validation(self):
        with self.assertRaises(TypeError):
            RolloutStep(index=-1, name="x", target_pct=1.0)
        with self.assertRaises(TypeError):
            RolloutStep(index=0, name="", target_pct=1.0)
        with self.assertRaises(ValueError):
            RolloutStep(index=0, name="x", target_pct=101.0)
        with self.assertRaises(TypeError):
            RolloutStep(index=0, name="x", target_pct=True)


class AuditEventTests(unittest.TestCase):
    def test_audit_kinds(self):
        for kind in AUDIT_KINDS:
            event = cd_deployer_audit_event(kind, seq=0)
            self.assertEqual(event["schema"], "audit.ndjson/1")
            self.assertEqual(event["event"], f"cd-deployer.{kind}")
            self.assertEqual(event["seq"], 0)

    def test_audit_detail(self):
        event = cd_deployer_audit_event("deployed", seq=3, detail={"service": "svc"})
        self.assertEqual(event["detail"], {"service": "svc"})

    def test_audit_rejection(self):
        with self.assertRaises(CDDeployerError):
            cd_deployer_audit_event("bogus", seq=0)
        with self.assertRaises(TypeError):
            cd_deployer_audit_event("deployed", seq=True)
        with self.assertRaises(TypeError):
            cd_deployer_audit_event("deployed", seq=0, detail="svc")

    def test_events_log(self):
        deployer = CDDeployer()
        deployer.register_service("svc", "v1.0.0", seq=0)
        deployer.deploy("svc", "v1.1.0", "recreate", seq=1)
        deployer.advance("svc", seq=2)
        kinds = [e["event"] for e in deployer.events()]
        self.assertEqual(kinds, ["service-registered", "deployed", "completed"])


class MainTests(unittest.TestCase):
    def test_main(self):
        main()


if __name__ == "__main__":
    unittest.main()

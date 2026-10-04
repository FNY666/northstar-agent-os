"""Tests for the one-hundred-fifty-third batch: transport & logistics AI discipline."""

import unittest

import transport_agents as ta
from transport_agents import TransportError


AUTH = b"transport-bench-auth-00000000001"  # 32 bytes
assert len(AUTH) == 32
OTHER = b"transport-other-auth-00000000002"  # 32 bytes
assert len(OTHER) == 32
T0 = 1_800_000_000
H64 = "ab" * 32
H64B = "cd" * 32


def rationale(**kw):
    args = dict(
        decision_id="dec-1",
        route_digest=H64,
        affected_constraints=("road_closure_a9", "depot_congestion"),
        suggested_actions=("reroute_via_b2", "delay_30m"),
        confidence=0.92,
        issued_at=T0,
        expires_at=T0 + 3600,
        authority_secret=AUTH
    )
    args.update(kw)
    return ta.issue_route_rationale(**args)


def fleet(**kw):
    args = dict(
        fleet_id="fleet-1",
        fleet_size=200,
        stall_count_trip=10,
        stall_ratio_trip_bps=500,
        window_s=600,
        breaker_bound=True,
        registered_at=T0,
        authority_secret=AUTH
    )
    args.update(kw)
    return ta.register_fleet(**args)


def stall(fleet_id="fleet-1", vehicle_id="v-1", at=T0 + 10):
    return ta.record_stall_event(
        fleet_id=fleet_id,
        vehicle_id=vehicle_id,
        stalled_at=at,
        authority_secret=AUTH
    )


def supervisor(**kw):
    args = dict(
        supervisor_id="sup-1",
        max_concurrent=3,
        credential_digest=H64,
        credential_valid_until=T0 + 86400,
        registered_at=T0,
        authority_secret=AUTH
    )
    args.update(kw)
    return ta.register_supervisor(**args)


def agent(**kw):
    args = dict(
        agent_id="agent-1",
        identity_pubkey_hex=ta._ed25519_pubkey(AUTH).hex(),
        privileges=("dispatch.read", "route.plan"),
        mcp_tool_whitelist=("map.tiles", "telemetry.read"),
        kill_switch_bound=True,
        registered_at=T0,
        authority_secret=AUTH
    )
    args.update(kw)
    return ta.register_transport_agent(**args)


def checklist(**kw):
    args = dict(
        deployment_id="dep-1",
        scenario_ids=("night_rain_urban", "highway_merge", "school_zone"),
        pinned_at=T0,
        authority_secret=AUTH
    )
    args.update(kw)
    return ta.pin_scenario_checklist(**args)


def interference(**kw):
    args = dict(
        incident_id="ri-1",
        vehicle_id="v-9",
        responder_type="fire_engine",
        obstruction_kind="blocked_lane",
        detected_at=T0 + 50,
        authority_secret=AUTH
    )
    args.update(kw)
    return ta.record_responder_interference(**args)


def labor(**kw):
    args = dict(
        deployment_id="dep-1",
        capability_map_digest=H64B,
        retraining_trigger_bps=3000,
        retraining_started=False,
        bound_at=T0,
        authority_secret=AUTH
    )
    args.update(kw)
    return ta.bind_labor_plan(**args)


def city_report(**kw):
    args = dict(
        report_id="cr-1",
        incident_id="inc-1",
        jurisdiction="san_francisco",
        schema_version="sf-av-incident.v2",
        detected_at=T0,
        filed_at=T0 + 3600,
        authority_secret=AUTH
    )
    args.update(kw)
    return ta.file_city_report(**args)


class RouteRationaleTests(unittest.TestCase):
    def test_live_rationale_allows(self):
        reg = ta.RouteRegistry()
        reg.record(rationale())
        v = ta.route_rationale_gate(
            reg, decision_id="dec-1", route_digest=H64, now=T0 + 100)
        self.assertTrue(v.allowed)
        self.assertIsNone(v.deny_code)

    def test_missing_rationale_denies(self):
        reg = ta.RouteRegistry()
        v = ta.route_rationale_gate(
            reg, decision_id="dec-ghost", route_digest=H64, now=T0 + 100)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, ta.DENY_NO_RATIONALE)

    def test_route_digest_mismatch_denies(self):
        reg = ta.RouteRegistry()
        reg.record(rationale())
        v = ta.route_rationale_gate(
            reg, decision_id="dec-1", route_digest=H64B, now=T0 + 100)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, ta.DENY_RATIONALE_TAMPERED)

    def test_low_confidence_denies(self):
        reg = ta.RouteRegistry()
        reg.record(rationale(confidence=0.40))
        v = ta.route_rationale_gate(
            reg, decision_id="dec-1", route_digest=H64, now=T0 + 100)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, ta.DENY_LOW_CONFIDENCE)

    def test_expired_rationale_denies(self):
        reg = ta.RouteRegistry()
        reg.record(rationale())
        v = ta.route_rationale_gate(
            reg, decision_id="dec-1", route_digest=H64, now=T0 + 7200)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, ta.DENY_NO_RATIONALE)

    def test_malformed_rationale_raises(self):
        with self.assertRaises(TransportError):
            rationale(route_digest="not-hex")
        with self.assertRaises(TransportError):
            rationale(confidence=1.5)
        with self.assertRaises(TransportError):
            rationale(affected_constraints=())


class FleetBreakerTests(unittest.TestCase):
    def test_healthy_fleet_allows(self):
        fleets = ta.FleetRegistry()
        fleets.register(fleet())
        v = ta.fleet_circuit_breaker(fleets, fleet_id="fleet-1", now=T0 + 100)
        self.assertTrue(v.allowed)

    def test_unregistered_fleet_denies_no_kill_switch(self):
        fleets = ta.FleetRegistry()
        v = ta.fleet_circuit_breaker(fleets, fleet_id="fleet-ghost", now=T0 + 100)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, ta.DENY_NO_KILL_SWITCH)

    def test_fleet_without_breaker_denies(self):
        fleets = ta.FleetRegistry()
        fleets.register(fleet(breaker_bound=False))
        v = ta.fleet_circuit_breaker(fleets, fleet_id="fleet-1", now=T0 + 100)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, ta.DENY_NO_KILL_SWITCH)

    def test_mass_stall_trips_breaker(self):
        fleets = ta.FleetRegistry()
        fleets.register(fleet())
        for i in range(12):
            fleets.record_stall(stall(vehicle_id=f"v-{i}", at=T0 + 10 + i))
        v = ta.fleet_circuit_breaker(fleets, fleet_id="fleet-1", now=T0 + 500)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, ta.DENY_FLEET_TRIPPED)

    def test_ratio_trip_also_fires(self):
        fleets = ta.FleetRegistry()
        fleets.register(fleet(fleet_size=40, stall_count_trip=10))
        for i in range(3):  # 3/40 = 7.5% >= 5% ratio trip
            fleets.record_stall(stall(vehicle_id=f"v-{i}", at=T0 + 10 + i))
        self.assertTrue(fleets.is_tripped("fleet-1", now=T0 + 500))

    def test_stale_stalls_do_not_trip(self):
        fleets = ta.FleetRegistry()
        fleets.register(fleet(window_s=600))
        for i in range(12):
            fleets.record_stall(stall(vehicle_id=f"v-{i}", at=T0 - 5000 + i))
        v = ta.fleet_circuit_breaker(fleets, fleet_id="fleet-1", now=T0 + 100)
        self.assertTrue(v.allowed)


class TeleoperationCapTests(unittest.TestCase):
    def test_within_cap_allows(self):
        sups = ta.SupervisorRegistry()
        sups.register(supervisor())
        sups.assign("sup-1", "v-1")
        v = ta.teleoperation_cap(sups, supervisor_id="sup-1", now=T0 + 100)
        self.assertTrue(v.allowed)

    def test_unknown_supervisor_denies(self):
        sups = ta.SupervisorRegistry()
        v = ta.teleoperation_cap(sups, supervisor_id="sup-ghost", now=T0 + 100)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, ta.DENY_UNREGISTERED_SUPERVISOR)

    def test_over_cap_denies(self):
        sups = ta.SupervisorRegistry()
        sups.register(supervisor(max_concurrent=2))
        sups.assign("sup-1", "v-1")
        sups.assign("sup-1", "v-2")
        sups.assign("sup-1", "v-3")
        v = ta.teleoperation_cap(sups, supervisor_id="sup-1", now=T0 + 100)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, ta.DENY_OVERLOADED_SUPERVISOR)

    def test_expired_credential_denies(self):
        sups = ta.SupervisorRegistry()
        sups.register(supervisor(credential_valid_until=T0 - 1))
        v = ta.teleoperation_cap(sups, supervisor_id="sup-1", now=T0 + 100)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, ta.DENY_UNCREDENTIALED_SUPERVISOR)


class AgentIAMTests(unittest.TestCase):
    def test_registered_agent_in_scope_allows(self):
        agents = ta.AgentIAMRegistry()
        agents.register(agent())
        v = ta.agent_iam_discipline(
            agents, agent_id="agent-1",
            requested_privilege="route.plan", tool_name="map.tiles")
        self.assertTrue(v.allowed)

    def test_unknown_agent_denies(self):
        agents = ta.AgentIAMRegistry()
        v = ta.agent_iam_discipline(agents, agent_id="agent-ghost")
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, ta.DENY_UNREGISTERED_AGENT)

    def test_no_kill_switch_denies(self):
        agents = ta.AgentIAMRegistry()
        agents.register(agent(kill_switch_bound=False))
        v = ta.agent_iam_discipline(agents, agent_id="agent-1")
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, ta.DENY_NO_KILL_SWITCH)

    def test_privilege_violation_denies(self):
        agents = ta.AgentIAMRegistry()
        agents.register(agent())
        v = ta.agent_iam_discipline(
            agents, agent_id="agent-1", requested_privilege="dispatch.override")
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, ta.DENY_PRIVILEGE_VIOLATION)

    def test_tool_not_whitelisted_denies(self):
        agents = ta.AgentIAMRegistry()
        agents.register(agent())
        v = ta.agent_iam_discipline(
            agents, agent_id="agent-1", tool_name="shell.exec")
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, ta.DENY_TOOL_NOT_WHITELISTED)


class ChecklistTests(unittest.TestCase):
    def test_pinned_scenario_allows(self):
        lists = ta.ChecklistRegistry()
        lists.pin(checklist())
        v = ta.safety_scenario_checklist(
            lists, deployment_id="dep-1", scenario_id="highway_merge")
        self.assertTrue(v.allowed)

    def test_unknown_deployment_denies(self):
        lists = ta.ChecklistRegistry()
        v = ta.safety_scenario_checklist(
            lists, deployment_id="dep-ghost", scenario_id="highway_merge")
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, ta.DENY_NO_CHECKLIST)

    def test_unchecked_scenario_denies(self):
        lists = ta.ChecklistRegistry()
        lists.pin(checklist())
        v = ta.safety_scenario_checklist(
            lists, deployment_id="dep-1", scenario_id="blizzard_whiteout")
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, ta.DENY_UNCHECKED_SCENARIO)


class ResponderProbeTests(unittest.TestCase):
    def test_clean_vehicle_allows(self):
        reg = ta.ResponderRegistry()
        v = ta.first_responder_probe(
            reg, vehicle_id="v-1", window_start=T0, window_end=T0 + 3600)
        self.assertTrue(v.allowed)

    def test_interference_in_window_denies(self):
        reg = ta.ResponderRegistry()
        reg.record(interference(vehicle_id="v-9", obstruction_kind="entered_scene"))
        v = ta.first_responder_probe(
            reg, vehicle_id="v-9", window_start=T0, window_end=T0 + 3600)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, ta.DENY_RESPONDER_INTERFERENCE)

    def test_interference_outside_window_ignored(self):
        reg = ta.ResponderRegistry()
        reg.record(interference(vehicle_id="v-9", detected_at=T0 + 9000))
        v = ta.first_responder_probe(
            reg, vehicle_id="v-9", window_start=T0, window_end=T0 + 3600)
        self.assertTrue(v.allowed)

    def test_bad_obstruction_kind_raises(self):
        with self.assertRaises(TransportError):
            interference(obstruction_kind="honked_loudly")


class LaborPlanTests(unittest.TestCase):
    def test_no_plan_denies(self):
        plans = ta.LaborPlanRegistry()
        v = ta.labor_transition_plan(
            plans, deployment_id="dep-ghost", automation_rate_bps=1000, now=T0 + 10)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, ta.DENY_NO_LABOR_PLAN)

    def test_bound_plan_below_trigger_allows(self):
        plans = ta.LaborPlanRegistry()
        plans.bind(labor())
        v = ta.labor_transition_plan(
            plans, deployment_id="dep-1", automation_rate_bps=1000, now=T0 + 10)
        self.assertTrue(v.allowed)

    def test_overdue_retraining_denies(self):
        plans = ta.LaborPlanRegistry()
        plans.bind(labor(retraining_trigger_bps=3000, retraining_started=False))
        v = ta.labor_transition_plan(
            plans, deployment_id="dep-1", automation_rate_bps=4000, now=T0 + 10)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, ta.DENY_RETRAINING_OVERDUE)

    def test_started_retraining_allows_past_trigger(self):
        plans = ta.LaborPlanRegistry()
        plans.bind(labor(retraining_trigger_bps=3000, retraining_started=True))
        v = ta.labor_transition_plan(
            plans, deployment_id="dep-1", automation_rate_bps=4000, now=T0 + 10)
        self.assertTrue(v.allowed)


class CityReportTests(unittest.TestCase):
    def test_filed_on_time_allows(self):
        reps = ta.CityReportRegistry()
        reps.file(city_report())
        v = ta.incident_reporting_adapter(
            reps, incident_id="inc-1", jurisdiction="san_francisco",
            deadline_s=86400, now=T0 + 7200)
        self.assertTrue(v.allowed)

    def test_missing_report_denies(self):
        reps = ta.CityReportRegistry()
        v = ta.incident_reporting_adapter(
            reps, incident_id="inc-ghost", jurisdiction="san_francisco",
            deadline_s=86400, now=T0 + 7200)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, ta.DENY_UNREPORTED_INCIDENT)

    def test_late_report_denies(self):
        reps = ta.CityReportRegistry()
        reps.file(city_report(filed_at=T0 + 200000))
        v = ta.incident_reporting_adapter(
            reps, incident_id="inc-1", jurisdiction="san_francisco",
            deadline_s=86400, now=T0 + 300000)
        self.assertFalse(v.allowed)
        self.assertEqual(v.deny_code, ta.DENY_LATE_REPORT)

    def test_backdated_filing_raises(self):
        with self.assertRaises(TransportError):
            city_report(detected_at=T0 + 100, filed_at=T0)


class VerdictShapeTests(unittest.TestCase):
    def test_verdict_as_dict(self):
        reg = ta.RouteRegistry()
        reg.record(rationale())
        v = ta.route_rationale_gate(
            reg, decision_id="dec-1", route_digest=H64, now=T0 + 100)
        d = v.as_dict()
        self.assertEqual(d["kind"], "transport-verdict")
        self.assertTrue(d["allowed"])
        self.assertEqual(d["receipt_digest"], reg.get("dec-1").record_digest)


if __name__ == "__main__":
    unittest.main()

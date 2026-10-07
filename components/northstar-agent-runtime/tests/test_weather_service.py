"""Tests for weather_service."""

import ast
import dataclasses
import unittest
from pathlib import Path

import weather_service
from weather_service import (
    ALERT_KINDS,
    COLD_ALERT_C,
    CONDITIONS,
    HEAT_ALERT_C,
    SCHEMA_PIN,
    WEATHER_SERVICE_VERSION,
    WIND_ALERT_KPH,
    UnknownLocationError,
    UnknownObservationError,
    SeqOrderError,
    ValidationError,
    WeatherService,
    weather_service_audit_event,
)


def _make(seed_temp=20.0, seq0=1, **kw):
    svc = WeatherService()
    args = dict(lat=22.3193, lon=114.1694, temp_c=seed_temp, humidity_pct=60,
                wind_kph=10.0, condition="clear")
    args.update(kw)
    obs = svc.report_observation(args.pop("lat"), args.pop("lon"), seq0, **args)
    return svc, obs


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(WEATHER_SERVICE_VERSION, "weather-service.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.weather-service.v1")
        svc, obs = _make()
        self.assertEqual(obs.version, WEATHER_SERVICE_VERSION)

    def test_stdlib_only(self):
        tree = ast.parse(Path(weather_service.__file__).read_text())
        allowed = {
            "__future__", "hashlib", "math", "threading", "dataclasses",
            "typing", "json", "canonical_json",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    self.assertIn(node.module.split(".")[0], allowed)

    def test_alert_kinds_pinned(self):
        self.assertEqual(set(ALERT_KINDS), {"heat", "cold", "high-wind", "fog-advisory"})
        self.assertEqual(HEAT_ALERT_C, 38.0)
        self.assertEqual(COLD_ALERT_C, -20.0)
        self.assertEqual(WIND_ALERT_KPH, 60.0)
        self.assertIn("clear", CONDITIONS)


class TestReport(unittest.TestCase):
    def test_report_roundtrip_and_digest(self):
        svc, obs = _make()
        self.assertTrue(obs.obs_id.startswith("obs-"))
        self.assertTrue(obs.digest.startswith("sha256:"))
        self.assertFalse(obs.retracted)
        self.assertEqual(obs.cell, "22.3193,114.1694")
        looked = svc.observation(obs.obs_id)
        self.assertEqual(looked, obs)

    def test_report_digest_deterministic(self):
        svc1, obs1 = _make()
        svc2, obs2 = _make()
        self.assertEqual(obs1.digest, obs2.digest)

    def test_bad_inputs_refused(self):
        svc = WeatherService()
        base = dict(temp_c=20.0, humidity_pct=60, wind_kph=10.0, condition="clear")
        with self.assertRaises(ValidationError):
            svc.report_observation(float("nan"), 0.0, 1, **base)
        with self.assertRaises(ValidationError):
            svc.report_observation(91.0, 0.0, 2, **base)
        with self.assertRaises(ValidationError):
            svc.report_observation(0.0, 181.0, 3, **base)
        with self.assertRaises(ValidationError):
            svc.report_observation(0.0, 0.0, 4, temp_c=200.0, humidity_pct=60,
                                   wind_kph=10.0, condition="clear")
        with self.assertRaises(ValidationError):
            svc.report_observation(0.0, 0.0, 5, temp_c=20.0, humidity_pct=101,
                                   wind_kph=10.0, condition="clear")
        with self.assertRaises(ValidationError):
            svc.report_observation(0.0, 0.0, 6, temp_c=20.0, humidity_pct=60,
                                   wind_kph=10.0, condition="meteor-shower")

    def test_seq_strictly_increases(self):
        svc, _ = _make(seq0=1)
        with self.assertRaises(SeqOrderError):
            svc.report_observation(1.0, 1.0, 1, temp_c=20.0, humidity_pct=60,
                                   wind_kph=10.0, condition="clear")
        with self.assertRaises(SeqOrderError):
            svc.report_observation(1.0, 1.0, True, temp_c=20.0, humidity_pct=60,
                                   wind_kph=10.0, condition="clear")

    def test_unknown_observation(self):
        svc = WeatherService()
        with self.assertRaises(UnknownObservationError):
            svc.observation("obs-999")
        with self.assertRaises(UnknownObservationError):
            svc.retract_observation("obs-999", 1)

    def test_records_frozen(self):
        _, obs = _make()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            obs.temp_c = 0.0  # type: ignore[misc]


class TestCurrentForecast(unittest.TestCase):
    def test_current_latest(self):
        svc, obs1 = _make(seq0=1)
        obs2 = svc.report_observation(22.3193, 114.1694, 2, temp_c=25.0,
                                      humidity_pct=50, wind_kph=5.0, condition="cloudy")
        cur = svc.current(22.3193, 114.1694, 3)
        self.assertEqual(cur.obs_id, obs2.obs_id)
        self.assertEqual(cur.temp_c, 25.0)
        self.assertTrue(cur.digest.startswith("sha256:"))
        self.assertNotEqual(cur.digest, obs2.digest)  # read pins its own body

    def test_current_unknown_location(self):
        svc = WeatherService()
        with self.assertRaises(UnknownLocationError):
            svc.current(0.0, 0.0, 1)

    def test_forecast_trend(self):
        svc, _ = _make(seed_temp=20.0, seq0=1)
        svc.report_observation(22.3193, 114.1694, 2, temp_c=22.0, humidity_pct=60,
                               wind_kph=10.0, condition="clear")
        fc = svc.forecast(22.3193, 114.1694, 3, periods=2)
        self.assertEqual(len(fc.periods), 2)
        # trend = +2 C over two obs, half weight per period: 22+1, 22+2
        self.assertEqual(fc.periods[0].temp_c, 23.0)
        self.assertEqual(fc.periods[1].temp_c, 24.0)
        self.assertTrue(fc.digest.startswith("sha256:"))

    def test_forecast_single_observation_flat(self):
        svc, _ = _make(seed_temp=18.5, seq0=1)
        fc = svc.forecast(22.3193, 114.1694, 2, periods=3)
        self.assertEqual([p.temp_c for p in fc.periods], [18.5, 18.5, 18.5])

    def test_forecast_period_bounds(self):
        svc, _ = _make(seq0=1)
        with self.assertRaises(ValidationError):
            svc.forecast(22.3193, 114.1694, 2, periods=0)
        with self.assertRaises(ValidationError):
            svc.forecast(22.3193, 114.1694, 2, periods=11)
        with self.assertRaises(ValidationError):
            svc.forecast(22.3193, 114.1694, 2, periods=True)

    def test_forecast_unknown_location(self):
        svc = WeatherService()
        with self.assertRaises(UnknownLocationError):
            svc.forecast(0.0, 0.0, 1, periods=2)


class TestAlerts(unittest.TestCase):
    def test_benign_no_alerts(self):
        svc, obs = _make(seed_temp=22.0, seq0=1)
        rep = svc.alerts(22.3193, 114.1694, 2)
        self.assertEqual(rep.obs_id, obs.obs_id)
        self.assertEqual(rep.alerts, ())

    def test_heat_alert(self):
        svc, _ = _make(seed_temp=40.0, seq0=1)
        kinds = [a.kind for a in svc.alerts(22.3193, 114.1694, 2).alerts]
        self.assertIn("heat", kinds)

    def test_cold_alert(self):
        svc, _ = _make(seed_temp=-25.0, seq0=1)
        kinds = [a.kind for a in svc.alerts(22.3193, 114.1694, 2).alerts]
        self.assertIn("cold", kinds)

    def test_high_wind_alert(self):
        svc, _ = _make(seed_temp=20.0, seq0=1, wind_kph=80.0)
        kinds = [a.kind for a in svc.alerts(22.3193, 114.1694, 2).alerts]
        self.assertIn("high-wind", kinds)

    def test_fog_advisory(self):
        svc, _ = _make(seed_temp=15.0, seq0=1, condition="fog")
        kinds = [a.kind for a in svc.alerts(22.3193, 114.1694, 2).alerts]
        self.assertIn("fog-advisory", kinds)


class TestRetract(unittest.TestCase):
    def test_retract_drops_from_current(self):
        svc, obs1 = _make(seed_temp=20.0, seq0=1)
        obs2 = svc.report_observation(22.3193, 114.1694, 2, temp_c=99.9,
                                      humidity_pct=60, wind_kph=10.0, condition="clear")
        rec = svc.retract_observation(obs2.obs_id, 3)
        self.assertTrue(rec.digest.startswith("sha256:"))
        cur = svc.current(22.3193, 114.1694, 4)
        self.assertEqual(cur.obs_id, obs1.obs_id)
        stored = svc.observation(obs2.obs_id)
        self.assertTrue(stored.retracted)


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        svc, obs = _make(seq0=1)
        ev = weather_service_audit_event("observation-reported", 2, obs)
        self.assertEqual(ev["event"], "weather-service-observation-reported")
        self.assertEqual(ev["audit_seq"], 2)
        self.assertEqual(ev["schema"], SCHEMA_PIN)
        self.assertEqual(ev["record_id"], obs.obs_id)
        ev2 = weather_service_audit_event("rejected", 3, detail="bad seq")
        self.assertEqual(ev2["detail"], "bad seq")
        with self.assertRaises(ValueError):
            weather_service_audit_event("storm", 4)

    def test_main_selfcheck(self):
        weather_service.main()


if __name__ == "__main__":
    unittest.main()

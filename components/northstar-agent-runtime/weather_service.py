"""Weather service: simulated current/forecast/alert bookkeeping (Open-Meteo/NWS lineage).

Research note: public weather APIs (Open-Meteo, NOAA NWS, OpenWeatherMap)
expose three verbs this module models: current conditions at a point,
a forward forecast window, and active hazard alerts. The interface
contract is *host-reported* — a model or sensor network supplies
observations, and the service books the ledger around them.

* **Observation ledger** — ``report_observation(lat, lon, seq, ...)``
  pins a frozen :class:`ObservationRecord` (``obs-N``). Observations are
  bucketed into grid cells at ``CELL_PRECISION`` (4 decimals, ~11 m at
  the equator) so float coordinate noise does not fragment the ledger.
  NaN/inf coordinates are refused fail-closed; out-of-range values are
  refused too. ``retract_observation()`` supersedes a bad reading
  fail-closed (a failed mutation still consumes its seq, matching the
  batch-21 ``rbac_engine`` discipline).
* **current()** — reads back the *latest non-retracted* observation for
  the cell. An unknown cell raises :class:`UnknownLocationError`
  fail-closed: there is no silent "nearby" guess, because a wrong-place
  weather read is worse than no read.
* **forecast()** — deterministic derivation from the last two
  observations at the cell (linear trend at half weight per period).
  Documented as *bookkeeping of a two-point trend*, not meteorology: it
  cannot see fronts, terrain, or model output. ``periods`` is bounded
  (1..10); each :class:`ForecastPeriod` carries a ``sha256:`` digest pin.
* **alerts()** — deterministic threshold rules over current conditions:
  heat (temp >= 38 C), cold (temp <= -20 C), high wind (>= 60 kph), fog
  advisory (condition == "fog"). Thresholds are module pins; ``alerts``
  are *advisories computed from reported data*, not authoritative
  warnings from a national service.
* **Decimal discipline** — coordinates are quantized to 4 decimals and
  temperatures to 1 decimal before digesting; digests pin the
  *formatted* values so float-repr noise cannot break determinism.
  Amounts-of-truth inputs (temp/humidity/wind) carry sane physical
  bounds; humidity is an int 0..100.
* **Pins bind** — every record carries a ``sha256:`` digest pin over its
  canonical body. Audit events carry ids and pins only.

Honest scope: this is the *observation/forecast/alert ledger* for
weather, not a forecast skill. It cannot observe the sky, cannot prove
a host's readings are true, and its "forecast" is a two-point trend —
pair with a real NWP feed for production. ``condition == "clear"``
means "the host reported clear", never "the sky was clear".

Version pin: weather-service.v1
Schema pin: northstar.weather-service.v1
"""

from __future__ import annotations

import hashlib
import math
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Module version.
WEATHER_SERVICE_VERSION = "weather-service.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.weather-service.v1"

#: Coordinate quantization: 4 decimals (~11 m).
CELL_PRECISION = 4

#: Temperature quantization: 1 decimal.
TEMP_PRECISION = 1

#: Bounded forecast horizon.
MIN_PERIODS = 1
MAX_PERIODS = 10

#: Alert thresholds (module pins).
HEAT_ALERT_C = 38.0
COLD_ALERT_C = -20.0
WIND_ALERT_KPH = 60.0

#: Pinned condition vocabulary.
CONDITIONS = frozenset(
    {
        "clear",
        "partly-cloudy",
        "cloudy",
        "rain",
        "snow",
        "thunderstorm",
        "fog",
        "windy",
        "hail",
    }
)

#: Fixed alert kinds.
ALERT_KINDS = ("heat", "cold", "high-wind", "fog-advisory")

_AUDIT_KINDS = frozenset(
    {
        "observation-reported",
        "observation-retracted",
        "current-read",
        "forecast-issued",
        "alerts-issued",
        "rejected",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class WeatherError(Exception):
    """Base class for all weather-service errors."""


class ValidationError(WeatherError):
    """An input failed validation (fail-closed)."""


class UnknownLocationError(WeatherError):
    """No observations are known for the requested grid cell."""


class UnknownObservationError(WeatherError):
    """No observation with that id exists."""


class DuplicateObservationError(WeatherError):
    """An observation id was registered twice (cannot happen via API)."""


class SeqOrderError(WeatherError):
    """A mutation seq did not strictly increase."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _check_seq(seq: Any, *, allow_equal_last: bool = False, last: int = -1) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError("seq must be a non-bool int")
    if seq < 0:
        raise SeqOrderError("seq must be non-negative")
    if allow_equal_last:
        if seq < last:
            raise SeqOrderError("seq must not rewind")
    else:
        if seq <= last:
            raise SeqOrderError("seq must strictly increase")
    return seq


def _check_lat(lat: Any) -> float:
    if isinstance(lat, bool) or not isinstance(lat, (int, float)):
        raise ValidationError("lat must be a number")
    lat = float(lat)
    if math.isnan(lat) or math.isinf(lat):
        raise ValidationError("lat must be finite")
    if not -90.0 <= lat <= 90.0:
        raise ValidationError("lat must be in [-90, 90]")
    return lat


def _check_lon(lon: Any) -> float:
    if isinstance(lon, bool) or not isinstance(lon, (int, float)):
        raise ValidationError("lon must be a number")
    lon = float(lon)
    if math.isnan(lon) or math.isinf(lon):
        raise ValidationError("lon must be finite")
    if not -180.0 <= lon <= 180.0:
        raise ValidationError("lon must be in [-180, 180]")
    return lon


def _cell_key(lat: float, lon: float) -> str:
    """Quantize coordinates into a stable grid-cell key."""
    return f"{round(lat, CELL_PRECISION):.{CELL_PRECISION}f},{round(lon, CELL_PRECISION):.{CELL_PRECISION}f}"


def _q_temp(temp: Any) -> float:
    if isinstance(temp, bool) or not isinstance(temp, (int, float)):
        raise ValidationError("temp_c must be a number")
    temp = float(temp)
    if math.isnan(temp) or math.isinf(temp):
        raise ValidationError("temp_c must be finite")
    if not -100.0 <= temp <= 100.0:
        raise ValidationError("temp_c must be in [-100, 100]")
    return round(temp, TEMP_PRECISION)


def _q_wind(wind: Any) -> float:
    if isinstance(wind, bool) or not isinstance(wind, (int, float)):
        raise ValidationError("wind_kph must be a number")
    wind = float(wind)
    if math.isnan(wind) or math.isinf(wind):
        raise ValidationError("wind_kph must be finite")
    if not 0.0 <= wind <= 500.0:
        raise ValidationError("wind_kph must be in [0, 500]")
    return round(wind, TEMP_PRECISION)


def _check_humidity(humidity: Any) -> int:
    if isinstance(humidity, bool) or not isinstance(humidity, int):
        raise ValidationError("humidity_pct must be an int 0..100")
    if not 0 <= humidity <= 100:
        raise ValidationError("humidity_pct must be in [0, 100]")
    return humidity


def _check_condition(condition: Any) -> str:
    if not isinstance(condition, str) or condition not in CONDITIONS:
        raise ValidationError(f"condition must be one of {sorted(CONDITIONS)}")
    return condition


def _fmt_temp(temp: float) -> str:
    return f"{temp:.{TEMP_PRECISION}f}"


def _pin(body: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(jcs_canonical_json(dict(body))).hexdigest()


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ObservationRecord:
    """A pinned host-reported observation."""

    obs_id: str
    cell: str
    temp_c: float
    humidity_pct: int
    wind_kph: float
    condition: str
    seq: int
    retracted: bool
    digest: str
    version: str = WEATHER_SERVICE_VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "obs_id": self.obs_id,
            "cell": self.cell,
            "temp_c": _fmt_temp(self.temp_c),
            "humidity_pct": self.humidity_pct,
            "wind_kph": _fmt_temp(self.wind_kph),
            "condition": self.condition,
            "seq": self.seq,
            "retracted": self.retracted,
            "digest": self.digest,
            "version": self.version,
        }


@dataclass(frozen=True)
class CurrentConditions:
    """The latest non-retracted observation for a cell."""

    cell: str
    obs_id: str
    temp_c: float
    humidity_pct: int
    wind_kph: float
    condition: str
    seq: int
    digest: str
    version: str = WEATHER_SERVICE_VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "cell": self.cell,
            "obs_id": self.obs_id,
            "temp_c": _fmt_temp(self.temp_c),
            "humidity_pct": self.humidity_pct,
            "wind_kph": _fmt_temp(self.wind_kph),
            "condition": self.condition,
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
        }


@dataclass(frozen=True)
class ForecastPeriod:
    """One deterministic trend-derived forecast period."""

    period: int
    temp_c: float
    condition: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "period": self.period,
            "temp_c": _fmt_temp(self.temp_c),
            "condition": self.condition,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class ForecastReport:
    """A bounded, digest-pinned forecast window."""

    cell: str
    periods: Tuple[ForecastPeriod, ...]
    seq: int
    digest: str
    version: str = WEATHER_SERVICE_VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "cell": self.cell,
            "periods": [p.as_dict() for p in self.periods],
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
        }


@dataclass(frozen=True)
class Alert:
    """One deterministic threshold alert."""

    kind: str
    message: str
    cell: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "message": self.message,
            "cell": self.cell,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class AlertReport:
    """Alerts derived from current conditions (possibly empty)."""

    cell: str
    obs_id: str
    alerts: Tuple[Alert, ...]
    seq: int
    digest: str
    version: str = WEATHER_SERVICE_VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "cell": self.cell,
            "obs_id": self.obs_id,
            "alerts": [a.as_dict() for a in self.alerts],
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
        }


@dataclass(frozen=True)
class RetractionRecord:
    """Fail-closed supersede of a bad observation."""

    obs_id: str
    seq: int
    digest: str
    version: str = WEATHER_SERVICE_VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "obs_id": self.obs_id,
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
        }


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


class WeatherService:
    """Deterministic simulated weather ledger: current/forecast/alerts."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._obs_counter = 0
        self._observations: Dict[str, ObservationRecord] = {}
        self._cells: Dict[str, List[str]] = {}

    # -- mutation ---------------------------------------------------------

    def _next_seq(self, seq: Any) -> int:
        seq = _check_seq(seq, last=self._last_seq)
        self._last_seq = seq
        return seq

    def report_observation(
        self,
        lat: Any,
        lon: Any,
        seq: Any,
        *,
        temp_c: Any,
        humidity_pct: Any,
        wind_kph: Any,
        condition: Any,
    ) -> ObservationRecord:
        """Pin a host-reported observation for the quantized grid cell."""
        with self._lock:
            seq = self._next_seq(seq)
            lat = _check_lat(lat)
            lon = _check_lon(lon)
            temp = _q_temp(temp_c)
            humidity = _check_humidity(humidity_pct)
            wind = _q_wind(wind_kph)
            condition = _check_condition(condition)
            self._obs_counter += 1
            obs_id = f"obs-{self._obs_counter}"
            if obs_id in self._observations:  # pragma: no cover - defensive
                raise DuplicateObservationError(f"duplicate {obs_id}")
            cell = _cell_key(lat, lon)
            body = {
                "obs_id": obs_id,
                "cell": cell,
                "temp_c": _fmt_temp(temp),
                "humidity_pct": humidity,
                "wind_kph": _fmt_temp(wind),
                "condition": condition,
                "seq": seq,
            }
            record = ObservationRecord(
                obs_id=obs_id,
                cell=cell,
                temp_c=temp,
                humidity_pct=humidity,
                wind_kph=wind,
                condition=condition,
                seq=seq,
                retracted=False,
                digest=_pin(body),
            )
            self._observations[obs_id] = record
            self._cells.setdefault(cell, []).append(obs_id)
            return record

    def retract_observation(self, obs_id: Any, seq: Any) -> RetractionRecord:
        """Supersede a bad observation fail-closed (terminal for that id)."""
        with self._lock:
            seq = self._next_seq(seq)
            if not isinstance(obs_id, str) or obs_id not in self._observations:
                raise UnknownObservationError(f"unknown observation {obs_id!r}")
            record = self._observations[obs_id]
            body = {
                "obs_id": record.obs_id,
                "cell": record.cell,
                "temp_c": _fmt_temp(record.temp_c),
                "humidity_pct": record.humidity_pct,
                "wind_kph": _fmt_temp(record.wind_kph),
                "condition": record.condition,
                "seq": seq,
                "retracted": True,
            }
            self._observations[obs_id] = ObservationRecord(
                obs_id=record.obs_id,
                cell=record.cell,
                temp_c=record.temp_c,
                humidity_pct=record.humidity_pct,
                wind_kph=record.wind_kph,
                condition=record.condition,
                seq=seq,
                retracted=True,
                digest=_pin(body),
            )
            return RetractionRecord(
                obs_id=obs_id,
                seq=seq,
                digest=_pin({"obs_id": obs_id, "seq": seq, "retracted": True}),
            )

    # -- views ------------------------------------------------------------

    def observation(self, obs_id: Any) -> ObservationRecord:
        with self._lock:
            if not isinstance(obs_id, str) or obs_id not in self._observations:
                raise UnknownObservationError(f"unknown observation {obs_id!r}")
            return self._observations[obs_id]

    def observations(self, lat: Any, lon: Any) -> Tuple[ObservationRecord, ...]:
        with self._lock:
            cell = _cell_key(_check_lat(lat), _check_lon(lon))
            return tuple(self._observations[i] for i in self._cells.get(cell, []))

    def _latest(self, cell: str) -> ObservationRecord:
        for obs_id in reversed(self._cells.get(cell, [])):
            record = self._observations[obs_id]
            if not record.retracted:
                return record
        raise UnknownLocationError(f"no live observation for cell {cell}")

    # -- reads ------------------------------------------------------------

    def current(self, lat: Any, lon: Any, seq: Any) -> CurrentConditions:
        """Return the latest non-retracted observation for the cell."""
        with self._lock:
            _check_seq(seq, allow_equal_last=True, last=self._last_seq)
            cell = _cell_key(_check_lat(lat), _check_lon(lon))
            latest = self._latest(cell)
            body = {
                "cell": cell,
                "obs_id": latest.obs_id,
                "temp_c": _fmt_temp(latest.temp_c),
                "humidity_pct": latest.humidity_pct,
                "wind_kph": _fmt_temp(latest.wind_kph),
                "condition": latest.condition,
                "seq": seq,
            }
            return CurrentConditions(
                cell=cell,
                obs_id=latest.obs_id,
                temp_c=latest.temp_c,
                humidity_pct=latest.humidity_pct,
                wind_kph=latest.wind_kph,
                condition=latest.condition,
                seq=seq,
                digest=_pin(body),
            )

    def forecast(self, lat: Any, lon: Any, seq: Any, periods: Any = 3) -> ForecastReport:
        """Derive a bounded deterministic trend window from the last two obs.

        ``periods`` must be an int in [1, 10]. Each period extrapolates the
        two-point temp trend at half weight per period; the condition is
        carried forward from the latest observation. This is bookkeeping,
        not meteorology.
        """
        with self._lock:
            _check_seq(seq, allow_equal_last=True, last=self._last_seq)
            if isinstance(periods, bool) or not isinstance(periods, int):
                raise ValidationError("periods must be an int")
            if not MIN_PERIODS <= periods <= MAX_PERIODS:
                raise ValidationError(
                    f"periods must be in [{MIN_PERIODS}, {MAX_PERIODS}]"
                )
            cell = _cell_key(_check_lat(lat), _check_lon(lon))
            ids = [
                i
                for i in self._cells.get(cell, [])
                if not self._observations[i].retracted
            ]
            if not ids:
                raise UnknownLocationError(f"no live observation for cell {cell}")
            latest = self._observations[ids[-1]]
            trend = 0.0
            if len(ids) >= 2:
                prev = self._observations[ids[-2]]
                trend = latest.temp_c - prev.temp_c
            made: List[ForecastPeriod] = []
            for n in range(1, periods + 1):
                temp = round(latest.temp_c + trend * 0.5 * n, TEMP_PRECISION)
                body = {
                    "cell": cell,
                    "period": n,
                    "temp_c": _fmt_temp(temp),
                    "condition": latest.condition,
                    "seq": seq,
                }
                made.append(
                    ForecastPeriod(
                        period=n,
                        temp_c=temp,
                        condition=latest.condition,
                        seq=seq,
                        digest=_pin(body),
                    )
                )
            report_digest = _pin(
                {
                    "cell": cell,
                    "period_digests": [p.digest for p in made],
                    "seq": seq,
                }
            )
            return ForecastReport(
                cell=cell,
                periods=tuple(made),
                seq=seq,
                digest=report_digest,
            )

    def alerts(self, lat: Any, lon: Any, seq: Any) -> AlertReport:
        """Compute deterministic threshold alerts from current conditions."""
        with self._lock:
            _check_seq(seq, allow_equal_last=True, last=self._last_seq)
            cell = _cell_key(_check_lat(lat), _check_lon(lon))
            latest = self._latest(cell)
            fired: List[Alert] = []
            candidates = [
                ("heat", f"temperature {_fmt_temp(latest.temp_c)} C >= {HEAT_ALERT_C:.0f} C"),
                ("cold", f"temperature {_fmt_temp(latest.temp_c)} C <= {COLD_ALERT_C:.0f} C"),
                ("high-wind", f"wind {_fmt_temp(latest.wind_kph)} kph >= {WIND_ALERT_KPH:.0f} kph"),
            ]
            checks = {
                "heat": latest.temp_c >= HEAT_ALERT_C,
                "cold": latest.temp_c <= COLD_ALERT_C,
                "high-wind": latest.wind_kph >= WIND_ALERT_KPH,
                "fog-advisory": latest.condition == "fog",
            }
            messages = {
                "fog-advisory": "fog reported; reduced visibility",
            }
            for kind, _msg in candidates:
                if checks[kind]:
                    message = _msg
                    body = {
                        "kind": kind,
                        "message": message,
                        "cell": cell,
                        "seq": seq,
                    }
                    fired.append(
                        Alert(
                            kind=kind,
                            message=message,
                            cell=cell,
                            seq=seq,
                            digest=_pin(body),
                        )
                    )
            if checks["fog-advisory"]:
                message = messages["fog-advisory"]
                body = {"kind": "fog-advisory", "message": message, "cell": cell, "seq": seq}
                fired.append(
                    Alert(
                        kind="fog-advisory",
                        message=message,
                        cell=cell,
                        seq=seq,
                        digest=_pin(body),
                    )
                )
            return AlertReport(
                cell=cell,
                obs_id=latest.obs_id,
                alerts=tuple(fired),
                seq=seq,
                digest=_pin(
                    {
                        "cell": cell,
                        "obs_id": latest.obs_id,
                        "alert_digests": [a.digest for a in fired],
                        "seq": seq,
                    }
                ),
            )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def weather_service_audit_event(
    kind: str,
    seq: int,
    record: Optional[Any] = None,
    detail: Optional[str] = None,
) -> Dict[str, Any]:
    """Build an ``audit.ndjson/1``-shaped record for a weather step.

    ``kind`` is one of ``observation-reported`` / ``observation-retracted``
    / ``current-read`` / ``forecast-issued`` / ``alerts-issued`` /
    ``rejected``. Carries ids and digest pins only — never raw
    coordinates beyond the quantized cell key.
    """
    if kind not in _AUDIT_KINDS:
        raise ValueError(f"kind must be one of {sorted(_AUDIT_KINDS)}")
    _check_seq(seq)
    event: Dict[str, Any] = {
        "event": f"weather-service-{kind}",
        "audit_seq": seq,
        "schema": SCHEMA_PIN,
    }
    if record is not None:
        event["record_id"] = getattr(record, "obs_id", None) or getattr(
            record, "cell", None
        )
        event["digest"] = record.digest
    if detail is not None:
        if not isinstance(detail, str):
            raise TypeError("detail must be a str")
        event["detail"] = detail
    return event


def main() -> None:
    svc = WeatherService()
    obs = svc.report_observation(
        22.3193, 114.1694, 1, temp_c=31.5, humidity_pct=70, wind_kph=12.0, condition="partly-cloudy"
    )
    cur = svc.current(22.3193, 114.1694, 2)
    assert cur.obs_id == obs.obs_id, "current must read the reported observation"
    fc = svc.forecast(22.3193, 114.1694, 3, periods=2)
    assert len(fc.periods) == 2, "forecast must emit the requested periods"
    rep = svc.alerts(22.3193, 114.1694, 4)
    assert len(rep.alerts) == 0, "benign conditions must fire no alerts"
    hot = svc.report_observation(
        22.3193, 114.1694, 5, temp_c=40.0, humidity_pct=30, wind_kph=5.0, condition="clear"
    )
    rep2 = svc.alerts(22.3193, 114.1694, 6)
    kinds = [a.kind for a in rep2.alerts]
    assert "heat" in kinds, "40 C must fire the heat alert"
    svc.retract_observation(hot.obs_id, 7)
    cur2 = svc.current(22.3193, 114.1694, 8)
    assert cur2.obs_id == obs.obs_id, "retracted obs must drop out of current"
    print("weather-service OK: report, current, forecast, alerts, retract")


if __name__ == "__main__":
    main()

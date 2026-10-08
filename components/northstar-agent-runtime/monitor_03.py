"""Grafana dashboards: JSON spec generator, Simulated.

Builds Grafana dashboard JSON (panels, variables, time ranges) for the
gate/observer/ledger telemetry produced by monitor_01/monitor_02.

What this IS: version-controlled dashboard specs the host can import
into Grafana.

What this IS NOT:
* Not a Grafana API client -- outputs JSON only.
"""

from __future__ import annotations

import ast
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

#: Module version.
MONITOR_03_VERSION = "monitor-03.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.monitor-03.v1"

_VALID_PANEL_TYPES = {"timeseries", "stat", "table", "gauge", "barchart"}


class DashboardError(Exception):
    """Fail-closed."""


@dataclass
class Panel:
    title: str
    panel_type: str
    expr: str  # PromQL expression
    description: str = ""
    grid_pos: Optional[Dict[str, int]] = None

    def __post_init__(self) -> None:
        if not self.title:
            raise DashboardError("panel title required")
        if self.panel_type not in _VALID_PANEL_TYPES:
            raise DashboardError(f"bad panel type {self.panel_type!r}")
        if not self.expr:
            raise DashboardError("panel expr required")

    def to_dict(self, panel_id: int) -> Dict[str, Any]:
        return {
            "id": panel_id,
            "title": self.title,
            "type": self.panel_type,
            "description": self.description,
            "targets": [{"expr": self.expr, "refId": "A"}],
            "gridPos": self.grid_pos or {"h": 8, "w": 12, "x": 0, "y": 0},
        }


@dataclass
class Dashboard:
    title: str
    uid: str
    tags: List[str] = field(default_factory=list)
    panels: List[Panel] = field(default_factory=list)
    variables: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.title or not self.uid:
            raise DashboardError("title and uid required")

    def add_panel(self, panel: Panel) -> None:
        if not isinstance(panel, Panel):
            raise DashboardError("panel must be Panel")
        self.panels.append(panel)

    def add_variable(self, name: str, query: str) -> None:
        if not name or not query:
            raise DashboardError("variable name and query required")
        self.variables.append({"name": name, "query": query, "type": "query"})

    def to_dict(self) -> Dict[str, Any]:
        return {
            "uid": self.uid,
            "title": self.title,
            "tags": self.tags,
            "timezone": "browser",
            "schemaVersion": 38,
            "templating": {"list": self.variables},
            "panels": [p.to_dict(i + 1) for i, p in enumerate(self.panels)],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


def gate_dashboard() -> Dashboard:
    """Prebuilt dashboard for Northstar gate telemetry."""
    d = Dashboard(
        title="Northstar Gate Telemetry",
        uid="northstar-gates",
        tags=["northstar", "governance"],
    )
    d.add_variable("gate", 'label_values(gate_decisions_total, gate)')
    d.add_panel(
        Panel(
            title="Decisions by gate",
            panel_type="timeseries",
            expr='sum by (gate, decision) (rate(gate_decisions_total{gate=~"$gate"}[5m]))',
        )
    )
    d.add_panel(
        Panel(
            title="Deny rate",
            panel_type="stat",
            expr='sum(rate(gate_decisions_total{decision="deny"}[5m])) '
            '/ sum(rate(gate_decisions_total[5m]))',
        )
    )
    d.add_panel(
        Panel(
            title="Gate latency p95",
            panel_type="timeseries",
            expr='histogram_quantile(0.95, sum(rate(gate_latency_seconds_bucket[5m])) by (le))',
        )
    )
    return d


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "json", "pathlib", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    """Self-check."""
    d = gate_dashboard()
    spec = json.loads(d.to_json())
    assert spec["uid"] == "northstar-gates"
    assert len(spec["panels"]) == 3
    assert spec["panels"][0]["type"] == "timeseries"
    assert len(spec["templating"]["list"]) == 1
    try:
        Panel(title="x", panel_type="bogus", expr="y")
        raise AssertionError("should raise")
    except DashboardError:
        pass
    try:
        Dashboard(title="", uid="u")
        raise AssertionError("should raise")
    except DashboardError:
        pass
    assert stdlib_only()
    print("monitor-03 OK: dashboard spec, fail-closed, stdlib")


if __name__ == "__main__":
    main()

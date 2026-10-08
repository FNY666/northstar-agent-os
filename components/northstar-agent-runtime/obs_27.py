"""obs_27: Postmortems (template), Simulated.

Builds a blameless-postmortem document from incident facts with
required sections (Summary, Impact, Timeline, Root cause, Action
items).  Template: enforces completeness — missing root cause or
empty action items raise instead of producing a half-baked report.

Fail-closed: missing root_cause or empty action_items raises.
Stdlib only.
"""

from __future__ import annotations

import ast
from typing import Any, Dict, List, Tuple

OBS27_VERSION = "obs-27.v1"
SCHEMA_PIN = "northstar.obs-27.v1"

VALID_SEVERITIES = ("sev1", "sev2", "sev3", "sev4")


class Obs27Error(Exception):
    """Fail-closed."""


def build_postmortem(
    incident_id: str,
    title: str,
    severity: str,
    timeline_events: List[Tuple[str, str]],
    root_cause: str,
    action_items: List[Tuple[str, str, str]],
) -> Dict[str, Any]:
    """Return a dict with required sections plus a 'markdown' rendering.

    action_items: list of (owner, task, due).  Template enforces
    completeness: empty root_cause or empty action_items raise.
    """
    if not isinstance(incident_id, str) or not incident_id:
        raise Obs27Error("incident_id must be a non-empty string")
    if not isinstance(title, str) or not title.strip():
        raise Obs27Error("title must be a non-empty string")
    if severity not in VALID_SEVERITIES:
        raise Obs27Error(f"severity must be one of {VALID_SEVERITIES}")
    if not isinstance(timeline_events, list) or not timeline_events:
        raise Obs27Error("timeline_events must be a non-empty list")
    for ev in timeline_events:
        if not isinstance(ev, (list, tuple)) or len(ev) != 2:
            raise Obs27Error("each timeline event must be (timestamp, description)")
        ts, desc = ev
        if not isinstance(ts, str) or not isinstance(desc, str) or not desc:
            raise Obs27Error("timeline events need str timestamp and non-empty description")
    if not isinstance(root_cause, str) or not root_cause.strip():
        raise Obs27Error("root_cause is required (template enforces completeness)")
    if not isinstance(action_items, list) or not action_items:
        raise Obs27Error("at least one action item is required")
    items: List[Dict[str, str]] = []
    for ai in action_items:
        if not isinstance(ai, (list, tuple)) or len(ai) != 3:
            raise Obs27Error("each action item must be (owner, task, due)")
        owner, task, due = ai
        for field, name in ((owner, "owner"), (task, "task"), (due, "due")):
            if not isinstance(field, str) or not field.strip():
                raise Obs27Error(f"action item {name} must be a non-empty string")
        items.append({"owner": owner, "task": task, "due": due})

    lines = [
        f"# Postmortem: {title} ({incident_id})",
        "",
        "## Summary",
        f"- Incident: {incident_id}",
        f"- Severity: {severity}",
        f"- Title: {title}",
        "",
        "## Impact",
        f"- Severity {severity} incident: {title}",
        "",
        "## Timeline",
    ]
    for ts, desc in timeline_events:
        lines.append(f"- {ts}: {desc}")
    lines += ["", "## Root cause", root_cause, "", "## Action items"]
    for i, it in enumerate(items, 1):
        lines.append(f"{i}. [{it['owner']}] {it['task']} (due: {it['due']})")

    return {
        "incident_id": incident_id,
        "title": title,
        "severity": severity,
        "summary": f"{incident_id} [{severity}]: {title}",
        "timeline": [
            {"at": ts, "event": desc} for ts, desc in timeline_events
        ],
        "root_cause": root_cause,
        "action_items": items,
        "markdown": "\n".join(lines) + "\n",
    }


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    doc = build_postmortem(
        "INC-1",
        "db down",
        "sev1",
        [("2026-10-08T10:00:00Z", "alert fired"), ("2026-10-08T10:30:00Z", "failover")],
        "disk full on primary",
        [("alice", "add disk alerts", "2026-10-15"), ("bob", "runbook for failover", "2026-10-20")],
    )
    assert "Summary" in doc["markdown"] and "Action items" in doc["markdown"]
    assert doc["action_items"][0]["owner"] == "alice"
    assert len(doc["timeline"]) == 2
    try:
        build_postmortem("INC-2", "t", "sev2", [("t", "e")], "", [("a", "b", "c")])
        raise AssertionError("should raise")
    except Obs27Error:
        pass
    try:
        build_postmortem("INC-3", "t", "sev2", [("t", "e")], "cause", [])
        raise AssertionError("should raise")
    except Obs27Error:
        pass
    try:
        build_postmortem("INC-4", "t", "sev9", [("t", "e")], "cause", [("a", "b", "c")])
        raise AssertionError("should raise")
    except Obs27Error:
        pass
    try:
        build_postmortem("INC-5", "t", "sev2", [("t", "e")], "cause", [("", "b", "c")])
        raise AssertionError("should raise")
    except Obs27Error:
        pass
    assert stdlib_only()
    print("obs_27 OK")


if __name__ == "__main__":
    main()

"""Tests for mcp_drift_monitor: snapshot, diff, fail-closed assessment."""
from __future__ import annotations

import unittest

from mcp_drift_monitor import (
    DriftAssessment,
    DriftType,
    McpToolSnapshot,
    ToolDrift,
    ToolPin,
    assess_drift,
    check_tools_list,
    detect_drift,
    is_sensitive_tool,
    snapshot_tools,
)

READ = {"name": "read_file", "description": "Read a file",
        "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}}
SEARCH = {"name": "search", "description": "Search the web",
          "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}}}
EXEC = {"name": "exec_command", "description": "Run a command",
        "inputSchema": {"type": "object", "properties": {"cmd": {"type": "string"}}}}


def snap(tools, server="s1"):
    return snapshot_tools(server, tools)


class SnapshotTests(unittest.TestCase):
    def test_snapshot_counts_tools(self):
        s = snap([READ, SEARCH])
        self.assertEqual(len(s.tools), 2)
        self.assertEqual(s.tool_names(), ("read_file", "search"))

    def test_snapshot_digest_stable(self):
        a = snap([READ, SEARCH])
        b = snap([SEARCH, READ])  # order-independent digest
        self.assertEqual(a.snapshot_digest, b.snapshot_digest)
        self.assertTrue(a.snapshot_digest.startswith("sha256:"))

    def test_snapshot_digest_changes_on_drift(self):
        a = snap([READ])
        b = snap([{**READ, "description": "Read a file, trust me"}])
        self.assertNotEqual(a.snapshot_digest, b.snapshot_digest)

    def test_snapshot_empty_server_rejected(self):
        with self.assertRaises(ValueError):
            snap([READ], server="")

    def test_snapshot_missing_name_rejected(self):
        with self.assertRaises(ValueError):
            snap([{"description": "x", "inputSchema": {}}])

    def test_snapshot_duplicate_names_rejected(self):
        with self.assertRaises(ValueError):
            snap([READ, dict(READ)])

    def test_snapshot_bad_schema_rejected(self):
        with self.assertRaises(ValueError):
            snap([{"name": "t", "inputSchema": "not-a-mapping"}])

    def test_pin_for_lookup(self):
        s = snap([READ])
        self.assertIsNotNone(s.pin_for("read_file"))
        self.assertIsNone(s.pin_for("nope"))

    def test_pin_rejects_empty_name(self):
        with self.assertRaises(ValueError):
            ToolPin(name="", description_digest="sha256:" + "0" * 64,
                    input_schema_digest="sha256:" + "0" * 64)

    def test_input_schema_alias_accepted(self):
        s = snap([{"name": "t", "description": "d",
                   "input_schema": {"type": "object"}}])
        self.assertEqual(len(s.tools), 1)


class DetectDriftTests(unittest.TestCase):
    def test_no_drift_empty(self):
        a = snap([READ, SEARCH])
        self.assertEqual(detect_drift(a, snap([READ, SEARCH])), ())

    def test_added_tool(self):
        drifts = detect_drift(snap([READ]), snap([READ, SEARCH]))
        self.assertEqual(len(drifts), 1)
        self.assertEqual(drifts[0].drift_type, DriftType.ADDED)
        self.assertEqual(drifts[0].tool, "search")

    def test_removed_tool(self):
        drifts = detect_drift(snap([READ, SEARCH]), snap([READ]))
        self.assertEqual(len(drifts), 1)
        self.assertEqual(drifts[0].drift_type, DriftType.REMOVED)
        self.assertEqual(drifts[0].tool, "search")

    def test_schema_changed(self):
        wider = {**READ, "inputSchema": {"type": "object",
                 "properties": {"path": {"type": "string"}, "mode": {"type": "string"}}}}
        drifts = detect_drift(snap([READ]), snap([wider]))
        self.assertEqual(len(drifts), 1)
        self.assertEqual(drifts[0].drift_type, DriftType.SCHEMA_CHANGED)

    def test_description_changed(self):
        renamed = {**READ, "description": "Read a file from disk"}
        drifts = detect_drift(snap([READ]), snap([renamed]))
        self.assertEqual(len(drifts), 1)
        self.assertEqual(drifts[0].drift_type, DriftType.DESCRIPTION_CHANGED)

    def test_schema_change_wins_over_description(self):
        both = {**READ, "description": "new desc",
                "inputSchema": {"type": "object"}}
        drifts = detect_drift(snap([READ]), snap([both]))
        self.assertEqual(drifts[0].drift_type, DriftType.SCHEMA_CHANGED)

    def test_cross_server_diff_rejected(self):
        with self.assertRaises(ValueError):
            detect_drift(snap([READ], "a"), snap([READ], "b"))

    def test_version_change_alone_is_not_drift(self):
        v2 = {**READ, "version": "2.0.0"}
        self.assertEqual(detect_drift(snap([READ]), snap([v2])), ())


class SensitiveToolTests(unittest.TestCase):
    def test_sensitive_substrings(self):
        for name in ("exec_command", "shell_run", "read_file", "network_fetch",
                     "EXEC", "my_shell_tool"):
            self.assertTrue(is_sensitive_tool(name), name)
        for name in ("search", "summarize", "translate"):
            self.assertFalse(is_sensitive_tool(name), name)


class AssessDriftTests(unittest.TestCase):
    def test_no_drift_allows(self):
        a = assess_drift([])
        self.assertEqual(a.decision, "allow")

    def test_sensitive_drift_denies(self):
        base = snap([EXEC])
        wider = {**EXEC, "inputSchema": {"type": "object",
                 "properties": {"cmd": {"type": "string"}, "raw": {"type": "boolean"}}}}
        drifts = detect_drift(base, snap([wider]))
        a = assess_drift(drifts)
        self.assertEqual(a.decision, "deny")
        self.assertIn("exec_command", a.reason)

    def test_sensitive_added_denies(self):
        drifts = detect_drift(snap([SEARCH]), snap([SEARCH, EXEC]))
        a = assess_drift(drifts)
        self.assertEqual(a.decision, "deny")

    def test_sensitive_removed_denies(self):
        drifts = detect_drift(snap([SEARCH, EXEC]), snap([SEARCH]))
        a = assess_drift(drifts)
        self.assertEqual(a.decision, "deny")

    def test_nonsensitive_drift_allows_with_log(self):
        base = snap([SEARCH])
        renamed = {**SEARCH, "description": "Search the whole web"}
        drifts = detect_drift(base, snap([renamed]))
        a = assess_drift(drifts)
        self.assertEqual(a.decision, "allow")
        self.assertEqual(len(a.drifts), 1)

    def test_assessment_rejects_bad_decision(self):
        with self.assertRaises(ValueError):
            DriftAssessment(decision="maybe")

    def test_assessment_as_dict(self):
        d = assess_drift([]).as_dict()
        self.assertEqual(d["decision"], "allow")
        self.assertEqual(d["drifts"], [])


class CheckToolsListTests(unittest.TestCase):
    def test_end_to_end_no_drift(self):
        base = snap([READ, SEARCH])
        a = check_tools_list("s1", base, [READ, SEARCH])
        self.assertEqual(a.decision, "allow")

    def test_end_to_end_drift_deny(self):
        base = snap([READ, EXEC])
        tampered = [READ, {**EXEC, "description": "Run anything, no questions"}]
        a = check_tools_list("s1", base, tampered)
        self.assertEqual(a.decision, "deny")

    def test_end_to_end_malformed_raises(self):
        base = snap([READ])
        with self.assertRaises(ValueError):
            check_tools_list("s1", base, [{"no": "name"}])

    def test_snapshot_frozen(self):
        s = snap([READ])
        with self.assertRaises(AttributeError):
            s.server = "x"  # type: ignore


if __name__ == "__main__":
    unittest.main()

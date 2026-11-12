"""Typed audit records for verified Agent Skills instruction loads."""
from __future__ import annotations

import hashlib
import json
import unittest

import support  # noqa: F401
from providers.base import SystemMessage
from support import RuntimeTestCase, text_turn, tool_turn
from tools import ToolRegistry, ToolResult, ToolSpec


class SkillLoadAuditTests(RuntimeTestCase):
    def test_verified_skill_read_is_recorded_without_body_or_resume_context(self):
        path = ".northstar/skills/demo/SKILL.md"
        body = (
            "---\nname: demo\ndescription: A harmless example skill.\n---\n\n"
            "Use the repository's documented formatting rules.\n"
        )
        digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
        root = self.workspace({path: body})
        store = self.session_store("skill-load-audit")
        runtime = self.runtime(
            [
                tool_turn("Read", {"path": path}, id="read-demo-skill"),
                text_turn("done"),
            ],
            workspace=root,
            sessions=store,
            skill_digests={path: digest},
        )

        report = self.drive(runtime, "Use the relevant skill.")

        self.assertEqual(report.subtype, "success")
        records, _dropped = store.read()
        loaded = [
            record
            for record in records
            if record.get("type") == "informational"
            and record.get("subtype") == "skill_loaded"
        ]
        self.assertEqual(len(loaded), 1)
        event = loaded[0]
        self.assertEqual(event["skill_name"], "demo")
        self.assertEqual(event["skill_path"], path)
        self.assertEqual(event["skill_digest"], f"sha256:{digest}")
        self.assertEqual(event["tool_use_id"], "read-demo-skill")
        self.assertEqual(event["turn_index"], 1)
        self.assertFalse(event["truncated"])
        self.assertFalse(event["sanitized"])
        self.assertNotIn(body, json.dumps(event))

        replayed = store.transcript()
        self.assertFalse(
            any(
                isinstance(message, SystemMessage)
                and message.subtype == "skill_loaded"
                for message in replayed
            )
        )

    def test_unpinned_skill_and_pinned_companion_resource_are_not_load_events(self):
        skill_path = ".northstar/skills/demo/SKILL.md"
        guide_path = ".northstar/skills/demo/guide.md"
        skill_body = "---\nname: demo\ndescription: Demo.\n---\n\nRead this safely.\n"
        guide_body = "A reviewed companion resource.\n"
        root = self.workspace({skill_path: skill_body, guide_path: guide_body})
        store = self.session_store("skill-load-negative")
        runtime = self.runtime(
            [
                tool_turn("Read", {"path": skill_path}, id="read-unpinned-skill"),
                tool_turn("Read", {"path": guide_path}, id="read-guide"),
                text_turn("done"),
            ],
            workspace=root,
            sessions=store,
            skill_digests={
                guide_path: hashlib.sha256(guide_body.encode("utf-8")).hexdigest()
            },
        )

        self.drive(runtime, "Read the available files.")

        records, _dropped = store.read()
        self.assertFalse(
            any(record.get("subtype") == "skill_loaded" for record in records)
        )

    def test_digest_mismatch_is_not_recorded_as_loaded(self):
        path = ".northstar/skills/demo/SKILL.md"
        body = "---\nname: demo\ndescription: Demo.\n---\n\nRead this safely.\n"
        root = self.workspace({path: body})
        store = self.session_store("skill-load-mismatch")
        runtime = self.runtime(
            [
                tool_turn("Read", {"path": path}, id="read-changed-skill"),
                text_turn("done"),
            ],
            workspace=root,
            sessions=store,
            skill_digests={path: "0" * 64},
        )

        self.drive(runtime, "Read the skill.")

        records, _dropped = store.read()
        self.assertFalse(
            any(record.get("subtype") == "skill_loaded" for record in records)
        )

    def test_custom_read_cannot_spoof_a_verified_skill_load(self):
        path = ".northstar/skills/demo/SKILL.md"
        body = "---\nname: demo\ndescription: Demo.\n---\n\nA safe skill.\n"
        digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
        root = self.workspace({path: body})
        store = self.session_store("skill-load-spoof")

        def fake_read(payload, ctx):
            return ToolResult(
                content=body,
                data={
                    "skill_integrity": "verified",
                    "skill_path": path,
                    "skill_digest": digest,
                    "truncated": False,
                },
            )

        registry = ToolRegistry(
            [
                ToolSpec(
                    name="Read",
                    description="Custom read handler",
                    input_schema={
                        "type": "object",
                        "properties": {"path": {"type": "string"}},
                        "required": ["path"],
                        "additionalProperties": False,
                    },
                    handler=fake_read,
                    kind="read",
                )
            ]
        )
        runtime = self.runtime(
            [
                tool_turn("Read", {"path": path}, id="fake-read"),
                text_turn("done"),
            ],
            workspace=root,
            tools=registry,
            sessions=store,
            skill_digests={path: digest},
        )

        self.drive(runtime, "Read the skill.")

        records, _dropped = store.read()
        self.assertFalse(
            any(record.get("subtype") == "skill_loaded" for record in records)
        )


if __name__ == "__main__":
    unittest.main()

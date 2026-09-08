"""Postconditions: the run's own verdict on whether the work happened.

The property under test is narrow and absolute: **a model that says it finished does
not decide whether it finished.** Everything here is offline and deterministic, and
the last class checks the two things that make it governance rather than a lint -
the checks are invisible to the model, and a repository can add them but never
remove or weaken one.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

import support  # noqa: F401  (bootstraps sys.path)
from support import RuntimeTestCase, tool_turn

from cli import main
from postconditions import (
    KINDS,
    PostCondition,
    PostConditionError,
    PostConditionSet,
    parse_cli_specs,
    parse_postconditions,
    summarise,
)
from providers.scripted import ScriptedProvider


class SpecTests(unittest.TestCase):
    def test_every_kind_is_declareable(self):
        for kind in KINDS:
            if kind == "contains":
                condition = PostCondition(kind=kind, path="a.txt", text="x")
            else:
                condition = PostCondition(kind=kind, path="a.txt")
            self.assertEqual(condition.kind, kind)

    def test_unknown_kind_is_an_error_not_a_warning(self):
        with self.assertRaises(PostConditionError) as caught:
            PostCondition(kind="tests-pass", path="a.txt")
        self.assertIn("expected one of", str(caught.exception))

    def test_paths_must_be_workspace_relative(self):
        for bad in ("/etc/passwd", "../outside.txt", "..", "/"):
            with self.subTest(bad=bad):
                with self.assertRaises(PostConditionError):
                    PostCondition(kind="exists", path=bad)

    def test_contains_needs_its_text(self):
        with self.assertRaises(PostConditionError):
            PostCondition(kind="contains", path="a.txt", text="  ")

    def test_count_is_bounded_below(self):
        with self.assertRaises(PostConditionError):
            PostCondition(kind="contains", path="a.txt", text="x", count=0)

    def test_cli_shorthand_keeps_colons_in_the_text(self):
        (condition,) = parse_cli_specs(["contains:notes.txt:usage: northstar run"])
        self.assertEqual((condition.kind, condition.path, condition.text), ("contains", "notes.txt", "usage: northstar run"))

    def test_cli_shorthand_rejects_a_missing_path(self):
        with self.assertRaises(PostConditionError):
            parse_cli_specs(["exists"])

    def test_parsed_tables_carry_only_what_is_allowed(self):
        with self.assertRaises(PostConditionError):
            parse_postconditions([{"kind": "exists", "path": "a", "script": "rm -rf /"}])
        (condition,) = parse_postconditions([{"kind": "contains", "path": "a", "text": "t", "count": 3}])
        self.assertEqual(condition.as_dict(), {"kind": "contains", "path": "a", "text": "t", "count": 3})

    def test_the_report_shape_is_json_serialisable(self):
        payload = PostCondition(kind="unchanged", path="a.txt").as_dict()
        self.assertEqual(json.loads(json.dumps(payload)), payload)


class EvaluationTests(unittest.TestCase):
    """The evaluator itself: digests before, digests after, no negotiation."""

    def setUp(self) -> None:
        import tempfile

        self.root = Path(tempfile.mkdtemp(prefix="nsar-post-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.root, ignore_errors=True))

    def build(self, specs, before: dict[str, str] | None = None) -> PostConditionSet:
        self.write(before or {})
        set_ = PostConditionSet(self.root, parse_cli_specs(specs) if isinstance(specs[0], str) else specs)
        set_.snapshot()
        return set_

    def write(self, files: dict[str, str]) -> None:
        for name, body in files.items():
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(body, encoding="utf-8")

    def clear(self) -> None:
        for child in sorted(self.root.iterdir(), reverse=True):
            if child.is_symlink() or child.is_file():
                child.unlink()
            else:
                __import__("shutil").rmtree(child, ignore_errors=True)

    def verdicts(self, specs, before, after):
        set_ = self.build(specs, before)
        self.clear()
        self.write(after or {})
        return set_.evaluate()

    def test_exists_and_absent_are_opposite_after_the_run(self):
        found, missing = self.verdicts(["exists:a.txt", "absent:a.txt"], {"a.txt": "x"}, {})
        self.assertFalse(found.ok, "the run deleted it, so 'exists' does not hold")
        self.assertTrue(missing.ok)
        found, missing = self.verdicts(["exists:a.txt", "absent:a.txt"], {}, {"a.txt": "x"})
        self.assertTrue(found.ok, "the run created it")
        self.assertFalse(missing.ok)

    def test_changed_counts_a_new_file_as_changed(self):
        (verdict,) = self.verdicts(["changed:a.txt"], {}, {"a.txt": "created by the run"})
        self.assertTrue(verdict.ok)

    def test_changed_fails_when_nothing_moved(self):
        (verdict,) = self.verdicts(["changed:a.txt"], {"a.txt": "same"}, {"a.txt": "same"})
        self.assertFalse(verdict.ok)
        self.assertEqual(verdict.detail, "unchanged")

    def test_changed_fails_when_the_file_vanished(self):
        (verdict,) = self.verdicts(["changed:a.txt"], {"a.txt": "x"}, {})
        self.assertFalse(verdict.ok)
        self.assertEqual(verdict.detail, "never created")

    def test_unchanged_is_the_read_only_enforcement(self):
        (ok,) = self.verdicts(["unchanged:lock.toml"], {"lock.toml": "v1"}, {"lock.toml": "v1"})
        self.assertTrue(ok.ok)
        (bad,) = self.verdicts(["unchanged:lock.toml"], {"lock.toml": "v1"}, {"lock.toml": "v1 tampered"})
        self.assertFalse(bad.ok)
        self.assertEqual(bad.detail, "was modified")
        self.assertNotEqual(bad.before, bad.after, "the audit carries both content addresses")

    def test_unchanged_holds_across_an_absent_file(self):
        (verdict,) = self.verdicts(["unchanged:ghost.txt"], {}, {})
        self.assertTrue(verdict.ok)

    def test_contains_counts_occurrences(self):
        (verdict,) = self.verdicts(["contains:a.txt:needle"], {}, {"a.txt": "needle and needle"})
        self.assertTrue(verdict.ok, "count defaults to 1")
        set_ = self.build([PostCondition(kind="contains", path="a.txt", text="needle", count=3)], {"a.txt": "needle and needle"})
        self.assertFalse(set_.evaluate()[0].ok)

    def test_contains_reports_a_missing_file_as_a_failure(self):
        set_ = self.build(["contains:gone.txt:needle"])
        (verdict,) = set_.evaluate()
        self.assertFalse(verdict.ok)
        self.assertIn("file missing", verdict.detail)

    def test_the_digest_never_follows_a_symlink_out_of_the_workspace(self):
        outside = self.root.parent / f"outside-{self.root.name}.txt"
        outside.write_text("secret", encoding="utf-8")
        self.addCleanup(outside.unlink, missing_ok=True)
        try:
            (self.root / "link.txt").symlink_to(outside)
        except (OSError, NotImplementedError):  # pragma: no cover - host without symlinks
            self.skipTest("symlinks unavailable here")
        # Rejected while building the verifier, so a run never starts on evidence
        # that would have come from outside the workspace.
        with self.assertRaises(PostConditionError) as caught:
            PostConditionSet(self.root, (PostCondition(kind="unchanged", path="link.txt"),))
        self.assertIn("escapes the workspace", str(caught.exception))

    def test_a_path_resolving_outside_the_workspace_is_refused_at_setup(self):
        # "a/../../x" passes a naive prefix check but resolves above the root, which
        # is where evidence from somewhere else would sneak in.
        with self.assertRaises(PostConditionError):
            PostConditionSet(self.root, (PostCondition(kind="exists", path="a/../../outside"),))

    def test_evaluation_only_reads(self):
        set_ = self.build(["changed:a.txt", "contains:a.txt:needle"], {"a.txt": "needle"})
        before = {child: child.stat().st_mtime_ns for child in [self.root / "a.txt"]}
        set_.evaluate()
        self.assertEqual({child: child.stat().st_mtime_ns for child in before}, before, "a verifier that writes is not a verifier")

    def test_summary_reports_the_structural_split(self):
        set_ = self.build(["unchanged:a.txt", "contains:a.txt:x"], {"a.txt": "x"})
        summary = summarise(set_.evaluate())
        self.assertEqual(summary["checked"], 2)
        self.assertEqual(summary["passed"], 2)
        self.assertEqual(summary["structural_passed"], 1, "contains is convenience, not proof")
        self.assertTrue(summary["ok"])
        self.assertEqual({row["kind"] for row in summary["results"]}, {"unchanged", "contains"})
        self.assertEqual({row["structural"] for row in summary["results"]}, {True, False})


class LoopIntegrationTests(RuntimeTestCase):
    def test_a_claim_of_done_without_the_artifact_ends_red(self):
        root = self.workspace()
        runtime = self.runtime(
            [{"text": "All done - I created out.txt and it is great."}],
            workspace=root,
            postconditions=[PostCondition(kind="exists", path="out.txt")],
        )
        report = self.drive(runtime)
        self.assertExactlyOneResult(report)
        self.assertEqual(report.subtype, "error_postconditions_failed")
        self.assertTrue(report.result.is_error)
        records = [event for event in report.events if getattr(event, "subtype", "") == "postconditions"]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].data["failed"], 1)
        self.assertEqual(records[0].data["results"][0]["detail"], "missing")

    def test_a_run_that_really_did_the_work_succeeds(self):
        root = self.workspace()
        runtime = self.runtime(
            [
                tool_turn("Write", {"path": "out.txt", "content": "real content"}),
                {"text": "written"},
            ],
            workspace=root,
            permission_mode="acceptEdits",
            postconditions=[PostCondition(kind="exists", path="out.txt"), PostCondition(kind="contains", path="out.txt", text="real")],
        )
        report = self.drive(runtime)
        self.assertEqual(report.subtype, "success")
        self.assertTrue((root / "out.txt").is_file())
        records = [event for event in report.events if getattr(event, "subtype", "") == "postconditions"]
        self.assertEqual(records[0].data["passed"], 2)

    def test_the_checks_are_never_shown_to_the_model(self):
        # This is the difference between a verification and a target: a model told
        # that out.txt must contain "real" writes exactly that string and nothing else.
        captured: list = []

        class Recording(ScriptedProvider):
            def generate(self, request):  # noqa: ANN001, D102
                captured.append(request)
                return super().generate(request)

        root = self.workspace({"secret.txt": "top secret inventory"})
        provider = Recording([{"text": "done"}])
        report = self.drive(
            self.runtime(
                provider=provider,
                workspace=root,
                postconditions=[
                    PostCondition(kind="exists", path="secret.txt"),
                    PostCondition(kind="contains", path="secret.txt", text="inventory"),
                ],
            )
        )
        self.assertEqual(report.subtype, "success")
        self.assertTrue(captured, "the provider was actually asked")
        joined = json.dumps([request.snapshot() for request in captured], default=str)
        self.assertNotIn("postcondition", joined.lower())
        self.assertNotIn("inventory", joined, "the file the check reads is not handed to the model")
        self.assertNotIn("never-written", joined)

    def test_unchanged_catches_a_run_that_touched_what_it_should_not(self):
        root = self.workspace({"keep.txt": "do not touch"})
        runtime = self.runtime(
            [
                tool_turn("Write", {"path": "keep.txt", "content": "touched anyway"}),
                {"text": "left it exactly as it was"},
            ],
            workspace=root,
            permission_mode="acceptEdits",
            postconditions=[PostCondition(kind="unchanged", path="keep.txt")],
        )
        report = self.drive(runtime)
        self.assertEqual(report.subtype, "error_postconditions_failed")
        self.assertEqual((root / "keep.txt").read_text(encoding="utf-8"), "touched anyway", "the file proves the check, not the model")

    def test_a_broken_condition_is_a_configuration_error_before_any_turn(self):
        from loop import AgentRuntime, RuntimeConfigurationError, RuntimeConfig

        root = self.workspace()
        with self.assertRaises(RuntimeConfigurationError) as caught:
            AgentRuntime(
                provider=ScriptedProvider([{"text": "x"}]),
                config=RuntimeConfig(workspace=root, postconditions=[PostCondition(kind="exists", path="a/../../outside")]),
            )
        self.assertIn("postconditions", str(caught.exception))

    def test_the_verdict_is_recorded_in_the_transcript(self):
        root = self.workspace()
        store = self.session_store()
        runtime = self.runtime(
            [{"text": "all done"}],
            workspace=root,
            sessions=store,
            postconditions=[PostCondition(kind="exists", path="never-written.txt")],
        )
        self.drive(runtime)
        records, _ = store.read(store.session_id)
        kinds = [record.get("type") for record in records]
        self.assertIn("postconditions", kinds, "the verdict is its own audit record type")
        bodies = json.dumps(records, default=str)
        self.assertIn("postconditions", bodies)
        self.assertIn("never-written.txt", bodies)

    def test_the_init_record_declares_the_checks_that_will_run(self):
        root = self.workspace()
        runtime = self.runtime(
            [{"text": "done"}],
            workspace=root,
            postconditions=[PostCondition(kind="unchanged", path="a.txt", text="", count=1)],
        )
        report = self.drive(runtime)
        init = next(event for event in report.events if getattr(event, "subtype", "") == "init")
        self.assertEqual(init.data["postconditions"], [{"kind": "unchanged", "path": "a.txt"}])


class PolicyFileTests(RuntimeTestCase):
    def write_policy(self, body: str) -> Path:
        root = self.workspace()
        policy = root / ".northstar" / "config.toml"
        policy.parent.mkdir(parents=True, exist_ok=True)
        policy.write_text(body, encoding="utf-8")
        return root

    def run_cli(self, *argv: str) -> tuple[int, str, str]:
        import contextlib
        import io

        out, err = io.StringIO(), io.StringIO()
        saved, sys.stdin = sys.stdin, io.StringIO("")
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = main(list(argv))
        finally:
            sys.stdin = saved
        return code, out.getvalue(), err.getvalue()

    def test_a_repository_can_require_a_check(self):
        root = self.write_policy('permission_mode = "default"\n\n[[verify]]\nkind = "exists"\npath = "out.txt"\n')
        code, out, _ = self.run_cli("run", "--workspace", str(root), "--prompt", "go", "--scripted-text", "done", "--json")
        self.assertEqual(code, 6, "the declared check ran and failed")
        self.assertIn("error_postconditions_failed", out)

    def test_an_unknown_key_in_verify_is_a_configuration_error(self):
        root = self.write_policy('[[verify]]\nkind = "exists"\npath = "a"\ncommand = "rm -rf /"\n')
        code, _, err = self.run_cli("run", "--workspace", str(root), "--prompt", "go", "--scripted-text", "done")
        self.assertEqual(code, 64)
        self.assertIn("unknown key(s)", err)

    def test_a_bogus_kind_in_the_policy_is_a_configuration_error(self):
        root = self.write_policy('[[verify]]\nkind = "vibes"\npath = "a"\n')
        code, _, err = self.run_cli("run", "--workspace", str(root), "--prompt", "go", "--scripted-text", "done")
        self.assertEqual(code, 64)
        self.assertIn("kind must be one of", err)

    def test_cli_and_policy_checks_are_both_enforced(self):
        # Neither side can drop the other's requirement: the merge is additive.
        root = self.write_policy('[[verify]]\nkind = "exists"\npath = "from-policy.txt"\n')
        code, out, _ = self.run_cli(
            "run",
            "--workspace",
            str(root),
            "--prompt",
            "go",
            "--scripted-text",
            "done",
            "--verify",
            "exists:from-cli.txt",
            "--json",
        )
        self.assertEqual(code, 6)
        record = next(
            json.loads(line)
            for line in out.splitlines()
            if json.loads(line).get("type") == "system" and json.loads(line).get("subtype") == "postconditions"
        )
        self.assertEqual(record["data"]["checked"], 2)
        self.assertEqual({row["path"] for row in record["data"]["results"]}, {"from-cli.txt", "from-policy.txt"})


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

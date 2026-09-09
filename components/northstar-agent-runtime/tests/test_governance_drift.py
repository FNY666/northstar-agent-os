"""The exec path must not be able to move the tree the file tools guard.

``test_governance_writes.py`` proves ``Write``/``Edit`` refuse ``.northstar/`` and ``.git/``.
This file proves the same sentence holds for a run that was *granted* ``Shell``: on bwrap the
governance tree is bound read-only so the write never happens, and on a host without user
namespaces the run re-hashes the tree after every exec-shaped result and refuses to call itself
a success - ``error_governance_drift`` (exit 8), with its own audit record type.

Both halves are pinned because they fail differently. A bind that silently did not hold would
read as protection; a watch that fired on ``.northstar/memory`` or on ``git add`` would make the
feature unusable. So the false-positive cases are asserted as hard as the true-positive ones, and
the end-to-end pair branches on what this host's backend can honestly promise rather than on
wishing it could.
"""
from __future__ import annotations

import json
from pathlib import Path

import support  # noqa: F401 - puts the runtime root on sys.path
from support import RuntimeTestCase, tool_turn

import governance_watch
import sessions
from checkpoints import build as build_checkpoint
from events import EXIT_CODES
from governance_watch import (
    GIT_WATCH_NAMES,
    IGNORED_RELATIVES,
    GovernanceWatch,
    compare,
    snapshot,
)
from providers.base import ResultMessage, SystemMessage
from session_replay import build_replay, checkpoint_reports, describe_checkpoint
from tools import ToolContext, ToolLimits, ToolSandbox
from tools.os_sandbox import (
    SandboxError,
    SandboxRequest,
    SandboxResult,
    _bwrap_argv,
    _validate_request,
    ensure_governance_dirs,
    probe_capabilities,
    probe_governance_binds,
)
from tools.shell import governance_binds

POLICY = 'schema_version = "northstar.policy.v1"\npermission_mode = "default"\n'
POKE = "printf 'x = 1\\n' > .northstar/config.toml"


def _init_data(report) -> dict:
    for event in report.events_of(SystemMessage):
        if event.subtype == "init":
            return dict(event.data)
    raise AssertionError("the run produced no init event")


def _drift_events(report) -> list[SystemMessage]:
    return [event for event in report.events_of(SystemMessage) if event.subtype == "governance_drift"]


def _bound() -> bool:
    """Whether this host can bind anything read-only, which decides the pass condition."""
    return probe_capabilities().bwrap_usable


class SnapshotTests(RuntimeTestCase):
    """The tree view itself: what counts as watched, and what is deliberately not."""

    def test_an_absent_prefix_is_recorded_rather_than_invisible(self):
        root = self.workspace()
        first = snapshot(root)
        self.assertEqual(first.items.get(".northstar"), "absent")
        self.assertEqual(first.items.get(".git"), "absent")
        self.assertFalse(first.truncated)
        # Creating it later is "added", not "the entry disappeared": a policy file that did not
        # exist at startup is the shape CVE-2026-25725 was, so it has to be visible.
        (root / ".northstar").mkdir()
        (root / ".northstar" / "config.toml").write_text(POLICY, encoding="utf-8")
        report = compare(root, first)
        self.assertEqual(report.added, (".northstar/config.toml",))
        self.assertNotIn(".northstar", report.removed)
        self.assertFalse(report.ok)

    def test_a_content_change_is_reported_with_both_digests(self):
        root = self.workspace({".northstar/config.toml": POLICY})
        watch = GovernanceWatch(root)
        before = watch.freeze()
        self.assertTrue(watch.frozen)
        (root / ".northstar" / "config.toml").write_text(POLICY + "deny_tools = []\n", encoding="utf-8")
        found = watch.check()
        assert found is not None
        self.assertEqual(found.changed, (".northstar/config.toml",))
        self.assertEqual(found.findings, ("changed:.northstar/config.toml",))
        payload = found.as_dict()
        self.assertEqual(payload["before"], before.digest)
        self.assertEqual(payload["after"], snapshot(root).digest)
        self.assertNotEqual(payload["before"], payload["after"])
        # Re-freezing after the change is silence: the watch reports a delta, not a state.
        again = GovernanceWatch(root)
        again.freeze()
        self.assertIsNone(again.check())

    def test_deleting_the_tree_is_a_removal(self):
        root = self.workspace({".northstar/config.toml": POLICY})
        watch = GovernanceWatch(root)
        watch.freeze()
        (root / ".northstar" / "config.toml").unlink()
        found = watch.check()
        assert found is not None
        self.assertEqual(found.removed, (".northstar/config.toml",))

    def test_documented_carveouts_are_not_drift(self):
        root = self.workspace({".northstar/config.toml": POLICY})
        watch = GovernanceWatch(root)
        watch.freeze()
        for relative in IGNORED_RELATIVES:
            path = root / relative
            path.mkdir(parents=True, exist_ok=True)
            (path / "written-by-design.txt").write_text("fine\n", encoding="utf-8")
        self.assertIsNone(watch.check())

    def test_under_git_only_what_can_execute_is_watched(self):
        root = self.workspace({".git/config": "[user]\nname = operator\n"})
        (root / ".git" / "objects").mkdir(parents=True)
        watch = GovernanceWatch(root)
        watch.freeze()
        # Ordinary git use churns these; treating that as an attack would make the run
        # unusable, and the audit trail a commit writes is not the policy.
        (root / ".git" / "index").write_text("staged\n", encoding="utf-8")
        (root / ".git" / "objects" / "loose").mkdir()
        (root / ".git" / "objects" / "loose" / "ab12cd").write_text("object\n", encoding="utf-8")
        self.assertIsNone(watch.check())
        # These two are the execution-bearing ones (``[alias]``, hooks) - both must fire.
        (root / ".git" / "config").write_text("[alias]\nping = !touch pwned\n", encoding="utf-8")
        (root / ".git" / "hooks").mkdir()
        (root / ".git" / "hooks" / "pre-commit").write_text("#!/bin/sh\n", encoding="utf-8")
        found = watch.check()
        assert found is not None
        self.assertEqual(sorted(found.changed + found.added), [".git/config", ".git/hooks/pre-commit"])
        self.assertIn("config", GIT_WATCH_NAMES)

    def test_the_entry_cap_is_visible_instead_of_silent(self):
        root = self.workspace({f".northstar/agents/agent-{index}.md": "x\n" for index in range(6)})
        original = governance_watch.MAX_ENTRIES
        governance_watch.MAX_ENTRIES = 3
        try:
            view = snapshot(root)
            self.assertTrue(view.truncated)
            self.assertLess(view.watched, 6, "the cap must cap")
            watch = GovernanceWatch(root)
            watch.freeze()
            self.assertTrue(watch.describe()["baseline"]["truncated"], "init has to say the baseline was truncated")
        finally:
            governance_watch.MAX_ENTRIES = original
        self.assertFalse(snapshot(root).truncated)

    def test_a_huge_file_is_named_and_sized_instead_of_hashed(self):
        root = self.workspace({".northstar/big.md": "x" * 4096 + "\n"})
        original = governance_watch.MAX_HASH_BYTES
        governance_watch.MAX_HASH_BYTES = 4
        try:
            view = snapshot(root)
            self.assertIn("oversized", view.items[".northstar/big.md"])
        finally:
            governance_watch.MAX_HASH_BYTES = original

    def test_a_disabled_watch_says_why_and_never_raises(self):
        root = self.workspace({".northstar/config.toml": POLICY})
        watch = GovernanceWatch(root, enabled=False)
        self.assertIsNone(watch.freeze())
        self.assertFalse(watch.frozen)
        self.assertIsNone(watch.check())
        described = watch.describe()
        self.assertFalse(described["enabled"])
        self.assertIn("--no-drift-check", described["reason"])
        self.assertNotIn("baseline", described)


class SandboxBindTests(RuntimeTestCase):
    """The prevention layer: what the bwrap argv asks for, and what a request may not name."""

    def test_the_governance_tree_is_bound_read_only_after_the_workspace(self):
        root = self.workspace({".northstar/config.toml": POLICY, ".git/config": "[a]\n"})
        request = SandboxRequest(
            argv=("/bin/true",),
            cwd=root,
            workspace=root,
            read_only_paths=(Path(".northstar"), Path(".git")),
            writable_paths=(Path(".northstar/memory"),),
        )
        argv = _bwrap_argv(request, bwrap_path="/usr/bin/bwrap")
        ro_positions = [index for index, item in enumerate(argv) if item == "--ro-bind-try"]
        rw_positions = [index for index, item in enumerate(argv) if item == "--bind-try"]
        workspace_position = argv.index("--bind")
        # Order is the whole point: bwrap lets the later bind win.
        self.assertTrue(all(index > workspace_position for index in ro_positions))
        self.assertTrue(rw_positions and all(index > max(ro_positions) for index in rw_positions))
        self.assertEqual(
            sorted(Path(argv[index + 1]).name for index in ro_positions),
            [".git", ".northstar"],
        )
        self.assertEqual([str(root / ".northstar" / "memory")], [argv[index + 1] for index in rw_positions])
        self.assertIn("--chdir", argv)
        self.assertEqual(argv[argv.index("--chdir") + 1], str(root))

    def test_a_path_that_escapes_the_workspace_is_refused(self):
        root = self.workspace()
        for escapee in ("../outside", "/etc"):
            with self.subTest(path=escapee):
                with self.assertRaises(SandboxError) as caught:
                    _validate_request(
                        SandboxRequest(
                            argv=("/bin/true",),
                            cwd=root,
                            workspace=root,
                            read_only_paths=(Path(escapee),),
                        )
                    )
                self.assertIn("escapes the workspace", str(caught.exception))

    def test_only_a_missing_dot_directory_child_of_the_workspace_is_created(self):
        root = self.workspace()
        created = ensure_governance_dirs(root, (Path(".northstar"), Path(".git"), Path("plain"), Path("a/b")))
        self.assertEqual({path.name for path in created}, {".northstar", ".git"})
        self.assertEqual((root / ".northstar").stat().st_mode & 0o777, 0o700)
        self.assertFalse((root / "plain").exists(), "a non-dot directory is the caller's business")
        self.assertFalse((root / "a").exists(), "a nested path is not this function's to invent")
        self.assertEqual(ensure_governance_dirs(root, (Path(".northstar"),)), [], "idempotent")

    def test_binds_come_from_the_limits_and_never_from_the_payload(self):
        root = self.workspace()
        limits = ToolLimits(protected_prefixes=(".northstar",))
        context = ToolContext(
            session_id="test",
            sandbox=ToolSandbox(root, limits=limits),
            limits=limits,
            services={"shell_backend": "process"},
        )
        read_only, writable = governance_binds(context)
        self.assertEqual(tuple(read_only), (Path(".northstar"),))
        self.assertEqual(tuple(writable), (Path(".northstar/memory"), Path(".northstar/tmp")))

        # No protected prefixes: nothing requested, so nothing is silently re-bound writable.
        open_limits = ToolLimits(protected_prefixes=())
        loose = ToolContext(
            session_id="test",
            sandbox=ToolSandbox(root, limits=open_limits),
            limits=open_limits,
            services={"shell_backend": "process"},
        )
        self.assertEqual(governance_binds(loose), ((), ()))

    def test_a_bind_that_did_not_hold_is_a_configuration_error_not_a_downgrade(self):
        """The probe's whole purpose: a promised read-only bind that failed must stop the run.

        ``--ro-bind-try`` is quiet when it cannot do the job, so without this gate a host whose
        bwrap refuses the bind would report "governance tree bound read-only" while the tree was
        open. The fake probe stands in for that host - it is the only way to test the branch on a
        machine with no user namespaces, and it keeps the assertion about *our* behaviour.
        """
        from tools import os_sandbox

        root = self.workspace({".northstar/config.toml": POLICY})
        request = SandboxRequest(
            argv=("/bin/true",), cwd=root, workspace=root, read_only_paths=(Path(".northstar"),)
        )
        seen: list[tuple] = []

        def verdict(ok: bool):
            def probe(workspace, paths, *, capabilities=None, phase=False):
                seen.append(tuple(sorted(str(path) for path in paths)))
                return ok, ".northstar is writable inside the sandbox: the read-only bind did not hold"

            return probe

        def run_with(probe):
            os_sandbox.reset_bind_verdicts()
            original_probe, original_caps = os_sandbox.probe_governance_binds, os_sandbox.probe_capabilities
            os_sandbox.probe_governance_binds = probe
            os_sandbox.probe_capabilities = lambda: os_sandbox.SandboxCapabilities(
                bwrap_path="/bin/echo", bwrap_usable=True, bwrap_detail="fake bwrap for the test"
            )
            try:
                return os_sandbox.run_sandboxed(request, backend="bwrap")
            except SandboxError as error:
                return error
            finally:
                os_sandbox.probe_governance_binds, os_sandbox.probe_capabilities = original_probe, original_caps
                os_sandbox.reset_bind_verdicts()

        try:
            failure = run_with(verdict(False))
            self.assertIsInstance(failure, SandboxError, f"a lying bind must not run: {failure!r}")
            self.assertIn("does not hold", str(failure))
            self.assertEqual(seen, [(".northstar",)], "the verdict is cached per (workspace, paths)")
            self.assertIsInstance(run_with(verdict(True)), SandboxResult)
        finally:
            os_sandbox.reset_bind_verdicts()

    def test_the_probe_never_writes_and_says_when_it_cannot_run(self):
        root = self.workspace()
        ok, detail = probe_governance_binds(root, [Path(".northstar")])
        self.assertFalse((root / ".northstar").exists(), "a self-check must not create workspace state")
        if _bound():  # pragma: no cover - hosts with user namespaces
            self.assertTrue(ok)
        else:
            self.assertFalse(ok, "an unverifiable host must not be reported as a pass")
            self.assertIn("not verifiable", detail)


class RunDriftTests(RuntimeTestCase):
    """End to end on this host's backend: a run must not sign off on its own loosening."""

    def shell_run(self, *, command: str, root: Path, **config_kwargs):
        store = sessions.SessionStore(root / "sessions", session_id="ns-drift")
        runtime = self.runtime(
            [tool_turn("Shell", {"command": command}), {"text": "done"}],
            workspace=root,
            sessions=store,
            allowed_tools=("Shell",),
            permission_mode="default",
            max_turns=5,
            **config_kwargs,
        )
        return runtime.run_collect("prove it"), store

    def test_writing_the_policy_by_shell_ends_the_run(self):
        root = self.workspace({".northstar/config.toml": POLICY})
        report, store = self.shell_run(command=POKE, root=root)
        result = self.assertExactlyOneResult(report)
        written = (root / ".northstar" / "config.toml").read_text(encoding="utf-8")
        if written == POLICY:
            # Prevention held (bwrap bound the tree read-only): the run goes on and says nothing.
            self.assertTrue(_bound(), "on a process-only host the file must have changed")
            self.assertEqual(result.subtype, "success")
            self.assertEqual(_drift_events(report), [])
            return
        self.assertEqual(result.subtype, "error_governance_drift")
        self.assertTrue(result.is_error)
        self.assertEqual(EXIT_CODES[result.subtype], 8)
        drift = _drift_events(report)
        self.assertEqual(len(drift), 1)
        self.assertIn(".northstar/config.toml", json.dumps(drift[0].data, sort_keys=True))
        self.assertEqual(drift[0].data["changed"], [".northstar/config.toml"])
        self.assertEqual(drift[0].data["exec_calls"], 1, "the record says how much had already run")
        self.assertTrue(any("governance tree" in str(item) for item in (result.errors or ())))
        records, _dropped = sessions.load_jsonl(store.path)
        self.assertIn("governance_drift", [record["type"] for record in records])

    def test_opting_out_is_permitted_and_disclosed(self):
        root = self.workspace({".northstar/config.toml": POLICY})
        report, _store = self.shell_run(command=POKE, root=root, governance_watch=False)
        result = self.assertExactlyOneResult(report)
        written = (root / ".northstar" / "config.toml").read_text(encoding="utf-8")
        self.assertEqual(_drift_events(report), [], "a disabled watch says nothing, in either direction")
        self.assertEqual(result.subtype, "success")
        if _bound():
            # Prevention does not depend on the watch: the bind still refused the write.
            self.assertEqual(written, POLICY)
        else:
            # The whole trade in one assertion - no bind, no watch, so nothing notices.
            self.assertNotEqual(written, POLICY)
        watch = _init_data(report)["governance_watch"]
        self.assertFalse(watch["enabled"])
        self.assertIn("--no-drift-check", watch["reason"])

    def test_the_carveouts_stay_writable_without_tripping_the_watch(self):
        root = self.workspace({".northstar/config.toml": POLICY})
        command = (
            "mkdir -p .northstar/memory .northstar/tmp"
            " && printf 'note\\n' > .northstar/memory/MEMORY.md"
            " && printf 'x\\n' > .northstar/tmp/scratch"
        )
        report, _store = self.shell_run(command=command, root=root)
        result = self.assertExactlyOneResult(report)
        self.assertEqual(_drift_events(report), [], "a documented carve-out must never read as drift")
        self.assertEqual(result.subtype, "success")

    def test_read_only_tools_never_disturb_the_watch(self):
        root = self.workspace({"notes.txt": "n\n"})
        runtime = self.runtime(
            [tool_turn("Write", {"path": "notes.txt", "content": "changed\n"}), {"text": "done"}],
            workspace=root,
            allowed_tools=("Write",),
            permission_mode="acceptEdits",
            max_turns=4,
        )
        report = runtime.run_collect("edit a normal file")
        result = self.assertExactlyOneResult(report)
        self.assertEqual(result.subtype, "success")
        self.assertEqual(_drift_events(report), [])
        self.assertEqual((root / "notes.txt").read_text(encoding="utf-8"), "changed\n")

    def test_the_watch_reports_itself_in_init_even_when_it_finds_nothing(self):
        root = self.workspace()
        runtime = self.runtime(
            [{"text": "nothing to run"}], workspace=root, allowed_tools=("Read",), max_turns=2
        )
        report = runtime.run_collect("go")
        watch = _init_data(report)["governance_watch"]
        self.assertTrue(watch["enabled"])
        self.assertEqual(tuple(watch["prefixes"]), ToolLimits().protected_prefixes)
        self.assertEqual(watch["ignored"], list(IGNORED_RELATIVES))
        self.assertIn("baseline", watch)
        self.assertEqual(_drift_events(report), [])

    def test_a_child_run_does_not_watch_the_same_tree_twice(self):
        root = self.workspace()
        for depth, expected in ((0, True), (1, False)):
            with self.subTest(depth=depth):
                runtime = self.runtime([{"text": "ok"}], workspace=root, depth=depth, max_turns=1)
                self.assertEqual(runtime.governance.describe()["enabled"], expected)


class ReplayTests(RuntimeTestCase):
    """The reader side: verification that scales, and a drift record with its own frame."""

    def session_with_checkpoints(self, turns: int = 4):
        store = sessions.SessionStore(self.workspace(), session_id="ns-fold")
        for turn in range(1, turns + 1):
            store.append("assistant", {"content": [{"type": "text", "text": f"turn {turn}"}]})
            store.append(
                "checkpoint",
                build_checkpoint(
                    session_id=store.session_id,
                    record_index=store._index,  # the store's own next index, as the loop passes it
                    transcript=store.transcript(),
                    turns=turn,
                    tool_calls=0,
                    cost_usd=0.0,
                    usage={},
                    model="scripted",
                    provider="scripted",
                    permission_mode="default",
                ),
            )
        records, _dropped = sessions.load_jsonl(store.path)
        return records

    def test_batch_verification_agrees_with_the_single_call_route(self):
        records = self.session_with_checkpoints()
        batch = checkpoint_reports(records)
        self.assertEqual(len(batch), 4)
        for report in batch:
            self.assertTrue(report.verified, report.detail)
            single = describe_checkpoint(records[report.record_index], records)
            self.assertEqual(single.status, report.status)
            self.assertEqual(single.digest, report.digest)

    def test_a_tampered_prefix_still_fails_in_the_batch_route(self):
        records = self.session_with_checkpoints()
        last = [record for record in records if record.get("type") == "assistant"][-1]
        last["content"] = [{"type": "text", "text": "edited after the fact"}]
        statuses = [report.status for report in checkpoint_reports(records)]
        # Everything before the edit still verifies; the boundary that covers it does not.
        self.assertEqual(statuses[:3], ["verified"] * 3)
        self.assertEqual(statuses[3:], ["digest-mismatch"])

    def test_a_boundary_longer_than_the_file_is_reported_not_indexed_past(self):
        # A truncated file is the incident-time case: the fast path must not reach for a
        # prefix that is not there, and it must agree with the single-call route.
        records = self.session_with_checkpoints()
        boundary = dict([record for record in records if record.get("type") == "checkpoint"][-1])
        boundary["transcript_len"] = 999
        records = [*records, boundary]
        fast = [report.status for report in checkpoint_reports(records)]
        slow = describe_checkpoint(boundary, records).status
        self.assertEqual(fast[-1], "prefix-short")
        self.assertEqual(slow, "prefix-short")
        self.assertEqual(fast[:-1], ["verified"] * 4)
        self.assertIn("shorter than its own checkpoint", checkpoint_reports(records)[-1].detail)

    def test_a_drift_record_becomes_its_own_frame(self):
        root = self.workspace()
        store = sessions.SessionStore(root, session_id="ns-drift-frame")
        store.record_system(
            SystemMessage(
                subtype="governance_drift",
                content="governance drift: 1 changed, 0 added, 0 removed of 1 watched",
                data={
                    "ok": False,
                    "changed": [".northstar/config.toml"],
                    "added": [],
                    "removed": [],
                    "watched": 1,
                    "truncated": False,
                    "before": "a" * 64,
                    "after": "b" * 64,
                    "summary": "1 changed, 0 added, 0 removed of 1 watched",
                },
            )
        )
        store.append("assistant", {"content": [{"type": "text", "text": "after"}]})
        store.record_result(ResultMessage(subtype="error_governance_drift"))
        records, _dropped = sessions.load_jsonl(store.path)
        replay = build_replay(records, session_id=store.session_id)
        frames = [frame for frame in replay.frames if frame.kind == "governance_drift"]
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].governance_drift, 1)
        self.assertIn("1 changed", frames[0].label)
        payload = frames[0].as_dict()
        self.assertEqual(payload["governance_drift"], 1)
        self.assertEqual(replay.counts["governance_drift"], 1)
        self.assertEqual(replay.counts["denials"], 0, "drift is not a denial and must not count as one")
        self.assertIn("governance drift record(s)", replay.summary())
        self.assertIn("governance drift", frames[0].line())

    def test_a_transcript_without_drift_keeps_the_old_frame_shape(self):
        records = self.session_with_checkpoints(turns=2)
        replay = build_replay(records, session_id="ns-fold")
        self.assertEqual(replay.counts["governance_drift"], 0)
        for frame in replay.frames:
            self.assertNotIn("governance_drift", frame.as_dict())
        self.assertNotIn("governance drift", replay.summary())


class RegistryTests(RuntimeTestCase):
    """A new wire token has to be registered on every side; this is the pin for that."""

    def test_the_drift_pair_is_registered_on_every_side_it_appears(self):
        from audit_export import _ERROR_TYPES
        from loop import RuntimeConfig
        from providers.base import RESULT_SUBTYPES, SYSTEM_SUBTYPES
        from sessions import RECORD_TYPES

        self.assertIn("error_governance_drift", RESULT_SUBTYPES)
        self.assertIn("governance_drift", SYSTEM_SUBTYPES)
        self.assertEqual(EXIT_CODES["error_governance_drift"], 8)
        self.assertIn("governance_drift", RECORD_TYPES)
        self.assertIn("governance_drift", _ERROR_TYPES, "the drift must show up as an error, not a note")
        self.assertTrue(RuntimeConfig(workspace=".").governance_watch, "on by default")

    def test_the_typescript_face_mirrors_the_exit_code(self):
        face = Path(sessions.__file__).resolve().parent / "sdk-ts" / "src" / "events.ts"
        line = next(
            (item for item in face.read_text(encoding="utf-8").splitlines() if "error_governance_drift" in item),
            "",
        )
        self.assertIn(": 8", line, f"TS mirror says: {line!r}")

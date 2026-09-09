"""The session lease: one writer per transcript, proven across processes.

Two rules drive every assertion here. The lock is the fact and the JSON is a claim, so a
reader may quote the file but must never treat it as authority. And a live holder is never
displaced, so the interesting case is not "expired" but "expired *and still holding*",
which is exactly what a timestamp-only lease gets wrong.
"""
from __future__ import annotations

import errno
import json
import os
import subprocess
import sys
import time
import unittest
from pathlib import Path

import support  # noqa: F401  (installs the sys.path shim)
from support import RuntimeTestCase, load_durable, text_turn, tool_turn

from durable_bridge import canonical_json as bridge_canonical_json
from events import EXIT_CODES
from hooks import HookRegistry
from loop import AgentRuntime, RuntimeConfig, RuntimeConfigurationError
from providers.scripted import ScriptedProvider
from session_lease import (
    DEFAULT_LEASE_SECONDS,
    LEASE_FIELDS,
    LEASE_SUFFIX,
    MAX_LEASE_SECONDS,
    MIN_LEASE_SECONDS,
    LeaseError,
    SessionBusyError,
    SessionLease,
    inspect_lease,
    lease_path_for,
    owner_id_for,
    validate_owner_id,
    validate_ttl,
)
from sessions import SessionStore

ROOT = Path(__file__).resolve().parents[1]

#: A child process that holds a lease, says so, and lets go when its stdin gets a line.
#: Real subprocesses, not two objects in one process: ``flock`` semantics are what is under
#: test, and an in-process pair only proves the code path, not the kernel's rule.
CHILD = """
import sys
sys.path.insert(0, {root!r})
from session_lease import SessionLease, SessionBusyError
lease = SessionLease(sys.argv[1], owner_id={owner!r}, ttl_seconds=30)
try:
    lease.acquire()
except SessionBusyError as error:
    print("BUSY " + (error.owner_id or "<unknown>"), flush=True)
    raise SystemExit(3)
print("HELD", flush=True)
sys.stdin.readline()
lease.release()
print("RELEASED", flush=True)
"""


def child_source(owner: str) -> str:
    return CHILD.format(root=str(ROOT), owner=owner)


class LeaseEnvelopeTests(RuntimeTestCase):
    """The envelope is durable-run's; the enforcement is not, and both facts are pinned."""

    def test_envelope_is_two_fields_written_in_place(self):
        lease = SessionLease(self.workspace() / "s.lease", owner_id="run-a", ttl_seconds=60)
        lease.acquire()
        value = json.loads(lease.path.read_text(encoding="utf-8"))
        lease.release()
        self.assertEqual(set(value), set(LEASE_FIELDS))
        self.assertEqual(sorted(LEASE_FIELDS), ["expires_at", "owner_id"])
        self.assertEqual(value["owner_id"], "run-a")
        self.assertIsInstance(value["expires_at"], int)

    def test_a_durable_reader_would_parse_what_we_write(self):
        """Key-compatible with ``runner.LeaseManager``, without pretending to be it.

        The two components disagree about enforcement on purpose (a timestamp reclaims; a
        held ``flock`` does not), so the only thing that has to match is what a reader
        parses. That is what this pins.
        """
        directory = self.workspace()

        mine = SessionLease(directory / "runtime.lease", owner_id="run-a", ttl_seconds=60)
        mine.acquire()
        my_value = json.loads(mine.path.read_text(encoding="utf-8"))
        mine.release()

        runner = load_durable("runner")
        path = directory / "durable.json"
        # Durable's own API, spelled the way it is spelled there: the manager is bound to a
        # path and every call carries the owner and the clock - which is exactly why its
        # lease is only a claim. The runtime's object binds an owner once and holds a
        # descriptor; the file is the part that has to agree, and it does.
        manager = runner.LeaseManager(path)
        lease = manager.acquire("run-a", now=int(time.time()), ttl_seconds=60)
        their_value = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(sorted(their_value), ["expires_at", "owner_id"])
        # The runtime's own reader, pointed at a durable-written file: the fields, the
        # types, and the "is this still claimed" reading all have to work across the two
        # writers, or the shared envelope is a story rather than a property.
        from_runtime = inspect_lease(path, probe=False)
        self.assertEqual(from_runtime.owner_id, their_value["owner_id"])
        self.assertEqual(from_runtime.expires_at, their_value["expires_at"])
        self.assertTrue(from_runtime.metadata_readable)
        manager.release("run-a")
        self.assertEqual(set(their_value), set(my_value))
        self.assertEqual(type(their_value["owner_id"]), type(my_value["owner_id"]))
        # Durable deletes its lease file on release; we keep ours as a trace. That is a real
        # divergence, and it is safe in both directions because a reader treats "no file" as
        # "no claim" (the second read below proves the runtime reader does).
        self.assertFalse(path.exists())
        self.assertEqual(inspect_lease(path, probe=False).owner_id, "")
        self.assertEqual(lease["owner_id"], "run-a")

    def test_the_write_is_in_place_because_replace_would_drop_the_lock(self):
        """``os.replace`` would unlink the inode the lock is held on. Guard the divergence."""
        lease = SessionLease(self.workspace() / "s.lease", owner_id="run-a", ttl_seconds=60)
        lease.acquire()
        inode = os.stat(lease.path).st_ino
        lease.heartbeat()
        lease.release()
        self.assertEqual(os.stat(lease.path).st_ino, inode, "a renewal must not swap the file")

    def test_file_is_private_even_when_the_directory_is_not_ours(self):
        directory = self.temp_dir() / "nested"
        lease = SessionLease(directory / "s.lease", owner_id="run-a", ttl_seconds=60)
        lease.acquire()
        self.assertEqual(os.stat(lease.path).st_mode & 0o777, 0o600)
        lease.release()

    def test_lease_path_is_the_sibling_of_the_transcript(self):
        path = lease_path_for("/tmp/sessions", "ns-20260908T000000Z-abc")
        self.assertEqual(path.parent.name, "sessions")
        self.assertEqual(path.name, f"ns-20260908T000000Z-abc{LEASE_SUFFIX}")

    def test_a_path_unsafe_session_id_is_refused_not_hashed(self):
        for bad in ("../escape", "a b", ""):
            with self.subTest(bad=bad), self.assertRaises(LeaseError):
                lease_path_for("/tmp/s", bad)

    def test_ttl_bounds_are_enforced_with_the_alternative_offered(self):
        self.assertEqual(validate_ttl(DEFAULT_LEASE_SECONDS), DEFAULT_LEASE_SECONDS)
        for bad in (MIN_LEASE_SECONDS - 1, MAX_LEASE_SECONDS + 1, True, 0, "90"):
            with self.subTest(bad=bad), self.assertRaises(LeaseError):
                validate_ttl(bad)
        with self.assertRaises(LeaseError) as caught:
            validate_ttl(1)
        self.assertIn("--no-session-lease", str(caught.exception))

    def test_owner_id_charset_is_the_run_contracts_rule(self):
        validate_owner_id("run-7")
        validate_owner_id("pid1234-abcdef01")
        for bad in ("has space", "with/slash", "with\\backslash", "x" * 129, "   "):
            with self.subTest(bad=bad), self.assertRaises(LeaseError):
                validate_owner_id(bad)

    def test_owner_id_prefers_the_run_id_and_falls_back_to_pid_plus_session(self):
        self.assertEqual(owner_id_for("run-7", session_id="s-1"), "run-7")
        fallback = owner_id_for(None, session_id="s-1")
        self.assertTrue(fallback.startswith(f"pid{os.getpid()}-"))
        self.assertIn("s-1", fallback)

    def test_busy_error_is_not_a_value_error(self):
        # The CLI maps configuration errors to exit 64. Contention must not join them: the
        # command was well formed, the session was busy.
        self.assertTrue(issubclass(SessionBusyError, RuntimeError))
        self.assertFalse(issubclass(SessionBusyError, ValueError))

    def test_both_busy_errno_spellings_are_accepted(self):
        import session_lease

        self.assertIn(errno.EAGAIN, session_lease._BUSY_ERRNOS)
        self.assertIn(errno.EWOULDBLOCK, session_lease._BUSY_ERRNOS)


class AcquisitionTests(RuntimeTestCase):
    def test_acquire_writes_the_owner_and_release_keeps_the_file(self):
        path = self.workspace() / "s.lease"
        lease = SessionLease(path, owner_id="run-a", ttl_seconds=60)
        status = lease.acquire()
        self.assertTrue(status.locked)
        self.assertEqual(status.owner_id, "run-a")
        self.assertTrue(lease.held)
        lease.release()
        # Not deleted, deliberately: unlinking races a waiter that already opened the
        # path, and the last owner is a useful trace. What release changes is the lock.
        self.assertTrue(path.exists())
        after = inspect_lease(path)
        self.assertFalse(after.locked)
        self.assertEqual(after.owner_id, "run-a")
        self.assertFalse(lease.held)

    def test_acquire_creates_the_directory_it_needs(self):
        directory = self.temp_dir() / "deep" / "deeper"
        lease = SessionLease(directory / "s.lease", owner_id="run-a", ttl_seconds=60)
        lease.acquire()
        self.assertTrue(directory.is_dir())
        lease.release()

    def test_double_acquire_on_one_object_is_a_mistake(self):
        lease = SessionLease(self.workspace() / "s.lease", owner_id="run-a", ttl_seconds=60)
        lease.acquire()
        with self.assertRaises(LeaseError):
            lease.acquire()
        lease.release()

    def test_release_is_idempotent_and_a_beat_without_a_lock_is_a_no_op(self):
        lease = SessionLease(self.workspace() / "s.lease", owner_id="run-a", ttl_seconds=60)
        # A no-op, not an error, because the loop calls this from a boundary a refused run
        # never reached; `held` is the flag callers must check before relying on it.
        beat = lease.heartbeat()
        # A no-op, not an error, because the loop calls this from a boundary a refused run
        # never reached - and nothing was claimed, so nothing is asserted about an owner.
        self.assertFalse(beat.locked)
        self.assertEqual(beat.owner_id, "")
        self.assertFalse(lease.held)
        lease.acquire()
        lease.release()
        lease.release()
        self.assertFalse(lease.held)

    def test_the_context_manager_releases_on_the_way_out(self):
        path = self.workspace() / "s.lease"
        with SessionLease(path, owner_id="run-a", ttl_seconds=60) as lease:
            self.assertTrue(inspect_lease(path).locked)
            self.assertTrue(lease.held)
        self.assertFalse(inspect_lease(path).locked)

    def test_a_body_that_raises_still_releases(self):
        path = self.workspace() / "s.lease"
        with self.assertRaises(RuntimeError):
            with SessionLease(path, owner_id="run-a", ttl_seconds=60):
                raise RuntimeError("the run died mid-flight")
        self.assertFalse(inspect_lease(path).locked)
        SessionLease(path, owner_id="run-b", ttl_seconds=60).acquire().locked and None

    def test_heartbeat_moves_the_promise_without_losing_the_lock(self):
        path = self.workspace() / "s.lease"
        clock = {"now": 1000.0}
        lease = SessionLease(path, owner_id="run-a", ttl_seconds=60, now=lambda: clock["now"])
        first = lease.acquire()
        clock["now"] += 10
        second = lease.heartbeat()
        self.assertEqual(second.expires_at, first.expires_at + 10)
        self.assertTrue(inspect_lease(path).locked)
        lease.release()

    def test_a_stale_holder_cannot_be_displaced_by_a_new_lease(self):
        """The divergence from durable-run, stated as a test.

        An expired ``expires_at`` on a file whose lock is still held means "this process
        forgot to renew", not "this file is free". Reclaiming on that reading is how two
        live writers end up inside one transcript.
        """
        path = self.workspace() / "s.lease"
        holder = SessionLease(path, owner_id="run-slow", ttl_seconds=MIN_LEASE_SECONDS, now=lambda: 0)
        holder.acquire()
        status = inspect_lease(path)
        self.assertTrue(status.expired)
        self.assertTrue(status.locked)
        with self.assertRaises(SessionBusyError) as caught:
            SessionLease(path, owner_id="run-new", ttl_seconds=60).acquire()
        self.assertEqual(caught.exception.owner_id, "run-slow")
        self.assertIn("run-slow", str(caught.exception))
        holder.release()

    def test_status_falls_back_to_its_own_word_when_the_file_lies(self):
        path = self.workspace() / "s.lease"
        lease = SessionLease(path, owner_id="run-a", ttl_seconds=60)
        lease.acquire()
        path.write_text("{corrupt", encoding="utf-8")
        status = lease.status()
        lease.release()
        # The object still knows what it wrote; `metadata_readable` is how it says "on my
        # word, not on the file's".
        self.assertEqual(status.owner_id, "run-a")
        self.assertFalse(status.metadata_readable)
        self.assertTrue(status.locked)

    def test_a_torn_envelope_reads_as_owner_unknown(self):
        path = self.workspace() / "s.lease"
        path.write_text('{"owner_id": "run-x", "expir', encoding="utf-8")
        status = inspect_lease(path)
        self.assertEqual(status.owner_id, "")
        self.assertFalse(status.metadata_readable)
        self.assertFalse(status.locked)

    def test_inspect_without_a_probe_reports_the_claim_not_the_fact(self):
        path = self.workspace() / "s.lease"
        lease = SessionLease(path, owner_id="run-a", ttl_seconds=60)
        lease.acquire()
        claim = inspect_lease(path, probe=False)
        held = inspect_lease(path)
        self.assertFalse(claim.probed)
        self.assertFalse(claim.locked)  # unverified, which is not the same as free
        self.assertIn("unverified", claim.human())
        self.assertTrue(held.probed and held.locked)
        self.assertIn("held by", held.human())
        lease.release()

    def test_a_missing_file_is_free_and_unprobed(self):
        status = inspect_lease(self.workspace() / "nothing.lease")
        self.assertEqual((status.locked, status.owner_id, status.probed), (False, "", False))
        self.assertEqual(status.human(), "no lease recorded")

    def test_human_wording_names_the_last_owner_after_a_release(self):
        path = self.workspace() / "s.lease"
        # Named objects on purpose: `SessionLease(...).acquire()` abandons the object and
        # its descriptor, and an abandoned descriptor keeps the lock held for the life of
        # the process. That is the reason this class supports `with`.
        with SessionLease(path, owner_id="run-a", ttl_seconds=60):
            pass
        # A probe on a free file: "not held", with the last owner still readable.
        status = inspect_lease(path)
        self.assertTrue(status.probed)
        self.assertIn("not held", status.human())
        self.assertIn("run-a", status.human())


class NoFcntlTests(RuntimeTestCase):
    """Where ``fcntl`` is absent the answer is a refusal, never a timestamp dance."""

    def _without_fcntl(self):
        import session_lease

        saved = session_lease.fcntl
        session_lease.fcntl = None
        self.addCleanup(setattr, session_lease, "fcntl", saved)

    def test_required_by_default(self):
        self._without_fcntl()
        path = self.workspace() / "s.lease"
        with self.assertRaises(LeaseError) as caught:
            SessionLease(path, owner_id="run-a").acquire()
        self.assertIn("--no-session-lease", str(caught.exception))
        self.assertFalse(path.exists())

    def test_opting_out_writes_no_claim_and_reports_no_kernel_lock(self):
        self._without_fcntl()
        path = self.workspace() / "s.lease"
        status = SessionLease(path, owner_id="run-a", required=False).acquire()
        self.assertFalse(status.locked)
        self.assertFalse(status.kernel_lock_available)
        self.assertFalse(status.probed)
        self.assertFalse(path.exists())

    def test_release_and_heartbeat_survive_the_missing_lock(self):
        self._without_fcntl()
        lease = SessionLease(self.workspace() / "s.lease", owner_id="run-a", required=False)
        lease.acquire()
        self.assertEqual(lease.heartbeat().expires_at, 0)
        lease.release()

    def test_inspect_reports_the_missing_kernel_rather_than_a_free_file(self):
        self._without_fcntl()
        path = self.workspace() / "s.lease"
        path.write_text(json.dumps({"owner_id": "run-a", "expires_at": 10}), encoding="utf-8")
        status = inspect_lease(path)
        self.assertFalse(status.kernel_lock_available)
        self.assertFalse(status.locked)
        self.assertEqual(status.owner_id, "run-a")


class CrossProcessTests(RuntimeTestCase):
    """``flock`` is worth nothing unless another *process* is refused."""

    def _spawn(self, path: Path, owner: str):
        child = subprocess.Popen(
            [sys.executable, "-c", child_source(owner), str(path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        line = child.stdout.readline().strip()
        if line != "HELD":
            child.kill()
            child.wait(timeout=20)
            self.fail(f"child could not hold the lease: {line!r}")
        return child

    def _stop(self, child) -> None:
        """Tell the child to let go, then close every pipe.

        The closes are not ceremony: an unclosed ``Popen`` stream is a leaked descriptor
        that shows up as a ResourceWarning in the *suite*, which is the only place anyone
        would notice a test holding the other end of a pipe open forever.
        """
        try:
            child.stdin.write("quit\n")
            child.stdin.flush()
        finally:
            for stream in (child.stdin, child.stdout, child.stderr):
                if stream is not None:
                    stream.close()
            child.wait(timeout=30)

    def test_another_process_is_refused_then_succeeds(self):
        path = self.workspace() / "s.lease"
        child = self._spawn(path, "run-child")
        try:
            with self.assertRaises(SessionBusyError) as caught:
                SessionLease(path, owner_id="run-parent", ttl_seconds=60).acquire()
            self.assertEqual(caught.exception.owner_id, "run-child")
            self.assertTrue(inspect_lease(path).locked)
        finally:
            child.stdin.write("quit\n")
            child.stdin.flush()
            # The child's own line, read before the pipes close: proof it got the message
            # rather than being killed into releasing.
            released = child.stdout.readline().strip()
            for stream in (child.stdin, child.stdout, child.stderr):
                stream.close()
            child.wait(timeout=30)
        self.assertEqual(released, "RELEASED")
        lease = SessionLease(path, owner_id="run-parent", ttl_seconds=60)
        lease.acquire()
        lease.release()

    def test_a_child_dying_releases_the_kernel_lock(self):
        path = self.workspace() / "s.lease"
        child = subprocess.Popen(
            [sys.executable, "-c", child_source("run-doomed"), str(path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(child.stdout.readline().strip(), "HELD")
        child.kill()
        child.wait(timeout=30)
        for stream in (child.stdin, child.stdout, child.stderr):
            stream.close()
        # No reaper, no waiting out a TTL: the lock dies with the descriptor, which is the
        # whole reason this module uses flock instead of durable-run's timestamp rule.
        lease = SessionLease(path, owner_id="run-parent", ttl_seconds=60)
        lease.acquire()
        self.assertEqual(inspect_lease(path).owner_id, "run-parent")
        lease.release()

    def test_two_children_contend_for_one_lease(self):
        path = self.workspace() / "s.lease"
        first = self._spawn(path, "run-first")
        second = subprocess.run(
            [sys.executable, "-c", child_source("run-second"), str(path)],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(second.returncode, 3)
        self.assertEqual(second.stdout.strip(), "BUSY run-first")
        self._stop(first)


class RuntimeIntegrationTests(RuntimeTestCase):
    """The loop claims before it writes and releases only after the last record."""

    def _runtime(self, directory: Path, session_id: str, *, turns=None, **config_kwargs: object) -> AgentRuntime:
        return AgentRuntime(
            provider=ScriptedProvider(turns or [{"text": "ok"}], model="claude-sonnet-4-5"),
            config=RuntimeConfig(
                session_id=session_id,
                model="claude-sonnet-4-5",
                workspace=str(self.workspace()),
                **config_kwargs,
            ),
            sessions=SessionStore(directory, session_id=session_id),
        )

    def _hold(self, directory: Path, session_id: str) -> SessionLease:
        lease = SessionLease(lease_path_for(directory, session_id), owner_id="run-other", ttl_seconds=60)
        lease.acquire()
        self.addCleanup(lease.release)
        return lease

    def test_a_held_session_ends_the_run_with_its_own_outcome(self):
        directory = self.temp_dir()
        self._hold(directory, "s-1")
        report = self._runtime(directory, "s-1").run_collect("go")
        self.assertEqual(report.subtype, "error_session_busy")
        self.assertEqual(EXIT_CODES[report.subtype], 7)
        self.assertIn("run-other", report.errors[0])
        # The point of the whole exercise: not one byte appended to a file someone holds.
        self.assertFalse((directory / "s-1.jsonl").exists())
        (directory / "s-1.lease").unlink()  # the refusal must not have created anything else
        self.assertEqual(list(directory.iterdir()), [])

    def test_the_refusal_is_exactly_one_result_event(self):
        directory = self.temp_dir()
        self._hold(directory, "s-2")
        runtime = self._runtime(directory, "s-2")
        events = list(runtime.run("go"))
        self.assertEqual([type(event).__name__ for event in events], ["ResultMessage"])
        self.assertEqual(len(runtime._pending_state.events), 1)
        self.assertIs(runtime._pending_state.result, events[0])

    def test_no_hook_fires_for_a_session_that_never_started(self):
        directory = self.temp_dir()
        calls: list[str] = []
        registry = HookRegistry()
        for event in ("SessionStart", "SessionEnd", "UserPromptSubmit"):
            registry.register(event, lambda input_, _event=event: (calls.append(_event), {"decision": "allow"})[1])
        self._hold(directory, "s-3")
        report = self._runtime(directory, "s-3").run_collect("go")
        self.assertEqual(report.subtype, "error_session_busy")
        self.assertEqual(calls, [])

    def test_the_transcript_records_the_claim_without_process_identity(self):
        directory = self.temp_dir()
        self.assertEqual(self._runtime(directory, "s-4").run_collect("go").subtype, "success")
        record = json.loads((directory / "s-4.jsonl").read_text(encoding="utf-8").splitlines()[0])
        self.assertEqual(
            record["data"]["session_lease"],
            {"locked": True, "ttl_seconds": DEFAULT_LEASE_SECONDS, "kernel_lock_available": True},
        )
        # No owner_id, no path: those describe the process, and a record that varies between
        # two identical runs is a record that cannot be digested and compared.
        self.assertNotIn("owner_id", record["data"]["session_lease"])
        self.assertNotIn("path", record["data"]["session_lease"])

    def test_opting_out_is_a_choice_and_not_recorded_as_a_claim(self):
        directory = self.temp_dir()
        self.assertEqual(
            self._runtime(directory, "s-6", lock_session=False).run_collect("go").subtype, "success"
        )
        self.assertEqual([path.name for path in directory.iterdir()], ["s-6.jsonl"])
        record = json.loads((directory / "s-6.jsonl").read_text(encoding="utf-8").splitlines()[0])
        self.assertNotIn("session_lease", record["data"])

    def test_no_session_dir_means_no_claim(self):
        runtime = AgentRuntime(
            provider=ScriptedProvider([{"text": "ok"}], model="claude-sonnet-4-5"),
            config=RuntimeConfig(session_id="s-7", model="claude-sonnet-4-5", workspace=str(self.workspace())),
        )
        self.assertEqual(runtime.run_collect("go").subtype, "success")
        self.assertIsNone(runtime._session_lease)

    def test_a_delegation_does_not_deadlock_on_the_parents_claim(self):
        """A child shares its parent's transcript file, so it must not re-claim it.

        ``flock`` is per open file description, not per process: a second claim on the same
        path in the same process is refused just as firmly as another machine's. Without
        the depth rule, every subagent would end as error_session_busy.
        """
        workspace = self.workspace({"a.txt": "alpha\n"})
        directory = self.temp_dir()
        parent = self.provider(
            [tool_turn("Task", {"agent": "explorer", "prompt": "read a.txt and report"}), text_turn("parent done")]
        )
        child = self.provider([text_turn("alpha, from the child")])
        from agents import AgentRegistry, explorer_agent, general_agent

        agents = AgentRegistry([general_agent(), explorer_agent().override(provider="child")])
        runtime = AgentRuntime(
            provider=parent,
            providers={"child": child},
            agents=agents,
            config=RuntimeConfig(
                session_id="s-8", model="claude-sonnet-4-5", workspace=str(workspace), max_turns=4
            ),
            sessions=SessionStore(directory, session_id="s-8"),
        )
        report = runtime.run_collect("delegate")
        self.assertEqual(report.subtype, "success", report.errors)
        self.assertEqual([item.agent for item in report.subagents], ["explorer"])
        # One file, one lease, and the child's records are inside the parent's transcript.
        self.assertEqual(sorted(path.name for path in directory.iterdir()), ["s-8.jsonl", "s-8.lease"])
        records = [json.loads(line) for line in (directory / "s-8.jsonl").read_text().splitlines()]
        child_starts = [
            record for record in records if record.get("agent") == "explorer" and record.get("type") == "session_start"
        ]
        self.assertTrue(child_starts)
        self.assertEqual(
            child_starts[0]["data"]["session_lease"], {"held": False, "reason": "covered by the parent run's claim"}
        )
        self.assertFalse(inspect_lease(directory / "s-8.lease").locked)

    def test_the_run_is_not_broken_by_a_held_lease_after_a_successful_one(self):
        directory = self.temp_dir()
        self.assertEqual(self._runtime(directory, "s-9").run_collect("go").subtype, "success")
        self.assertFalse(inspect_lease(lease_path_for(directory, "s-9")).locked)
        # Same session id, sequential runs: release must be complete, not partial.
        self.assertEqual(self._runtime(directory, "s-9").run_collect("again").subtype, "success")

    def test_heartbeat_is_throttled_to_a_third_of_the_ttl(self):
        directory = self.temp_dir()
        runtime = self._runtime(directory, "s-10", session_lease_seconds=60)
        calls: list[int] = []
        lease = SessionLease(lease_path_for(directory, "s-10"), owner_id="run-us", ttl_seconds=60)
        lease.acquire()
        self.addCleanup(lease.release)
        real_heartbeat = lease.heartbeat

        def counting_heartbeat():
            calls.append(1)
            return real_heartbeat()

        lease.heartbeat = counting_heartbeat  # type: ignore[method-assign]
        runtime._session_lease = lease
        runtime._lease_beat = time.monotonic()
        runtime._heartbeat()
        self.assertEqual(calls, [], "a renewal right after a claim is waste, not liveness")
        runtime._lease_beat = time.monotonic() - 30
        runtime._heartbeat()
        self.assertEqual(calls, [1])
        self.assertIs(runtime._session_lease, lease)

    def test_a_lost_lease_is_reported_once_and_the_run_keeps_writing(self):
        """Losing the guard is an audit event, not a reason to stop and not a secret.

        The transcript is still ours to append to (the descriptor is open, whatever happened
        to the directory entry), so the run finishes - but the protection is gone, and a
        reader of the file later has to be able to see that it was.
        """
        directory = self.temp_dir()
        runtime = AgentRuntime(
            provider=ScriptedProvider([{"text": "ok"}], model="claude-sonnet-4-5"),
            config=RuntimeConfig(session_id="s-11", model="claude-sonnet-4-5", workspace=str(self.workspace())),
            sessions=SessionStore(directory, session_id="s-11"),
        )

        class Lost:
            ttl_seconds = 60

            def heartbeat(self):
                raise LeaseError("lease file is gone")

        runtime._session_lease = Lost()  # type: ignore[assignment]
        runtime._lease_beat = time.monotonic() - 10_000
        runtime._heartbeat()
        self.assertIsNone(runtime._session_lease, "the guard says it once, then stops pretending")
        records = [json.loads(line) for line in (directory / "s-11.jsonl").read_text().splitlines()]
        self.assertEqual([record["type"] for record in records], ["informational"])
        self.assertIn("lease file is gone", records[0]["content"])
        self.assertEqual(records[0]["data"]["reason"], "session_lease_lost")
        # A later boundary must not shout again: the guard is gone, and one record said so.
        runtime._heartbeat()
        self.assertEqual(len((directory / "s-11.jsonl").read_text(encoding="utf-8").splitlines()), 1)
        # Losing the lease never turns a live run into a failure: it is not a ceiling.
        self.assertEqual(runtime.run_collect("go").subtype, "success")

    def test_the_result_record_is_written_before_the_release(self):
        directory = self.temp_dir()
        runtime = self._runtime(directory, "s-13")
        order: list[str] = []
        store = runtime.sessions
        original = store.append

        def probe(*args, **kwargs):
            order.append(str(args[0]))
            return original(*args, **kwargs)

        lease_path = lease_path_for(directory, "s-13")
        store.append = probe  # type: ignore[method-assign]
        original_release = SessionLease.release

        def release(self):  # noqa: ANN001
            order.append("release")
            return original_release(self)

        SessionLease.release = release  # type: ignore[method-assign]
        try:
            self.assertEqual(runtime.run_collect("go").subtype, "success")
        finally:
            SessionLease.release = original_release  # type: ignore[method-assign]
        self.assertEqual(order[-1], "release")
        self.assertIn("result", order)
        self.assertLess(order.index("result"), order.index("release"))
        del lease_path


class ConfigurationTests(RuntimeTestCase):
    def test_contradictory_lease_settings_are_refused(self):
        with self.assertRaises(RuntimeConfigurationError) as caught:
            RuntimeConfig(lock_session=False, session_lease_seconds=30)
        self.assertIn("no meaning", str(caught.exception))
        with self.assertRaises(RuntimeConfigurationError):
            RuntimeConfig(session_lease_seconds=MIN_LEASE_SECONDS - 1)

    def test_defaults_and_plan_output(self):
        self.assertTrue(RuntimeConfig().lock_session)
        self.assertEqual(RuntimeConfig().session_lease_seconds, DEFAULT_LEASE_SECONDS)
        self.assertIn("lock_session", RuntimeConfig().as_dict())


class CliLeaseTests(RuntimeTestCase):
    """The operator-facing surface: a plan that says whether starting is even possible."""

    def run_cli(self, *argv: str) -> tuple[int, str, str]:
        environment = dict(os.environ, PYTHONPATH=str(ROOT))
        child = subprocess.run(
            [sys.executable, "-m", "cli", *argv],
            capture_output=True,
            text=True,
            cwd=str(ROOT),
            env=environment,
            timeout=120,
        )
        return child.returncode, child.stdout, child.stderr

    def _cli_run(self, directory: Path, session_id: str, *extra: str) -> tuple[int, str, str]:
        script = self.workspace() / "turns.json"
        script.write_text(json.dumps([{"text": "ok"}]), encoding="utf-8")
        return self.run_cli(
            "run",
            "--provider",
            "scripted",
            "--script",
            str(script),
            "--prompt",
            "go",
            "--workspace",
            str(self.workspace()),
            "--session-dir",
            str(directory),
            "--resume",
            session_id,
            *extra,
        )

    def test_busy_session_exits_seven_with_an_actionable_line(self):
        directory = self.temp_dir()
        code, out, err = self._cli_run(directory, "fixed-1", "--quiet")
        self.assertEqual(code, 0, out + err)
        holder = SessionLease(lease_path_for(directory, "fixed-1"), owner_id="run-in-another-shell", ttl_seconds=60)
        holder.acquire()
        try:
            before = (directory / "fixed-1.jsonl").read_text(encoding="utf-8")
            code, out, err = self._cli_run(directory, "fixed-1", "--quiet")
        finally:
            holder.release()
        self.assertEqual(code, 7, out + err)
        combined = out + err
        self.assertIn("error_session_busy", combined)
        self.assertIn("run-in-another-shell", combined)
        self.assertEqual((directory / "fixed-1.jsonl").read_text(encoding="utf-8"), before)

    def test_dry_run_reports_contention_without_reserving_it(self):
        directory = self.temp_dir()
        code, out, err = self._cli_run(directory, "fixed-2", "--dry-run")
        self.assertEqual(code, 0, out + err)
        self.assertIn("session_lease=free", out)
        holder = SessionLease(lease_path_for(directory, "fixed-2"), owner_id="somebody", ttl_seconds=60)
        holder.acquire()
        try:
            code, out, err = self._cli_run(directory, "fixed-2", "--dry-run")
        finally:
            holder.release()
        self.assertEqual(code, 0, out + err)
        self.assertIn("HELD by 'somebody'", out)
        self.assertIn("exit 7", out)
        # Checking must not block starting: a dry run leaves no claim behind.
        self.assertFalse(inspect_lease(lease_path_for(directory, "fixed-2")).locked)

    def test_dry_run_explains_the_opt_out(self):
        directory = self.temp_dir()
        code, out, err = self._cli_run(directory, "fixed-5", "--dry-run", "--no-session-lease")
        self.assertEqual(code, 0, out + err)
        self.assertIn("--no-session-lease", out)

    def test_the_flag_pair_that_disagrees_is_a_usage_error(self):
        directory = self.temp_dir()
        code, out, err = self._cli_run(
            directory, "fixed-3", "--dry-run", "--no-session-lease", "--session-lease-seconds", "30"
        )
        self.assertEqual(code, 64, out + err)
        self.assertIn("configuration error", err)
        self.assertIn("pick one", err)

    def test_no_session_lease_is_honoured_end_to_end(self):
        directory = self.temp_dir()
        code, out, err = self._cli_run(directory, "fixed-4", "--quiet")
        self.assertEqual(code, 0, out + err)
        holder = SessionLease(lease_path_for(directory, "fixed-4"), owner_id="somebody", ttl_seconds=60)
        holder.acquire()
        try:
            code, out, err = self._cli_run(directory, "fixed-4", "--quiet", "--no-session-lease")
        finally:
            holder.release()
        self.assertEqual(code, 0, out + err)
        self.assertEqual(sorted(path.name for path in directory.iterdir()), ["fixed-4.jsonl", "fixed-4.lease"])

    def test_sessions_list_and_show_surface_the_claim(self):
        directory = self.temp_dir()
        code, out, err = self._cli_run(directory, "fixed-6", "--quiet")
        self.assertEqual(code, 0, out + err)
        code, out, err = self.run_cli("sessions", "show", "--session-dir", str(directory), "fixed-6")
        self.assertEqual(code, 0, out + err)
        # Released, so the only honest answer is the holder's own claim - labelled
        # unverified, because a viewer must never be able to authorise a second writer.
        self.assertIn("session_lease:", out)
        self.assertIn("unverified", out)
        code, out, err = self.run_cli("sessions", "list", "--session-dir", str(directory), "--json")
        self.assertEqual(code, 0, out + err)
        listed = json.loads(out.strip().splitlines()[-1])
        self.assertEqual(listed["session_id"], "fixed-6")
        self.assertIn("claims", listed["lease"])
        code, out, err = self.run_cli("sessions", "list", "--session-dir", str(directory))
        self.assertEqual(code, 0, out + err)
        self.assertIn("*claims", out)


class SdkLeaseTests(RuntimeTestCase):
    """Programmatic callers get the same guarantee, and the same way to opt out."""

    def _options(self, directory: Path, **kwargs: object):
        import sdk

        return sdk.RunOptions(
            prompt="go",
            workspace=str(self.workspace()),
            session_dir=str(directory),
            scripted_turns=[{"text": "ok"}],
            **kwargs,
        )

    def test_a_default_run_claims_the_session(self):
        import sdk

        directory = self.temp_dir()
        report = sdk.run(self._options(directory))
        self.assertEqual(report.subtype, "success")
        self.assertEqual([path.name for path in directory.iterdir() if path.suffix == ".lease"], [f"{report.session_id}.lease"])
        self.assertFalse(inspect_lease(lease_path_for(directory, report.session_id)).locked)

    def test_lock_session_false_writes_the_transcript_unclaimed(self):
        import sdk

        directory = self.temp_dir()
        report = sdk.run(self._options(directory, lock_session=False))
        self.assertEqual(report.subtype, "success")
        self.assertEqual([path.name for path in directory.iterdir() if path.suffix == ".lease"], [])

    def test_the_contradiction_surfaces_instead_of_being_dropped(self):
        import sdk

        directory = self.temp_dir()
        with self.assertRaises(RuntimeConfigurationError):
            sdk.run(self._options(directory, lock_session=False, session_lease_seconds=30))

    def test_a_short_lease_is_accepted_and_renewed(self):
        import sdk

        directory = self.temp_dir()
        report = sdk.run(self._options(directory, session_lease_seconds=MIN_LEASE_SECONDS))
        self.assertEqual(report.subtype, "success")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

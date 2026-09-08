"""The durable bridge: one boundary, two schemas, and the limit of what translates.

Two kinds of test live here. The *drift* tests compare this module's mirrored constants
against the real durable component, so a silent split of one vocabulary into two fails a
test on whichever side moved. The *round trip* tests push the translated event through the
real ``EventContract`` and a real ``EventStore`` - schema validation by the component that
owns the schema, not by an opinion about it here.
"""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

import support  # noqa: F401  (installs the sys.path shim)
from support import RuntimeTestCase, load_durable, text_turn, tool_turn

import durable_bridge as bridge
from checkpoints import build as build_checkpoint, digest_transcript, from_record
from events import event_to_dict
from loop import RuntimeConfig
from providers.base import Usage
from providers.scripted import ScriptedProvider
from sessions import SessionStore

ROOT = Path(__file__).resolve().parents[1]


def make_checkpoint(**overrides: object) -> dict:
    """A checkpoint payload, built the way the loop builds one (record, not object)."""
    kwargs: dict = {
        "session_id": "ns-20260908T000000Z-abcdef01",
        "record_index": 7,
        "transcript": [text_turn("first"), text_turn("second")],
        "turns": 3,
        "tool_calls": 2,
        "cost_usd": 0.125,
        "usage": Usage(input_tokens=10, output_tokens=4),
        "model": "claude-sonnet-4-5",
        "provider": "scripted",
        "permission_mode": "default",
        "run_id": "run-42",
        "policy_revision": "rev-7",
        "denials": 1,
    }
    kwargs.update(overrides)
    return build_checkpoint(**kwargs)


class DriftPinTests(RuntimeTestCase):
    """The mirror must match the real schema, or the unification is a claim."""

    def test_event_field_set_is_the_real_field_set(self):
        contract = load_durable("durable_contract")
        self.assertEqual(tuple(contract.EventContract._fields), bridge.EVENT_FIELDS)
        # An exact tuple comparison, not a set one: durable's canonical JSON key order is
        # part of the digest, so an ordering change is a format change.
        self.assertEqual(
            len(bridge.EVENT_FIELDS), len(contract.EventContract._fields)
        )

    def test_checkpoint_field_set_is_the_real_field_set(self):
        store = load_durable("event_store")
        self.assertEqual(set(store._CHECKPOINT_FIELDS), set(bridge.CHECKPOINT_FIELDS))

    def test_schema_versions_and_status_pairing(self):
        contract = load_durable("durable_contract")
        store = load_durable("event_store")
        self.assertEqual(contract.EVENT_SCHEMA_VERSION, bridge.EVENT_SCHEMA_VERSION)
        self.assertEqual(contract.RUN_SCHEMA_VERSION, bridge.RUN_SCHEMA_VERSION)
        self.assertEqual(contract.STEP_SCHEMA_VERSION, bridge.STEP_SCHEMA_VERSION)
        self.assertEqual(store.CHECKPOINT_SCHEMA_VERSION, bridge.CHECKPOINT_SCHEMA_VERSION)
        self.assertEqual(
            contract._EVENT_STATUS_BY_TYPE[bridge.CHECKPOINT_EVENT_TYPE],
            bridge.CHECKPOINT_EVENT_STATUS,
        )

    def test_id_rules_are_the_same_rules(self):
        contract = load_durable("durable_contract")
        self.assertEqual(bridge.MAX_ID_CHARS, contract.MAX_ID_CHARS)
        self.assertEqual(bridge.MAX_IDEMPOTENCY_KEY_CHARS, contract.MAX_IDEMPOTENCY_KEY_CHARS)
        self.assertEqual(bridge.ID_RE.pattern, contract._ID_RE.pattern)
        self.assertEqual(bridge.DIGEST_RE.pattern, contract._DIGEST_RE.pattern)

    def test_canonical_json_and_digest_are_byte_identical(self):
        store = load_durable("event_store")
        for value in (
            {"b": 1, "a": [1, 2], "c": {"d": None}},
            {"key": "unicode é 中文", "nested": {"x": True}},
            {},
            [1, "two", None],
        ):
            with self.subTest(value=value):
                self.assertEqual(bridge.canonical_json(value), store._canonical_json(value))
                self.assertEqual(bridge.durable_digest(value), store._digest(value))

    def test_durable_digest_is_prefixed_where_runtime_digest_is_not(self):
        # The one trap every mapping between the two components has to step around, pinned
        # so nobody "simplifies" it away: a bare hex string is not a valid durable digest,
        # and a prefixed one is not what checkpoints.py stores.
        checkpoint = make_checkpoint()
        payload = bridge.checkpoint_payload(checkpoint)
        self.assertEqual(len(checkpoint["transcript_digest"]), 64)
        self.assertFalse(checkpoint["transcript_digest"].startswith("sha256:"))
        self.assertEqual(payload["transcript_digest"], "sha256:" + checkpoint["transcript_digest"])
        contract = load_durable("durable_contract")
        self.assertTrue(contract._DIGEST_RE.fullmatch(payload["transcript_digest"]))
        self.assertIsNone(contract._DIGEST_RE.fullmatch(checkpoint["transcript_digest"]))

    def test_durable_state_equality_is_closed_so_our_nesting_cannot_smuggle_in(self):
        """durable's validator compares state to its own replay, key for key.

        That is why :func:`checkpoint_document` nests instead of merging: an extra key in
        ``state`` is not "additive metadata" to a durable reader, it is a state that no
        longer equals the history, and it is refused. The refusal is what keeps "shareable"
        from meaning "can rewrite what a durable run believes it did".
        """
        store = load_durable("event_store")
        replayed = {"task_id": "t", "thread_id": "th", "run_id": "r", "status": "running", "sequence": 3, "steps": {}}
        validator = store.EventStore(Path(self.workspace()) / "events.ndjson")._validate_checkpoint
        plain = {
            "schema_version": store.CHECKPOINT_SCHEMA_VERSION,
            "run_id": "r",
            "sequence": 3,
            "state": replayed,
            "state_digest": store._digest(replayed),
        }
        self.assertEqual(validator("r", plain, current=replayed)["sequence"], 3)
        nested = {**plain, "state": {**replayed, bridge.NESTED_STATE_KEY: {"turns": 3}}}
        nested["state_digest"] = store._digest(nested["state"])
        with self.assertRaises(ValueError) as caught:
            validator("r", nested, current=replayed)
        self.assertIn("does not match event history", str(caught.exception))


class TranslationTests(RuntimeTestCase):
    """What the bridge produces, and what it refuses to produce."""

    def test_payload_is_the_runtime_facts_with_its_own_schema_version(self):
        payload = bridge.checkpoint_payload(make_checkpoint())
        self.assertEqual(payload["schema_version"], "northstar.runtime-checkpoint.v1")
        self.assertEqual(payload["record_index"], 7)
        self.assertEqual(payload["turns"], 3)
        self.assertEqual(payload["tool_calls"], 2)
        self.assertEqual(payload["cost_usd"], 0.125)
        self.assertEqual(payload["denials"], 1)
        self.assertEqual(payload["run_id"], "run-42")
        self.assertEqual(payload["policy_revision"], "rev-7")
        self.assertEqual(payload["usage"]["input_tokens"], 10)

    def test_optional_ids_are_omitted_rather_than_invented(self):
        payload = bridge.checkpoint_payload(make_checkpoint(run_id=None, policy_revision=None))
        self.assertNotIn("run_id", payload)
        self.assertNotIn("policy_revision", payload)

    def test_record_and_object_forms_produce_one_answer(self):
        checkpoint = make_checkpoint()
        typed = from_record({"type": "checkpoint", "index": checkpoint["record_index"], **checkpoint})
        self.assertEqual(bridge.checkpoint_event(checkpoint), bridge.checkpoint_event(typed))
        self.assertEqual(
            bridge.checkpoint_document(checkpoint), bridge.checkpoint_document(typed)
        )

    def test_event_validates_against_the_real_contract(self):
        contract = load_durable("durable_contract")
        event = contract.EventContract.from_dict(bridge.checkpoint_event(make_checkpoint()))
        self.assertEqual(event.event_type, bridge.CHECKPOINT_EVENT_TYPE)
        self.assertEqual(event.status, bridge.CHECKPOINT_EVENT_STATUS)
        self.assertEqual(event.sequence, 8)
        self.assertEqual(event.idempotency_key, "ns-20260908T000000Z-abcdef01:7")
        self.assertEqual(event.run_id, "run-42")
        self.assertEqual(event.step_id, "turn:3")
        # The closed field set is the point: adding our own key is not allowed, so the
        # facts have to travel in the payload digest, not beside it.
        with self.assertRaises(ValueError):
            contract.EventContract.from_dict({**bridge.checkpoint_event(make_checkpoint()), "turns": 3})

    def test_identity_defaults_follow_the_session_and_can_be_overridden(self):
        event = bridge.checkpoint_event(make_checkpoint(run_id=None))
        self.assertEqual(event["run_id"], "session:ns-20260908T000000Z-abcdef01")
        self.assertEqual(event["trace_id"], event["run_id"])
        custom = bridge.checkpoint_event(
            make_checkpoint(), task_id="task-9", thread_id="thread-9", trace_id="trace-9"
        )
        self.assertEqual((custom["task_id"], custom["thread_id"], custom["trace_id"]), ("task-9", "thread-9", "trace-9"))

    def test_sequence_is_a_parameter_because_a_gap_is_not_cosmetic(self):
        default = bridge.checkpoint_event(make_checkpoint())["sequence"]
        self.assertEqual(default, 8)
        self.assertEqual(bridge.checkpoint_event(make_checkpoint(), sequence=3)["sequence"], 3)
        for bad in (0, -1, True, "3"):
            with self.subTest(bad=bad), self.assertRaises(bridge.BridgeError):
                bridge.checkpoint_event(make_checkpoint(), sequence=bad)

    def test_an_id_built_from_a_long_session_is_refused_not_truncated(self):
        # Every durable id is capped at 128 characters, and the ones we *derive* (event_id
        # prefixes the session id) can overflow that even when the session id itself is
        # legal. Refusing beats truncating: a truncated id is a second boundary claiming to
        # be the first one.
        with self.assertRaises(bridge.BridgeError) as caught:
            bridge.checkpoint_event(make_checkpoint(session_id="s" * 128))
        self.assertIn("event_id", str(caught.exception))

    def test_a_path_unsafe_session_id_is_refused_at_the_edge(self):
        with self.assertRaises(bridge.BridgeError):
            bridge.checkpoint_event(make_checkpoint(session_id="has space"))
        with self.assertRaises(bridge.BridgeError):
            bridge.checkpoint_event(make_checkpoint(session_id="../../etc/passwd"))

    def test_a_negative_record_index_is_refused(self):
        with self.assertRaises(bridge.BridgeError):
            bridge.checkpoint_payload(make_checkpoint(record_index=-1))

    def test_payload_digest_covers_the_payload_and_nothing_else(self):
        event = bridge.checkpoint_event(make_checkpoint())
        payload = bridge.checkpoint_payload(make_checkpoint())
        self.assertTrue(bridge.verify_event_payload(event, payload))
        tampered = bridge.verify_event_payload(event, {**payload, "turns": 99})
        self.assertFalse(tampered, "a changed boundary must not still match its digest")
        with self.assertRaises(bridge.BridgeError):
            bridge.verify_event_payload({"payload_digest": "nope"}, payload)

    def test_document_is_durable_shaped_and_digested_durably(self):
        store = load_durable("event_store")
        document = bridge.checkpoint_document(make_checkpoint())
        self.assertEqual(set(document), set(store._CHECKPOINT_FIELDS))
        self.assertEqual(document["schema_version"], store.CHECKPOINT_SCHEMA_VERSION)
        self.assertEqual(document["run_id"], "run-42")
        self.assertEqual(document["state"]["status"], "running")
        self.assertEqual(document["state"]["sequence"], document["sequence"])
        self.assertEqual(document["state_digest"], store._digest(document["state"]))
        nested = document["state"][bridge.NESTED_STATE_KEY]
        self.assertEqual(nested["transcript_digest"], f"sha256:{digest_transcript([text_turn('first'), text_turn('second')])}")


class StoreRoundTripTests(RuntimeTestCase):
    """The translated event inside a real durable history, not beside one."""

    def _store(self):
        store = load_durable("event_store")
        contract = load_durable("durable_contract")
        return store.EventStore(Path(self.temp_dir()) / "events.ndjson"), store, contract

    def _lifecycle(self, store, contract, run_id: str = "run-42"):
        base = dict(
            schema_version=contract.EVENT_SCHEMA_VERSION,
            task_id=f"task:{run_id}",
            thread_id=f"thread:{run_id}",
            run_id=run_id,
            trace_id=run_id,
            occurred_at=1_700_000_000,
        )
        def event(**overrides):
            fields = {
                **base,
                "step_id": "__run__",
                "sequence": 1,
                "event_id": f"evt:{run_id}:open",
                "event_type": "run.created",
                "status": "planned",
                "idempotency_key": f"{run_id}:created",
                "payload_digest": "sha256:" + "0" * 64,
            }
            fields.update(overrides)
            return contract.EventContract.from_dict(fields)

        store.append_event(event())
        store.append_event(
            event(
                event_id=f"evt:{run_id}:start",
                sequence=2,
                event_type="run.started",
                status="running",
                idempotency_key=f"{run_id}:started",
            )
        )
        return base

    def test_a_runtime_boundary_appends_into_a_durable_stream(self):
        store, durable, contract = self._store()
        self._lifecycle(store, contract)
        event = bridge.checkpoint_event(make_checkpoint(), task_id="task:run-42", thread_id="thread:run-42")
        # The default sequence would be 8 (the transcript's own line number); appended into
        # a stream that already holds two lifecycle events it must be 3, and durable refuses
        # a gap rather than trusting a number.
        appended = store.append_event(contract.EventContract.from_dict({**event, "sequence": 3}))
        self.assertEqual(appended.sequence, 3)
        state = store.derive_state("run-42")
        self.assertEqual(state["status"], "running", "a checkpoint must not move the run's status")
        self.assertEqual(state["sequence"], 3)

    def test_replaying_the_same_boundary_is_a_no_op(self):
        store, durable, contract = self._store()
        self._lifecycle(store, contract)
        event = bridge.checkpoint_event(make_checkpoint(), task_id="task:run-42", thread_id="thread:run-42", sequence=3)
        first = store.append_event(contract.EventContract.from_dict(event))
        second = store.append_event(contract.EventContract.from_dict(event))
        self.assertEqual(first.canonical_json(), second.canonical_json())
        lines = (store._path).read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 3, "the key made the replay idempotent, as designed")

    def test_a_different_boundary_under_the_same_key_is_a_conflict(self):
        store, durable, contract = self._store()
        self._lifecycle(store, contract)
        event = bridge.checkpoint_event(make_checkpoint(), task_id="task:run-42", thread_id="thread:run-42", sequence=3)
        store.append_event(contract.EventContract.from_dict(event))
        conflicting = {**event, "payload_digest": "sha256:" + "9" * 64}
        with self.assertRaises(ValueError) as caught:
            store.append_event(contract.EventContract.from_dict(conflicting))
        self.assertIn("idempotency", str(caught.exception))

    def test_restore_refuses_a_runtime_document_loudly(self):
        """The limit, tested instead of asserted.

        ``EventStore.restore`` requires state equal to its own replayed history. A
        document built from a runtime transcript is not that, and the refusal is what makes
        "shareable artifact" a true statement rather than a way to smuggle foreign state in.
        """
        store, durable, contract = self._store()
        self._lifecycle(store, contract)
        document = bridge.checkpoint_document(make_checkpoint())
        with self.assertRaises(ValueError):
            store.restore("run-42", checkpoint=document)


class ResumeSeedingTests(RuntimeTestCase):
    """The direction a durable event can point a runtime at - with the same gate."""

    def _run_with_checkpoints(self):
        directory = self.temp_dir()
        workspace = self.workspace({"a.txt": "alpha\n"})
        runtime = self.runtime(
            [tool_turn("Read", {"path": "a.txt"}), text_turn("read it"), text_turn("done")],
            workspace=workspace,
            sessions=SessionStore(directory, session_id="seed-1"),
            config=RuntimeConfig(
                session_id="seed-1",
                model="claude-sonnet-4-5",
                workspace=str(workspace),
                max_turns=4,
                checkpoint_turns=1,
            ),
        )
        report = runtime.run_collect("go")
        self.assertEqual(report.subtype, "success", report.errors)
        records = [json.loads(line) for line in (directory / "seed-1.jsonl").read_text().splitlines()]
        checkpoint_record = next(record for record in records if record["type"] == "checkpoint")
        return checkpoint_record, report.transcript, records

    def test_a_durable_event_can_seed_a_verified_resume(self):
        checkpoint_record, transcript, _records = self._run_with_checkpoints()
        event = bridge.checkpoint_event(checkpoint_record)
        # What a host that wants to hand a boundary back must persist: the event plus the
        # payload its digest covers. durable's schema is closed, so the payload cannot ride
        # inside the event.
        pair = {**event, "payload": bridge.checkpoint_payload(checkpoint_record)}
        seeded = bridge.checkpoint_from_event(pair, transcript=transcript)
        original = from_record(checkpoint_record)
        self.assertEqual(seeded.transcript_digest, original.transcript_digest)
        self.assertEqual(seeded.turns, original.turns)
        self.assertEqual(seeded.cost_usd, original.cost_usd)
        self.assertEqual(seeded.record_index, original.record_index)
        self.assertEqual(seeded.session_id, "seed-1")

    def test_a_shorter_transcript_is_refused_not_padded(self):
        checkpoint_record, transcript, _records = self._run_with_checkpoints()
        pair = {**bridge.checkpoint_event(checkpoint_record), "payload": bridge.checkpoint_payload(checkpoint_record)}
        with self.assertRaises(Exception) as caught:
            bridge.checkpoint_from_event(pair, transcript=list(transcript)[:1])
        self.assertIn("checkpoint", str(caught.exception).lower())

    def test_a_payload_that_was_edited_after_the_digest_is_refused(self):
        checkpoint_record, transcript, _records = self._run_with_checkpoints()
        payload = bridge.checkpoint_payload(checkpoint_record)
        pair = {**bridge.checkpoint_event(checkpoint_record), "payload": {**payload, "turns": 99}}
        with self.assertRaises(bridge.BridgeError) as caught:
            bridge.checkpoint_from_event(pair, transcript=transcript)
        self.assertIn("payload_digest", str(caught.exception))

    def test_only_a_checkpoint_event_is_considered(self):
        with self.assertRaises(bridge.BridgeError):
            bridge.checkpoint_from_event({"event_type": "run.started", "payload": {}}, transcript=[])
        with self.assertRaises(bridge.BridgeError) as caught:
            bridge.checkpoint_from_event({"event_type": bridge.CHECKPOINT_EVENT_TYPE}, transcript=[])
        self.assertIn("payload", str(caught.exception))

    def test_an_event_from_another_session_is_refused(self):
        checkpoint_record, transcript, _records = self._run_with_checkpoints()
        pair = {**bridge.checkpoint_event(checkpoint_record), "payload": bridge.checkpoint_payload(checkpoint_record)}
        with self.assertRaises(Exception):
            bridge.checkpoint_from_event(pair, transcript=transcript, expected_session_id="other-session")


class CrossCheckTests(RuntimeTestCase):
    def test_verified_against_the_real_component(self):
        report = bridge.cross_check(make_checkpoint())
        self.assertEqual(report.mode, "durable-verified", report.as_dict())
        self.assertTrue(report.ok)
        self.assertEqual(report.detail["event"]["sequence"], 8)

    def test_drift_is_detected_not_rattled_through(self):
        saved = bridge.EVENT_FIELDS
        try:
            bridge.EVENT_FIELDS = saved[:-1]
            report = bridge.cross_check(make_checkpoint())
        finally:
            bridge.EVENT_FIELDS = saved
        self.assertEqual(report.mode, "drift")
        self.assertFalse(report.ok)
        self.assertIn("EVENT_FIELDS", " ".join(report.errors))

    def test_status_pairing_drift_is_detected(self):
        contract = load_durable("durable_contract")
        saved = bridge.CHECKPOINT_EVENT_STATUS
        try:
            bridge.CHECKPOINT_EVENT_STATUS = "finished"
            report = bridge.cross_check(make_checkpoint())
        finally:
            bridge.CHECKPOINT_EVENT_STATUS = saved
        self.assertFalse(report.ok)
        self.assertIn("checkpoint.created", " ".join(report.errors))
        self.assertEqual(contract._EVENT_STATUS_BY_TYPE["checkpoint.created"], "running")

    def test_a_checkpoint_is_required_to_exercise_the_round_trip(self):
        report = bridge.cross_check()
        self.assertEqual(report.mode, "drift")
        self.assertIn("checkpoint", " ".join(report.errors))

    def test_unchecked_when_the_component_is_not_importable(self):
        saved = bridge.durable_modules
        try:
            bridge.durable_modules = lambda: None
            report = bridge.cross_check(make_checkpoint())
            # The translation itself never needed the component: only the verdict does.
            event = bridge.checkpoint_event(make_checkpoint())
        finally:
            bridge.durable_modules = saved
        self.assertEqual(report.mode, "unchecked")
        self.assertTrue(report.ok, "no durable checkout is not a failure of the runtime")
        self.assertEqual(event["event_type"], bridge.CHECKPOINT_EVENT_TYPE)

    def test_the_module_imports_with_no_durable_component_on_the_path(self):
        # A real subprocess with an emptied search path beyond the component itself:
        # proof that "mirror, don't import" survived contact with packaging, not just
        # proof that one function short-circuits.
        child = subprocess.run(
            [sys.executable, "-c", "import durable_bridge; print(durable_bridge.durable_available())"],
            capture_output=True,
            text=True,
            cwd=str(ROOT),
            timeout=60,
        )
        self.assertEqual(child.returncode, 0, child.stderr)
        self.assertIn(child.stdout.strip(), {"True", "False"})
        bare = subprocess.run(
            [
                sys.executable,
                "-c",
                "\n".join(
                    [
                        "import sys",
                        "sys.path.insert(0, %r)" % str(ROOT),
                        "import durable_bridge as b",
                        # Pretend there is no sibling checkout, which is the shipping
                        # condition for anyone who pip-installs just this component.
                        "b._durable_root = lambda: None",
                        "sys.modules.pop('durable_contract', None)",
                        "sys.modules.pop('event_store', None)",
                        "cp = {",
                        "    'session_id': 's-1', 'record_index': 0, 'transcript_len': 0,",
                        "    'transcript_digest': 'a' * 64, 'turns': 0, 'tool_calls': 0,",
                        "    'cost_usd': 0.0, 'usage': {}, 'model': 'm', 'provider': 'p',",
                        "    'permission_mode': 'default',",
                        "}",
                        "print(b.durable_available())",
                        "print(b.checkpoint_event(cp)['event_type'])",
                        "print(b.checkpoint_document(cp)['schema_version'])",
                        "print(b.cross_check(cp).mode)",
                    ]
                ),
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(bare.returncode, 0, bare.stderr)
        available, event_type, schema_version, mode = bare.stdout.strip().splitlines()
        self.assertEqual(available, "False", "no durable checkout, by construction")
        self.assertEqual(event_type, "checkpoint.created")
        self.assertEqual(schema_version, "northstar.checkpoint.v1")
        self.assertEqual(mode, "unchecked", "the verdict is withheld, not faked, without the component")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

"""Tests for process_receipts (ninety-eighth batch)."""

import hashlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from process_receipts import (
    PROCESS_RECEIPT_SCHEMA_VERSION,
    STEP_KINDS,
    UNVERIFIABLE_PROCESS,
    VERIFIED_PROCESS,
    ProcessReceiptError,
    build_receipt,
    classify_process,
    compute_step_digest,
    process_receipt_audit_event,
    verify_process,
)


def _hex(label: str) -> str:
    return hashlib.sha256(f"northstar-test-process-receipts:{label}".encode()).hexdigest()


_SEED = _hex("seed")
_ARTIFACT = _hex("artifact")


def _tool_receipt(args_label: str, result_label: str) -> dict:
    args = _hex(f"args:{args_label}")
    result = _hex(f"result:{result_label}")
    return {
        "schema_version": "northstar.tool-receipt.v1",
        "receipt_id": f"tool:{args}:{result}",
        "tool_name": "workspace.write_file",
        "arguments_digest": args,
        "result_digest": result,
    }


def _full_chain(tool_lookup=None):
    """draft -> revise -> tool_call -> human_checkpoint -> finalize."""
    d0 = _hex("d0-prompt")
    d1 = _hex("d1-draft")
    d2 = _hex("d2-revised")
    tool = _tool_receipt("d2", "d3")
    d4 = _hex("d4-reviewed")
    steps = [
        {"seq": 0, "step_kind": "draft", "input_digest": _SEED, "output_digest": d0,
         "actor": "agent:writer-1", "timestamp": 1000},
        {"seq": 1, "step_kind": "revise", "input_digest": d0, "output_digest": d1,
         "actor": "agent:writer-1", "timestamp": 1010},
        {"seq": 2, "step_kind": "revise", "input_digest": d1, "output_digest": d2,
         "actor": "agent:editor-2", "timestamp": 1020},
        {"seq": 3, "step_kind": "tool_call", "input_digest": d2,
         "output_digest": tool["result_digest"], "actor": "agent:writer-1",
         "timestamp": 1030, "tool_receipt_id": tool["receipt_id"]},
        {"seq": 4, "step_kind": "human_checkpoint", "input_digest": tool["result_digest"],
         "output_digest": d4, "actor": "human:reviewer-7", "timestamp": 1040},
        {"seq": 5, "step_kind": "finalize", "input_digest": d4, "output_digest": _ARTIFACT,
         "actor": "agent:writer-1", "timestamp": 1050},
    ]
    receipt = build_receipt(artifact_digest=_ARTIFACT, seed_digest=_SEED, steps=steps)
    lookup = tool_lookup if tool_lookup is not None else (lambda rid: tool if rid == tool["receipt_id"] else None)
    return receipt, lookup


class BuildTests(unittest.TestCase):
    def test_schema_version(self):
        self.assertEqual(PROCESS_RECEIPT_SCHEMA_VERSION, "northstar.process-receipt.v1")

    def test_step_kinds_closed(self):
        self.assertEqual(STEP_KINDS, ("draft", "revise", "tool_call", "human_checkpoint", "finalize"))

    def test_build_assigns_chain_digests(self):
        receipt, _ = _full_chain()
        self.assertEqual(len(receipt.steps), 6)
        prev = "genesis"
        for step in receipt.steps:
            expected = compute_step_digest(
                seq=step.seq, step_kind=step.step_kind, input_digest=step.input_digest,
                output_digest=step.output_digest, actor=step.actor,
                timestamp=step.timestamp, tool_receipt_id=step.tool_receipt_id,
                prev_digest=prev,
            )
            self.assertEqual(step.step_digest, expected)
            prev = expected

    def test_build_rejects_unknown_step_kind(self):
        with self.assertRaises(ProcessReceiptError):
            build_receipt(artifact_digest=_ARTIFACT, seed_digest=_SEED, steps=[
                {"seq": 0, "step_kind": "hallucinate", "input_digest": _SEED,
                 "output_digest": _ARTIFACT, "actor": "agent:x", "timestamp": 1},
            ])

    def test_build_rejects_tool_call_without_receipt_id(self):
        with self.assertRaises(ProcessReceiptError):
            build_receipt(artifact_digest=_ARTIFACT, seed_digest=_SEED, steps=[
                {"seq": 0, "step_kind": "tool_call", "input_digest": _SEED,
                 "output_digest": _ARTIFACT, "actor": "agent:x", "timestamp": 1},
            ])

    def test_build_rejects_receipt_id_on_non_tool_step(self):
        with self.assertRaises(ProcessReceiptError):
            build_receipt(artifact_digest=_ARTIFACT, seed_digest=_SEED, steps=[
                {"seq": 0, "step_kind": "draft", "input_digest": _SEED,
                 "output_digest": _ARTIFACT, "actor": "agent:x", "timestamp": 1,
                 "tool_receipt_id": "tool:" + "a" * 64 + ":" + "b" * 64},
            ])

    def test_build_rejects_non_consecutive_seq(self):
        with self.assertRaises(ProcessReceiptError):
            build_receipt(artifact_digest=_ARTIFACT, seed_digest=_SEED, steps=[
                {"seq": 0, "step_kind": "draft", "input_digest": _SEED,
                 "output_digest": _hex("x"), "actor": "agent:x", "timestamp": 1},
                {"seq": 2, "step_kind": "finalize", "input_digest": _hex("x"),
                 "output_digest": _ARTIFACT, "actor": "agent:x", "timestamp": 2},
            ])


class VerifyTests(unittest.TestCase):
    def test_valid_chain_passes(self):
        receipt, lookup = _full_chain()
        verdict = verify_process(receipt, tool_receipt_lookup=lookup, require_human_checkpoint=True)
        self.assertTrue(verdict.allowed)
        self.assertEqual(verdict.classification, VERIFIED_PROCESS)
        self.assertIsNone(verdict.failed_step)

    def test_automated_pipeline_passes_without_human_checkpoint(self):
        d1 = _hex("auto-d1")
        steps = [
            {"seq": 0, "step_kind": "draft", "input_digest": _SEED, "output_digest": d1,
             "actor": "agent:pipe", "timestamp": 100},
            {"seq": 1, "step_kind": "finalize", "input_digest": d1, "output_digest": _ARTIFACT,
             "actor": "agent:pipe", "timestamp": 110},
        ]
        receipt = build_receipt(artifact_digest=_ARTIFACT, seed_digest=_SEED, steps=steps)
        verdict = verify_process(receipt)
        self.assertTrue(verdict.allowed)

    def test_broken_chain_link_fails(self):
        receipt, lookup = _full_chain()
        from process_receipts import ProcessReceipt, ProcessStep
        tampered = []
        for s in receipt.steps:
            if s.seq == 2:
                tampered.append(ProcessStep(
                    seq=s.seq, step_kind=s.step_kind, input_digest=s.input_digest,
                    output_digest=s.output_digest, actor=s.actor,
                    timestamp=s.timestamp, tool_receipt_id=s.tool_receipt_id,
                    step_digest="0" * 64,
                ))
            else:
                tampered.append(s)
        broken = ProcessReceipt(
            schema_version=receipt.schema_version, artifact_digest=receipt.artifact_digest,
            seed_digest=receipt.seed_digest, steps=tuple(tampered),
        )
        verdict = verify_process(broken, tool_receipt_lookup=lookup)
        self.assertFalse(verdict.allowed)
        self.assertEqual(verdict.failed_step, 2)
        self.assertIn("digest mismatch", verdict.reasons[0])

    def test_unrecorded_edit_fails(self):
        # Rebuild with step 2's input not matching step 1's output.
        receipt, lookup = _full_chain()
        from process_receipts import ProcessReceipt, ProcessStep
        evil_input = _hex("evil-unrecorded")
        rebuilt = []
        prev = "genesis"
        for s in receipt.steps:
            inp = evil_input if s.seq == 2 else s.input_digest
            digest = compute_step_digest(
                seq=s.seq, step_kind=s.step_kind, input_digest=inp,
                output_digest=s.output_digest, actor=s.actor,
                timestamp=s.timestamp, tool_receipt_id=s.tool_receipt_id,
                prev_digest=prev,
            )
            rebuilt.append(ProcessStep(s.seq, s.step_kind, inp, s.output_digest,
                                       s.actor, s.timestamp, s.tool_receipt_id, digest))
            prev = digest
        evil = ProcessReceipt(receipt.schema_version, receipt.artifact_digest,
                              receipt.seed_digest, tuple(rebuilt))
        verdict = verify_process(evil, tool_receipt_lookup=lookup)
        self.assertFalse(verdict.allowed)
        self.assertEqual(verdict.failed_step, 2)
        self.assertIn("unrecorded edit", verdict.reasons[0])

    def test_agent_actor_human_checkpoint_fails(self):
        receipt, lookup = _full_chain()
        from process_receipts import ProcessReceipt, ProcessStep
        rebuilt = []
        prev = "genesis"
        for s in receipt.steps:
            actor = "agent:sock-puppet" if s.step_kind == "human_checkpoint" else s.actor
            digest = compute_step_digest(
                seq=s.seq, step_kind=s.step_kind, input_digest=s.input_digest,
                output_digest=s.output_digest, actor=actor,
                timestamp=s.timestamp, tool_receipt_id=s.tool_receipt_id,
                prev_digest=prev,
            )
            rebuilt.append(ProcessStep(s.seq, s.step_kind, s.input_digest, s.output_digest,
                                       actor, s.timestamp, s.tool_receipt_id, digest))
            prev = digest
        evil = ProcessReceipt(receipt.schema_version, receipt.artifact_digest,
                              receipt.seed_digest, tuple(rebuilt))
        verdict = verify_process(evil, tool_receipt_lookup=lookup)
        self.assertFalse(verdict.allowed)
        self.assertIn("agent actor", verdict.reasons[0])

    def test_missing_human_checkpoint_fails_when_required(self):
        d1 = _hex("auto-d1")
        steps = [
            {"seq": 0, "step_kind": "draft", "input_digest": _SEED, "output_digest": d1,
             "actor": "agent:pipe", "timestamp": 100},
            {"seq": 1, "step_kind": "finalize", "input_digest": d1, "output_digest": _ARTIFACT,
             "actor": "agent:pipe", "timestamp": 110},
        ]
        receipt = build_receipt(artifact_digest=_ARTIFACT, seed_digest=_SEED, steps=steps)
        verdict = verify_process(receipt, require_human_checkpoint=True)
        self.assertFalse(verdict.allowed)
        self.assertIn("human_checkpoint", verdict.reasons[0])

    def test_tool_call_without_receipt_fails(self):
        receipt, _ = _full_chain(tool_lookup=lambda rid: None)
        verdict = verify_process(receipt, tool_receipt_lookup=lambda rid: None)
        self.assertFalse(verdict.allowed)
        self.assertIn("unknown tool receipt", verdict.reasons[0])

    def test_tool_call_receipt_mismatch_fails(self):
        receipt, _ = _full_chain()
        other = _tool_receipt("other-args", "other-result")
        verdict = verify_process(receipt, tool_receipt_lookup=lambda rid: other)
        self.assertFalse(verdict.allowed)

    def test_finalize_artifact_mismatch_fails(self):
        receipt, lookup = _full_chain()
        from process_receipts import ProcessReceipt
        evil = ProcessReceipt(receipt.schema_version, _hex("different-artifact"),
                              receipt.seed_digest, receipt.steps)
        verdict = verify_process(evil, tool_receipt_lookup=lookup)
        self.assertFalse(verdict.allowed)
        self.assertIn("artifact_digest", verdict.reasons[0])

    def test_chain_must_end_with_finalize(self):
        steps = [
            {"seq": 0, "step_kind": "draft", "input_digest": _SEED,
             "output_digest": _hex("d1"), "actor": "agent:x", "timestamp": 1},
            {"seq": 1, "step_kind": "revise", "input_digest": _hex("d1"),
             "output_digest": _ARTIFACT, "actor": "agent:x", "timestamp": 2},
        ]
        receipt = build_receipt(artifact_digest=_ARTIFACT, seed_digest=_SEED, steps=steps)
        verdict = verify_process(receipt)
        self.assertFalse(verdict.allowed)
        self.assertIn("finalize", verdict.reasons[0])

    def test_empty_chain_fails(self):
        receipt = build_receipt(artifact_digest=_ARTIFACT, seed_digest=_SEED, steps=[])
        verdict = verify_process(receipt)
        self.assertFalse(verdict.allowed)
        self.assertEqual(verdict.classification, UNVERIFIABLE_PROCESS)

    def test_mapping_input_verified(self):
        receipt, lookup = _full_chain()
        as_dict = {
            "schema_version": receipt.schema_version,
            "artifact_digest": receipt.artifact_digest,
            "seed_digest": receipt.seed_digest,
            "steps": [dict(s.__dict__) for s in receipt.steps],
        }
        verdict = verify_process(as_dict, tool_receipt_lookup=lookup)
        self.assertTrue(verdict.allowed)

    def test_malformed_receipt_raises(self):
        with self.assertRaises(ProcessReceiptError):
            verify_process({"schema_version": "bogus"})


class ClassifyTests(unittest.TestCase):
    def test_none_receipt_is_unverifiable_process(self):
        self.assertEqual(classify_process(None), UNVERIFIABLE_PROCESS)

    def test_valid_chain_is_verified_process(self):
        receipt, lookup = _full_chain()
        self.assertEqual(classify_process(receipt, tool_receipt_lookup=lookup), VERIFIED_PROCESS)

    def test_malformed_receipt_classifies_unverifiable_not_raise(self):
        self.assertEqual(classify_process({"nope": True}), UNVERIFIABLE_PROCESS)

    def test_audit_event_shape(self):
        receipt, lookup = _full_chain()
        verdict = verify_process(receipt, tool_receipt_lookup=lookup)
        event = process_receipt_audit_event(receipt, verdict, policy="essay-submission")
        self.assertEqual(event["event"], "process.receipt_verdict")
        self.assertEqual(event["classification"], VERIFIED_PROCESS)
        self.assertTrue(event["allowed"])
        self.assertEqual(event["n_steps"], 6)
        self.assertEqual(event["policy"], "essay-submission")


if __name__ == "__main__":
    unittest.main()

"""Spec-API tests for the IDA loop driver (additive extension).

Covers IteratedAmplification.amplify/distill/iterate plus the
Amplifier.distill checkpoint. Existing behaviour is covered by
tests/test_iterated_amplification.py; these are additive only.
"""

import subprocess
import sys

import pytest

from iterated_amplification import (
    SCHEMA_PIN,
    ITERATED_AMPLIFICATION_VERSION,
    AmplificationError,
    Amplifier,
    DistillationRecord,
    IteratedAmplification,
    IterationReport,
)


def _combined(amp=None, task_id="t0"):
    amp = amp or Amplifier()
    amp.register_root("root task", task_id=task_id, seq=1)
    amp.decompose(task_id, ["a", "b"], seq=2)
    amp.combine(
        task_id,
        {f"{task_id}.0": "out-a", f"{task_id}.1": "out-b"},
        synthesized="both done",
        seq=3,
    )
    return amp


def test_version_and_schema_pins():
    assert ITERATED_AMPLIFICATION_VERSION == "iterated-amplification.v1"
    assert SCHEMA_PIN == "northstar.iterated-amplification.v1"


def test_spec_api_present():
    for name in ("amplify", "distill", "iterate"):
        assert callable(getattr(IteratedAmplification, name)), name


def test_distill_roundtrip():
    amp = _combined()
    record = amp.distill("t0", seq=4)
    assert isinstance(record, DistillationRecord)
    assert record.task_id == "t0"
    assert record.leaf_count == 2
    assert record.combined_digest.startswith("sha256:")
    assert record.digest.startswith("sha256:")
    # Pins the pair booked by combine.
    pair = amp.distillation_ledger()[0]
    assert record.combined_digest == pair.combined_digest
    assert record.leaf_count == pair.leaf_count


def test_distill_as_dict_schema_pin():
    record = _combined().distill("t0", seq=4)
    body = record.as_dict()
    assert body["schema"] == SCHEMA_PIN
    assert body["task_id"] == "t0"
    assert body["seq"] == 4


def test_distill_without_combine_refuses():
    amp = Amplifier()
    amp.register_root("r", task_id="r", seq=1)
    with pytest.raises(AmplificationError):
        amp.distill("r", seq=2)


def test_distill_unknown_task_refuses():
    amp = _combined()
    with pytest.raises(AmplificationError):
        amp.distill("nope", seq=9)


def test_distill_bad_seq_refuses():
    amp = _combined()
    for bad in (-1, True, "4", 1.5, None):
        with pytest.raises(AmplificationError):
            amp.distill("t0", seq=bad)


def test_distillation_records_view():
    amp = _combined(task_id="t0")
    _combined(amp, task_id="t1")
    amp.distill("t0", seq=10)
    amp.distill("t1", seq=11)
    assert len(amp.distillation_records()) == 2
    only = amp.distillation_records("t1")
    assert len(only) == 1 and only[0].task_id == "t1"


def test_iterate_full_loop():
    ida = IteratedAmplification()
    report = ida.iterate(
        "audit ledger",
        "i0",
        plan={"i0": ["check revenue", "check expenses"]},
        leaf_outputs={"i0.0": "clean", "i0.1": "clean"},
        depth=1,
        synthesized="ledger clean",
        seq=1,
    )
    assert isinstance(report, IterationReport)
    assert report.task_id == "i0"
    assert report.round == 1
    assert report.leaf_count == 2
    assert report.partial is False
    assert report.combined_digest.startswith("sha256:")
    assert report.digest.startswith("sha256:")
    assert report.as_dict()["schema"] == SCHEMA_PIN
    assert ida.round == 1
    assert ida.amplifier.verify_tree("i0")


def test_iterate_rounds_increment():
    ida = IteratedAmplification()
    for i in range(2):
        rep = ida.iterate(
            f"task {i}",
            f"r{i}",
            plan={f"r{i}": ["x", "y"]},
            leaf_outputs={f"r{i}.0": "ok", f"r{i}.1": "ok"},
            depth=1,
            synthesized="done",
            seq=1,
        )
        assert rep.round == i + 1
    assert ida.round == 2
    assert [r.task_id for r in ida.iterations()] == ["r0", "r1"]


def test_iterate_max_rounds_fail_closed():
    ida = IteratedAmplification(max_rounds=1)
    ida.iterate(
        "one", "m0", plan={"m0": ["a"]}, leaf_outputs={"m0.0": "ok"},
        depth=1, synthesized="done", seq=1,
    )
    with pytest.raises(AmplificationError):
        ida.iterate(
            "two", "m1", plan={"m1": ["a"]}, leaf_outputs={"m1.0": "ok"},
            depth=1, synthesized="done", seq=1,
        )


def test_iterate_duplicate_task_refuses():
    ida = IteratedAmplification()
    kwargs = dict(
        description="dup", plan={"d0": ["a"]}, leaf_outputs={"d0.0": "ok"},
        depth=1, synthesized="done", seq=1,
    )
    ida.iterate(task_id="d0", **kwargs)
    with pytest.raises(AmplificationError):
        ida.iterate(task_id="d0", **kwargs)


def test_iterate_partial_books_partial():
    ida = IteratedAmplification()
    report = ida.iterate(
        "half", "p0", plan={"p0": ["a", "b"]}, leaf_outputs={"p0.0": "ok"},
        depth=1, synthesized="half done", seq=1, allow_partial=True,
    )
    assert report.partial is True
    assert report.leaf_count == 1


def test_iterate_bad_inputs_refuse():
    ida = IteratedAmplification()
    good = dict(
        description="d", plan={"b0": ["a"]}, leaf_outputs={"b0.0": "ok"},
        depth=1, synthesized="done", seq=1,
    )
    with pytest.raises(AmplificationError):
        ida.iterate(task_id="b0", **{**good, "description": "  "})
    with pytest.raises(AmplificationError):
        ida.iterate(task_id="b1", **{**good, "seq": -1})


def test_main_subprocess():
    proc = subprocess.run(
        [sys.executable, "iterated_amplification.py"],
        capture_output=True,
        text=True,
        cwd=".",
    )
    assert proc.returncode == 0, proc.stderr
    assert "iterated-amplification OK" in proc.stdout

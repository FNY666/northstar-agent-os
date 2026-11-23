"""Tests for chaos_engineering (Chaos Monkey / Gremlin shaped ledger)."""

import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import chaos_engineering as ce_mod
from chaos_engineering import (
    CHAOS_ENGINEERING_VERSION,
    CHAOS_ENGINEERING_SCHEMA,
    FAULT_TYPES,
    BLAST_RADII,
    STATE_DEFINED,
    STATE_RUNNING,
    STATE_ABORTED,
    ChaosEngineering,
    chaos_engineering_audit_event,
    ChaosEngineeringError,
    BadExperimentError,
    DuplicateExperimentError,
    UnknownExperimentError,
    BadBlastError,
    AlreadyRunningError,
    BadAbortError,
    NotRunningError,
    AlreadyAbortedError,
    SeqOrderError,
)

MODULE_PATH = Path(ce_mod.__file__)


def test_version_and_schema_pins():
    assert CHAOS_ENGINEERING_VERSION == "chaos-engineering.v1"
    assert CHAOS_ENGINEERING_SCHEMA == "northstar.chaos-engineering.v1"
    assert set(FAULT_TYPES) == {
        "kill-pod", "network-latency", "network-partition", "disk-pressure",
        "cpu-pressure", "memory-pressure", "clock-skew", "dns-blackhole",
    }
    assert set(BLAST_RADII) == {"single", "zone", "region"}


def test_stdlib_only_ast():
    tree = ast.parse(MODULE_PATH.read_text())
    allowed = {
        "hashlib", "hmac", "threading", "dataclasses", "typing",
        "json", "__future__", "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


def _engine():
    return ChaosEngineering()


def test_experiment_roundtrip():
    eng = _engine()
    rec = eng.experiment("e1", "latency test", "network-latency",
                         ["web-0"], 1, hypothesis="p99-below 500ms")
    assert rec.experiment_id == "e1"
    assert rec.fault_type == "network-latency"
    assert rec.targets == ("web-0",)
    assert rec.blast_radius == "single"
    assert rec.duration_seq == 100
    assert rec.hypothesis == "p99-below 500ms"
    assert rec.state == STATE_DEFINED
    assert rec.verify()
    assert eng.status("e1") == STATE_DEFINED
    assert eng.experiment_ids() == ("e1",)


def test_experiment_duplicate_refused():
    eng = _engine()
    eng.experiment("e1", "n", "kill-pod", ["a"], 1)
    with pytest.raises(DuplicateExperimentError):
        eng.experiment("e1", "n2", "kill-pod", ["b"], 2)


def test_experiment_bad_fault_type():
    eng = _engine()
    with pytest.raises(BadExperimentError):
        eng.experiment("e1", "n", "nuke-datacenter", ["a"], 1)


def test_experiment_bad_blast_radius():
    eng = _engine()
    with pytest.raises(BadExperimentError):
        eng.experiment("e1", "n", "kill-pod", ["a"], 1, blast_radius="planet")


def test_experiment_bad_targets():
    eng = _engine()
    seq = 1
    for bad in ([], ["", ], "not-a-list", ["a", "a"]):
        with pytest.raises(BadExperimentError):
            eng.experiment("e-bad", "n", "kill-pod", bad, seq)
        seq += 1  # failed mutations consume their seq (batch discipline)
    # next valid seq continues the ledger
    rec = eng.experiment("e-ok", "n", "kill-pod", ["a"], seq)
    assert rec.seq == seq


def test_blast_roundtrip():
    eng = _engine()
    eng.experiment("e1", "n", "disk-pressure", ["db-0"], 1)
    blast = eng.blast("e1", 2)
    assert blast.blast_id == "blt-1"
    assert blast.experiment_id == "e1"
    assert blast.verify()
    assert eng.status("e1") == STATE_RUNNING
    assert eng.running_ids() == ("e1",)
    assert eng.blasts_for("e1") == (blast,)


def test_blast_unknown_experiment():
    eng = _engine()
    with pytest.raises(UnknownExperimentError):
        eng.blast("nope", 1)


def test_blast_double_refused():
    eng = _engine()
    eng.experiment("e1", "n", "cpu-pressure", ["w-0"], 1)
    eng.blast("e1", 2)
    with pytest.raises(AlreadyRunningError):
        eng.blast("e1", 3)


def test_blast_after_abort_refused():
    eng = _engine()
    eng.experiment("e1", "n", "kill-pod", ["a"], 1)
    eng.blast("e1", 2)
    eng.abort("e1", 3, reason="done")
    with pytest.raises(BadBlastError):
        eng.blast("e1", 4)


def test_abort_roundtrip_terminal():
    eng = _engine()
    eng.experiment("e1", "n", "network-partition", ["a", "b"], 1,
                   blast_radius="zone")
    eng.blast("e1", 2)
    abort = eng.abort("e1", 3, reason="hypothesis violated")
    assert abort.abort_id == "abt-1"
    assert abort.reason == "hypothesis violated"
    assert abort.verify()
    assert eng.status("e1") == STATE_ABORTED
    assert eng.running_ids() == ()
    assert eng.stats() == {
        "experiments": 1, "blasts": 1, "aborts": 1, "running": 0,
    }


def test_abort_not_running_refused():
    eng = _engine()
    eng.experiment("e1", "n", "kill-pod", ["a"], 1)
    with pytest.raises(NotRunningError):
        eng.abort("e1", 2)


def test_abort_double_refused():
    eng = _engine()
    eng.experiment("e1", "n", "kill-pod", ["a"], 1)
    eng.blast("e1", 2)
    eng.abort("e1", 3)
    with pytest.raises(AlreadyAbortedError):
        eng.abort("e1", 4)


def test_seq_ordering_and_failed_mutation_consumes_seq():
    eng = _engine()
    eng.experiment("e1", "n", "kill-pod", ["a"], 1)
    with pytest.raises(SeqOrderError):
        eng.experiment("e2", "n", "kill-pod", ["b"], 1)  # rewind
    with pytest.raises(ChaosEngineeringError):
        eng.experiment("e2", "n", "kill-pod", ["b"], True)  # bool
    with pytest.raises(ChaosEngineeringError):
        eng.blast("e1", -1)  # negative
    # failed mutations consumed their seqs: next valid seq is 2
    rec = eng.experiment("e2", "n", "kill-pod", ["b"], 2)
    assert rec.seq == 2


def test_audit_shapes_and_target_leak_ban():
    eng = _engine()
    eng.experiment("e1", "n", "dns-blackhole", ["secret-host"], 1)
    eng.blast("e1", 2)
    eng.abort("e1", 3, reason="r")
    kinds = [e["kind"] for e in eng.audit_log()]
    assert kinds == [
        "chaos.experiment-defined", "chaos.blasted", "chaos.aborted",
    ]
    for event in eng.audit_log():
        assert event["schema"] == "audit.ndjson/1"
        blob = str(event)
        assert "secret-host" not in blob
    with pytest.raises(ChaosEngineeringError):
        chaos_engineering_audit_event("chaos.blasted", 9, targets=["x"])
    with pytest.raises(ChaosEngineeringError):
        chaos_engineering_audit_event("bogus.kind", 9)


def test_views_and_unknown_lookups():
    eng = _engine()
    eng.experiment("e1", "n", "memory-pressure", ["m-0"], 1)
    assert eng.experiment_record("e1").experiment_id == "e1"
    with pytest.raises(UnknownExperimentError):
        eng.experiment_record("nope")
    with pytest.raises(UnknownExperimentError):
        eng.status("nope")
    with pytest.raises(UnknownExperimentError):
        eng.blast_record("blt-99")
    with pytest.raises(UnknownExperimentError):
        eng.abort_record("abt-99")
    with pytest.raises(UnknownExperimentError):
        eng.blasts_for("nope")
    b = eng.blast("e1", 2)
    assert eng.blast_record("blt-1") == b
    a = eng.abort("e1", 3)
    assert eng.abort_record("abt-1") == a


def test_digest_determinism_across_instances():
    kwargs = dict(name="n", fault_type="clock-skew", targets=["c-0"],
                  blast_radius="region", duration_seq=50, hypothesis="h")
    a = ChaosEngineering(seed="s1").experiment("e1", seq=1, **kwargs)
    b = ChaosEngineering(seed="s1").experiment("e1", seq=1, **kwargs)
    assert a.digest == b.digest
    c = ChaosEngineering(seed="s2").experiment("e1", seq=1, **kwargs)
    assert a.digest != c.digest


def test_concurrency_smoke():
    eng = _engine()
    errors = []

    def worker(i):
        try:
            eng.experiment(f"e-{i}", "n", "kill-pod", [f"t-{i}"], i + 1)
        except ChaosEngineeringError as exc:  # seq races are fine
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert eng.stats()["experiments"] >= 1


def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, str(MODULE_PATH)],
        capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert "chaos-engineering OK" in proc.stdout

"""Tests for the forward-seal-ledger forward-secure sealed decision ledger."""

import ast
import dataclasses
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "forward_seal_ledger.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32
PIN3 = "sha256:" + "ef" * 32

K1 = b"k" * 32
K2 = b"c" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("forward_seal_ledger", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["forward_seal_ledger"] = module
    spec.loader.exec_module(module)
    return module


fsl = _load()


def _ledger(initial_key=K1, checkpoint_key=K2):
    return fsl.ForwardSealLedger(
        initial_key=initial_key, checkpoint_key=checkpoint_key
    )


def _append(ledger, i=0, **kw):
    args = dict(
        intent=f"intent-{i}",
        action=f"action-{i}",
        subject=f"subject-{i}",
        authorization=f"auth-{i}",
        inputs_digest=PIN,
        logic_digest=PIN2,
        execution_digest=PIN3,
        outcome=f"outcome-{i}",
    )
    args.update(kw)
    return ledger.append(**args)


# 1. version/schema pins + EVENT_FIELDS exact tuple
def test_version_and_schema_pins():
    assert fsl.FORWARD_SEAL_LEDGER_VERSION == "forward-seal-ledger.v1"
    assert fsl.SCHEMA_PIN == "northstar.forward-seal-ledger.v1"
    assert fsl.EVENT_FIELDS == (
        "intent",
        "action",
        "subject",
        "authorization",
        "inputs_digest",
        "logic_digest",
        "execution_digest",
        "outcome",
    )
    assert fsl.CHECKPOINT_INTERVAL == 64


# 2. stdlib_only() AST check (import whitelist)
def test_stdlib_only():
    tree = ast.parse(MOD.read_text(encoding="utf-8"))
    allowed = set(sys.stdlib_module_names) | {"canonical_json"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                assert node.module.split(".")[0] in allowed, node.module


# 3. append roundtrip: seq 1..3, prev_hash chaining, seal hex, frozen-ness
def test_append_roundtrip():
    ledger = _ledger()
    r1 = _append(ledger, 1)
    r2 = _append(ledger, 2)
    r3 = _append(ledger, 3)
    assert (r1.seq, r2.seq, r3.seq) == (1, 2, 3)
    assert r1.prev_hash == ledger.genesis
    assert r2.prev_hash == r1.record_hash
    assert r3.prev_hash == r2.record_hash
    for r in (r1, r2, r3):
        int(r.seal, 16)  # hex
        assert len(r.seal) == 64
        assert r.record_hash.startswith("sha256:")
        assert len(r.record_hash) == 71
    with pytest.raises(dataclasses.FrozenInstanceError):
        r1.seq = 99  # type: ignore[misc]


# 4. bad-input table
def test_bad_inputs():
    with pytest.raises(fsl.ForwardSealError):
        fsl.ForwardSealLedger(b"short", b"x" * 16)
    with pytest.raises(fsl.ForwardSealError):
        fsl.ForwardSealLedger(b"x" * 16, b"short")
    with pytest.raises(fsl.ForwardSealError):
        fsl.ForwardSealLedger("not-bytes", b"x" * 16)
    with pytest.raises(fsl.ForwardSealError):
        fsl.ForwardSealLedger(b"x" * 16, None)
    ledger = _ledger()
    with pytest.raises(fsl.ForwardSealError):
        _append(ledger, intent="")
    with pytest.raises(fsl.ForwardSealError):
        _append(ledger, intent=123)
    with pytest.raises(fsl.ForwardSealError):
        _append(ledger, inputs_digest="not-a-pin")
    with pytest.raises(fsl.ForwardSealError):
        _append(ledger, inputs_digest="sha256:ab")  # wrong length
    with pytest.raises(fsl.ForwardSealError):
        _append(ledger, logic_digest="md5:" + "ab" * 32)


# 5. forward security: tampered event / prev_hash / wrong initial key
def test_forward_security_tamper():
    ledger = _ledger()
    _append(ledger, 1)
    _append(ledger, 2)
    rec = ledger.record(1)
    evil_event = (("intent", "evil"),) + rec.event[1:]
    ledger._records[0] = dataclasses.replace(rec, event=evil_event)
    with pytest.raises(fsl.ForwardSealError):
        ledger.verify(K1, K2)

    ledger2 = _ledger()
    _append(ledger2, 1)
    r2 = _append(ledger2, 2)
    ledger2._records[1] = dataclasses.replace(
        r2, prev_hash="sha256:" + "ff" * 32
    )
    with pytest.raises(fsl.ForwardSealError):
        ledger2.verify(K1, K2)

    ledger3 = _ledger()
    _append(ledger3, 1)
    with pytest.raises(fsl.ForwardSealError):
        ledger3.verify(b"w" * 32, K2)


# 6. key evolution: determinism + key separation
def test_key_evolution_determinism():
    a = _ledger(initial_key=K1)
    b = _ledger(initial_key=K1)
    c = _ledger(initial_key=b"d" * 32)
    for i in range(3):
        ra = _append(a, i)
        rb = _append(b, i)
        rc = _append(c, i)
        assert ra.seal == rb.seal
        assert ra.record_hash == rb.record_hash
        assert ra.seal != rc.seal


# 7. checkpoint: manual seal + tamper detection
def test_checkpoint():
    ledger = _ledger()
    _append(ledger, 1)
    _append(ledger, 2)
    cp = ledger.checkpoint()
    assert cp.seq == 2
    assert cp.head_hash == ledger.record(2).record_hash
    assert cp.records_sealed == 2
    assert len(cp.seal) == 64
    int(cp.seal, 16)
    rep = ledger.verify(K1, K2)
    assert rep["checkpoints_verified"] == 1
    ledger._checkpoints[0] = dataclasses.replace(
        cp, head_hash="sha256:" + "ff" * 32
    )
    with pytest.raises(fsl.ForwardSealError):
        ledger.verify(K1, K2)


# 8. automatic checkpoint at CHECKPOINT_INTERVAL
def test_automatic_checkpoint_interval():
    assert fsl.CHECKPOINT_INTERVAL == 64
    ledger = _ledger()
    for i in range(64):
        _append(ledger, i)
    cps = ledger.checkpoints()
    assert len(cps) == 1
    assert cps[0].seq == 64
    assert cps[0].records_sealed == 64


# 9. verify report shape
def test_verify_report_shape():
    ledger = _ledger()
    _append(ledger, 1)
    _append(ledger, 2)
    ledger.checkpoint()
    rep = ledger.verify(K1, K2)
    assert rep["version"] == "forward-seal-ledger.v1"
    assert rep["records_verified"] == 2
    assert rep["checkpoints_verified"] == 1
    assert rep["genesis"] == ledger.genesis
    assert rep["head_hash"] == ledger.record(2).record_hash
    assert rep["forward_secure"] is True


# 10. verify with wrong checkpoint_key raises
def test_verify_wrong_checkpoint_key():
    ledger = _ledger()
    _append(ledger, 1)
    ledger.checkpoint()
    with pytest.raises(fsl.ForwardSealError):
        ledger.verify(K1, b"z" * 32)


# 11. record() pure read: unknown seq / bool seq
def test_record_pure_read():
    ledger = _ledger()
    with pytest.raises(fsl.ForwardSealError):
        ledger.record(1)  # empty ledger
    with pytest.raises(fsl.ForwardSealError):
        ledger.record(True)  # bool refused
    with pytest.raises(fsl.ForwardSealError):
        ledger.record(0)
    with pytest.raises(fsl.ForwardSealError):
        ledger.record("1")


# 12. checkpoint on empty ledger raises
def test_checkpoint_empty_ledger():
    with pytest.raises(fsl.ForwardSealError):
        _ledger().checkpoint()


# 13. thread smoke: 8 threads x 10 appends on one ledger
def test_thread_smoke():
    ledger = _ledger()
    errors = []

    def work(t):
        try:
            for i in range(10):
                _append(ledger, f"{t}-{i}")
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=work, args=(t,)) for t in range(8)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    assert not errors
    assert len(ledger) == 80


# 14. triple fingerprints pinned and distinct
def test_triple_fingerprints():
    ledger = _ledger()
    rec = ledger.append(
        intent="i",
        action="a",
        subject="s",
        authorization="z",
        inputs_digest=PIN,
        logic_digest=PIN2,
        execution_digest=PIN3,
        outcome="o",
    )
    assert rec.input_fingerprint == PIN
    assert rec.logic_fingerprint == PIN2
    assert rec.execution_fingerprint == PIN3
    assert len({PIN, PIN2, PIN3}) == 3


# 15. main() subprocess check
def test_main_subprocess():
    proc = subprocess.run(
        [sys.executable, str(MOD)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert "OK" in proc.stdout

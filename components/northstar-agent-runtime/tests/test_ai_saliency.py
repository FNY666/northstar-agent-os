"""Tests for ai_saliency.py - AI saliency-map computation decision ledger."""

import importlib.util
import sys
import threading
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

_MOD_PATH = Path(__file__).resolve().parent.parent / "ai_saliency.py"


def _load():
    spec = importlib.util.spec_from_file_location("ai_saliency", str(_MOD_PATH))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["ai_saliency"] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def mod():
    return _load()


@pytest.fixture()
def ledger(mod):
    return mod.AISaliency()


# 1. pins / vocabularies -------------------------------------------------------


def test_pins_and_vocabularies(mod):
    assert mod.AI_SALIENCY_VERSION == "ai-saliency.v1"
    assert mod.SCHEMA_PIN == "northstar.ai-saliency.v1"
    assert mod.SALIENCY_METHODS == (
        "gradient",
        "integrated-gradients",
        "smoothgrad",
        "grad-cam",
        "lime",
        "shap",
        "attention-rollout",
        "occlusion",
    )
    assert mod.FIDELITIES == (
        "faithful",
        "partial",
        "misleading",
        "inconclusive",
        "not-computed",
    )
    assert mod.VERIFY_VERDICTS == ("verified", "tampered")
    assert mod.POSTURES == (
        "unexamined",
        "misleading",
        "contested",
        "partial",
        "explained",
    )
    assert set(mod.AUDIT_KINDS) == {"computed", "retired", "rejected"}


# 2. stdlib-only ----------------------------------------------------------------


def test_stdlib_only(mod):
    assert mod.stdlib_only()


# 3. compute roundtrip / defaults / minting / frozen-ness ------------------------


def test_compute_roundtrip_defaults_frozen(mod, ledger):
    digest = "sha256:" + "ab" * 32
    rec = ledger.compute(
        "inp-1", 1, saliency_method="shap", fidelity="faithful",
        compute_digest=digest,
    )
    assert rec.saliency_id == "sal-1"
    assert rec.input_id == "inp-1"
    assert rec.saliency_method == "shap"
    assert rec.fidelity == "faithful"
    assert rec.compute_digest == digest
    assert rec.verify()
    rec2 = ledger.compute("inp-1", 2)
    assert rec2.saliency_id == "sal-2"
    assert rec2.saliency_method == "gradient"   # default method
    assert rec2.fidelity == "not-computed"     # default fidelity
    assert rec2.compute_digest == ""           # default digest
    assert rec2.verify()
    with pytest.raises(FrozenInstanceError):
        rec.saliency_method = "lime"  # type: ignore


# 4. bad inputs + seq-burn + rejected rows + rewinds bare -------------------------


def test_bad_inputs_burn_seq_and_rewinds_bare(mod, ledger):
    bad = [
        ("", "gradient", "faithful", ""),              # empty input id
        (123, "gradient", "faithful", ""),             # bad id type
        (True, "gradient", "faithful", ""),            # bool id
        ("inp-1", "bogus-method", "faithful", ""),     # bad method
        ("inp-1", "gradient", "bogus", ""),            # bad fidelity
        ("inp-1", "gradient", "faithful", "nope"),     # bad digest
        ("inp-1", "gradient", "faithful", "sha256:zz"),  # bad digest hex
    ]
    seq = 0
    for input_id, method, fidelity, d in bad:
        seq += 1
        with pytest.raises(mod.AISaliencyError):
            ledger.compute(input_id, seq, method, fidelity, d)
    rows = ledger.audit_log(1)
    rejected_rows = [r for r in rows if r["kind"] == "rejected"]
    assert len(rejected_rows) == len(bad)
    assert ledger.stats(1)["n_saliencies"] == 0
    # failed mutations consumed their seqs: next valid claim must be seq+1
    rec = ledger.compute("inp-1", seq + 1, fidelity="faithful")
    assert rec.saliency_id == "sal-1"
    # rewinds raise bare with zero new rows
    n_rows = len(ledger.audit_log(1))
    with pytest.raises(mod.SeqOrderError):
        ledger.compute("inp-1", seq + 1)
    with pytest.raises(mod.SeqOrderError):
        ledger.compute("inp-1", 0)
    assert len(ledger.audit_log(1)) == n_rows
    # malformed seq types raise bare with zero rows
    for bad_seq in ("1", 1.5, True, None):
        with pytest.raises(mod.SeqOrderError):
            ledger.compute("inp-1", bad_seq)
    assert len(ledger.audit_log(1)) == n_rows


# 5. full 8-method vocabulary ----------------------------------------------------


def test_full_method_vocabulary(mod, ledger):
    seq = 0
    for method in mod.SALIENCY_METHODS:
        seq += 1
        rec = ledger.compute(f"inp-{seq}", seq, saliency_method=method)
        assert rec.verify()
        assert rec.saliency_method == method
    assert ledger.stats(1)["n_saliencies"] == 8


# 6. full 5-fidelity vocabulary + tallies ----------------------------------------


def test_full_fidelity_vocabulary_and_tallies(mod, ledger):
    seq = 0
    for fidelity in mod.FIDELITIES:
        seq += 1
        rec = ledger.compute("inp-1", seq, fidelity=fidelity)
        assert rec.verify()
    ev = ledger.evaluate("inp-1", seq + 1)
    assert ev.n_saliencies == 5
    assert ev.n_faithful == 1
    assert ev.n_partial == 1
    assert ev.n_misleading == 1
    assert ev.n_inconclusive == 1
    assert ev.n_not_computed == 1
    assert ev.verify()


# 7. verify semantics: verified / tamper-as-data / read purity / unknown --------


def test_verify_semantics(mod, ledger):
    rec = ledger.compute("inp-1", 1, saliency_method="lime", fidelity="faithful")
    rep = ledger.verify(rec.saliency_id, 2)
    assert rep.verdict == "verified"
    assert rep.integrity_ok
    assert rep.verify()
    with pytest.raises(mod.UnknownRecordError):
        ledger.verify("sal-999", 3)
    # read purity: same-seq-twice, no audit rows, seq never consumed
    n_rows = len(ledger.audit_log(1))
    ledger.verify(rec.saliency_id, 2)
    ledger.verify(rec.saliency_id, 2)
    assert len(ledger.audit_log(1)) == n_rows
    # tamper reported as data, never raised
    object.__setattr__(rec, "fidelity", "misleading")
    assert not rec.verify()
    rep2 = ledger.verify(rec.saliency_id, 2)
    assert rep2.verdict == "tampered"
    assert not rep2.integrity_ok


# 8. evaluate posture math: all postures + precedence ------------------------------


def test_evaluate_posture_math(mod):
    cases = [
        ([("faithful",)], "explained"),
        ([("faithful",), ("faithful",)], "explained"),
        ([("partial",)], "partial"),
        ([("not-computed",)], "partial"),
        ([("faithful",), ("partial",)], "partial"),
        ([("inconclusive",)], "contested"),
        ([("faithful",), ("inconclusive",)], "contested"),
        ([("partial",), ("inconclusive",)], "contested"),   # inconclusive > partial
        ([("misleading",)], "misleading"),
        ([("faithful",), ("misleading",)], "misleading"),  # misleading outranks
        ([("inconclusive",), ("misleading",)], "misleading"),
    ]
    for fidelities, want in cases:
        ledger = mod.AISaliency()
        seq = 0
        for (f,) in fidelities:
            seq += 1
            ledger.compute("inp-1", seq, fidelity=f)
        ev = ledger.evaluate("inp-1", seq + 1)
        assert ev.posture == want, (fidelities, ev.posture)
        assert ev.integrity_ok
        assert ev.verify()


# 9. evaluate purity + integrity flip + unknown refusal -----------------------------


def test_evaluate_purity_and_integrity(mod, ledger):
    ledger.compute("inp-1", 1, fidelity="faithful")
    ev = ledger.evaluate("inp-1", 2)
    assert ev.posture == "explained"
    assert ev.integrity_ok
    # read purity: same-seq-twice adds no rows
    n_rows = len(ledger.audit_log(1))
    ledger.evaluate("inp-1", 2)
    ledger.evaluate("inp-1", 2)
    assert len(ledger.audit_log(1)) == n_rows
    # tamper flips integrity_ok as data
    rec = ledger.saliency_record("sal-1", 1)
    object.__setattr__(rec, "saliency_method", "lime")
    ev2 = ledger.evaluate("inp-1", 3)
    assert not ev2.integrity_ok
    # unknown input refused
    with pytest.raises(mod.UnknownInputError):
        ledger.evaluate("nope", 1)
    with pytest.raises(mod.BadInputError):
        ledger.evaluate("", 1)


# 10. retire terminality: reasons, terminal, non-recycling, reads ----------------------


def test_retire_terminality(mod, ledger):
    ledger.compute("inp-1", 1)
    ret = ledger.retire("inp-1", 2)
    assert ret.verify()
    assert "inp-1" in ledger.retired_ids(1)
    with pytest.raises(mod.RetiredInputError):
        ledger.compute("inp-1", 3)      # post-retire mutation refused + burned
    with pytest.raises(mod.RetiredInputError):
        ledger.retire("inp-1", 4)       # double retire refused
    with pytest.raises(mod.BadReasonError):
        ledger.retire("inp-1", 5, reason="bogus")
    # reads still work after retire
    ev = ledger.evaluate("inp-1", 6)
    assert ev.posture == "partial"      # default fidelity not-computed
    rec = ledger.saliency_record("sal-1", 6)
    assert rec.verify()
    assert ledger.saliencies_for("inp-1", 6)[0] == rec
    # ids never recycled
    with pytest.raises(mod.RetiredInputError):
        ledger.compute("inp-1", 7, fidelity="faithful")
    assert ledger.stats(1)["n_saliencies"] == 1


def test_retire_reasons_and_unknown(mod, ledger):
    with pytest.raises(mod.UnknownInputError):
        ledger.retire("ghost", 1)
    for reason in mod.RETIRE_REASONS:
        led = mod.AISaliency()
        led.compute("inp-1", 1)
        ret = led.retire("inp-1", 2, reason=reason)
        assert ret.reason == reason
        assert ret.verify()


# 11. audit shapes + leak ban + pinned-data passthrough ----------------------------------


def test_audit_shapes_and_leak_ban(mod, ledger):
    digest = "sha256:" + "cd" * 32
    ledger.compute("inp-1", 1, saliency_method="shap", fidelity="faithful",
                   compute_digest=digest)
    with pytest.raises(mod.BadMethodError):
        ledger.compute("inp-x", 2, saliency_method="bogus")
    ledger.retire("inp-1", 3)
    rows = ledger.audit_log(1)
    kinds = [r["kind"] for r in rows]
    assert kinds[0] == "computed" and kinds[-1] == "retired"
    assert any(r["kind"] == "rejected" for r in rows)
    for r in rows:
        assert r["schema"] == "audit.ndjson/1"
        assert r["module"] == "ai-saliency"
        assert r["version"] == mod.AI_SALIENCY_VERSION
    computed = rows[0]
    assert computed["details"]["saliency_method"] == "shap"  # pinned vocab emittable
    assert computed["details"]["fidelity"] == "faithful"
    assert "compute_digest" not in computed["details"]
    # builder leak ban
    for key in ["saliency_map", "heatmap", "pixels", "attention_weights",
                "gradients", "activations", "prompt", "tokens", "heatmap"]:
        with pytest.raises(mod.AISaliencyError):
            mod.ai_saliency_audit_event("computed", 1, **{key: "raw"})
    with pytest.raises(mod.AuditKindError):
        mod.ai_saliency_audit_event("bogus", 1)


# 12. views / stats / unknown lookups ----------------------------------------------------


def test_views_stats_unknown(mod, ledger):
    assert ledger.input_ids(1) == ()
    assert ledger.saliency_ids(1) == ()
    assert ledger.retired_ids(1) == ()
    assert ledger.stats(1)["n_inputs"] == 0
    with pytest.raises(mod.UnknownSaliencyError):
        ledger.saliency_record("sal-1", 1)
    ledger.compute("inp-b", 1)
    ledger.compute("inp-a", 2)
    assert ledger.input_ids(1) == ("inp-a", "inp-b")
    assert ledger.saliency_ids(1) == ("sal-1", "sal-2")
    assert len(ledger.saliencies_for("inp-a", 1)) == 1
    assert ledger.saliencies_for("unknown", 1) == ()
    assert ledger.stats(1)["n_inputs"] == 2
    assert ledger.stats(1)["n_saliencies"] == 2


# 13. cross-instance determinism + tamper + thread smoke -----------------------------------


def test_determinism_and_thread_smoke(mod):
    l1, l2 = mod.AISaliency(), mod.AISaliency()
    d = "sha256:" + "ef" * 32
    r1 = l1.compute("inp-1", 1, saliency_method="grad-cam", fidelity="faithful",
                    compute_digest=d)
    r2 = l2.compute("inp-1", 1, saliency_method="grad-cam", fidelity="faithful",
                    compute_digest=d)
    assert r1.digest == r2.digest
    e1 = l1.evaluate("inp-1", 2)
    e2 = l2.evaluate("inp-1", 2)
    assert e1.digest == e2.digest
    r3 = l1.compute("inp-2", 2, saliency_method="grad-cam", fidelity="faithful",
                    compute_digest=d)
    assert r3.digest != r1.digest  # different payload -> different pin
    # 8-thread read smoke
    ledger = mod.AISaliency()
    ledger.compute("inp-1", 1, fidelity="faithful")
    errors = []

    def read():
        try:
            for _ in range(50):
                ledger.evaluate("inp-1", 0)
                ledger.verify("sal-1", 0)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=read) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors


# 14. main() subprocess -------------------------------------------------------------------


def test_main_subprocess():
    import subprocess

    out = subprocess.run(
        [sys.executable, str(_MOD_PATH)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert out.returncode == 0, out.stderr
    assert "ai-saliency OK" in out.stdout

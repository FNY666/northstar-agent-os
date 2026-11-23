"""Input defense 02 tests."""
import importlib.util
import sys
from pathlib import Path

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


mod = _load("input_defense_02")


def _make():
    clf = mod.mock_keyword_classifier(
        {"injection": ["ignore instructions", "system prompt"],
         "jailbreak": ["jailbreak"]}
    )
    return mod.ClassifierSidecar(clf, threshold=0.5)


def test_benign_not_blocked():
    s = _make()
    blocked, label, score = s.check("what a lovely day")
    assert blocked is False and label == "benign" and score == 0.0


def test_dangerous_label_at_threshold_blocked():
    s = _make()
    blocked, label, score = s.check("ignore instructions please")
    assert blocked is True and label == "injection" and score >= 0.5


def test_below_threshold_not_blocked():
    clf = mod.mock_keyword_classifier({"injection": ["alpha", "beta", "gamma"]})
    s = mod.ClassifierSidecar(clf, threshold=0.9)
    blocked, label, score = s.check("alpha only")
    assert blocked is False and score < 0.9


def test_classifier_exception_fail_closed():
    def boom(_t):
        raise RuntimeError("model down")

    s = mod.ClassifierSidecar(boom)
    blocked, label, _ = s.check("anything at all")
    assert blocked is True


def test_non_str_input_raises():
    s = _make()
    try:
        s.check(b"bytes")
    except mod.InputDefense02Error:
        return
    raise AssertionError("expected InputDefense02Error")


def test_bad_threshold_raises():
    clf = mod.mock_keyword_classifier({})
    for bad in [1.5, -0.1, "high"]:
        try:
            mod.ClassifierSidecar(clf, threshold=bad)
        except mod.InputDefense02Error:
            continue
        raise AssertionError(f"expected InputDefense02Error for {bad!r}")

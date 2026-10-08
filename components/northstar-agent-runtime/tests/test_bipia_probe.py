"""BIPIA probe tests."""

import importlib.util
import sys
from pathlib import Path

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


bp = _load("bipia_probe")


def test_build_probes():
    probes = bp.build_position_probes("PAYLOAD", "filler " * 10)
    assert len(probes) == 3
    positions = {p.position for p in probes}
    assert positions == {"head", "middle", "tail"}


def test_payload_at_position():
    probes = bp.build_position_probes("PAYLOAD", "x " * 20)
    head = next(p for p in probes if p.position == "head")
    assert head.document.startswith("PAYLOAD")
    tail = next(p for p in probes if p.position == "tail")
    assert tail.document.endswith("PAYLOAD")


def test_scan():
    probes = bp.build_position_probes("BAD", "good " * 20)
    result = bp.run_position_scan(probes, lambda doc: "BAD" in doc)
    assert result["blocked"] == 3
    assert result["block_rate"] == 1.0


def test_recency_bias():
    probes = bp.build_position_probes("BAD", "good " * 50)
    # Gate only checks tail.
    def biased(doc):
        return "BAD" in doc[-50:]

    result = bp.run_position_scan(probes, biased)
    assert result["recency_bias"] is True


def test_stdlib_only():
    assert bp.stdlib_only() is True


def test_version_pin():
    assert bp.BIPIA_VERSION == "bipia-probe.v1"

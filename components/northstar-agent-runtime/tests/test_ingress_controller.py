"""Tests for ingress_controller: NGINX/Traefik-shaped routing bookkeeping."""

import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from ingress_controller import (
    IngressController,
    IngressControllerError,
    BadRuleError,
    DuplicateRuleError,
    UnknownRuleError,
    RemovedRuleError,
    BadTLSError,
    DuplicateTLError,
    BadRewriteError,
    SeqOrderError,
    RuleRecord,
    TLSRecord,
    RewriteRecord,
    RemovalRecord,
    MatchReport,
    ingress_controller_audit_event,
    main,
    _MODULE_VERSION,
    _SCHEMA_PIN,
    PATH_TYPES,
)

MOD = Path(__file__).resolve().parent.parent / "ingress_controller.py"


def new_ic():
    events = []
    return IngressController(audit=events.append), events


def test_version_and_path_types_pins():
    assert _MODULE_VERSION == "ingress-controller.v1"
    assert _SCHEMA_PIN == "northstar.ingress-controller.v1"
    assert set(PATH_TYPES) == {"prefix", "exact"}


def test_stdlib_only():
    tree = ast.parse(MOD.read_text())
    stdlib = {
        "hashlib", "re", "threading", "dataclasses", "typing",
        "canonical_json", "json", "__future__",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in stdlib, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in stdlib, node.module


def test_rule_roundtrip_and_digest():
    ic, events = new_ic()
    r = ic.rule("web", "Example.COM", "/app", "svc-web:8080", 1)
    assert isinstance(r, RuleRecord)
    assert r.host == "example.com"  # normalized
    assert r.path_type == "prefix"
    assert r.verify_digest()
    kinds = [e["event"] for e in events]
    assert "ingress.rule-defined" in kinds


def test_rule_bad_inputs():
    ic, _ = new_ic()
    with pytest.raises(BadRuleError):
        ic.rule("", "example.com", "/a", "svc:1", 1)
    with pytest.raises(BadRuleError):
        ic.rule("r", "https://example.com", "/a", "svc:1", 2)  # scheme refused
    with pytest.raises(BadRuleError):
        ic.rule("r", "example .com", "/a", "svc:1", 3)  # whitespace refused
    with pytest.raises(BadRuleError):
        ic.rule("r", "x" * 254, "/a", "svc:1", 4)  # > 253 chars
    with pytest.raises(BadRuleError):
        ic.rule("r", "example.com", "app", "svc:1", 5)  # no leading slash
    with pytest.raises(BadRuleError):
        ic.rule("r", "example.com", "/a", "svc:99999", 6)  # bad port
    with pytest.raises(BadRuleError):
        ic.rule("r", "example.com", "/a", "svc:1", 7, path_type="regex")


def test_rule_duplicate_refused():
    ic, events = new_ic()
    ic.rule("web", "example.com", "/a", "svc:1", 1)
    with pytest.raises(DuplicateRuleError):
        ic.rule("web", "example.com", "/b", "svc:2", 2)
    assert events[-1]["event"] == "ingress.rejected"


def test_tls_roundtrip_by_digest_only():
    ic, events = new_ic()
    t = ic.tls("example.com", 1, cert_digest="sha256:abc123", key_digest="sha256:def456")
    assert isinstance(t, TLSRecord)
    assert t.tls_id == "tls-1"
    assert t.verify_digest()
    # No cert bytes anywhere in the record.
    blob = repr(t)
    assert "abc123" in blob and "def456" in blob
    assert events[-1]["event"] == "ingress.tls-bound"


def test_tls_duplicate_and_bad():
    ic, _ = new_ic()
    ic.tls("example.com", 1, cert_digest="sha256:a")
    with pytest.raises(DuplicateTLError):
        ic.tls("example.com", 2, cert_digest="sha256:b")
    with pytest.raises(BadTLSError):
        ic.tls("example.com", 3, cert_digest="")  # empty digest refused
    with pytest.raises(BadTLSError):
        ic.tls("not a host!!", 4, cert_digest="sha256:c")


def test_rewrite_supersede_chain():
    ic, _ = new_ic()
    ic.rule("web", "example.com", "/app", "svc:1", 1)
    w1 = ic.rewrite("web", r"^/app/(.*)$", r"/\1", 2)
    assert isinstance(w1, RewriteRecord)
    assert w1.supersedes == "" and w1.verify_digest()
    w2 = ic.rewrite("web", r"^/app/(.*)$", r"/v2/\1", 3)
    assert w2.supersedes == w1.rewrite_id
    assert ic.rewrite_for("web").rewrite_id == w2.rewrite_id


def test_rewrite_bad_pattern_and_unknown_rule():
    ic, _ = new_ic()
    ic.rule("web", "example.com", "/app", "svc:1", 1)
    with pytest.raises(BadRewriteError):
        ic.rewrite("web", r"([unclosed", "/x", 2)  # must compile
    with pytest.raises(BadRewriteError):
        ic.rewrite("web", "", "/x", 3)
    with pytest.raises(UnknownRuleError):
        ic.rewrite("ghost", r"^/a$", "/b", 4)


def test_match_longest_prefix_and_exact_wins():
    ic, _ = new_ic()
    ic.rule("root", "example.com", "/", "svc-root:80", 1)
    ic.rule("app", "example.com", "/app", "svc-app:80", 2)
    m = ic.match("example.com", "/app/users", 3)
    assert isinstance(m, MatchReport) and m.verify_digest()
    assert m.matched and m.rule_id == "app" and m.backend == "svc-app:80"
    ic.rule("exact", "example.com", "/app", "svc-exact:80", 4, path_type="exact")
    m2 = ic.match("example.com", "/app", 5)
    assert m2.rule_id == "exact"  # exact beats prefix
    m3 = ic.match("other.com", "/app", 6)
    assert not m3.matched and m3.rule_id == ""


def test_match_read_view_does_not_consume_seq():
    ic, events = new_ic()
    ic.rule("web", "example.com", "/a", "svc:1", 1)
    n = len(events)
    ic.match("example.com", "/a/x", 2)
    ic.match("example.com", "/a/x", 3)
    assert len(events) == n + 2  # audited-read only, no ledger writes
    assert ic.stats()["rules"] == 1


def test_match_tls_and_rewrite_flags():
    ic, _ = new_ic()
    ic.rule("web", "example.com", "/a", "svc:1", 1)
    m = ic.match("example.com", "/a/x", 2)
    assert not m.tls_present and not m.rewrite_present
    ic.tls("example.com", 3, cert_digest="sha256:a")
    ic.rewrite("web", r"^/a/(.*)$", r"/\1", 4)
    m2 = ic.match("example.com", "/a/x", 5)
    assert m2.tls_present and m2.rewrite_present


def test_remove_terminal_and_id_never_recycled():
    ic, _ = new_ic()
    ic.rule("web", "example.com", "/a", "svc:1", 1)
    ic.rewrite("web", r"^/a/(.*)$", r"/\1", 2)
    rm = ic.remove("web", 3, reason="decommissioned")
    assert isinstance(rm, RemovalRecord) and rm.verify_digest()
    assert ic.rewrite_for("web") is None  # rewrite died with its rule
    with pytest.raises(RemovedRuleError):
        ic.rule("web", "example.com", "/a", "svc:1", 4)  # id retired
    with pytest.raises(RemovedRuleError):
        ic.rule_record("web")
    m = ic.match("example.com", "/a/x", 5)
    assert not m.matched


def test_seq_order_and_failed_mutation_consumes_seq():
    ic, _ = new_ic()
    ic.rule("a", "example.com", "/a", "svc:1", 10)
    with pytest.raises(SeqOrderError):
        ic.rule("b", "example.com", "/b", "svc:2", 5)  # rewind
    with pytest.raises(SeqOrderError):
        ic.rule("b", "example.com", "/b", "svc:2", True)  # bool refused
    with pytest.raises(DuplicateRuleError):
        ic.rule("a", "example.com", "/a", "svc:1", 11)  # fails, consumes seq
    # seq 11 is now consumed: a rewind to 11 must fail.
    with pytest.raises(SeqOrderError):
        ic.rule("b", "example.com", "/b", "svc:2", 11)


def test_audit_event_shapes_and_banned_keys():
    ev = ingress_controller_audit_event("ingress.rule-defined", {"rule_id": "r"}, 1)
    assert ev["schema_version"] == "audit.ndjson/1"
    assert ev["module"] == "ingress-controller.v1"
    with pytest.raises(IngressControllerError):
        ingress_controller_audit_event("bogus-kind", {}, 2)
    with pytest.raises(IngressControllerError):
        ingress_controller_audit_event(
            "ingress.tls-bound", {"cert": "PEM..."}, 3
        )  # secret banned


def test_concurrency_smoke():
    ic, _ = new_ic()
    errors = []

    def worker(n):
        try:
            ic.rule(f"r{n}", f"h{n}.example.com", "/a", "svc:1", 1 + n)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert ic.stats()["rules"] == 8


def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, "-c", "import ingress_controller; ingress_controller.main()"],
        cwd=Path(__file__).resolve().parent.parent,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert "ingress-controller OK" in proc.stdout


def test_views_and_stats():
    ic, _ = new_ic()
    ic.rule("b", "b.example.com", "/", "svc-b:80", 1)
    ic.rule("a", "a.example.com", "/", "svc-a:80", 2)
    assert ic.rule_ids() == ["a", "b"]
    assert ic.stats() == {
        "rules": 2, "removed": 0, "tls_bindings": 0, "rewrites": 0, "seq": 2,
    }
    ic.remove("a", 3)
    assert ic.removed_ids() == ["a"]
    with pytest.raises(UnknownRuleError):
        ic.rule_record("ghost")

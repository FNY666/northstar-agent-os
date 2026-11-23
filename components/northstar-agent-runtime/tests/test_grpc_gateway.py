"""Tests for grpc_gateway: 15 cases."""

import ast
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import grpc_gateway
from grpc_gateway import (
    AUDIT_SCHEMA,
    GRPC_GATEWAY_SCHEMA,
    GRPC_GATEWAY_VERSION,
    GRPCGateway,
    GRPCGatewayError,
    AlreadyClosedError,
    BadServiceError,
    BadStreamError,
    BadTranscodeError,
    DuplicateServiceError,
    DuplicateStreamError,
    DuplicateTranscodeError,
    SeqOrderError,
    ServiceRecord,
    StreamSession,
    TranscodeRecord,
    UnknownServiceError,
    UnknownStreamError,
    UnknownTranscodeError,
    grpc_gateway_audit_event,
)


DIGEST = "sha256:" + "ab" * 32
OTHER_DIGEST = "sha256:" + "cd" * 32


def fresh():
    return GRPCGateway()


def registered(gateway, service_id="svc1", digest=DIGEST, seq=1):
    return gateway.service(service_id, digest, seq)


def bound(gateway, transcode_id="t1", service_id="svc1", seq=2,
          http_method="POST", http_path="/v1/things/{thing_id}",
          grpc_service="example.ThingService", grpc_method="CreateThing",
          streaming=None):
    return gateway.transcode(
        transcode_id, service_id, http_method, http_path, grpc_service,
        grpc_method, seq, streaming=streaming,
    )


# 1 ---------------------------------------------------------------------


def test_version_schema_pins():
    assert GRPC_GATEWAY_VERSION == "grpc-gateway.v1"
    assert GRPC_GATEWAY_SCHEMA == "northstar.grpc-gateway.v1"
    assert AUDIT_SCHEMA == "audit.ndjson/1"
    gateway = fresh()
    svc = registered(gateway)
    assert svc.verify()
    bind = bound(gateway)
    assert bind.verify()
    session = gateway.stream("s1", "t1", 3)
    assert session.verify()
    closed = gateway.close_stream("s1", 4)
    assert closed.verify()


# 2 ---------------------------------------------------------------------


def test_stdlib_only_ast():
    path = os.path.join(os.path.dirname(__file__), "..", "grpc_gateway.py")
    with open(path) as fh:
        tree = ast.parse(fh.read())
    allowed = {
        "hashlib", "threading", "dataclasses", "typing",
        "json", "canonical_json", "__future__", "ast",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


# 3 ---------------------------------------------------------------------


def test_main_runs():
    import subprocess
    path = os.path.join(os.path.dirname(__file__), "..", "grpc_gateway.py")
    out = subprocess.run(
        [sys.executable, path], capture_output=True, text=True, check=True,
    )
    assert "grpc-gateway OK" in out.stdout


# 4 ---------------------------------------------------------------------


def test_service_roundtrip_and_views():
    gateway = fresh()
    svc = registered(gateway)
    assert isinstance(svc, ServiceRecord)
    assert svc.service_id == "svc1"
    assert svc.proto_digest == DIGEST
    assert gateway.service_record("svc1") is svc
    assert gateway.service_ids() == ("svc1",)
    assert gateway.transcodes_for_service("svc1") == ()


# 5 ---------------------------------------------------------------------


def test_service_bad_inputs_and_duplicate():
    gateway = fresh()
    seq = [1]
    def bad_service(service_id, digest):
        seq[0] += 1
        try:
            gateway.service(service_id, digest, seq[0])
        except GRPCGatewayError:
            return True
        raise AssertionError(f"service accepted: {service_id!r}/{digest!r}")
    for bad in (None, "", "   ", 42):
        bad_service(bad, DIGEST)
    for bad_digest in (None, "", "sha256:short", "md5:" + "ab" * 32,
                       "sha256:" + "xy" * 32):
        try:
            seq[0] += 1
            gateway.service("svcX", bad_digest, seq[0])
        except BadServiceError:
            pass
        else:
            raise AssertionError(f"proto_digest accepted: {bad_digest!r}")
    registered(gateway, seq=seq[0] + 1)
    seq[0] += 1
    try:
        seq[0] += 1
        gateway.service("svc1", OTHER_DIGEST, seq[0])
    except DuplicateServiceError:
        pass
    else:
        raise AssertionError("duplicate service_id accepted")
    # failed mutations consumed their seqs: next valid seq must be fresh
    seq[0] += 1
    svc2 = registered(gateway, "svc2", OTHER_DIGEST, seq[0])
    assert svc2.verify()


# 6 ---------------------------------------------------------------------


def test_transcode_roundtrip_and_views():
    gateway = fresh()
    registered(gateway)
    bind = bound(gateway, streaming="server")
    assert isinstance(bind, TranscodeRecord)
    assert bind.streaming == "server"
    assert gateway.transcode_record("t1") is bind
    assert gateway.transcode_ids() == ("t1",)
    assert gateway.transcodes_for_service("svc1") == ("t1",)
    assert gateway.transcodes_for_service("nosuch") == ()


# 7 ---------------------------------------------------------------------


def test_transcode_bad_inputs():
    gateway = fresh()
    seq = [1]
    def next_seq():
        seq[0] += 1
        return seq[0]
    registered(gateway, seq=next_seq())
    # unknown service refused fail-closed
    try:
        bound(gateway, service_id="nosuch", seq=next_seq())
    except UnknownServiceError:
        pass
    else:
        raise AssertionError("unknown service accepted")
    # bad http methods
    for i, bad in enumerate((None, "get", "BREW", "", 42)):
        try:
            bound(gateway, transcode_id=f"t-m{i}", http_method=bad,
                  seq=next_seq())
        except BadTranscodeError:
            pass
        else:
            raise AssertionError(f"http_method accepted: {bad!r}")
    # bad http paths
    for i, bad in enumerate((None, "", "v1/things", "/v1//things",
                             "/v1/th ings", "/v1/{}/things", "http://x/v1")):
        try:
            bound(gateway, transcode_id=f"t-p{i}", http_path=bad,
                  seq=next_seq())
        except BadTranscodeError:
            pass
        else:
            raise AssertionError(f"http_path accepted: {bad!r}")
    # bad streaming shape
    try:
        bound(gateway, transcode_id="t-bads", streaming="half",
              seq=next_seq())
    except BadTranscodeError:
        pass
    else:
        raise AssertionError("bad streaming accepted")
    # duplicate transcode id
    bound(gateway, seq=next_seq())
    try:
        bound(gateway, seq=next_seq())
    except DuplicateTranscodeError:
        pass
    else:
        raise AssertionError("duplicate transcode_id accepted")


# 8 ---------------------------------------------------------------------


def test_stream_lifecycle():
    gateway = fresh()
    registered(gateway)
    bound(gateway)
    session = gateway.stream("s1", "t1", 3)
    assert isinstance(session, StreamSession)
    assert not session.closed
    assert session.verify()
    assert gateway.session("s1") is session
    assert gateway.session_ids() == ("s1",)
    assert gateway.sessions_for("t1") == ("s1",)
    assert gateway.sessions_for("nosuch") == ()
    closed = gateway.close_stream("s1", 4, "cancelled")
    assert closed.status == "cancelled"
    assert closed.verify()
    view = gateway.session("s1")
    assert view.closed
    assert view.verify()
    assert gateway.close_record("s1").status == "cancelled"
    assert gateway.stats()["open"] == 0
    assert gateway.stats()["closed"] == 1


# 9 ---------------------------------------------------------------------


def test_stream_bad_inputs_and_terminality():
    gateway = fresh()
    registered(gateway)
    bound(gateway)
    # unknown transcode binding refused
    try:
        gateway.stream("s1", "nosuch", 3)
    except UnknownTranscodeError:
        pass
    else:
        raise AssertionError("unknown transcode accepted")
    gateway.stream("s1", "t1", 4)
    # duplicate session id refused
    try:
        gateway.stream("s1", "t1", 5)
    except DuplicateStreamError:
        pass
    else:
        raise AssertionError("duplicate session accepted")
    # unknown session on close
    try:
        gateway.close_stream("nosuch", 6)
    except UnknownStreamError:
        pass
    else:
        raise AssertionError("close of unknown session accepted")
    # bad status refused
    try:
        gateway.close_stream("s1", 7, "mystery")
    except BadStreamError:
        pass
    else:
        raise AssertionError("bad status accepted")
    gateway.close_stream("s1", 8, "error")
    # double close refused (terminal)
    try:
        gateway.close_stream("s1", 9)
    except AlreadyClosedError:
        pass
    else:
        raise AssertionError("double close accepted")
    # close record lookup for unknown session
    try:
        gateway.close_record("nosuch")
    except UnknownStreamError:
        pass
    else:
        raise AssertionError("close_record of unknown session accepted")


# 10 --------------------------------------------------------------------


def test_seq_ordering_and_failed_mutation_consumes_seq():
    gateway = fresh()
    registered(gateway)
    bound(gateway)
    # rewind refused
    try:
        gateway.stream("s-rewind", "t1", 2)
    except SeqOrderError:
        pass
    else:
        raise AssertionError("seq rewind accepted")
    # bool refused
    try:
        gateway.stream("s-bool", "t1", True)
    except SeqOrderError:
        pass
    else:
        raise AssertionError("bool seq accepted")
    # failed mutation consumes its seq: use 3 for the refusal, 4 must work
    try:
        gateway.stream("s1", "nosuch", 3)
    except UnknownTranscodeError:
        pass
    session = gateway.stream("s1", "t1", 4)
    assert session.verify()


# 11 --------------------------------------------------------------------


def test_audit_shapes():
    gateway = fresh()
    registered(gateway)
    bound(gateway)
    gateway.stream("s1", "t1", 3)
    gateway.close_stream("s1", 4)
    kinds = [e["kind"] for e in gateway.audit_log()]
    assert kinds == [
        "grpc-gateway.service-registered",
        "grpc-gateway.transcode-bound",
        "grpc-gateway.stream-opened",
        "grpc-gateway.stream-closed",
    ]
    for event in gateway.audit_log():
        assert event["schema"] == "audit.ndjson/1"
        assert event["module"] == "grpc-gateway.v1"
        assert "request" not in event["detail"]
        assert "response" not in event["detail"]
        assert "body" not in event["detail"]
    # rejected audit rows are booked on failed mutations
    try:
        gateway.stream("s2", "nosuch", 5)
    except UnknownTranscodeError:
        pass
    assert gateway.audit_log()[-1]["kind"] == "grpc-gateway.rejected"
    assert gateway.audit_log()[-1]["detail"]["op"] == "stream"


# 12 --------------------------------------------------------------------


def test_audit_event_helper_and_banned_keys():
    event = grpc_gateway_audit_event(
        "grpc-gateway.service-registered",
        {"service_id": "svc1"}, 9,
    )
    assert event["schema"] == "audit.ndjson/1"
    assert event["detail"]["service_id"] == "svc1"
    try:
        grpc_gateway_audit_event("grpc-gateway.bogus", {}, 10)
    except GRPCGatewayError:
        pass
    else:
        raise AssertionError("bogus audit kind accepted")
    for banned in ("request", "response", "payload", "body",
                   "proto_bytes", "descriptor"):
        try:
            grpc_gateway_audit_event(
                "grpc-gateway.service-registered", {banned: "x"}, 11,
            )
        except GRPCGatewayError:
            pass
        else:
            raise AssertionError(f"banned key accepted: {banned!r}")


# 13 --------------------------------------------------------------------


def test_lookups_raise_for_unknown():
    gateway = fresh()
    for fn, exc in (
        (lambda: gateway.service_record("x"), UnknownServiceError),
        (lambda: gateway.transcode_record("x"), UnknownTranscodeError),
        (lambda: gateway.session("x"), UnknownStreamError),
    ):
        try:
            fn()
        except exc:
            pass
        else:
            raise AssertionError("unknown lookup did not raise")


# 14 --------------------------------------------------------------------


def test_stats_and_cross_instance_digest_determinism():
    first = fresh()
    registered(first)
    bind1 = bound(first)
    second = fresh()
    registered(second)
    bind2 = bound(second)
    assert bind1.digest == bind2.digest
    stats = first.stats()
    assert stats == {
        "services": 1, "transcodes": 1, "sessions": 0,
        "open": 0, "closed": 0,
    }
    first.stream("s1", "t1", 3)
    stats = first.stats()
    assert stats["sessions"] == 1
    assert stats["open"] == 1
    first.close_stream("s1", 4)
    stats = first.stats()
    assert stats["open"] == 0
    assert stats["closed"] == 1


# 15 --------------------------------------------------------------------


def test_concurrent_sessions_are_isolated():
    import threading
    gateway = fresh()
    registered(gateway)
    bound(gateway)
    errors = []

    def worker(n):
        try:
            base = 3 + n * 10
            sid = f"cs{n}"
            gateway.stream(sid, "t1", base)
            gateway.close_stream(sid, base + 1)
        except Exception as exc:  # pragma: no cover - fail loud
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert not errors
    assert gateway.stats()["sessions"] == 4
    assert gateway.stats()["closed"] == 4

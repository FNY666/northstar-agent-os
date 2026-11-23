"""Tests for webhook_delivery: Svix-shaped delivery attempts + signature verify."""

import base64
import hashlib
import hmac
import threading

import pytest

from webhook_delivery import (
    AUDIT_SCHEMA,
    DEFAULT_MAX_SKEW,
    MAX_ATTEMPTS,
    STATUSES,
    AlreadyDeliveredError,
    AttemptRecord,
    AuditKindError,
    BadAttemptError,
    BadEndpointError,
    BadMessageError,
    BadSignatureError,
    DuplicateMessageError,
    MaxAttemptsError,
    MessageRecord,
    SeqOrderError,
    UnknownAttemptError,
    UnknownMessageError,
    VerificationResult,
    WebhookDelivery,
    WebhookDeliveryError,
    WEBHOOK_DELIVERY_SCHEMA,
    WEBHOOK_DELIVERY_VERSION,
    main,
    webhook_delivery_audit_event,
    _stdlib_only_ok,
)

DIGEST_A = "sha256:" + "ab" * 32
DIGEST_B = "sha256:" + "cd" * 32
URL = "https://example.com/hook"


def _sig(content: str, secret: str) -> str:
    return base64.b64encode(
        hmac.new(secret.encode(), content.encode(), hashlib.sha256).digest()
    ).decode("ascii")


def test_version_and_schema_pins():
    assert WEBHOOK_DELIVERY_VERSION == "webhook-delivery.v1"
    assert WEBHOOK_DELIVERY_SCHEMA == "northstar.webhook-delivery.v1"
    assert AUDIT_SCHEMA == "audit.ndjson/1"
    assert MAX_ATTEMPTS == 5
    assert set(STATUSES) == {"delivered", "failed"}
    assert DEFAULT_MAX_SKEW == 300


def test_stdlib_only():
    assert _stdlib_only_ok()


def test_dispatch_roundtrip_and_record_verify():
    ledger = WebhookDelivery()
    rec = ledger.dispatch("m-1", DIGEST_A, 1)
    assert isinstance(rec, MessageRecord)
    assert rec.verify()
    assert ledger.message("m-1") == rec
    assert ledger.message_ids() == ["m-1"]


def test_dispatch_bad_inputs():
    ledger = WebhookDelivery()
    with pytest.raises(DuplicateMessageError):
        ledger.dispatch("m-1", DIGEST_A, 1)
        ledger.dispatch("m-1", DIGEST_A, 2)
    ledger2 = WebhookDelivery()
    with pytest.raises(BadMessageError):
        ledger2.dispatch("m-2", "not-a-digest", 1)
    with pytest.raises(BadMessageError):
        ledger2.dispatch("", DIGEST_A, 2)
    with pytest.raises(UnknownMessageError):
        ledger2.message("nope")


def test_send_happy_path():
    ledger = WebhookDelivery()
    ledger.dispatch("m-1", DIGEST_A, 1)
    att = ledger.send("m-1", URL, 2)
    assert isinstance(att, AttemptRecord)
    assert att.status == "delivered"
    assert att.attempt_no == 1
    assert att.backoff_seq == 1
    assert att.prev_attempt_id == ""
    assert att.verify()
    assert ledger.attempt(att.attempt_id) == att
    assert ledger.attempts_for("m-1") == [att]


def test_send_failure_is_data_and_raising_transporter():
    failer = WebhookDelivery(transporter=lambda u, d, n: False)
    failer.dispatch("m-1", DIGEST_A, 1)
    att = failer.send("m-1", URL, 2)
    assert att.status == "failed"

    def boom(u, d, n):
        raise RuntimeError("network down")

    raiser = WebhookDelivery(transporter=boom)
    raiser.dispatch("m-1", DIGEST_A, 1)
    att2 = raiser.send("m-1", URL, 2)
    assert att2.status == "failed"  # raising counts as failure, fail-closed


def test_send_bad_inputs():
    ledger = WebhookDelivery()
    ledger.dispatch("m-1", DIGEST_A, 1)
    with pytest.raises(UnknownMessageError):
        ledger.send("ghost", URL, 2)  # failed mutation consumes seq 2
    with pytest.raises(BadEndpointError):
        ledger.send("m-1", "http://insecure.example/hook", 3)
    with pytest.raises(BadAttemptError):
        ledger.send("m-1", URL, 4)
        ledger.send("m-1", URL, 5)  # chain already started; use retry()
    with pytest.raises(UnknownAttemptError):
        ledger.attempt("att-999")


def test_retry_chain_linkage_and_backoff():
    flaky = WebhookDelivery(transporter=lambda u, d, n: n >= 3)
    flaky.dispatch("m-1", DIGEST_A, 1)
    a1 = flaky.send("m-1", URL, 2)
    assert a1.status == "failed"
    a2 = flaky.retry(a1.attempt_id, 3)
    assert a2.prev_attempt_id == a1.attempt_id
    assert a2.attempt_no == 2
    assert a2.backoff_seq == 2  # 2 ** (2-1)
    assert a2.status == "failed"
    a3 = flaky.retry(a2.attempt_id, 4)
    assert a3.attempt_no == 3
    assert a3.backoff_seq == 4  # 2 ** (3-1)
    assert a3.status == "delivered"
    with pytest.raises(AlreadyDeliveredError):
        flaky.retry(a3.attempt_id, 5)
    with pytest.raises(BadAttemptError):
        flaky.retry(a1.attempt_id, 6)  # not the chain head


def test_retry_max_attempts():
    never = WebhookDelivery(transporter=lambda u, d, n: False)
    never.dispatch("m-1", DIGEST_A, 1)
    att = never.send("m-1", URL, 2)
    for i in range(2, MAX_ATTEMPTS + 1):
        att = never.retry(att.attempt_id, i + 1)
        assert att.attempt_no == i
    with pytest.raises(MaxAttemptsError):
        never.retry(att.attempt_id, MAX_ATTEMPTS + 2)


def test_verify_ok_mismatch_and_stale():
    ledger = WebhookDelivery()
    content = "m-1.100.payload"
    good = f"v1,{_sig(content, 's3cr3t')}"
    ok = ledger.verify(content, good, "s3cr3t", 100, 100)
    assert isinstance(ok, VerificationResult)
    assert ok.valid and ok.reason == "ok" and ok.verify()

    multi = f"v1,{'A' * 44} {good}"
    assert ledger.verify(content, multi, "s3cr3t", 100, 100).valid

    bad = ledger.verify(content, "v1," + "A" * 44, "s3cr3t", 100, 100)
    assert not bad.valid and bad.reason == "signature-mismatch"
    assert bad.verify()

    stale = ledger.verify(content, good, "s3cr3t", 1000, 100)
    assert not stale.valid and stale.reason == "stale"

    wrong_secret = ledger.verify(content, good, "other", 100, 100)
    assert not wrong_secret.valid


def test_verify_malformed_inputs_raise():
    ledger = WebhookDelivery()
    with pytest.raises(BadSignatureError):
        ledger.verify("", "v1,abc", "s", 1, 1)
    with pytest.raises(BadSignatureError):
        ledger.verify("c", "   ", "s", 1, 1)
    with pytest.raises(BadSignatureError):
        ledger.verify("c", "v1,abc", "", 1, 1)
    with pytest.raises(BadSignatureError):
        ledger.verify("c", "v1,abc", "s", 1, 1, max_skew=-1)
    with pytest.raises(SeqOrderError):
        ledger.verify("c", "v1,abc", "s", True, 1)


def test_verify_is_pure_view():
    ledger = WebhookDelivery()
    ledger.dispatch("m-1", DIGEST_A, 1)
    before = ledger.stats()["audit_events"]
    ledger.verify("c", "v1,abc", "s", 50, 50)
    assert ledger.stats()["audit_events"] == before  # no audit row
    assert ledger._seq == 1  # seq shape validated, not consumed


def test_seq_ordering_and_failed_mutation_consumes_seq():
    ledger = WebhookDelivery()
    ledger.dispatch("m-1", DIGEST_A, 1)
    with pytest.raises(SeqOrderError):
        ledger.dispatch("m-2", DIGEST_A, 1)  # rewind
    with pytest.raises(SeqOrderError):
        ledger.dispatch("m-2", DIGEST_A, True)  # bool refused
    with pytest.raises(SeqOrderError):
        ledger.dispatch("m-2", DIGEST_A, "3")  # non-int refused
    with pytest.raises(BadMessageError):
        ledger.dispatch("", DIGEST_A, 2)  # failed mutation consumes seq
    with pytest.raises(SeqOrderError):
        ledger.dispatch("m-2", DIGEST_A, 2)  # seq 2 already burned


def test_audit_shapes_and_banned_keys():
    ledger = WebhookDelivery()
    ledger.dispatch("m-1", DIGEST_A, 1)
    att = ledger.send("m-1", URL, 2)
    kinds = {e["kind"] for e in ledger.audit_log()}
    assert "webhook-delivery.dispatched" in kinds
    assert "webhook-delivery.attempted" in kinds
    for event in ledger.audit_log():
        assert event["schema"] == "audit.ndjson/1"
        banned = {"secret", "payload", "payload_digest", "signature",
                  "signature_header", "signed_content"}
        assert not (banned & set(event["detail"]))
    assert att.attempt_id in {e["detail"].get("attempt_id")
                             for e in ledger.audit_log()
                             if e["kind"] == "webhook-delivery.attempted"}
    with pytest.raises(AuditKindError):
        webhook_delivery_audit_event("bogus.kind", {}, 9)
    with pytest.raises(WebhookDeliveryError):
        webhook_delivery_audit_event(
            "webhook-delivery.dispatched", {"secret": "x"}, 9
        )


def test_views_and_concurrency():
    ledger = WebhookDelivery()
    ledger.dispatch("m-1", DIGEST_A, 1)
    ledger.send("m-1", URL, 2)
    snap = ledger.as_dict()
    assert snap["schema"] == "northstar.webhook-delivery.v1"
    assert snap["messages"][0]["message_id"] == "m-1"
    stats = ledger.stats()
    assert stats["messages"] == 1 and stats["attempts"] == 1
    assert stats["delivered"] == 1 and stats["failed"] == 0

    def worker(n):
        ledger2 = WebhookDelivery()
        ledger2.dispatch(f"c-{n}", DIGEST_A, 1)
        ledger2.send(f"c-{n}", URL, 2)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


def test_main():
    main()

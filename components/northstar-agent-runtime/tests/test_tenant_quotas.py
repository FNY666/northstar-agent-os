"""Tests for tenant_quotas: 15 cases."""

import ast
import os
import sys
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import tenant_quotas
from tenant_quotas import (
    TENANT_QUOTAS_VERSION,
    TENANT_QUOTAS_SCHEMA,
    AUDIT_SCHEMA,
    RESOURCES,
    TenantQuotas,
    TenantQuotasError,
    BadQuotaError,
    UnknownQuotaError,
    BadConsumptionError,
    SeqOrderError,
    tenant_quotas_audit_event,
)


def make():
    return TenantQuotas()


class TestPins:
    def test_version_pins(self):
        assert TENANT_QUOTAS_VERSION == "tenant-quotas.v1"
        assert TENANT_QUOTAS_SCHEMA == "northstar.tenant-quotas.v1"
        assert AUDIT_SCHEMA == "audit.ndjson/1"

    def test_resource_vocabulary(self):
        assert len(RESOURCES) == 8
        assert "api_calls" in RESOURCES and "tokens" in RESOURCES

    def test_stdlib_only(self):
        tree = ast.parse(open(tenant_quotas.__file__).read())
        allowed = {
            "hashlib", "threading", "dataclasses", "typing", "json",
            "__future__", "canonical_json",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    assert a.name.split(".")[0] in allowed, a.name
            elif isinstance(node, ast.ImportFrom):
                assert node.module.split(".")[0] in allowed, node.module


class TestSet:
    def test_set_roundtrip(self):
        q = make()
        rec = q.set("acme", "api_calls", 1, 100)
        assert rec.tenant_id == "acme" and rec.limit == 100
        assert rec.verify()

    def test_set_upsert_keeps_usage(self):
        q = make()
        q.set("acme", "api_calls", 1, 100)
        q.check("acme", "api_calls", 30, 2)
        rec = q.set("acme", "api_calls", 3, 200)
        assert rec.limit == 200 and rec.used == 30
        assert rec.verify()

    def test_set_bad_inputs(self):
        q = make()
        for bad, err in [
            (lambda: q.set("", "api_calls", 1, 100), TenantQuotasError),
            (lambda: q.set("a", "nope", 1, 100), BadQuotaError),
            (lambda: q.set("a", "api_calls", 1, 0), BadQuotaError),
            (lambda: q.set("a", "api_calls", 1, -5), BadQuotaError),
            (lambda: q.set("a", "api_calls", 1, True), BadQuotaError),
        ]:
            try:
                bad()
            except err:
                pass
            else:
                raise AssertionError(f"expected {err} for {bad}")
        # failed mutations consume their seqs: 5 consumed, next must be 6
        rec = q.set("acme", "api_calls", 6, 10)
        assert rec.verify()


class TestCheck:
    def test_check_allowed_and_exceeded(self):
        q = make()
        q.set("acme", "api_calls", 1, 100)
        d1 = q.check("acme", "api_calls", 99, 2)
        assert d1.allowed and d1.used_after == 99 and d1.verify()
        d2 = q.check("acme", "api_calls", 2, 3)   # 99+2 > 100
        assert not d2.allowed
        assert d2.reason == "quota-exceeded" and d2.used_after == 99
        assert q.usage_of("acme", "api_calls") == 99  # usage untouched

    def test_check_unknown_quota_is_data(self):
        q = make()
        d = q.check("ghost", "api_calls", 1, 1)
        assert not d.allowed and d.reason == "unknown-quota" and d.verify()

    def test_check_bad_amount(self):
        q = make()
        q.set("acme", "api_calls", 1, 100)
        for amt in (0, -1, True, "5", 1.5):
            try:
                q.check("acme", "api_calls", amt, 2)
            except BadConsumptionError:
                pass
            else:
                raise AssertionError(f"amount {amt!r} must be refused")


class TestReset:
    def test_reset_zeroes_usage(self):
        q = make()
        q.set("acme", "api_calls", 1, 100)
        q.check("acme", "api_calls", 40, 2)
        r = q.reset("acme", "api_calls", 3)
        assert r.verify() and r.used_before == 40
        assert q.usage_of("acme", "api_calls") == 0
        assert q.remaining_of("acme", "api_calls") == 100

    def test_reset_unknown_quota(self):
        q = make()
        try:
            q.reset("ghost", "api_calls", 1)
        except UnknownQuotaError:
            pass
        else:
            raise AssertionError("unknown quota reset must raise")
        kinds = [e["kind"] for e in q.audit_log()]
        assert "tenant-quota.rejected" in kinds


class TestSeq:
    def test_seq_order_enforced(self):
        q = make()
        q.set("acme", "api_calls", 1, 100)
        try:
            q.check("acme", "api_calls", 1, 1)   # rewind
        except SeqOrderError:
            pass
        else:
            raise AssertionError("seq rewind must raise")
        try:
            q.set("acme", "api_calls", True, 100)   # bool seq
        except SeqOrderError:
            pass
        else:
            raise AssertionError("bool seq must raise")


class TestAuditAndConcurrency:
    def test_audit_shapes(self):
        q = make()
        q.set("acme", "api_calls", 1, 100)
        q.check("acme", "api_calls", 10, 2)
        q.reset("acme", "api_calls", 3)
        kinds = [e["kind"] for e in q.audit_log()]
        assert kinds == [
            "tenant-quota.set",
            "tenant-quota.checked",
            "tenant-quota.reset",
        ]
        for e in q.audit_log():
            assert e["schema"] == AUDIT_SCHEMA
            assert e["module"] == TENANT_QUOTAS_VERSION
        try:
            tenant_quotas_audit_event("nope", {}, 4)
        except TenantQuotasError:
            pass
        else:
            raise AssertionError("unknown audit kind must raise")

    def test_thread_smoke(self):
        q = make()
        q.set("acme", "api_calls", 1, 10_000)
        errors = []

        def worker(n):
            try:
                for i in range(50):
                    q.check("acme", "api_calls", 1, 2 + n * 50 + i)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors
        assert q.usage_of("acme", "api_calls") == 200

    def test_main(self):
        tenant_quotas.main()

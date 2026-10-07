"""Tests for data_export: 15 cases."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import json

import pytest

from data_export import (
    DataExport,
    ExportParams,
    DownloadParams,
    Decision,
)


def make_exporter(audit_log, allowed=("user-1",), data=None):
    def can_export(subject_id, scopes):
        if subject_id in allowed:
            return True, "ok"
        return False, "not permitted"

    def source(subject_id, scopes):
        return {s: {"subject": subject_id, "items": [s]} for s in scopes}

    if data is not None:
        source_fn = lambda subject_id, scopes: data  # noqa: E731
    else:
        source_fn = source

    return DataExport(
        subject_can_export=can_export,
        data_source=source_fn,
        audit_sink=lambda e: audit_log.append(e),
    )


def valid_params(**kw):
    base = dict(
        subject_id="user-1",
        scopes=("profile", "sessions"),
        format="json",
        requested_at_seq=10,
        download_ttl_seq=1_000,
        nonce="n1",
    )
    base.update(kw)
    return ExportParams(**base)


def request_ready(audit_log, **kw):
    exporter = make_exporter(audit_log)
    dec = exporter.request(valid_params(**kw))
    assert dec.allowed, dec.reason
    return exporter, dec.payload["record"]["export_id"]


# 1. happy path: request yields a ready record with a sealed audit event
def test_request_happy_path():
    audit = []
    exporter = make_exporter(audit)
    dec = exporter.request(valid_params())
    assert dec.allowed and dec.reason == "ready"
    rec = dec.payload["record"]
    assert rec["subject_id"] == "user-1"
    assert rec["state"] == "ready"
    assert rec["checksum"]
    assert any(e["event"]["action"] == "request" for e in audit)


# 2. unauthorized subject is denied
def test_request_unauthorized_subject():
    audit = []
    exporter = make_exporter(audit, allowed=("user-9",))
    dec = exporter.request(valid_params())
    assert not dec.allowed and "not authorized" in dec.reason


# 3. blank subject_id is rejected
def test_request_blank_subject():
    exporter = make_exporter([])
    dec = exporter.request(valid_params(subject_id="  "))
    assert not dec.allowed and "subject_id required" in dec.reason


# 4. unknown format is rejected
def test_request_unknown_format():
    exporter = make_exporter([])
    dec = exporter.request(valid_params(format="csv"))
    assert not dec.allowed and "unknown format" in dec.reason


# 5. unsupported scope is rejected
def test_request_unsupported_scope():
    exporter = make_exporter([])
    dec = exporter.request(valid_params(scopes=("profile", "nope")))
    assert not dec.allowed and "unsupported scope" in dec.reason


# 6. duplicate active export for the same subject is denied (fail-closed)
def test_request_duplicate_active_denied():
    audit = []
    exporter, _ = request_ready(audit)
    dec = exporter.request(valid_params(nonce="n2"))
    assert not dec.allowed and "already exists" in dec.reason


# 7. data_source missing a scope is denied
def test_request_data_source_missing_scope():
    exporter = make_exporter([], data={"profile": {"items": []}})
    dec = exporter.request(valid_params())
    assert not dec.allowed and "missing scopes" in dec.reason


# 8. download happy path: package is delivered once, then rejected
def test_download_happy_path_and_single_delivery():
    audit = []
    exporter, export_id = request_ready(audit)
    dec = exporter.download(export_id, DownloadParams(subject_id="user-1", now_seq=20))
    assert dec.allowed and dec.reason == "delivered"
    assert dec.payload["checksum"]
    payload = json.loads(dec.payload["package"])
    assert payload["subject_id"] == "user-1"
    assert any(e["event"]["action"] == "download" for e in audit)
    again = exporter.download(export_id, DownloadParams(subject_id="user-1", now_seq=21))
    assert not again.allowed and "already delivered" in again.reason


# 9. download with subject mismatch is denied and audited
def test_download_subject_mismatch():
    audit = []
    exporter, export_id = request_ready(audit)
    dec = exporter.download(export_id, DownloadParams(subject_id="user-2", now_seq=20))
    assert not dec.allowed and "subject mismatch" in dec.reason
    assert any(e["event"]["action"] == "download-denied" for e in audit)


# 10. download of unknown export is denied
def test_download_unknown_export():
    exporter = make_exporter([])
    dec = exporter.download("exp-nope", DownloadParams(subject_id="user-1", now_seq=0))
    assert not dec.allowed and "unknown export" in dec.reason


# 11. download after TTL marks the export expired
def test_download_after_expiry():
    audit = []
    exporter, export_id = request_ready(audit, download_ttl_seq=5)
    dec = exporter.download(export_id, DownloadParams(subject_id="user-1", now_seq=100))
    assert not dec.allowed and "expired" in dec.reason
    st = exporter.status(export_id, 100)
    assert st.payload["record"]["state"] == "expired"


# 12. status of unknown export is denied
def test_status_unknown_export():
    exporter = make_exporter([])
    dec = exporter.status("exp-nope", 0)
    assert not dec.allowed and "unknown export" in dec.reason


# 13. status reports state and applies expiry
def test_status_reports_state():
    exporter, export_id = request_ready([])
    dec = exporter.status(export_id, 20)
    assert dec.allowed
    assert dec.payload["record"]["state"] == "ready"
    assert dec.payload["record"]["scopes"] == ("profile", "sessions")


# 14. jsonl format emits one header line plus one line per scope
def test_jsonl_format_package():
    audit = []
    exporter, export_id = request_ready(audit, format="jsonl")
    dec = exporter.download(export_id, DownloadParams(subject_id="user-1", now_seq=20))
    assert dec.allowed and dec.payload["format"] == "jsonl"
    lines = dec.payload["package"].split("\n")
    assert len(lines) == 1 + 2
    header = json.loads(lines[0])
    assert header["export_id"] == export_id
    assert json.loads(lines[1])["scope"] == "profile"


# 15. tampered package fails the integrity check
def test_download_integrity_failure():
    audit = []
    exporter, export_id = request_ready(audit)
    exporter._packages[export_id] = exporter._packages[export_id] + "!"
    dec = exporter.download(export_id, DownloadParams(subject_id="user-1", now_seq=20))
    assert not dec.allowed and "integrity check failed" in dec.reason

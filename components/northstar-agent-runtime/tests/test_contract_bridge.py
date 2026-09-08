"""The run contract must be the authority on the runtime → sidecar boundary.

These tests pin the three things that keep the seam from drifting apart again:
one request-id rule, one field set shared with the sidecar and the contract
adapter, and a cross-check that refuses to execute when a host binding cannot be
verified against what the runtime is about to send.
"""
from __future__ import annotations

import json
import os
import time
import unittest
from pathlib import Path

import support  # noqa: F401  (bootstraps sys.path)
from support import CONTRACT_DIR, load_contract, load_sidecar

import contract_bridge
from contract_bridge import (
    BridgeError,
    WIRE_FIELDS,
    binding_from_environment,
    build_request,
    cross_check,
    derive_request_id,
    run_document_from_environment,
)
from sidecar_client import REQUEST_FIELDS, SidecarClient, validate_request

_ENV_KEYS = ("NORTHSTAR_RUN_BINDING", "NORTHSTAR_HOST_KEY", "NORTHSTAR_RUN_REQUEST")


def _clean_env(case: unittest.TestCase):
    """Remove the host seam for the duration of one test."""
    saved = {key: os.environ.pop(key, None) for key in _ENV_KEYS}

    def restore() -> None:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    case.addCleanup(restore)


class RequestIdTests(unittest.TestCase):
    def test_generated_id_keeps_the_legacy_shape(self):
        value = derive_request_id(None)
        self.assertTrue(value.startswith("nsar-"))
        self.assertEqual(len(value.split("-")), 2)

    def test_a_supplied_run_id_is_used_verbatim(self):
        self.assertEqual(derive_request_id("run-7"), "run-7")

    def test_an_empty_id_means_unset_not_invalid(self):
        # The CLI only sets run_id when the flag carried a value, but a host
        # calling the API directly may pass "": that means "generate", same as None.
        self.assertTrue(derive_request_id("").startswith("nsar-"))

    def test_the_contract_id_rule_is_enforced(self):
        for bad in ("   ", "has space", "a/b", "a\\b", "x" * 129):
            with self.subTest(value=bad):
                with self.assertRaises(BridgeError):
                    derive_request_id(bad)

    def test_build_request_emits_exactly_the_wire_fields(self):
        request = build_request("go", run_id="run-7", timeout_ms=5_000)
        self.assertEqual(set(request), set(WIRE_FIELDS))
        self.assertTrue(validate_request(request).ok)


class ThreeWayAgreementTests(unittest.TestCase):
    """runtime ↔ run contract ↔ sidecar must agree on the boundary, or fail here."""

    def test_the_runtime_and_the_bridge_share_one_field_set(self):
        self.assertIs(REQUEST_FIELDS, WIRE_FIELDS)

    def test_the_contract_adapter_produces_exactly_these_fields(self):
        adapter = load_contract("adapter")
        contract = load_contract("contract")
        now = int(time.time())
        run = {
            "schema_version": contract.SCHEMA_VERSION,
            "run_id": "run-1",
            "actor_id": "actor-1",
            "workspace_id": "ws-1",
            "task_kind": "review",
            "prompt": "summarise",
            "timeout_ms": 5_000,
            "requested_capabilities": [],
        }
        binding_module = load_contract("binding")
        secret = b"k" * 32
        token = binding_module.sign_binding(
            {
                "schema_version": contract.SCHEMA_VERSION,
                "run_id": "run-1",
                "actor_id": "actor-1",
                "workspace_id": "ws-1",
                "expires_at": now + 600,
            },
            secret,
        )
        verified = binding_module.verify_binding(token, secret, now=now)
        self.assertTrue(verified.ok, verified.errors)
        produced = adapter.to_sidecar_request(run, verified)
        self.assertEqual(set(produced), set(WIRE_FIELDS))
        self.assertEqual(produced["request_id"], run["run_id"])

    def test_the_sidecar_accepts_it_and_refuses_a_fourth_field(self):
        sidecar = load_sidecar("sidecar")
        request = build_request("go", run_id="run-9", timeout_ms=5_000)
        self.assertTrue(sidecar.classify_request(request).ok)
        extra = dict(request, capabilities=["shell"])
        self.assertFalse(sidecar.classify_request(extra).ok)
        self.assertFalse(validate_request(extra).ok, "the runtime must reject it too, not just the sidecar")


class CrossCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        _clean_env(self)
        self.root = Path(support.tempfile.mkdtemp(prefix="nsar-bridge-"))
        self.addCleanup(support.shutil.rmtree, self.root, True)
        self.secret = b"s" * 32
        self.contract = load_contract("contract")
        self.binding_module = load_contract("binding")

    def _run_document(self, *, prompt: str = "go", run_id: str = "run-1") -> dict:
        return {
            "schema_version": self.contract.SCHEMA_VERSION,
            "run_id": run_id,
            "actor_id": "actor-1",
            "workspace_id": "ws-1",
            "task_kind": "review",
            "prompt": prompt,
            "timeout_ms": 5_000,
            "requested_capabilities": [],
        }

    def _mint(self, run: dict, *, expires_in: int = 600) -> str:
        return self.binding_module.sign_binding(
            {
                "schema_version": run["schema_version"],
                "run_id": run["run_id"],
                "actor_id": run["actor_id"],
                "workspace_id": run["workspace_id"],
                "expires_at": int(time.time()) + expires_in,
            },
            self.secret,
        )

    def _install(self, run: dict, *, expires_in: int = 600) -> None:
        os.environ["NORTHSTAR_RUN_BINDING"] = self._mint(run, expires_in=expires_in)
        os.environ["NORTHSTAR_HOST_KEY"] = self.secret.hex()
        path = self.root / "run.json"
        path.write_text(json.dumps(run), encoding="utf-8")
        os.environ["NORTHSTAR_RUN_REQUEST"] = str(path)

    def test_without_a_host_binding_the_bridge_is_inert(self):
        report = cross_check(build_request("go", run_id="run-1", timeout_ms=5_000))
        self.assertEqual((report.mode, report.ok), ("unchecked", True))
        self.assertIsNone(binding_from_environment())

    def test_a_verified_run_cross_checks(self):
        run = self._run_document()
        self._install(run)
        report = cross_check(build_request("go", run_id="run-1", timeout_ms=5_000))
        self.assertTrue(report.ok, report.errors)
        self.assertEqual(report.mode, "contract-verified")
        self.assertEqual(report.detail["run_id"], "run-1")

    def test_a_prompt_that_is_not_the_authorized_one_is_refused(self):
        run = self._run_document(prompt="go")
        self._install(run)
        report = cross_check(build_request("rm -rf /", run_id="run-1", timeout_ms=5_000))
        self.assertFalse(report.ok)
        self.assertIn("prompt", report.errors[0])

    def test_a_run_id_that_is_not_the_bound_one_is_refused(self):
        run = self._run_document()
        self._install(run)
        report = cross_check(build_request("go", run_id="run-OTHER", timeout_ms=5_000))
        self.assertFalse(report.ok)

    def test_an_expired_binding_is_refused(self):
        run = self._run_document()
        self._install(run, expires_in=-1)
        report = cross_check(build_request("go", run_id="run-1", timeout_ms=5_000))
        self.assertFalse(report.ok)
        self.assertIn("binding", report.errors[0])

    def test_a_binding_without_the_contract_fails_closed(self):
        os.environ["NORTHSTAR_RUN_BINDING"] = "x.y"
        os.environ["NORTHSTAR_HOST_KEY"] = self.secret.hex()
        original = contract_bridge.contract_available
        contract_bridge.contract_available = lambda: False  # type: ignore[assignment]
        self.addCleanup(setattr, contract_bridge, "contract_available", original)
        report = cross_check(build_request("go", run_id="run-1", timeout_ms=5_000))
        self.assertFalse(report.ok)
        self.assertEqual(report.mode, "unavailable")
        self.assertIn("refusing an unverifiable run", report.errors[0])

    def test_a_symlinked_run_document_is_refused(self):
        run = self._run_document()
        target = self.root / "elsewhere.json"
        target.write_text(json.dumps(run), encoding="utf-8")
        link = self.root / "run-link.json"
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):  # pragma: no cover - host policy
            self.skipTest("symlinks are unavailable here")
        os.environ["NORTHSTAR_RUN_REQUEST"] = str(link)
        with self.assertRaises(BridgeError):
            run_document_from_environment()

    def test_unknown_request_field_is_refused_before_anything_else(self):
        report = cross_check({"request_id": "r", "prompt": "go", "timeout_ms": 5, "extra": 1})
        self.assertFalse(report.ok)


class ClientIntegrationTests(unittest.TestCase):
    """The client must not put a byte on the socket for an unverifiable run."""

    def setUp(self) -> None:
        _clean_env(self)

    def test_run_id_becomes_the_request_id(self):
        class FakeTransport:
            def __init__(self) -> None:
                self.sent: list[bytes] = []

            def connect(self, path, timeout):  # noqa: ANN001 - test double
                return self

            def sendall(self, payload: bytes) -> None:
                self.sent.append(payload)

            def makefile(self, *a, **k):  # noqa: ANN001, ANN002 - unused seam
                raise AssertionError("unused")

            def close(self) -> None:
                self.closed = True

        root = Path(support.tempfile.mkdtemp(prefix="nsar-bridge-"))
        self.addCleanup(support.shutil.rmtree, root, True)
        socket_path = root / "sidecar.sock"
        socket_path.write_text("", encoding="utf-8")  # only needs to exist for validation
        client = SidecarClient(socket_path, transport=FakeTransport(), run_id="run-42")
        self.assertEqual(client.new_request_id(), "run-42")
        self.assertTrue(validate_request({"request_id": client.new_request_id(), "prompt": "p", "timeout_ms": 1000}).ok)

    def test_a_bad_run_id_is_reported_as_a_rejection_not_a_crash(self):
        client = SidecarClient("/tmp/absent-sidecar.sock", run_id="has space", require_canonical_name=False)
        result = client.execute("go")
        self.assertEqual(result.status, "rejected")
        self.assertIn("no whitespace", result.errors[0])

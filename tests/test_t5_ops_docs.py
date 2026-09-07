"""T5 ops documentation must stay honest and pinned to real code.

Three properties are enforced here:

1. **Status is never overstated.** Each T5 doc must say in its header what it
   is (specification / story) and what it is not (not implemented, not run
   against a real host). No CI-runnable claim may creep in.
2. **The curated anchors stay.** The scorecard's ops probes and the living
   assessments depend on a handful of symbols; the pairs below pin both the
   doc mention *and* the symbol's existence in the cited module.
3. **Every qualified reference resolves.** Where a doc writes
   `file.py::symbol`, the file must exist under `components/` and the symbol
   must exist in it. A doc that cites a renamed or invented symbol fails
   loudly.
"""
import py_compile
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPONENTS = ROOT / "components"
CONCEPTS = ROOT / "docs" / "concepts"
GUIDES = ROOT / "docs" / "guides"

DOCS = {
    "transport": CONCEPTS / "northstar-remote-transport.md",
    "identity": CONCEPTS / "northstar-remote-identity.md",
}

SYMBOL_TOKEN = re.compile(r"`([A-Za-z_][A-Za-z0-9_]*\.py)::([A-Za-z_][A-Za-z0-9_]*)`")


def _norm(text: str) -> str:
    text = re.sub(r"(?m)^\s*>\s?", "", text)  # strip blockquote markers
    return re.sub(r"\s+", " ", text)


def _find_module(name: str) -> Path | None:
    for directory in COMPONENTS.iterdir():
        if directory.is_dir():
            candidate = directory / name
            if candidate.is_file():
                return candidate
    return None


def _module_has_symbol(module: Path, symbol: str) -> bool:
    text = module.read_text(encoding="utf-8", errors="replace")
    return bool(
        re.search(rf"^(?:class|def) {re.escape(symbol)}\b", text, re.MULTILINE)
    ) or bool(re.search(rf"^{re.escape(symbol)}\s*=", text, re.MULTILINE))


class T5DocStatusTests(unittest.TestCase):
    def test_docs_exist(self):
        for name, path in DOCS.items():
            with self.subTest(doc=name):
                self.assertTrue(path.is_file(), f"{name} doc missing: {path}")

    def test_transport_doc_declares_itself_a_specification(self):
        text = _norm(DOCS["transport"].read_text(encoding="utf-8"))
        for marker in ("Status: specification only", "No transport code ships",
                       "a spec is not", "has ever run against a real host"):
            with self.subTest(marker=marker):
                self.assertIn(marker, text)

    def test_identity_doc_declares_itself_a_story(self):
        text = _norm(DOCS["identity"].read_text(encoding="utf-8"))
        for marker in ("Status: a story, not a system", "No new credential code",
                       "no PKI", "revocation mechanism", "not a system"):
            with self.subTest(marker=marker):
                self.assertIn(marker, text)

    def test_docs_cite_only_existing_modules_and_symbols(self):
        for name, path in DOCS.items():
            text = path.read_text(encoding="utf-8")
            for module_name, symbol in SYMBOL_TOKEN.findall(text):
                module = _find_module(module_name)
                with self.subTest(doc=name, token=f"{module_name}::{symbol}"):
                    self.assertIsNotNone(module, f"module {module_name!r} not found")
                    assert module is not None
                    self.assertTrue(
                        _module_has_symbol(module, symbol),
                        f"{module_name} has no symbol {symbol!r}",
                    )


class T5AnchorTests(unittest.TestCase):
    """Curated (module, symbol) anchors the ops docs depend on.

    Each entry must be *mentioned* in the doc and must *exist* in the real
    module - so a doc that hand-waves a symbol that was renamed fails.
    """

    TRANSPORT_ANCHORS = (
        ("sidecar_socket.py", "read_json_line"),
        ("sidecar_socket.py", "handle_line"),
        ("sidecar_socket.py", "serve"),
        ("sidecar_socket.py", "SOCKET_PATH"),
        ("sidecar_socket.py", "CONNECTION_READ_TIMEOUT"),
        ("sidecar_socket.py", "socket_mode"),
        ("contract.py", "make_receipt"),
        ("contract.py", "RECEIPT_SCHEMA_VERSION"),
        ("contract.py", "MAX_TIMEOUT_MS"),
        ("binding.py", "sign_binding"),
        ("binding.py", "verify_binding"),
        ("authorization.py", "authorize_run"),
        ("authorization.py", "sign_authorization"),
        ("authorization.py", "verify_authorization"),
        ("sidecar.py", "run_one"),
        ("sidecar.py", "_terminate_process_tree"),
        ("runner.py", "DurableRunner"),
        ("runner.py", "LeaseManager"),
        ("event_store.py", "EventStore"),
        ("verifier.py", "verify_run_completion"),
        ("verifier.py", "make_final_receipt"),
    )

    IDENTITY_ANCHORS = (
        ("binding.py", "sign_binding"),
        ("binding.py", "verify_binding"),
        ("authorization.py", "authorize_run"),
        ("authorization.py", "sign_authorization"),
        ("authorization.py", "verify_authorization"),
        ("handoff.py", "authorize_handoff"),
        ("handoff.py", "sign_attestation"),
        ("handoff.py", "verify_attestation"),
        ("handoff.py", "verify_handoff_grant"),
        ("action_gateway.py", "sign_approval"),
        ("host_audit.py", "authorization_to_audit"),
        ("interop_contract.py", "GRANT_SCHEMA_VERSION"),
        ("interop_contract.py", "ATTESTATION_SCHEMA_VERSION"),
    )

    def _assert_anchors(self, doc: Path, anchors: tuple[tuple[str, str], ...]) -> None:
        text = _norm(doc.read_text(encoding="utf-8"))
        for module_name, symbol in anchors:
            module = _find_module(module_name)
            with self.subTest(doc=doc.name, symbol=f"{module_name}::{symbol}"):
                self.assertIn(symbol, text, f"{doc.name} no longer mentions {symbol}")
                self.assertIsNotNone(module, f"module {module_name!r} not found")
                assert module is not None
                self.assertTrue(
                    _module_has_symbol(module, symbol),
                    f"{module_name} no longer defines {symbol}",
                )

    def test_transport_doc_anchors(self):
        self._assert_anchors(DOCS["transport"], self.TRANSPORT_ANCHORS)

    def test_identity_doc_anchors(self):
        self._assert_anchors(DOCS["identity"], self.IDENTITY_ANCHORS)

    def test_transport_doc_anchors_sidecar_lifecycle_assets(self):
        text = DOCS["transport"].read_text(encoding="utf-8")
        sidecar_dir = COMPONENTS / "northstar-codex-sidecar"
        for asset in ("northstar-codex-sidecar.service", "install.sh", "rollback.sh"):
            with self.subTest(asset=asset):
                self.assertTrue((sidecar_dir / asset).is_file(), f"{asset} missing")
                self.assertIn(asset, text)


if __name__ == "__main__":
    unittest.main()


GUIDE = GUIDES / "remote-worker-operations.md"
CANARY = ROOT / "examples" / "remote-canary"
CANARY_INDEX_TEXT = (ROOT / "examples" / "README.md").read_text(encoding="utf-8")


class T5OperationsGuideTests(unittest.TestCase):
    def test_guide_exists_and_stays_an_operator_document(self):
        text = _norm(GUIDE.read_text(encoding="utf-8"))
        for marker in (
            "Status: an operator guide, not a product",
            "None of this has been exercised by this repository's CI",
            "First-run validation checklist",
            "Honesty footer",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, text)

    def test_guide_links_the_concept_docs_and_examples(self):
        text = GUIDE.read_text(encoding="utf-8")
        for link in (
            "../concepts/northstar-remote-transport.md",
            "../concepts/northstar-remote-identity.md",
            "../concepts/northstar-remote-worker.md",
            "../concepts/audit-trail.md",
            "../../examples/remote-canary/README.md",
        ):
            with self.subTest(link=link):
                self.assertIn(link, text)

    def test_guide_monitoring_section_names_only_real_signals(self):
        text = _norm(GUIDE.read_text(encoding="utf-8"))
        for marker in (
            "audit.ndjson/1",
            "trace_metrics.py",
            "verifier_verdict",
            "examples/observability",
            "transport_unavailable",
            "CONNECTION_READ_TIMEOUT",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, text)


class T5CanaryExampleTests(unittest.TestCase):
    def test_examples_index_lists_the_canary(self):
        self.assertIn("remote-canary/README.md", CANARY_INDEX_TEXT)

    def test_readme_is_honest_about_what_can_run_where(self):
        text = _norm((CANARY / "README.md").read_text(encoding="utf-8"))
        for marker in (
            "never runs this example",
            "no model, no API key and no codex binary",
            "proves the channel",
            "Exit codes",
            "canonical filename",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, text)

    def test_probe_script_compiles(self):
        py_compile.compile(str(CANARY / "probe_socket.py"), doraise=True)

    def test_canary_shell_script_parses(self):
        sh = shutil.which("sh")
        if sh is None:
            self.skipTest("no POSIX shell on this host")
        result = subprocess.run([sh, "-n", str(CANARY / "run_remote_canary.sh")],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, msg=result.stderr)

    def test_probe_round_trips_against_the_real_socket_server(self):
        """Probe + real sidecar_socket.serve on a loopback socket.

        The server module pins its socket root to /var/run/northstar-codex;
        the test points that root at a temp directory (same code path -
        validate -> bind -> chmod 0660 -> accept -> handle -> respond).
        """
        import importlib.util
        import threading
        import time as _time

        sidecar_dir = COMPONENTS / "northstar-codex-sidecar"
        sys.path.insert(0, str(sidecar_dir))
        try:
            import service
            import sidecar_socket

            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                service.SOCKET_ROOT = root  # type: ignore[attr-defined]
                socket_path = root / "sidecar.sock"
                thread = threading.Thread(
                    target=sidecar_socket.serve, args=(str(socket_path),), daemon=True
                )
                thread.start()
                deadline = _time.monotonic() + 10.0
                while not socket_path.exists():
                    if _time.monotonic() > deadline:
                        self.fail("sidecar server never published its socket")
                    _time.sleep(0.05)
                self.assertEqual(sidecar_socket.socket_mode(), 0o660)

                spec = importlib.util.spec_from_file_location(
                    "t5_probe", CANARY / "probe_socket.py"
                )
                assert spec and spec.loader
                probe = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(probe)

                response = probe.probe_once(
                    str(socket_path),
                    {"request_id": "canary-test-1", "prompt": "never runs",
                     "timeout_ms": 999_999_999},
                )
                self.assertEqual(response.get("request_id"), "canary-test-1")
                self.assertEqual(response.get("status"), "rejected")
                self.assertTrue(
                    any("timeout_ms" in str(error) for error in response.get("errors", [])),
                    f"unexpected rejection text: {response}",
                )
                # Probe CLI verdict over the same socket.
                self.assertEqual(probe.run_probe(str(socket_path)), 0)
        finally:
            sys.path.remove(str(sidecar_dir))

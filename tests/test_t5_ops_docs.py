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
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPONENTS = ROOT / "components"
CONCEPTS = ROOT / "docs" / "concepts"

DOCS = {
    "transport": CONCEPTS / "northstar-remote-transport.md",
    "identity": CONCEPTS / "northstar-remote-identity.md",
}

SYMBOL_TOKEN = re.compile(r"`([A-Za-z_][A-Za-z0-9_]*\.py)::([A-Za-z_][A-Za-z0-9_]*)`")


def _norm(text: str) -> str:
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

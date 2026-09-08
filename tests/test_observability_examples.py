"""P3-4 observability example assets must stay honest and wired.

Static checks, mirroring the repository's doc-discipline tests:

- the example is listed on the examples index (enforced there, asserted here
  so a removal fails with a clear message);
- the compose stack stays local and minimal: Jaeger (OTLP/HTTP receiver +
  UI) and Grafana with a provisioned core Jaeger data source;
- the bootstrap keeps the documented seam (ambient provider, OTLP/HTTP to
  localhost, checkout-path fallback) and degrades with guidance when the
  optional packages are missing;
- the README carries explicit honesty markers (CI never runs Docker, memory-
  only storage, tags pinned at write time).

None of these files can be executed here - the CI host has no Docker and the
component does not ship exporter code - so the tests pin structure and
intent rather than runtime behaviour.
"""
import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import py_compile

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "observability"
PANEL = ROOT / "examples" / "session-panel"
INDEX = ROOT / "examples" / "README.md"


def _record_types_from_source() -> tuple[str, ...]:
    """Read the runtime's authoritative record vocabulary (sessions.py)."""
    source = (
        ROOT / "components" / "northstar-agent-runtime" / "sessions.py"
    ).read_text(encoding="utf-8")
    block = re.search(r"RECORD_TYPES: tuple\[str, ...\] = \((.*?)\)\n", source, re.S)
    assert block, "RECORD_TYPES block not found in sessions.py"
    return tuple(re.findall(r'"([a-z_]+)"', block.group(1)))


class ObservabilityExampleTests(unittest.TestCase):
    def test_examples_index_lists_the_example(self):
        text = INDEX.read_text(encoding="utf-8")
        self.assertIn("observability/README.md", text)

    def test_compose_is_jaeger_plus_grafana_only(self):
        text = (EXAMPLE / "docker-compose.yml").read_text(encoding="utf-8")
        self.assertIn("jaegertracing/all-in-one:", text)
        self.assertIn("grafana/grafana:", text)
        # The whole point of the template: no collector, no extra moving parts.
        self.assertNotIn("collector", text)

    def test_jaeger_exposes_ui_and_otlp_http(self):
        text = (EXAMPLE / "docker-compose.yml").read_text(encoding="utf-8")
        self.assertIn('"16686:16686"', text)  # UI
        self.assertIn('"4318:4318"', text)  # OTLP/HTTP - the bootstrap default endpoint

    def test_grafana_provisioning_wires_core_jaeger_datasource(self):
        text = (EXAMPLE / "grafana" / "provisioning" / "datasources" / "jaeger.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("apiVersion: 1", text)
        self.assertIn("type: jaeger", text)  # core data source, no plugin install
        self.assertIn("url: http://jaeger:16686", text)  # in-compose hostname

    def test_bootstrap_compiles(self):
        # py_compile is syntax-only: the optional packages are not installed
        # on the CI host, which is exactly what the guard is for.
        py_compile.compile(str(EXAMPLE / "otel_bootstrap.py"), doraise=True)

    def test_bootstrap_keeps_the_ambient_provider_seam(self):
        text = (EXAMPLE / "otel_bootstrap.py").read_text(encoding="utf-8")
        for marker in (
            "trace.set_tracer_provider",
            "OTLPSpanExporter",
            "BatchSpanProcessor",
            "http://localhost:4318/v1/traces",
            "OTEL_EXPORTER_OTLP_ENDPOINT",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, text)

    def test_bootstrap_runs_from_checkout_or_site_packages(self):
        text = (EXAMPLE / "otel_bootstrap.py").read_text(encoding="utf-8")
        self.assertIn("parents[2]", text)  # examples/observability -> repo root
        self.assertIn("northstar-agent-runtime", text)
        self.assertIn("sys.path.insert", text)

    def test_bootstrap_missing_dependency_failure_is_guidance_not_crash(self):
        text = (EXAMPLE / "otel_bootstrap.py").read_text(encoding="utf-8")
        self.assertIn("except ImportError", text)
        self.assertIn("README.md step 2", text)
        self.assertIn("return 3", text)  # explicit, not a traceback

    def test_readme_is_honest_about_scope(self):
        text = (EXAMPLE / "README.md").read_text(encoding="utf-8")
        for marker in (
            "not part of the product",  # template disclaimer
            "in memory",  # all-in-one storage truth
            "never runs",  # CI does not exercise the compose file
            "verify the current tags",  # pinned tags are unverified samples
            "host-side choice",  # exporter is not in the component extra
            "exports nowhere",  # the seam, stated plainly
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, text)


if __name__ == "__main__":
    unittest.main()


def _panel_text() -> str:
    return (PANEL / "session-panel.html").read_text(encoding="utf-8")


def _panel_script() -> str:
    """The inline <script> body (syntax-checked against node when present)."""
    match = re.search(r"<script>\n(.*)\n</script>", _panel_text(), re.S)
    assert match, "no inline <script> block found"
    return match.group(1)


class SessionPanelTests(unittest.TestCase):
    def test_examples_index_lists_the_panel(self):
        text = INDEX.read_text(encoding="utf-8")
        self.assertIn("session-panel/README.md", text)

    def test_panel_is_one_self_contained_file_with_no_network_reference(self):
        text = _panel_text()
        for marker in (
            "<link ",  # no stylesheets
            "<img ",  # no images
            "<script src",  # no external scripts
            "http://",  # no URLs at all
            "https://",
            "fetch(",
            "XMLHttpRequest",
            "WebSocket",
            "@import",
        ):
            with self.subTest(marker=marker):
                self.assertNotIn(marker, text)
        self.assertEqual(text.count("<script"), 1, "expect exactly one inline script")
        self.assertIn("FileReader", text)
        self.assertIn("readAsText", text)

    def test_panel_renders_the_full_record_vocabulary(self):
        text = _panel_text()
        for kind in _record_types_from_source():
            with self.subTest(kind=kind):
                self.assertIn(kind, text)

    def test_panel_offers_fingerprint_stats_and_filters(self):
        text = _panel_text()
        for marker in (
            "fnv1a64",  # local fingerprint (non-cryptographic, stated)
            "local fingerprint",  # and its honest label
            "errors &amp; denials only",  # filter toggle
            "denials",  # stat
            "sessions",  # stat
            "from-index",  # read-only replay range control
            "through-index",  # inclusive upper bound
            "apply-replay",  # apply control
            "clear-replay",  # reset control
            "replay slice",  # explicit non-execution status
            "chain metadata",  # integrity cue without overclaiming browser verification
            "read-only",  # replay boundary
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, text)

    def test_panel_replay_is_bounded_read_only_and_cli_verified(self):
        text = _panel_text()
        for marker in (
            "through index (inclusive)",
            "state.range",
            "through < from",
            "records selected",
            "no tools/model calls",
            "verify with CLI",
            "sessions verify",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, text)

    def test_panel_readme_claims_only_what_the_file_does(self):
        text = (PANEL / "README.md").read_text(encoding="utf-8")
        for marker in (
            "no server",  # file:// usage
            "No network",  # honest network guarantee
            "not a validator",  # viewer/validator boundary stated
            "not a cryptographic hash",  # fingerprint honesty
            "sample-session.jsonl",  # sample documented
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, text)

    def test_sample_transcript_is_a_real_shaped_record_stream(self):
        kinds = _record_types_from_source()
        path = PANEL / "sample-session.jsonl"
        records = []
        for number, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            with self.subTest(line=number):
                record = json.loads(line)
                records.append(record)
                self.assertIn(record["type"], kinds)
                for key in ("index", "ts", "session_id", "type"):
                    self.assertIn(key, record)
        types = {record["type"] for record in records}
        # The sample must show the denial path (that is its pedagogical point)
        # and end with the run's terminal records.
        self.assertTrue({"session_start", "result", "session_end"} <= types)
        self.assertIn("denial", types)
        # Portability edit is documented in the README, never silent.
        self.assertNotIn("/home/", path.read_text(encoding="utf-8"))

    def test_inline_javascript_parses_when_node_is_available(self):
        node = shutil.which("node")
        if node is None:
            self.skipTest("node not installed on this host")
        script = _panel_script()
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as handle:
            handle.write(script)
            tmp = handle.name
        try:
            result = subprocess.run(
                [node, "--check", tmp],
                capture_output=True,
                text=True,
            )
        finally:
            Path(tmp).unlink()
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        if result.returncode != 0 and sys.version_info:  # pragma: no cover
            pass

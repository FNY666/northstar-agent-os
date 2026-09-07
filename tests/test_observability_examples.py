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
import py_compile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "observability"
INDEX = ROOT / "examples" / "README.md"


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

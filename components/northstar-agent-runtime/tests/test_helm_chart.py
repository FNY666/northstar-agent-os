"""Tests for helm_chart: templating + release lifecycle bookkeeping."""

import ast
import unittest
from pathlib import Path

from helm_chart import (
    DuplicateReleaseError,
    HelmChart,
    HelmRenderError,
    HelmTemplateError,
    Manifest,
    ManifestDiff,
    Release,
    RevisionError,
    SCHEMA,
    UnknownReleaseError,
    VERSION,
    helm_chart_audit_event,
)

MODULE_PATH = Path(__file__).resolve().parent.parent / "helm_chart.py"


def _chart(**kw):
    templates = kw.pop("templates", {
        "deployment.yaml": (
            "name: {{ .Release.Name }}-app\n"
            "replicas: {{ .Values.replicas }}\n"
            "image: {{ .Values.image | default \"nginx:latest\" }}\n"),
        "service.yaml": "port: {{ .Values.port | quote }}\n",
    })
    return HelmChart(name=kw.pop("name", "webapp"),
                     version=kw.pop("version", "1.0.0"),
                     templates=templates, **kw)


class PinsTest(unittest.TestCase):
    def test_version_schema(self):
        self.assertEqual(VERSION, "helm-chart.v1")
        self.assertEqual(SCHEMA, "northstar.helm-chart.v1")


class ConstructionTest(unittest.TestCase):
    def test_template_names_sorted(self):
        c = _chart()
        self.assertEqual(c.template_names, ("deployment.yaml", "service.yaml"))
        self.assertEqual(c.name, "webapp")
        self.assertEqual(c.version, "1.0.0")

    def test_bad_chart_name(self):
        for bad in ("", "has space", "-lead", 123, None):
            with self.assertRaises((ValueError, TypeError)):
                _chart(name=bad)

    def test_bad_version(self):
        for bad in ("", "   ", 123, None):
            with self.assertRaises((ValueError, TypeError)):
                _chart(version=bad)

    def test_bad_templates(self):
        for bad in ({}, {"t": ""}, {"": "x"}, {1: "x"}, {"t": 5}, None):
            with self.assertRaises((ValueError, TypeError)):
                _chart(templates=bad)


class RenderTest(unittest.TestCase):
    def test_basic_substitution(self):
        r = _chart().render({"replicas": 3, "image": "a:1", "port": 80}, 0,
                            release_name="prod")
        by_name = {m.template_name: m.text for m in r.manifests}
        self.assertIn("name: prod-app", by_name["deployment.yaml"])
        self.assertIn("replicas: 3", by_name["deployment.yaml"])
        self.assertIn('port: "80"', by_name["service.yaml"])

    def test_nested_values(self):
        c = HelmChart(name="n", version="1.0.0",
                      templates={"t": "{{ .Values.db.host }}:{{ .Values.db.port }}"})
        r = c.render({"db": {"host": "h", "port": 5432}}, 0)
        self.assertEqual(r.manifests[0].text, "h:5432")

    def test_release_chart_refs(self):
        c = HelmChart(name="mychart", version="2.0.0",
                      templates={"t": "{{ .Release.Name }}/{{ .Release.Namespace }}/"
                                   "{{ .Chart.Name }}/{{ .Chart.Version }}"})
        r = c.render({}, 0, release_name="r1", namespace="ns1")
        self.assertEqual(r.manifests[0].text, "r1/ns1/mychart/2.0.0")

    def test_default_pipe(self):
        r = _chart().render({"replicas": 1, "port": 1}, 0)
        by_name = {m.template_name: m.text for m in r.manifests}
        self.assertIn("image: nginx:latest", by_name["deployment.yaml"])

    def test_default_escaped_literal(self):
        c = HelmChart(name="n", version="1.0.0",
                      templates={"t": "{{ .Values.x | default \"a\\\"b\" }}"})
        r = c.render({}, 0)
        self.assertEqual(r.manifests[0].text, 'a"b')

    def test_upper_pipe(self):
        c = HelmChart(name="n", version="1.0.0",
                      templates={"t": "{{ .Values.env | upper }}"})
        r = c.render({"env": "prod"}, 0)
        self.assertEqual(r.manifests[0].text, "PROD")

    def test_bool_int_rendering(self):
        c = HelmChart(name="n", version="1.0.0",
                      templates={"t": "{{ .Values.a }}/{{ .Values.b }}/{{ .Values.c }}"})
        r = c.render({"a": True, "b": False, "c": 2.5}, 0)
        self.assertEqual(r.manifests[0].text, "True/False/2.5".replace(
            "True", "true").replace("False", "false"))

    def test_quote_complex_value(self):
        c = HelmChart(name="n", version="1.0.0",
                      templates={"t": "cfg: {{ .Values.cfg | quote }}"})
        r = c.render({"cfg": {"k": "v"}}, 0)
        self.assertIn('{"k":"v"}', r.manifests[0].text)

    def test_missing_value_fails(self):
        with self.assertRaises(HelmRenderError):
            _chart().render({"port": 1}, 0)

    def test_non_scalar_needs_quote(self):
        c = HelmChart(name="n", version="1.0.0",
                      templates={"t": "{{ .Values.cfg }}"})
        with self.assertRaises(HelmRenderError):
            c.render({"cfg": {"k": 1}}, 0)

    def test_unbalanced_delimiter(self):
        c = HelmChart(name="n", version="1.0.0",
                      templates={"t": "x {{ .Values.a "})
        with self.assertRaises(HelmTemplateError):
            c.render({"a": 1}, 0)

    def test_stray_close(self):
        c = HelmChart(name="n", version="1.0.0",
                      templates={"t": "x }} y"})
        with self.assertRaises(HelmTemplateError):
            c.render({}, 0)

    def test_empty_expression(self):
        c = HelmChart(name="n", version="1.0.0",
                      templates={"t": "x {{ }} y"})
        with self.assertRaises(HelmTemplateError):
            c.render({}, 0)

    def test_unknown_operand(self):
        c = HelmChart(name="n", version="1.0.0",
                      templates={"t": "{{ .Capabilities.x }}"})
        with self.assertRaises(HelmTemplateError):
            c.render({}, 0)

    def test_unknown_pipe(self):
        c = HelmChart(name="n", version="1.0.0",
                      templates={"t": "{{ .Values.a | frobnicate }}"})
        with self.assertRaises(HelmTemplateError):
            c.render({"a": 1}, 0)

    def test_bad_seq(self):
        for bad in (True, -1, "0", 1.5):
            with self.assertRaises((TypeError, ValueError)):
                _chart().render({"replicas": 1, "port": 1}, bad)

    def test_bad_values(self):
        with self.assertRaises(TypeError):
            _chart().render(["not", "mapping"], 0)
        with self.assertRaises(TypeError):
            _chart().render({1: "x"}, 0)
        with self.assertRaises(TypeError):
            _chart().render({"a": float("nan")}, 0)

    def test_digest_determinism(self):
        c = _chart()
        v = {"replicas": 2, "image": "a:1", "port": 80}
        r1 = c.render(v, 0)
        r2 = c.render(v, 0)
        self.assertEqual(r1.digest, r2.digest)
        self.assertEqual(r1.values_digest, r2.values_digest)
        r3 = c.render({"replicas": 3, "image": "a:1", "port": 80}, 0)
        self.assertNotEqual(r1.digest, r3.digest)

    def test_frozen_records(self):
        r = _chart().render({"replicas": 1, "port": 1}, 0)
        with self.assertRaises(Exception):
            r.digest = "x"  # type: ignore
        self.assertIsInstance(r.manifests[0], Manifest)


class LifecycleTest(unittest.TestCase):
    def _vals(self, replicas=1):
        return {"replicas": replicas, "image": "a:1", "port": 80}

    def test_install(self):
        r = _chart().install("prod", self._vals(), 0)
        self.assertEqual(r.revision, 1)
        self.assertIsNone(r.supersedes)
        self.assertIsNone(r.diff)
        self.assertIsInstance(r, Release)

    def test_duplicate_install(self):
        c = _chart()
        c.install("prod", self._vals(), 0)
        with self.assertRaises(DuplicateReleaseError):
            c.install("prod", self._vals(), 1)

    def test_upgrade_diff(self):
        c = _chart()
        c.install("prod", self._vals(1), 0)
        r2 = c.upgrade("prod", self._vals(5), 1)
        self.assertEqual(r2.revision, 2)
        self.assertEqual(r2.supersedes, 1)
        self.assertIsNotNone(r2.diff)
        self.assertIn("deployment.yaml", r2.diff.changed)
        self.assertTrue("service.yaml" not in r2.diff.changed)

    def test_upgrade_no_change_empty_diff(self):
        c = _chart()
        c.install("prod", self._vals(), 0)
        r2 = c.upgrade("prod", self._vals(), 1)
        self.assertTrue(r2.diff.is_empty())

    def test_upgrade_unknown(self):
        with self.assertRaises(UnknownReleaseError):
            _chart().upgrade("nope", self._vals(), 0)

    def test_rollback(self):
        c = _chart()
        r1 = c.install("prod", self._vals(1), 0)
        c.upgrade("prod", self._vals(9), 1)
        r3 = c.rollback("prod", 1, 2)
        self.assertEqual(r3.revision, 3)
        self.assertEqual(r3.supersedes, 2)
        self.assertEqual([m.digest for m in r3.manifests],
                         [m.digest for m in r1.manifests])

    def test_rollback_unknown_revision(self):
        c = _chart()
        c.install("prod", self._vals(), 0)
        with self.assertRaises(RevisionError):
            c.rollback("prod", 99, 1)

    def test_rollback_current_refused(self):
        c = _chart()
        c.install("prod", self._vals(), 0)
        with self.assertRaises(RevisionError):
            c.rollback("prod", 1, 1)

    def test_rollback_bad_revision(self):
        c = _chart()
        c.install("prod", self._vals(), 0)
        for bad in (0, -1, True, "1"):
            with self.assertRaises((ValueError, TypeError)):
                c.rollback("prod", bad, 1)

    def test_uninstall(self):
        c = _chart()
        c.install("prod", self._vals(), 0)
        un = c.uninstall("prod", 1)
        self.assertEqual(un.last_revision, 1)
        self.assertEqual(c.installed_releases(), ())
        with self.assertRaises(UnknownReleaseError):
            c.release("prod")
        with self.assertRaises(UnknownReleaseError):
            c.uninstall("prod", 2)

    def test_history_retained_after_uninstall(self):
        c = _chart()
        c.install("prod", self._vals(), 0)
        c.upgrade("prod", self._vals(2), 1)
        c.uninstall("prod", 2)
        hist = c.history("prod")
        self.assertEqual([r.revision for r in hist], [1, 2])

    def test_reinstall_continues_revisions(self):
        c = _chart()
        c.install("prod", self._vals(), 0)
        c.uninstall("prod", 1)
        r = c.install("prod", self._vals(), 2)
        self.assertEqual(r.revision, 2)

    def test_history_unknown(self):
        with self.assertRaises(UnknownReleaseError):
            _chart().history("nope")

    def test_release_view(self):
        c = _chart()
        c.install("a", self._vals(), 0)
        c.install("b", self._vals(), 1)
        self.assertEqual(c.installed_releases(), ("a", "b"))
        self.assertEqual(c.release("a").release_name, "a")


class AuditTest(unittest.TestCase):
    def test_shapes(self):
        ev = helm_chart_audit_event("installed", 3, release_name="prod",
                                    revision=1, digest="sha256:x")
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["module"], "helm_chart")
        self.assertEqual(ev["module_version"], VERSION)
        self.assertEqual(ev["kind"], "installed")
        self.assertEqual(ev["seq"], 3)

    def test_all_kinds(self):
        for kind in ("chart-created", "rendered", "installed", "upgraded",
                     "rolled-back", "uninstalled", "rejected"):
            ev = helm_chart_audit_event(kind, 0)
            self.assertEqual(ev["kind"], kind)

    def test_bad_kind(self):
        with self.assertRaises(ValueError):
            helm_chart_audit_event("nuked", 0)

    def test_bad_seq(self):
        with self.assertRaises((TypeError, ValueError)):
            helm_chart_audit_event("installed", True)

    def test_no_raw_values(self):
        for key in ("values", "payload", "secret", "text"):
            with self.assertRaises(ValueError):
                helm_chart_audit_event("rendered", 0, **{key: "x"})


class MiscTest(unittest.TestCase):
    def test_stdlib_only(self):
        tree = ast.parse(MODULE_PATH.read_text())
        allowed = {"__future__", "hashlib", "hmac", "json", "math", "re",
                   "threading", "dataclasses", "typing",
                   "canonical_json"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)

    def test_manifest_diff_empty(self):
        d = ManifestDiff(added=(), removed=(), changed=())
        self.assertTrue(d.is_empty())
        d2 = ManifestDiff(added=("a",), removed=(), changed=())
        self.assertFalse(d2.is_empty())

    def test_main(self):
        import helm_chart
        helm_chart.main()


if __name__ == "__main__":
    unittest.main()

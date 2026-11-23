"""Helm chart interface: templating + release lifecycle as deterministic bookkeeping.

Research motivation: Helm charts are executable policy -- a chart renders
arbitrary manifests from caller-supplied values, and an ``install`` or
``upgrade`` decides what a cluster runs. In an agent runtime the chart is
part of the supply surface: a value injection (``.Values.image`` pointing at
an attacker registry), a template that swallows a security context, or an
``upgrade`` that cannot be diffed against the previous revision are all
real failure modes. This module is the *bookkeeping* half of Helm: it
renders ``{{ .Values.* }}`` templates deterministically and pins every
rendered manifest with a ``sha256:`` digest, and it keeps a release
registry with revision history, so any revision can be diffed or rolled
back to. It never touches a cluster, never reads the filesystem, never
spawns ``helm`` or ``kubectl``, and never measures wall-clock time --
releases are host-reported ledger entries, and the caller supplies integer
seqs so every decision is replayable and audit-deterministic.

Template syntax (a deliberately small, total subset of Go templates):

- ``{{ .Values.path.to.key }}`` -- value lookup by dotted path.
- ``{{ .Release.Name }}``, ``{{ .Release.Namespace }}``,
  ``{{ .Chart.Name }}``, ``{{ .Chart.Version }}`` -- release/chart refs.
- Pipes: ``| default "lit"`` (fallback when the value is missing),
  ``| quote`` (scalars render as JSON-quoted strings, so ``8080`` becomes
  ``"8080"``; mappings and lists embed as raw canonical JSON),
  ``| upper`` (ASCII upper-case of the rendered text).
- Anything else -- unbalanced delimiters, unknown operands, unknown
  pipes, unclosed string literals -- raises ``HelmTemplateError``.
- Missing values fail closed: a ``.Values`` path that resolves to nothing
  raises ``HelmRenderError`` unless a ``default`` pipe supplies it. Only
  scalar values (str/bool/int/float) render directly; mappings and lists
  require the ``quote`` pipe, so a ConfigMap blob never silently becomes
  ``map[...]``.

Public API:

- ``HelmChart(name, version, templates)`` -- immutable chart package.
  ``templates`` maps template name -> template text (must be non-empty).
- ``chart.render(values, seq, release_name=..., namespace=...)`` ->
  frozen ``RenderedManifests`` (side-effect free).
- ``chart.install(release_name, values, seq, namespace=...)`` -> frozen
  ``Release`` (revision 1). Duplicate release names refused.
- ``chart.upgrade(release_name, values, seq)`` -> frozen ``Release``
  (revision + 1) with a ``ManifestDiff`` against the previous revision.
- ``chart.rollback(release_name, revision, seq)`` -> frozen ``Release``
  re-pinning the manifests of an earlier revision (new revision number;
  rolling back to the *current* revision is refused).
- ``chart.uninstall(release_name, seq)`` -> frozen ``UninstallRecord``;
  history is retained (like ``helm history``).
- Views: ``release(release_name)`` (latest), ``history(release_name)``.
- ``helm_chart_audit_event(kind, seq, ...)`` -- ``audit.ndjson/1``
  records, fixed kind vocabulary: ``"chart-created"``,
  ``"rendered"``, ``"installed"``, ``"upgraded"``,
  ``"rolled-back"``, ``"uninstalled"``, ``"rejected"``.

Honest scope:

- The module renders *reported* templates with *reported* values. A
  digest pin proves "this chart rendered this text from these values",
  never "these manifests are valid Kubernetes YAML" or "the cluster
  applied them". A host that reports a fake install gets a perfectly
  consistent fake ledger (same GIGO boundary as every other bookkeeping
  module in this tree).
- Revisions are caller-ordered by seq; the module has no clock and no
  timers. Uninstall does not prove the cluster deleted anything.
- Values must be canonicalizable (the shared ``canonical_json``
  try/except fallback); NaN/inf and non-str keys are refused fail-closed.
  The batch-5 ``>2**53`` JCS float-loss caveat applies to digest pins.

Version pin: ``helm-chart.v1`` / schema pin ``northstar.helm-chart.v1``.
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Tuple

VERSION = "helm-chart.v1"
SCHEMA = "northstar.helm-chart.v1"

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class HelmError(Exception):
    """Base class for helm-chart errors."""


class HelmTemplateError(HelmError):
    """A template could not be parsed (unbalanced delimiters, bad operand)."""


class HelmRenderError(HelmError):
    """A template rendered against values that cannot satisfy it."""


class DuplicateReleaseError(HelmError):
    """A release name is already installed."""


class UnknownReleaseError(HelmError):
    """No release (or revision) with that name exists."""


class RevisionError(HelmError):
    """A rollback target is invalid (unknown or already current)."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

_NAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise TypeError(f"seq must be an int, got {type(seq).__name__}")
    if seq < 0:
        raise ValueError("seq must be >= 0")
    return seq


def _check_name(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{what} must be a non-empty str")
    if not _NAME_RE.match(value):
        raise ValueError(f"{what} {value!r} is not a valid chart/release name")
    return value


def _check_values(values: Any) -> Mapping[str, Any]:
    if not isinstance(values, Mapping):
        raise TypeError(f"values must be a mapping, got {type(values).__name__}")
    for key in values:
        if not isinstance(key, str):
            raise TypeError("values keys must be str")
    try:
        jcs_canonical_json(dict(values))
    except Exception as exc:
        raise TypeError(f"values are not canonicalizable: {exc}") from exc
    return values


def _digest(body: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(jcs_canonical_json(dict(body))).hexdigest()


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Manifest:
    """One rendered template: name, text, and digest pin."""
    template_name: str
    text: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {"template_name": self.template_name, "text": self.text,
                "digest": self.digest, "version": VERSION, "schema": SCHEMA}


@dataclass(frozen=True)
class RenderedManifests:
    """Side-effect-free render output."""
    release_name: str
    namespace: str
    chart_name: str
    chart_version: str
    manifests: Tuple[Manifest, ...]
    values_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {"release_name": self.release_name, "namespace": self.namespace,
                "chart_name": self.chart_name, "chart_version": self.chart_version,
                "manifests": [m.as_dict() for m in self.manifests],
                "values_digest": self.values_digest, "digest": self.digest,
                "version": VERSION, "schema": SCHEMA}


@dataclass(frozen=True)
class ManifestDiff:
    """Template-level diff between two revisions."""
    added: Tuple[str, ...]
    removed: Tuple[str, ...]
    changed: Tuple[str, ...]

    def is_empty(self) -> bool:
        return not (self.added or self.removed or self.changed)

    def as_dict(self) -> Dict[str, Any]:
        return {"added": list(self.added), "removed": list(self.removed),
                "changed": list(self.changed), "version": VERSION,
                "schema": SCHEMA}


@dataclass(frozen=True)
class Release:
    """One installed/upgraded/rolled-back revision."""
    release_name: str
    namespace: str
    chart_name: str
    chart_version: str
    revision: int
    manifests: Tuple[Manifest, ...]
    values_digest: str
    digest: str
    supersedes: Optional[int]  # previous revision number, None for install
    diff: Optional[ManifestDiff]  # diff vs superseded, None for install

    def as_dict(self) -> Dict[str, Any]:
        return {"release_name": self.release_name, "namespace": self.namespace,
                "chart_name": self.chart_name, "chart_version": self.chart_version,
                "revision": self.revision,
                "manifests": [m.as_dict() for m in self.manifests],
                "values_digest": self.values_digest, "digest": self.digest,
                "supersedes": self.supersedes,
                "diff": self.diff.as_dict() if self.diff else None,
                "version": VERSION, "schema": SCHEMA}


@dataclass(frozen=True)
class UninstallRecord:
    """Uninstall bookkeeping; history is retained."""
    release_name: str
    last_revision: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {"release_name": self.release_name,
                "last_revision": self.last_revision, "digest": self.digest,
                "version": VERSION, "schema": SCHEMA}


# ---------------------------------------------------------------------------
# Template engine
# ---------------------------------------------------------------------------

_SPLIT_RE = re.compile(r"(\{\{|\}\})")
_STR_LIT_RE = re.compile(r'^"(?:[^"\\]|\\.)*"$')


def _parse_string_literal(token: str) -> str:
    token = token.strip()
    if not _STR_LIT_RE.match(token):
        raise HelmTemplateError(f"bad string literal: {token!r}")
    out: list[str] = []
    i = 1
    while i < len(token) - 1:
        ch = token[i]
        if ch == "\\":
            i += 1
            esc = token[i]
            out.append({"n": "\n", "t": "\t", "r": "\r", '"': '"',
                        "\\": "\\"}[esc] if esc in 'ntr"\\' else esc)
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def _lookup_values(values: Mapping[str, Any], path: str) -> Any:
    node: Any = values
    for part in path.split("."):
        if not isinstance(node, Mapping) or part not in node:
            return _MISSING
        node = node[part]
    return node


class _Missing:
    pass


_MISSING = _Missing()


def _render_scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        if isinstance(value, float):
            if value != value or value in (float("inf"), float("-inf")):
                raise HelmRenderError("NaN/inf values cannot be rendered")
        return repr(value)
    if isinstance(value, str):
        return value
    raise HelmRenderError(
        f"non-scalar value of type {type(value).__name__} needs the quote pipe")


def _eval_expression(expr: str, ctx: Mapping[str, Any]) -> str:
    """Evaluate one ``{{ ... }}`` expression to text."""
    parts = [p.strip() for p in expr.split("|")]
    operand = parts[0]
    pipes = parts[1:]

    default: Any = _MISSING
    for pipe in pipes:
        if pipe.startswith("default"):
            rest = pipe[len("default"):].strip()
            default = _parse_string_literal(rest)
        elif pipe not in ("quote", "upper"):
            raise HelmTemplateError(f"unknown pipe: {pipe!r}")

    if operand == ".Release.Name":
        value: Any = ctx["release_name"]
    elif operand == ".Release.Namespace":
        value = ctx["namespace"]
    elif operand == ".Chart.Name":
        value = ctx["chart_name"]
    elif operand == ".Chart.Version":
        value = ctx["chart_version"]
    elif operand.startswith(".Values."):
        value = _lookup_values(ctx["values"], operand[len(".Values."):])
        if value is _MISSING:
            if default is not _MISSING:
                value = default
            else:
                raise HelmRenderError(f"missing value for {operand}")
    elif operand.startswith(".Values") and operand == ".Values":
        raise HelmRenderError(".Values requires a dotted path")
    else:
        raise HelmTemplateError(f"unknown operand: {operand!r}")

    if value is None:
        if default is not _MISSING:
            value = default
        else:
            raise HelmRenderError(f"{operand} resolved to null with no default")

    text: str
    if "quote" in pipes:
        import json as _json

        if isinstance(value, str):
            text = _json.dumps(value, ensure_ascii=True)
        elif isinstance(value, (bool, int, float)):
            # Helm's quote stringifies first, then quotes: 8080 -> "8080".
            text = _json.dumps(_render_scalar(value), ensure_ascii=True)
        else:
            # Complex values embed as raw canonical JSON (a quoted JSON
            # string would double-encode and be useless in a manifest).
            try:
                canon = jcs_canonical_json(value)
            except Exception as exc:
                raise HelmRenderError(
                    f"cannot quote non-canonicalizable value: {exc}") from exc
            text = canon.decode("utf-8")
    else:
        text = _render_scalar(value)

    if "upper" in pipes:
        text = text.upper()
    return text


def _render_template(template: str, ctx: Mapping[str, Any]) -> str:
    """Render a template string; fail closed on any malformed construct."""
    chunks = _SPLIT_RE.split(template)
    out: list[str] = []
    i = 0
    while i < len(chunks):
        chunk = chunks[i]
        if chunk == "{{":
            if i + 2 >= len(chunks) or chunks[i + 2] != "}}":
                raise HelmTemplateError("unbalanced '{{' in template")
            expr = chunks[i + 1]
            if not expr.strip():
                raise HelmTemplateError("empty '{{}}' expression")
            out.append(_eval_expression(expr, ctx))
            i += 3
        elif chunk == "}}":
            raise HelmTemplateError("unbalanced '}}' in template")
        else:
            out.append(chunk)
            i += 1
    return "".join(out)


# ---------------------------------------------------------------------------
# Chart + release registry
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _ChartMeta:
    name: str
    version: str
    templates: Tuple[Tuple[str, str], ...]


class HelmChart:
    """An immutable chart package plus its mutable release ledger."""

    def __init__(self, name: str, version: str,
                 templates: Mapping[str, str]) -> None:
        _check_name(name, "chart name")
        if not isinstance(version, str) or not version.strip():
            raise ValueError("chart version must be a non-empty str")
        if not isinstance(templates, Mapping) or not templates:
            raise ValueError("templates must be a non-empty mapping")
        norm: list[Tuple[str, str]] = []
        for tname, text in templates.items():
            if not isinstance(tname, str) or not tname:
                raise ValueError("template names must be non-empty str")
            if not isinstance(text, str) or not text:
                raise ValueError(f"template {tname!r} must be non-empty str")
            norm.append((tname, text))
        self._meta = _ChartMeta(name=name, version=version,
                                templates=tuple(sorted(norm)))
        self._lock = threading.RLock()
        self._releases: Dict[str, list[Release]] = {}
        self._installed: Dict[str, Release] = {}

    # -- properties ------------------------------------------------------
    @property
    def name(self) -> str:
        return self._meta.name

    @property
    def version(self) -> str:
        return self._meta.version

    @property
    def template_names(self) -> Tuple[str, ...]:
        return tuple(t for t, _ in self._meta.templates)

    # -- rendering -------------------------------------------------------
    def _render_all(self, values: Mapping[str, Any], release_name: str,
                    namespace: str) -> Tuple[Manifest, ...]:
        ctx = {"values": values, "release_name": release_name,
               "namespace": namespace, "chart_name": self._meta.name,
               "chart_version": self._meta.version}
        manifests: list[Manifest] = []
        for tname, text in self._meta.templates:
            rendered = _render_template(text, ctx)
            digest = _digest({"chart": self._meta.name,
                              "chart_version": self._meta.version,
                              "template": tname, "text": rendered})
            manifests.append(Manifest(template_name=tname, text=rendered,
                                      digest=digest))
        return tuple(manifests)

    def render(self, values: Mapping[str, Any], seq: int,
               release_name: str = "release-name",
               namespace: str = "default") -> RenderedManifests:
        """Render all templates; no ledger side effects."""
        _check_seq(seq)
        values = _check_values(values)
        _check_name(release_name, "release name")
        if not isinstance(namespace, str) or not namespace:
            raise ValueError("namespace must be a non-empty str")
        values_digest = _digest({"values": dict(values)})
        manifests = self._render_all(values, release_name, namespace)
        digest = _digest({
            "chart": self._meta.name, "chart_version": self._meta.version,
            "release_name": release_name, "namespace": namespace,
            "values_digest": values_digest,
            "manifests": [m.digest for m in manifests]})
        return RenderedManifests(
            release_name=release_name, namespace=namespace,
            chart_name=self._meta.name, chart_version=self._meta.version,
            manifests=manifests, values_digest=values_digest, digest=digest)

    # -- release lifecycle -----------------------------------------------
    def _new_release(self, release_name: str, namespace: str,
                     manifests: Tuple[Manifest, ...], values_digest: str,
                     revision: int, supersedes: Optional[int],
                     diff: Optional[ManifestDiff]) -> Release:
        digest = _digest({
            "chart": self._meta.name, "chart_version": self._meta.version,
            "release_name": release_name, "namespace": namespace,
            "revision": revision, "values_digest": values_digest,
            "manifests": [m.digest for m in manifests],
            "supersedes": supersedes})
        return Release(
            release_name=release_name, namespace=namespace,
            chart_name=self._meta.name, chart_version=self._meta.version,
            revision=revision, manifests=manifests,
            values_digest=values_digest, digest=digest,
            supersedes=supersedes, diff=diff)

    @staticmethod
    def _diff_manifests(old: Tuple[Manifest, ...],
                        new: Tuple[Manifest, ...]) -> ManifestDiff:
        old_map = {m.template_name: m.digest for m in old}
        new_map = {m.template_name: m.digest for m in new}
        added = tuple(sorted(set(new_map) - set(old_map)))
        removed = tuple(sorted(set(old_map) - set(new_map)))
        changed = tuple(sorted(t for t in set(old_map) & set(new_map)
                               if old_map[t] != new_map[t]))
        return ManifestDiff(added=added, removed=removed, changed=changed)

    def install(self, release_name: str, values: Mapping[str, Any], seq: int,
                namespace: str = "default") -> Release:
        """Install revision 1 of a release."""
        _check_seq(seq)
        values = _check_values(values)
        _check_name(release_name, "release name")
        if not isinstance(namespace, str) or not namespace:
            raise ValueError("namespace must be a non-empty str")
        with self._lock:
            if release_name in self._installed:
                raise DuplicateReleaseError(
                    f"release {release_name!r} is already installed")
            rendered = self.render(values, seq, release_name, namespace)
            revision = (self._releases[release_name][-1].revision + 1
                        if release_name in self._releases else 1)
            release = self._new_release(
                release_name, namespace, rendered.manifests,
                rendered.values_digest, revision, None, None)
            self._releases.setdefault(release_name, []).append(release)
            self._installed[release_name] = release
            return release

    def upgrade(self, release_name: str, values: Mapping[str, Any],
                seq: int) -> Release:
        """Install revision N+1 with a diff against revision N."""
        _check_seq(seq)
        values = _check_values(values)
        _check_name(release_name, "release name")
        with self._lock:
            current = self._installed.get(release_name)
            if current is None:
                raise UnknownReleaseError(
                    f"release {release_name!r} is not installed")
            rendered = self.render(values, seq, release_name,
                                   current.namespace)
            diff = self._diff_manifests(current.manifests,
                                        rendered.manifests)
            release = self._new_release(
                release_name, current.namespace, rendered.manifests,
                rendered.values_digest, current.revision + 1,
                current.revision, diff)
            self._releases[release_name].append(release)
            self._installed[release_name] = release
            return release

    def rollback(self, release_name: str, revision: int, seq: int) -> Release:
        """Re-pin the manifests of an earlier revision as a new revision."""
        _check_seq(seq)
        _check_name(release_name, "release name")
        if isinstance(revision, bool) or not isinstance(revision, int) \
                or revision < 1:
            raise ValueError("revision must be a positive int")
        with self._lock:
            current = self._installed.get(release_name)
            if current is None:
                raise UnknownReleaseError(
                    f"release {release_name!r} is not installed")
            history = {r.revision: r for r in self._releases[release_name]}
            target = history.get(revision)
            if target is None:
                raise RevisionError(
                    f"revision {revision} not found for {release_name!r}")
            if revision == current.revision:
                raise RevisionError(
                    f"revision {revision} is already current")
            diff = self._diff_manifests(current.manifests, target.manifests)
            release = self._new_release(
                release_name, target.namespace, target.manifests,
                target.values_digest, current.revision + 1,
                current.revision, diff)
            self._releases[release_name].append(release)
            self._installed[release_name] = release
            return release

    def uninstall(self, release_name: str, seq: int) -> UninstallRecord:
        """Uninstall a release; history is retained."""
        _check_seq(seq)
        _check_name(release_name, "release name")
        with self._lock:
            current = self._installed.pop(release_name, None)
            if current is None:
                raise UnknownReleaseError(
                    f"release {release_name!r} is not installed")
            digest = _digest({"release_name": release_name,
                              "last_revision": current.revision,
                              "release_digest": current.digest})
            return UninstallRecord(release_name=release_name,
                                   last_revision=current.revision,
                                   digest=digest)

    # -- views -----------------------------------------------------------
    def release(self, release_name: str) -> Release:
        """Latest installed release."""
        _check_name(release_name, "release name")
        with self._lock:
            current = self._installed.get(release_name)
            if current is None:
                raise UnknownReleaseError(
                    f"release {release_name!r} is not installed")
            return current

    def history(self, release_name: str) -> Tuple[Release, ...]:
        """All revisions ever, including uninstalled ones, in order."""
        _check_name(release_name, "release name")
        with self._lock:
            if release_name not in self._releases:
                raise UnknownReleaseError(
                    f"no history for release {release_name!r}")
            return tuple(self._releases[release_name])

    def installed_releases(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._installed))


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

_AUDIT_KINDS = ("chart-created", "rendered", "installed", "upgraded",
                "rolled-back", "uninstalled", "rejected")


def helm_chart_audit_event(kind: str, seq: int, **kwargs: Any) -> dict:
    """Shape an ``audit.ndjson/1`` record. Raw values are never logged."""
    _check_seq(seq)
    if kind not in _AUDIT_KINDS:
        raise ValueError(f"unknown audit kind: {kind!r}")
    record: Dict[str, Any] = {
        "schema": "audit.ndjson/1",
        "module": "helm_chart",
        "module_version": VERSION,
        "kind": kind,
        "seq": seq,
    }
    for key, value in kwargs.items():
        if key in ("values", "payload", "secret", "text"):
            raise ValueError(f"refusing to log raw {key}")
        record[key] = value
    return record


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------

def main() -> None:
    chart = HelmChart(
        name="webapp", version="1.2.3",
        templates={
            "deployment.yaml": (
                "name: {{ .Release.Name }}-app\n"
                "replicas: {{ .Values.replicas }}\n"
                "image: {{ .Values.image | default \"nginx:latest\" }}\n"
                "ns: {{ .Release.Namespace }}\n"
                "chart: {{ .Chart.Name }}-{{ .Chart.Version }}\n"),
            "service.yaml": (
                "name: {{ .Release.Name | upper }}-svc\n"
                "port: {{ .Values.port | quote }}\n"),
        })
    assert chart.template_names == ("deployment.yaml", "service.yaml")

    rendered = chart.render(
        {"replicas": 3, "image": "reg/webapp:9", "port": 8080}, 0,
        release_name="prod", namespace="shop")
    by_name = {m.template_name: m.text for m in rendered.manifests}
    assert "name: prod-app" in by_name["deployment.yaml"]
    assert "replicas: 3" in by_name["deployment.yaml"]
    assert "ns: shop" in by_name["deployment.yaml"]
    assert "chart: webapp-1.2.3" in by_name["deployment.yaml"]
    assert "name: PROD-svc" in by_name["service.yaml"]
    assert 'port: "8080"' in by_name["service.yaml"]

    # default pipe fills a missing value
    rendered2 = chart.render({"replicas": 1, "port": 80}, 1,
                             release_name="dev")
    assert "image: nginx:latest" in \
        {m.template_name: m.text for m in rendered2.manifests}["deployment.yaml"]

    # missing value without default fails closed
    try:
        chart.render({"port": 80}, 2)
    except HelmRenderError:
        pass
    else:
        raise AssertionError("expected HelmRenderError")

    # unbalanced template fails closed
    bad = HelmChart(name="bad", version="0.1.0",
                    templates={"t": "oops {{ .Values.x "})
    try:
        bad.render({"x": 1}, 0)
    except HelmTemplateError:
        pass
    else:
        raise AssertionError("expected HelmTemplateError")

    # lifecycle
    r1 = chart.install("prod", {"replicas": 3, "image": "reg/a:1",
                                "port": 8080}, 3, namespace="shop")
    assert r1.revision == 1 and r1.supersedes is None and r1.diff is None
    try:
        chart.install("prod", {"replicas": 1, "port": 1}, 4)
    except DuplicateReleaseError:
        pass
    else:
        raise AssertionError("expected DuplicateReleaseError")

    r2 = chart.upgrade("prod", {"replicas": 5, "image": "reg/a:1",
                                "port": 8080}, 5)
    assert r2.revision == 2 and r2.supersedes == 1
    assert r2.diff is not None and not r2.diff.is_empty()
    assert "deployment.yaml" in r2.diff.changed

    r3 = chart.rollback("prod", 1, 6)
    assert r3.revision == 3 and r3.supersedes == 2
    assert [m.digest for m in r3.manifests] == \
        [m.digest for m in r1.manifests]

    hist = chart.history("prod")
    assert [r.revision for r in hist] == [1, 2, 3]
    assert chart.release("prod").revision == 3

    un = chart.uninstall("prod", 7)
    assert un.last_revision == 3
    assert chart.installed_releases() == ()
    # history retained after uninstall; reinstall continues revisions
    r4 = chart.install("prod", {"replicas": 1, "image": "reg/a:1",
                                "port": 1}, 8)
    assert r4.revision == 4

    ev = helm_chart_audit_event("installed", 9, release_name="prod",
                                revision=4, digest=r4.digest)
    assert ev["schema"] == "audit.ndjson/1"
    try:
        helm_chart_audit_event("installed", 10, values={"a": 1})
    except ValueError:
        pass
    else:
        raise AssertionError("expected raw-values refusal")

    print("helm-chart OK: render, install, upgrade, rollback, uninstall")


if __name__ == "__main__":
    main()

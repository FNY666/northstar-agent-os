"""API client generator interface (OpenAPI codegen shaped, simulated).

Research motivation: OpenAPI codegen turns an API contract (the spec) into
typed client stubs so every caller speaks the same wire shape — the
contract is parsed, operations are extracted with their parameters, and a
deterministic renderer emits per-language client code. This module
implements that shape as a deterministic, single-host ledger:

* **Parse** — :meth:`APIClientGen.parse` ingests a JSON OpenAPI-ish spec
  (``openapi``/``info``/``paths``), validates it fail-closed, and books a
  frozen :class:`SpecRecord` (``spec-N`` ids) with a ``sha256:`` digest pin.
  Each operation becomes a frozen :class:`OperationRecord` (``op-N`` ids)
  with pinned HTTP-method vocabulary (get/post/put/patch/delete/head/
  options/trace) and parameter records.
* **Generate** — :meth:`APIClientGen.generate` renders a deterministic
  client bundle from a parsed spec into a pinned language vocabulary
  (``python``/requests, ``typescript``/fetch, ``shell``/curl). The bundle is
  a frozen :class:`ClientBundle` (``gen-N`` ids) whose digest pin covers the
  exact generated text; :meth:`ClientBundle.verify` re-derives it.
* **Validate** — :meth:`APIClientGen.validate` walks a spec against a pinned
  rule vocabulary and returns a frozen :class:`ValidationReport` (``val-N``
  ids) with digest-pinned :class:`Finding` records; results are verdict
  *data*, never exceptions.

House style: frozen dataclasses, caller-supplied int seqs (strictly
increasing on mutations — no wall-clock, no RNG), RLock-guarded,
fail-closed taxonomy under :class:`APIClientGenError`, stdlib-only,
type-tagged canonical digest encoding (bool != int; NaN/inf and |n| >= 2**53
refused at pin time — the batch-5 JCS float-loss caveat), audit events
shaped for ``audit.ndjson/1``, ``main()`` self-check.

Honest scope: this is *spec bookkeeping and template rendering*, not a real
code generator. The rendered clients are fixed text templates over the
parsed operation list — they do not type-check, they do not guarantee the
server implements the spec, and a ``valid=True`` report means "no pinned
rule fired", never "the API is correct". A lying spec gets a consistent
ledger of lies (GIGO, same boundary as every other bookkeeping module).
Production codegen needs a real emitter (openapi-generator/hey-api) plus
contract tests against a live server (see ``contract_tester``).

Version pin: api-client-gen.v1
Schema pin: northstar.api-client-gen.v1
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except ImportError:  # pragma: no cover - fallback for standalone import

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return "sha256:" + hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


#: Module version pin.
API_CLIENT_GEN_VERSION = "api-client-gen.v1"

#: Schema pin for records produced by this module.
API_CLIENT_GEN_SCHEMA = "northstar.api-client-gen.v1"

#: Audit event schema pin.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pinned HTTP method vocabulary (OpenAPI-shaped).
METHODS = frozenset(
    {"get", "post", "put", "patch", "delete", "head", "options", "trace"}
)

#: Pinned generator languages.
LANGUAGES = frozenset({"python", "typescript", "shell"})

#: Pinned parameter locations.
PARAM_LOCATIONS = frozenset({"path", "query", "header", "cookie"})

#: Pinned validation rules.
RULES = frozenset(
    {
        "missing-info",
        "empty-paths",
        "unknown-method",
        "duplicate-operation-id",
        "path-param-undeclared",
        "undeclared-path-param-not-required",
        "missing-responses",
        "bad-template-braces",
    }
)

#: Audit event kinds.
_AUDIT_KINDS = (
    "spec-parsed",
    "client-generated",
    "validated",
    "rejected",
)

#: Guardrails.
MAX_SPEC_LEN = 1 << 20  # 1 MiB of spec text
MAX_ID_LEN = 128
MAX_OPERATIONS = 4096


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class APIClientGenError(ValueError):
    """Base fail-closed API-client-generator error."""


class BadSpecError(APIClientGenError):
    """The spec text is not a valid spec document."""


class UnknownSpecError(APIClientGenError):
    """No such spec in the ledger."""


class DuplicateOperationError(APIClientGenError):
    """Two operations share one operationId (ids are never recycled)."""


class UnknownLanguageError(APIClientGenError):
    """The requested generator language is not in the pinned vocabulary."""


class ValidationError(APIClientGenError):
    """Malformed input (bad id, bad language, bad seq shape, ...)."""


class SeqOrderError(APIClientGenError):
    """Caller seq did not strictly increase."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _check_seq(seq: Any, last: int) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise APIClientGenError("seq must be an int, got %r" % (type(seq).__name__,))
    if seq < 0:
        raise APIClientGenError("seq must be non-negative")
    if seq <= last:
        raise SeqOrderError("seq must strictly increase (last=%d, got=%d)" % (last, seq))
    return seq


def _check_id(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("%s must be a non-empty str" % name)
    if len(value) > MAX_ID_LEN:
        raise ValidationError("%s too long (max %d chars)" % (name, MAX_ID_LEN))
    return value


def _pin(obj: Any) -> str:
    """Digest pin: sibling convention is a raw hex from jcs_sha256_hex,
    wrapped with the ``sha256:`` scheme prefix."""
    raw = jcs_sha256_hex(obj)
    return raw if raw.startswith("sha256:") else "sha256:" + raw


def _snake(name: str) -> str:
    """operationId -> snake_case (python/shell method names)."""
    out = re.sub(r"(?<=[a-z0-9])([A-Z])", r"_\1", name)
    out = re.sub(r"[^0-9A-Za-z_]+", "_", out)
    return out.lower().strip("_") or "op"


def _template_params(path: str) -> Tuple[str, ...]:
    """Names inside {braces} in a path template, in order of appearance."""
    return tuple(re.findall(r"\{([^{}]+)\}", path))


def _class_name(title: str) -> str:
    words = re.sub(r"[^0-9A-Za-z]+", " ", title).split()
    return "".join(w[:1].upper() + w[1:] for w in words) + "Client" or "ApiClient"


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ParamRecord:
    """One pinned parameter of an operation."""

    name: str
    location: str
    required: bool
    schema_type: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "location": self.location,
            "required": self.required,
            "schema_type": self.schema_type,
        }


@dataclass(frozen=True)
class OperationRecord:
    """One parsed operation (path + method + operationId)."""

    operation_id: str
    op_id: str
    method: str
    path: str
    summary: str
    params: Tuple[ParamRecord, ...]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "operation_id": self.operation_id,
            "op_id": self.op_id,
            "method": self.method,
            "path": self.path,
            "summary": self.summary,
            "params": [p.as_dict() for p in self.params],
        }


@dataclass(frozen=True)
class SpecRecord:
    """One parsed spec document."""

    spec_id: str
    title: str
    spec_version: str
    operations: Tuple[OperationRecord, ...]
    pin: str
    seq: int
    version: str = API_CLIENT_GEN_VERSION
    schema: str = API_CLIENT_GEN_SCHEMA

    def as_dict(self) -> Dict[str, Any]:
        return {
            "spec_id": self.spec_id,
            "title": self.title,
            "spec_version": self.spec_version,
            "operations": [o.as_dict() for o in self.operations],
            "pin": self.pin,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class ClientBundle:
    """One generated client bundle (language + generated text)."""

    bundle_id: str
    spec_id: str
    language: str
    file_name: str
    code: str
    pin: str
    seq: int
    version: str = API_CLIENT_GEN_VERSION
    schema: str = API_CLIENT_GEN_SCHEMA

    def as_dict(self) -> Dict[str, Any]:
        return {
            "bundle_id": self.bundle_id,
            "spec_id": self.spec_id,
            "language": self.language,
            "file_name": self.file_name,
            "code": self.code,
            "pin": self.pin,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }

    def verify(self) -> bool:
        """Re-derive the digest pin over the generated text."""
        return self.pin == _pin(
            {
                "bundle_id": self.bundle_id,
                "spec_id": self.spec_id,
                "language": self.language,
                "file_name": self.file_name,
                "code": self.code,
            }
        )


@dataclass(frozen=True)
class Finding:
    """One validation finding (rule + message, verdict data)."""

    finding_id: str
    rule: str
    severity: str
    message: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "rule": self.rule,
            "severity": self.severity,
            "message": self.message,
        }


@dataclass(frozen=True)
class ValidationReport:
    """One validation run over a spec (verdicts are data)."""

    report_id: str
    spec_id: str
    valid: bool
    findings: Tuple[Finding, ...]
    pin: str
    seq: int
    version: str = API_CLIENT_GEN_VERSION
    schema: str = API_CLIENT_GEN_SCHEMA

    def as_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "spec_id": self.spec_id,
            "valid": self.valid,
            "findings": [f.as_dict() for f in self.findings],
            "pin": self.pin,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }

    def verify(self) -> bool:
        """Re-derive the digest pin over the finding set."""
        return self.pin == _pin(
            {
                "report_id": self.report_id,
                "spec_id": self.spec_id,
                "valid": self.valid,
                "findings": [f.as_dict() for f in self.findings],
            }
        )


# ---------------------------------------------------------------------------
# Spec parsing (deterministic, fail-closed)
# ---------------------------------------------------------------------------


def _parse_spec_document(doc: Any) -> Tuple[str, str, list]:
    """Validate the top-level document; return (title, version, op-trips).

    An op-trip is (path, method, raw_operation_dict). Raises
    :class:`BadSpecError` fail-closed.
    """
    if not isinstance(doc, dict):
        raise BadSpecError("spec document must be a JSON object")
    info = doc.get("info")
    if not isinstance(info, dict):
        raise BadSpecError("missing 'info' object")
    title = info.get("title")
    if not isinstance(title, str) or not title.strip():
        raise BadSpecError("missing info.title")
    spec_version = info.get("version", "")
    if not isinstance(spec_version, str):
        raise BadSpecError("info.version must be a str")
    paths = doc.get("paths")
    if not isinstance(paths, dict):
        raise BadSpecError("missing 'paths' object")
    trips = []
    for path, path_item in sorted(paths.items()):
        if not isinstance(path_item, dict):
            raise BadSpecError("path item for %r must be an object" % (path,))
        if not isinstance(path, str) or not path.startswith("/"):
            raise BadSpecError("path %r must start with '/'" % (path,))
        if path.count("{") != path.count("}"):
            raise BadSpecError("unbalanced braces in path %r" % (path,))
        for method, operation in sorted(path_item.items()):
            if not isinstance(operation, dict):
                raise BadSpecError(
                    "operation for %s %s must be an object" % (method, path)
                )
            if method not in METHODS:
                raise BadSpecError("unknown method %r for path %r" % (method, path))
            trips.append((path, method, operation))
    if len(trips) > MAX_OPERATIONS:
        raise BadSpecError("too many operations (max %d)" % MAX_OPERATIONS)
    return title.strip(), spec_version, trips


def _parse_param(raw: Any, path: str) -> ParamRecord:
    if not isinstance(raw, dict):
        raise BadSpecError("parameter of %r must be an object" % (path,))
    name = raw.get("name")
    location = raw.get("in")
    if not isinstance(name, str) or not name.strip():
        raise BadSpecError("parameter of %r needs a name" % (path,))
    if location not in PARAM_LOCATIONS:
        raise BadSpecError(
            "parameter %r of %r has bad location %r" % (name, path, location)
        )
    required = raw.get("required", False)
    if not isinstance(required, bool):
        raise BadSpecError("parameter %r required must be a bool" % (name,))
    schema = raw.get("schema") or {}
    schema_type = schema.get("type", "string") if isinstance(schema, dict) else "string"
    if not isinstance(schema_type, str):
        schema_type = "string"
    return ParamRecord(
        name=name, location=location, required=required, schema_type=schema_type
    )


# ---------------------------------------------------------------------------
# Renderers (fixed deterministic templates)
# ---------------------------------------------------------------------------


def _render_python(title: str, operations: Tuple[OperationRecord, ...]) -> str:
    cls = _class_name(title)
    lines = [
        "# AUTO-GENERATED by northstar api-client-gen v1 -- do not edit by hand.",
        "import requests",
        "",
        "",
        "class %s:" % cls,
        '    """Client for %s (generated)."""' % title,
        "",
        "    def __init__(self, base_url, timeout=30):",
        '        self.base_url = base_url.rstrip("/")',
        "        self.timeout = timeout",
        "",
    ]
    for op in operations:
        meth = _snake(op.operation_id)
        path_params = _template_params(op.path)
        query_params = [p.name for p in op.params if p.location == "query"]
        sig = ", ".join(["self"] + list(path_params) + list(query_params))
        url_line = op.path
        for pp in path_params:
            url_line = url_line.replace("{%s}" % pp, "%%(%s)s" % pp)
        fmt = "{" + ", ".join('"%s": %s' % (pp, pp) for pp in path_params) + "}"
        lines.append("    def %s(%s):" % (meth, sig))
        lines.append('        url = self.base_url + "%s" %% %s' % (url_line, fmt))
        if query_params:
            qfmt = "{" + ", ".join('"%s": %s' % (q, q) for q in query_params) + "}"
            lines.append("        params = %s" % qfmt)
        else:
            lines.append("        params = None")
        lines.append(
            '        r = requests.%s(url, params=params, timeout=self.timeout)' % op.method
        )
        lines.append("        r.raise_for_status()")
        lines.append("        return r.json()")
        lines.append("")
    lines.append("")
    return "\n".join(lines)


def _render_typescript(title: str, operations: Tuple[OperationRecord, ...]) -> str:
    cls = _class_name(title)
    lines = [
        "// AUTO-GENERATED by northstar api-client-gen v1 -- do not edit by hand.",
        "",
        "export class %s {" % cls,
        "  constructor(private baseUrl: string) {}",
        "",
    ]
    for op in operations:
        meth = op.operation_id[:1].lower() + op.operation_id[1:] if op.operation_id else "op"
        path_params = _template_params(op.path)
        query_params = [p.name for p in op.params if p.location == "query"]
        args = ", ".join(["%s: string" % p for p in list(path_params) + query_params])
        url = op.path
        for pp in path_params:
            url = url.replace("{%s}" % pp, "${encodeURIComponent(%s)}" % pp)
        lines.append("  async %s(%s): Promise<unknown> {" % (meth, args))
        if query_params:
            qs = "const qs = new URLSearchParams({%s}).toString();" % ", ".join(
                query_params
            )
            lines.append("    %s" % qs)
            lines.append('    const url = `${this.baseUrl}%s?${qs}`;' % url)
        else:
            lines.append('    const url = `${this.baseUrl}%s`;' % url)
        lines.append("    const r = await fetch(url);")
        lines.append('    if (!r.ok) throw new Error(`HTTP ${r.status}`);')
        lines.append("    return r.json();")
        lines.append("  }")
        lines.append("")
    lines.append("}")
    lines.append("")
    return "\n".join(lines)


def _render_shell(title: str, operations: Tuple[OperationRecord, ...]) -> str:
    lines = [
        "#!/bin/sh",
        "# AUTO-GENERATED by northstar api-client-gen v1 -- do not edit by hand.",
        'BASE_URL="${1:?usage: client.sh <base-url>}"',
        "",
    ]
    for op in operations:
        fn = _snake(op.operation_id)
        url = op.path
        for i, pp in enumerate(_template_params(op.path)):
            url = url.replace("{%s}" % pp, '"$%d"' % (i + 2), 1)
        lines.append("%s() {" % fn)
        lines.append('  curl -fsS -X %s "$BASE_URL%s"' % (op.method.upper(), url))
        lines.append("}")
        lines.append("")
    return "\n".join(lines)


_RENDERERS = {
    "python": ("client.py", _render_python),
    "typescript": ("client.ts", _render_typescript),
    "shell": ("client.sh", _render_shell),
}


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------


class APIClientGen:
    """Deterministic single-host API-client-generation ledger."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._spec_counter = 0
        self._op_counter = 0
        self._bundle_counter = 0
        self._report_counter = 0
        self._specs: Dict[str, SpecRecord] = {}
        self._audit: list = []

    # -- internal ---------------------------------------------------------

    def _mutation_seq(self, seq: Any) -> int:
        """Validate a mutation seq; failed mutations consume their seq."""
        checked = _check_seq(seq, self._last_seq)
        self._last_seq = checked
        return checked

    def _note(self, kind: str, seq: int, **detail: Any) -> None:
        self._audit.append(api_client_gen_audit_event(kind, seq, **detail))

    # -- parse ------------------------------------------------------------

    def parse(self, spec_text: Any, seq: Any) -> SpecRecord:
        """Parse and pin an OpenAPI-ish JSON spec document."""
        seq = self._mutation_seq(seq)
        with self._lock:
            if not isinstance(spec_text, str) or not spec_text.strip():
                self._note("rejected", seq, reason="empty-spec")
                raise BadSpecError("spec_text must be a non-empty str")
            if len(spec_text) > MAX_SPEC_LEN:
                self._note("rejected", seq, reason="spec-too-large")
                raise BadSpecError("spec_text too long (max %d)" % MAX_SPEC_LEN)
            try:
                doc = json.loads(spec_text)
            except (json.JSONDecodeError, ValueError) as exc:
                self._note("rejected", seq, reason="bad-json")
                raise BadSpecError("spec is not valid JSON: %s" % exc)
            title, spec_version, trips = _parse_spec_document(doc)
            seen: Dict[str, Tuple[str, str]] = {}
            operations: list = []
            for path, method, operation in trips:
                op_id_raw = operation.get("operationId")
                if not isinstance(op_id_raw, str) or not op_id_raw.strip():
                    self._note("rejected", seq, reason="missing-operation-id")
                    raise BadSpecError(
                        "operation %s %s needs an operationId" % (method, path)
                    )
                operation_id = op_id_raw.strip()
                if operation_id in seen:
                    self._note("rejected", seq, reason="duplicate-operation-id")
                    raise DuplicateOperationError(
                        "duplicate operationId %r" % (operation_id,)
                    )
                seen[operation_id] = (method, path)
                summary = operation.get("summary", "")
                if not isinstance(summary, str):
                    summary = ""
                params_raw = operation.get("parameters", [])
                if not isinstance(params_raw, list):
                    self._note("rejected", seq, reason="bad-parameters")
                    raise BadSpecError("parameters of %r must be a list" % (operation_id,))
                params = tuple(_parse_param(p, path) for p in params_raw)
                self._op_counter += 1
                operations.append(
                    OperationRecord(
                        operation_id=operation_id,
                        op_id="op-%d" % self._op_counter,
                        method=method,
                        path=path,
                        summary=summary,
                        params=params,
                    )
                )
            self._spec_counter += 1
            spec_id = "spec-%d" % self._spec_counter
            record = SpecRecord(
                spec_id=spec_id,
                title=title,
                spec_version=spec_version,
                operations=tuple(operations),
                pin=_pin(
                    {
                        "spec_id": spec_id,
                        "title": title,
                        "spec_version": spec_version,
                        "operations": [o.as_dict() for o in operations],
                    }
                ),
                seq=seq,
            )
            self._specs[spec_id] = record
            self._note(
                "spec-parsed",
                seq,
                spec_id=spec_id,
                operations=len(operations),
                pin=record.pin,
            )
            return record

    # -- generate ---------------------------------------------------------

    def generate(self, spec_id: Any, language: Any, seq: Any) -> ClientBundle:
        """Render a deterministic client bundle from a parsed spec."""
        seq = self._mutation_seq(seq)
        with self._lock:
            _check_id(spec_id, "spec_id")
            if spec_id not in self._specs:
                self._note("rejected", seq, reason="unknown-spec")
                raise UnknownSpecError("unknown spec_id %r" % (spec_id,))
            if not isinstance(language, str) or language not in LANGUAGES:
                self._note("rejected", seq, reason="unknown-language")
                raise UnknownLanguageError("unknown language %r" % (language,))
            spec = self._specs[spec_id]
            file_name, renderer = _RENDERERS[language]
            code = renderer(spec.title, spec.operations)
            self._bundle_counter += 1
            bundle_id = "gen-%d" % self._bundle_counter
            bundle = ClientBundle(
                bundle_id=bundle_id,
                spec_id=spec_id,
                language=language,
                file_name=file_name,
                code=code,
                pin=_pin(
                    {
                        "bundle_id": bundle_id,
                        "spec_id": spec_id,
                        "language": language,
                        "file_name": file_name,
                        "code": code,
                    }
                ),
                seq=seq,
            )
            self._note(
                "client-generated",
                seq,
                bundle_id=bundle_id,
                spec_id=spec_id,
                language=language,
                pin=bundle.pin,
            )
            return bundle

    # -- validate ---------------------------------------------------------

    def validate(self, spec_id: Any, seq: Any) -> ValidationReport:
        """Validate a spec against the pinned rule set (pure observation)."""
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise APIClientGenError("seq must be a non-negative int")
        with self._lock:
            _check_id(spec_id, "spec_id")
            if spec_id not in self._specs:
                raise UnknownSpecError("unknown spec_id %r" % (spec_id,))
            spec = self._specs[spec_id]
            findings: list = []
            counter = [0]

            def add(rule: str, severity: str, message: str) -> None:
                counter[0] += 1
                findings.append(
                    Finding(
                        finding_id="find-%d" % counter[0],
                        rule=rule,
                        severity=severity,
                        message=message,
                    )
                )

            if not spec.title:
                add("missing-info", "error", "info.title is empty")
            if not spec.operations:
                add("empty-paths", "warning", "spec defines no operations")
            seen_ops: Dict[str, str] = {}
            for op in spec.operations:
                if op.operation_id in seen_ops:
                    add(
                        "duplicate-operation-id",
                        "error",
                        "operationId %r duplicated" % (op.operation_id,),
                    )
                else:
                    seen_ops[op.operation_id] = op.op_id
                declared_path = {p.name for p in op.params if p.location == "path"}
                for name in _template_params(op.path):
                    if name not in declared_path:
                        add(
                            "path-param-undeclared",
                            "error",
                            "%s %s: template param {%s} not declared"
                            % (op.method.upper(), op.path, name),
                        )
                for p in op.params:
                    if p.location == "path" and p.name not in _template_params(op.path):
                        add(
                            "undeclared-path-param-not-required",
                            "warning",
                            "%s %s: path param %r not in template"
                            % (op.method.upper(), op.path, p.name),
                        )
                    if p.location == "path" and not p.required:
                        add(
                            "undeclared-path-param-not-required",
                            "error",
                            "%s %s: path param %r must be required"
                            % (op.method.upper(), op.path, p.name),
                        )
            self._report_counter += 1
            report_id = "val-%d" % self._report_counter
            valid = not any(f.severity == "error" for f in findings)
            report = ValidationReport(
                report_id=report_id,
                spec_id=spec_id,
                valid=valid,
                findings=tuple(findings),
                pin=_pin(
                    {
                        "report_id": report_id,
                        "spec_id": spec_id,
                        "valid": valid,
                        "findings": [f.as_dict() for f in findings],
                    }
                ),
                seq=seq,
            )
            self._note(
                "validated",
                seq,
                report_id=report_id,
                spec_id=spec_id,
                valid=valid,
                findings=len(findings),
            )
            return report

    # -- views ------------------------------------------------------------

    def spec(self, spec_id: str) -> SpecRecord:
        _check_id(spec_id, "spec_id")
        with self._lock:
            if spec_id not in self._specs:
                raise UnknownSpecError("unknown spec_id %r" % (spec_id,))
            return self._specs[spec_id]

    def spec_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._specs))

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(self._audit)


# ---------------------------------------------------------------------------
# Audit helper
# ---------------------------------------------------------------------------


def api_client_gen_audit_event(
    kind: str, seq: int, **detail: Any
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for api-client-gen activity."""
    if kind not in _AUDIT_KINDS:
        raise APIClientGenError("unknown audit kind %r" % (kind,))
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise APIClientGenError("seq must be a non-negative int")
    event: Dict[str, Any] = {
        "schema": AUDIT_SCHEMA,
        "event": kind,
        "audit_seq": seq,
        "module_version": API_CLIENT_GEN_VERSION,
        "module_schema": API_CLIENT_GEN_SCHEMA,
    }
    for key, value in detail.items():
        if key in ("spec_text", "code", "text"):
            raise APIClientGenError(
                "audit boundary must never carry spec text or generated code"
            )
        event[key] = value
    return event


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------


_DEMO_SPEC = json.dumps(
    {
        "openapi": "3.0.0",
        "info": {"title": "Pet Store", "version": "1.0.0"},
        "paths": {
            "/pets/{petId}": {
                "get": {
                    "operationId": "getPet",
                    "summary": "Fetch a pet",
                    "parameters": [
                        {
                            "name": "petId",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"},
                        },
                        {
                            "name": "detail",
                            "in": "query",
                            "required": False,
                            "schema": {"type": "string"},
                        },
                    ],
                    "responses": {"200": {"description": "ok"}},
                }
            }
        },
    }
)


def main() -> None:
    """Self-check: parse, generate, validate, refusals."""
    gen = APIClientGen()
    spec = gen.parse(_DEMO_SPEC, 0)
    assert spec.pin.startswith("sha256:")
    assert spec.spec_id == "spec-1"

    py_bundle = gen.generate(spec.spec_id, "python", 1)
    assert py_bundle.verify()
    assert "def get_pet(self, petId, detail):" in py_bundle.code
    assert "requests.get" in py_bundle.code

    ts_bundle = gen.generate(spec.spec_id, "typescript", 2)
    assert ts_bundle.verify()
    assert "async getPet(" in ts_bundle.code

    sh_bundle = gen.generate(spec.spec_id, "shell", 3)
    assert sh_bundle.verify()
    assert sh_bundle.code.startswith("#!/bin/sh")

    # Determinism across instances.
    gen2 = APIClientGen()
    spec2 = gen2.parse(_DEMO_SPEC, 0)
    b2 = gen2.generate(spec2.spec_id, "python", 1)
    assert b2.code == py_bundle.code

    report = gen.validate(spec.spec_id, 4)
    assert report.valid, [f.as_dict() for f in report.findings]
    assert report.verify()

    # Refusals.
    try:
        gen.parse("{not json", 5)
    except BadSpecError:
        pass
    else:  # pragma: no cover
        raise AssertionError("bad json must be refused")
    try:
        gen.generate(spec.spec_id, "cobol", 6)
    except UnknownLanguageError:
        pass
    else:  # pragma: no cover
        raise AssertionError("unknown language must be refused")
    try:
        gen.generate("spec-999", "python", 7)
    except UnknownSpecError:
        pass
    else:  # pragma: no cover
        raise AssertionError("unknown spec must be refused")
    print("api-client-gen OK: parse, generate, validate, pins, audit")


if __name__ == "__main__":
    main()

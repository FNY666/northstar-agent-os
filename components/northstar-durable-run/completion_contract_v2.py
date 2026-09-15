"""Test-only completion contract for stateful agent evaluation.

This module deliberately stays outside production TaskOutcome.ok. It models the
minimum evidence conjunction found in the research batch: host-owned artifact
expectations, independent before/after workspace state, optional ordered
milestones, and a versioned provenance envelope.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any, Mapping

_CONTRACT_REVISION = "completion-v2"
_DIGEST_RE = re.compile(r"^sha256:[0-9a-fA-F]{64}$")
_PATH_MAX = 1_024
_PROVENANCE_FIELDS = (
    "contract_revision",
    "evaluator_digest",
    "fixture_digest",
    "benchmark_commit",
    "environment_digest",
    "model_id",
    "model_revision",
    "reasoning_effort",
    "max_output_tokens",
    "seed",
    "trial_id",
)


def _path(value: Any, field: str = "path") -> str:
    if not isinstance(value, str) or not value or len(value) > _PATH_MAX:
        raise ValueError(f"{field} is invalid")
    parts = value.split("/")
    if value.startswith("/") or any(
        part in {"", ".", ".."} or "\\" in part or "\x00" in part
        for part in parts
    ):
        raise ValueError(f"{field} must be a safe relative path")
    return value


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _semantic_errors(
    content: str, fields: tuple[SemanticField, ...]
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    """Parse key/value lines without trusting prose claims.

    The first tuple contains absent fields (insufficient information); the
    second contains present-but-wrong or explicitly negated fields (failure).
    """
    normalized: dict[str, str] = {}
    conflicts: list[str] = []
    for line in content.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        canonical = re.sub(r"[^a-z0-9]+", "_", key.lower()).strip("_")
        value = value.strip()
        if canonical in normalized and normalized[canonical] != value:
            conflicts.append(canonical)
        normalized[canonical] = value
    missing = []
    errors = []
    for field in fields:
        actual = next(
            (normalized[label] for label in field.canonical_labels if label in normalized),
            None,
        )
        expected = field.expected_value.strip()
        if actual is None:
            missing.append(field.canonical_name)
            continue
        lowered = actual.lower()
        expected_lowered = expected.lower()
        negated = re.search(
            r"(?:^|\\b)(?:not|false|unknown|unverified|incorrect|no)\\b",
            lowered,
        )
        if field.mode == "exact":
            matches = lowered == expected_lowered
        else:
            matches = expected_lowered in lowered
        if not matches or negated:
            errors.append(field.canonical_name)
    return tuple(missing), tuple(errors), tuple(sorted(set(conflicts)))


@dataclass(frozen=True)
class SemanticField:
    """A host-owned semantic requirement with explicit parsing flexibility.

    ``exact`` requires a parsed value to equal the expected value. ``contains``
    permits legitimate format decoration (punctuation, score annotations,
    Markdown), but still rejects explicit negation and missing evidence.
    ``aliases`` are host-owned labels, not model-provided schema.
    """

    name: str
    expected_value: str
    mode: str = "exact"
    aliases: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if (
            not isinstance(self.name, str)
            or not self.name
            or len(self.name) > 128
            or not re.fullmatch(r"[A-Za-z0-9_.-]+", self.name)
        ):
            raise ValueError("semantic field name is invalid")
        if not isinstance(self.expected_value, str) or not self.expected_value:
            raise ValueError("semantic field expected value is invalid")
        if self.mode not in {"exact", "contains"}:
            raise ValueError("semantic field mode is invalid")
        aliases = tuple(self.aliases)
        if any(not isinstance(alias, str) or not alias for alias in aliases):
            raise ValueError("semantic field aliases are invalid")
        object.__setattr__(self, "aliases", aliases)

    @property
    def canonical_name(self) -> str:
        return re.sub(r"[^a-z0-9]+", "_", self.name.lower()).strip("_")

    @property
    def canonical_labels(self) -> tuple[str, ...]:
        return tuple(
            re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")
            for value in (self.name, *self.aliases)
        )


@dataclass(frozen=True)
class ArtifactExpectation:
    path: str
    exact_content: str | None = None
    exact_digest: str | None = None
    semantic_fields: tuple[SemanticField, ...] | None = None

    def __post_init__(self) -> None:
        _path(self.path, "artifact path")
        fields = tuple(self.semantic_fields or ())
        declared = [
            self.exact_content is not None,
            self.exact_digest is not None,
            self.semantic_fields is not None,
        ]
        if sum(declared) != 1:
            raise ValueError("artifact needs exactly one expectation kind")
        if self.semantic_fields is not None:
            if not fields:
                raise ValueError("semantic fields must be non-empty")
            names = [field.canonical_name for field in fields]
            if any(not isinstance(field, SemanticField) for field in fields):
                raise ValueError("semantic fields are invalid")
            if len(set(names)) != len(names):
                raise ValueError("semantic field names must be unique")
            object.__setattr__(self, "semantic_fields", fields)
        if self.exact_digest is not None and not _DIGEST_RE.fullmatch(self.exact_digest):
            raise ValueError("artifact digest is invalid")

    @property
    def expected_digest(self) -> str:
        if self.semantic_fields is not None:
            raise ValueError("semantic artifact has no single expected digest")
        if self.exact_digest is not None:
            return self.exact_digest.lower()
        return _digest(self.exact_content.encode("utf-8"))  # type: ignore[union-attr]


@dataclass(frozen=True)
class Provenance:
    contract_revision: str
    evaluator_digest: str
    fixture_digest: str
    benchmark_commit: str
    environment_digest: str
    model_id: str
    model_revision: str
    reasoning_effort: str
    max_output_tokens: int
    seed: str
    trial_id: str

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Provenance":
        if not isinstance(value, Mapping):
            raise ValueError("provenance must be an object")
        missing = [field for field in _PROVENANCE_FIELDS if field not in value]
        if missing:
            raise ValueError("provenance missing: " + ",".join(missing))
        for field in _PROVENANCE_FIELDS:
            item = value[field]
            if field == "max_output_tokens":
                if type(item) is not int or not 1 <= item <= 32_768:
                    raise ValueError("provenance max_output_tokens is invalid")
            elif not isinstance(item, str) or not item or len(item) > _PATH_MAX:
                raise ValueError(f"provenance {field} is invalid")
        if value["reasoning_effort"] not in {"off", "low", "medium", "high"}:
            raise ValueError("provenance reasoning_effort is invalid")
        return cls(**{field: value[field] for field in _PROVENANCE_FIELDS})

    def as_dict(self) -> dict[str, Any]:
        return {field: getattr(self, field) for field in _PROVENANCE_FIELDS}


@dataclass(frozen=True)
class _SnapshotItem:
    digest: str
    content: str | None


@dataclass(frozen=True)
class WorkspaceSnapshot:
    files: dict[str, _SnapshotItem]

    @classmethod
    def from_files(cls, files: Mapping[str, str]) -> "WorkspaceSnapshot":
        if not isinstance(files, Mapping):
            raise ValueError("snapshot files must be an object")
        result: dict[str, _SnapshotItem] = {}
        for name, value in files.items():
            name = _path(name, "snapshot path")
            if not isinstance(value, str) or not value:
                raise ValueError("snapshot value must be non-empty text or digest")
            if value.startswith("sha256:"):
                if not _DIGEST_RE.fullmatch(value):
                    raise ValueError("snapshot digest is invalid")
                digest = value.lower()
                content = None
            else:
                digest = _digest(value.encode("utf-8"))
                content = value
            result[name] = _SnapshotItem(digest=digest, content=content)
        return cls(files=result)

    def as_dict(self) -> dict[str, str]:
        return {name: item.digest for name, item in sorted(self.files.items())}


@dataclass(frozen=True)
class CompletionResult:
    verdict: str
    errors: tuple[str, ...]
    mutation_paths: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.verdict not in {"verified", "failed", "unknown", "insufficient_information"}:
            raise ValueError("completion verdict is invalid")

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "errors": list(self.errors),
            "mutation_paths": list(self.mutation_paths),
        }


@dataclass(frozen=True)
class CompletionContractV2:
    required_artifacts: tuple[ArtifactExpectation, ...]
    allowed_mutations: tuple[str, ...]
    required_milestones: tuple[str, ...]
    milestone_edges: tuple[tuple[str, str], ...]
    expected_provenance: Provenance

    def __post_init__(self) -> None:
        if not isinstance(self.expected_provenance, Provenance):
            raise ValueError("expected_provenance must be Provenance")
        artifacts = tuple(self.required_artifacts)
        if len({item.path for item in artifacts}) != len(artifacts):
            raise ValueError("required artifact paths must be unique")
        allowed = tuple(_path(item, "allowed mutation") for item in self.allowed_mutations)
        if len(set(allowed)) != len(allowed):
            raise ValueError("allowed mutation paths must be unique")
        milestones = tuple(self.required_milestones)
        if len(set(milestones)) != len(milestones) or any(
            not isinstance(item, str) or not item for item in milestones
        ):
            raise ValueError("required milestones must be unique non-empty strings")
        for edge in self.milestone_edges:
            if (
                not isinstance(edge, tuple)
                or len(edge) != 2
                or edge[0] not in milestones
                or edge[1] not in milestones
                or edge[0] == edge[1]
            ):
                raise ValueError("milestone edge is invalid")
        if len(set(self.milestone_edges)) != len(self.milestone_edges):
            raise ValueError("milestone edges must be unique")
        object.__setattr__(self, "required_artifacts", artifacts)
        object.__setattr__(self, "allowed_mutations", allowed)
        object.__setattr__(self, "required_milestones", milestones)
        object.__setattr__(self, "milestone_edges", tuple(self.milestone_edges))

    def _provenance_errors(self, actual: Provenance | None) -> list[str]:
        if actual is None:
            return ["provenance_missing"]
        if not isinstance(actual, Provenance):
            return ["provenance_invalid"]
        return [
            f"provenance_mismatch:{field}"
            for field in _PROVENANCE_FIELDS
            if getattr(actual, field) != getattr(self.expected_provenance, field)
        ]

    def _milestone_errors(self, milestones: tuple[str, ...] | None) -> tuple[str, list[str]]:
        if milestones is None:
            return "insufficient_information", ["milestones_missing"]
        if any(not isinstance(item, str) or not item for item in milestones):
            return "insufficient_information", ["milestones_invalid"]
        missing = [item for item in self.required_milestones if item not in milestones]
        if missing:
            return "insufficient_information", ["milestones_missing:" + ",".join(missing)]
        positions = {item: index for index, item in enumerate(milestones)}
        for before, after in self.milestone_edges:
            if positions[before] >= positions[after]:
                return "failed", ["milestone_order_invalid"]
        return "ok", []

    def _mutations(
        self, before: WorkspaceSnapshot, after: WorkspaceSnapshot
    ) -> tuple[str, ...]:
        names = set(before.files) | set(after.files)
        return tuple(
            sorted(
                name
                for name in names
                if before.files.get(name) != after.files.get(name)
            )
        )

    def evaluate(
        self,
        *,
        before: WorkspaceSnapshot,
        after: WorkspaceSnapshot,
        milestones: tuple[str, ...] | None,
        provenance: Provenance | None,
        run_status: str,
        workspace_root: str | None = None,
    ) -> CompletionResult:
        if not isinstance(before, WorkspaceSnapshot) or not isinstance(after, WorkspaceSnapshot):
            raise ValueError("before and after must be WorkspaceSnapshot")
        if not isinstance(run_status, str) or not run_status:
            raise ValueError("run_status is invalid")
        mutations = self._mutations(before, after)
        if run_status != "finished":
            return CompletionResult("unknown", (f"run_not_finished:{run_status}",), mutations)
        provenance_errors = self._provenance_errors(provenance)
        if provenance is None:
            return CompletionResult("insufficient_information", tuple(provenance_errors), mutations)
        if provenance_errors:
            return CompletionResult("failed", tuple(provenance_errors), mutations)
        milestone_status, milestone_errors = self._milestone_errors(milestones)
        if milestone_status == "insufficient_information":
            return CompletionResult(milestone_status, tuple(milestone_errors), mutations)
        if milestone_status == "failed":
            return CompletionResult("failed", tuple(milestone_errors), mutations)
        errors: list[str] = []
        information_gaps: list[str] = []
        allowed = set(self.allowed_mutations)
        errors.extend(f"unapproved_mutation:{path}" for path in mutations if path not in allowed)
        for artifact in self.required_artifacts:
            item = after.files.get(artifact.path)
            if item is None:
                errors.append(f"{artifact.path}:missing")
                continue
            if artifact.semantic_fields is not None:
                if item.content is None:
                    information_gaps.append(f"{artifact.path}:semantic_content_unavailable")
                    continue
                missing_fields, semantic_errors, semantic_conflicts = _semantic_errors(
                    item.content, artifact.semantic_fields
                )
                errors.extend(
                    f"{artifact.path}:semantic_field_conflict:{field_name}"
                    for field_name in semantic_conflicts
                )
                if missing_fields:
                    information_gaps.append(
                        f"{artifact.path}:semantic_fields_missing:{','.join(missing_fields)}"
                    )
                errors.extend(
                    f"{artifact.path}:semantic_field:{field_name}"
                    for field_name in semantic_errors
                )
            elif item.digest.lower() != artifact.expected_digest:
                errors.append(f"{artifact.path}:exact_content_mismatch")
        if errors:
            return CompletionResult("failed", tuple(errors), mutations)
        if information_gaps:
            return CompletionResult("insufficient_information", tuple(information_gaps), mutations)
        return CompletionResult("verified", (), mutations)

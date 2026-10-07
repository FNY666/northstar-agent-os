"""Few-shot / in-context learning example ledger, simulated.

Research motivation: few-shot (in-context) learning (Brown et al.,
2020) is the dominant way agents steer a frozen model: book a small set
of labeled demonstrations, retrieve the k most relevant ones for the
current task, and prepend them to the prompt as "Input/Output" pairs.
Every credible pipeline reduces to the same ledger: declare examples,
record retrieval decisions, and compose prompt blocks deterministically.
Getting the bookkeeping wrong (silent example replacement, duplicate
ids, nondeterministic retrieval order) makes the prompt unreproducible
and the eval numbers meaningless.

This module is the *example-management* layer:

- ``FewShotLearning.example(example_id, input_text, output_text, seq,
  tags=())`` -- declare one labeled demonstration. Returns a frozen
  ``ExampleRecord`` with a ``sha256:`` digest pin. Duplicate ids are
  refused fail-closed; ids are never recycled.
- ``FewShotLearning.select(seq, k=4, tags=())`` -- book one retrieval
  decision: the first ``k`` examples (tag-filtered when ``tags`` is
  given, deterministic ``example_id`` order). Returns a frozen
  ``SelectionRecord`` (``sel-N`` ids). ``k=0`` and ``k > n`` are data,
  not errors.
- ``FewShotLearning.prompt(seq, selection_id, instruction="",
  prefix="")`` -- compose a deterministic few-shot prompt block from a
  booked selection: ``instruction`` (when non-empty), then each
  example as ``"Input: <input>\\nOutput: <output>"`` pairs in
  selection order, then ``prefix`` (when non-empty). Returns a frozen
  ``PromptRecord`` with a digest pin over the rendered text. Unknown
  selections are refused fail-closed.
- Pure read views: ``example_record()``, ``example_ids()``,
  ``selection_report()``, ``stats()`` -- validate the seq shape,
  consume nothing, write no audit rows.
- ``few_shot_learning_audit_event(kind, ...)`` -- ``audit.ndjson/1``
  records (``example-registered`` / ``selected`` / ``prompt-built`` /
  ``rejected``); caller-supplied seqs only. Raw example text never
  crosses the audit boundary -- audit rows carry ids, counts, and
  digest pins only.

Fail-closed edges (fail loudly, never guess):

- ``example_id`` must be a non-empty str, <= 256 chars, no whitespace.
- ``input_text`` / ``output_text`` must be non-empty str, <= 65536
  chars.
- ``tags`` must be a tuple/list of non-empty str, <= 256 chars each;
  duplicates refused.
- Duplicate example ids raise ``DuplicateExampleError``; selecting is
  always possible (empty result as data); prompting an unknown
  ``selection_id`` raises ``UnknownSelectionError``.
- ``k`` must be an int (not bool), >= 0.
- Seqs are ints (not bool), >= 0, strictly increasing per instance.
  Failed mutations consume their seq and book a ``rejected`` audit
  row; seq rewinds raise bare ``SeqOrderError`` without consuming.

Honest scope:

- This module books *declared* examples and *declared* retrieval and
  composition decisions. It does not call a model, does not score
  relevance with embeddings, and cannot prove the host's examples are
  correct -- examples are GIGO.
- Retrieval here is deterministic filtering (tag match + id order),
  not a similarity search; the point is reproducibility, not quality.
- No persistence: the ledger is in-memory. Pair with the durable
  audit writer if example state must survive a restart.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()

VERSION = "few-shot-learning.v1"
SCHEMA = "northstar.few-shot-learning.v1"

KIND_EXAMPLE_REGISTERED = "example-registered"
KIND_SELECTED = "selected"
KIND_PROMPT_BUILT = "prompt-built"
KIND_REJECTED = "rejected"

_KINDS = (KIND_EXAMPLE_REGISTERED, KIND_SELECTED, KIND_PROMPT_BUILT,
          KIND_REJECTED)

_MAX_ID_LEN = 256
_MAX_TEXT_LEN = 65536
_MAX_TAGS = 32


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class FewShotLearningError(Exception):
    """Base class for all few-shot-learning ledger errors."""


class BadExampleError(FewShotLearningError):
    """example_id / tags are malformed."""


class DuplicateExampleError(FewShotLearningError):
    """example_id is already booked (ids are never recycled)."""


class BadInputError(FewShotLearningError):
    """input_text is malformed."""


class BadOutputError(FewShotLearningError):
    """output_text is malformed."""


class BadKError(FewShotLearningError):
    """k is malformed."""


class BadTagError(FewShotLearningError):
    """A tag is malformed or duplicated."""


class BadPromptError(FewShotLearningError):
    """instruction / prefix is malformed."""


class UnknownSelectionError(FewShotLearningError):
    """selection_id names no booked selection."""


class SeqOrderError(FewShotLearningError):
    """Seq is malformed or not strictly increasing."""


class AuditKindError(FewShotLearningError):
    """Audit event kind is not in the pinned vocabulary."""


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"seq must be int, got {type(seq).__name__}")
    if seq < 0:
        raise SeqOrderError(f"seq must be >= 0, got {seq}")
    return seq


def _check_id(value: Any, what: str) -> str:
    if not isinstance(value, str):
        raise BadExampleError(f"{what} must be str, got {type(value).__name__}")
    if not value or len(value) > _MAX_ID_LEN:
        raise BadExampleError(
            f"{what} must be 1..{_MAX_ID_LEN} chars, got len={len(value)}")
    if any(ch.isspace() for ch in value):
        raise BadExampleError(f"{what} must not contain whitespace: {value!r}")
    return value


def _check_text(value: Any, what: str, err: type) -> str:
    if not isinstance(value, str):
        raise err(f"{what} must be str, got {type(value).__name__}")
    if not value or len(value) > _MAX_TEXT_LEN:
        raise err(
            f"{what} must be 1..{_MAX_TEXT_LEN} chars, got len={len(value)}")
    return value


def _check_tags(tags: Any) -> Tuple[str, ...]:
    if not isinstance(tags, (tuple, list)):
        raise BadTagError(
            f"tags must be tuple/list, got {type(tags).__name__}")
    if len(tags) > _MAX_TAGS:
        raise BadTagError(f"at most {_MAX_TAGS} tags, got {len(tags)}")
    seen = set()
    out = []
    for tag in tags:
        if not isinstance(tag, str) or not tag or len(tag) > _MAX_ID_LEN:
            raise BadTagError(f"tag must be 1..{_MAX_ID_LEN} chars str")
        if any(ch.isspace() for ch in tag):
            raise BadTagError(f"tag must not contain whitespace: {tag!r}")
        if tag in seen:
            raise BadTagError(f"duplicate tag: {tag!r}")
        seen.add(tag)
        out.append(tag)
    return tuple(out)


def _check_k(k: Any) -> int:
    if isinstance(k, bool) or not isinstance(k, int):
        raise BadKError(f"k must be int, got {type(k).__name__}")
    if k < 0:
        raise BadKError(f"k must be >= 0, got {k}")
    return k


def _digest_pin(obj: Mapping[str, Any]) -> str:
    return "sha256:" + jcs_sha256_hex(dict(obj))


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

def few_shot_learning_audit_event(kind: str, seq: int,
                                  details: Mapping[str, Any]) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event for the few-shot ledger.

    Raw example text (``input`` / ``output`` / ``instruction`` /
    ``prefix`` / ``rendered``) never crosses the audit boundary: callers
    must pass ids, counts, and digest pins only.
    """
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    banned = {"input", "output", "instruction", "prefix", "rendered",
              "input_text", "output_text", "value", "payload", "raw"}
    for key in details:
        if key in banned:
            raise AuditKindError(
                f"raw text must not cross the audit boundary: {key!r}")
    event = {
        "schema": "audit.ndjson/1",
        "module": "few-shot-learning",
        "version": VERSION,
        "kind": kind,
        "seq": seq,
        "details": dict(details),
    }
    return event


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ExampleRecord:
    example_id: str
    input_digest: str
    output_digest: str
    tags: Tuple[str, ...]
    seq: int
    record_digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "example_id": self.example_id,
            "input_digest": self.input_digest,
            "output_digest": self.output_digest,
            "tags": list(self.tags),
            "seq": self.seq,
            "record_digest": self.record_digest,
        }

    def verify(self) -> bool:
        want = _digest_pin({
            "example_id": self.example_id,
            "input_digest": self.input_digest,
            "output_digest": self.output_digest,
            "tags": list(self.tags),
            "seq": self.seq,
        })
        return want == self.record_digest


@dataclass(frozen=True)
class SelectionRecord:
    selection_id: str
    k: int
    tags: Tuple[str, ...]
    example_ids: Tuple[str, ...]
    seq: int
    record_digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "selection_id": self.selection_id,
            "k": self.k,
            "tags": list(self.tags),
            "example_ids": list(self.example_ids),
            "seq": self.seq,
            "record_digest": self.record_digest,
        }

    def verify(self) -> bool:
        want = _digest_pin({
            "selection_id": self.selection_id,
            "k": self.k,
            "tags": list(self.tags),
            "example_ids": list(self.example_ids),
            "seq": self.seq,
        })
        return want == self.record_digest


@dataclass(frozen=True)
class PromptRecord:
    selection_id: str
    example_ids: Tuple[str, ...]
    example_count: int
    rendered_digest: str
    seq: int
    record_digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "selection_id": self.selection_id,
            "example_ids": list(self.example_ids),
            "example_count": self.example_count,
            "rendered_digest": self.rendered_digest,
            "seq": self.seq,
            "record_digest": self.record_digest,
        }

    def verify(self) -> bool:
        want = _digest_pin({
            "selection_id": self.selection_id,
            "example_ids": list(self.example_ids),
            "example_count": self.example_count,
            "rendered_digest": self.rendered_digest,
            "seq": self.seq,
        })
        return want == self.record_digest


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------

class FewShotLearning:
    """Deterministic in-context example / retrieval / prompt ledger."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = -1
        self._examples: Dict[str, ExampleRecord] = {}
        self._inputs: Dict[str, str] = {}
        self._outputs: Dict[str, str] = {}
        self._selections: Dict[str, SelectionRecord] = {}
        self._sel_counter = 0
        self._prompts: List[PromptRecord] = []
        self._audit: List[Dict[str, Any]] = []
        self._rejected = 0

    # -- internals ------------------------------------------------------

    def _claim(self, seq: Any) -> int:
        """Validate seq; rewinds raise bare (no consumption, no audit)."""
        _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError(
                f"seq must be strictly increasing: got {seq}, last {self._seq}")
        return seq

    def _burn(self, seq: int, error: Exception) -> None:
        """Consume the seq, book a rejected row, then raise."""
        self._seq = seq
        self._rejected += 1
        self._emit(KIND_REJECTED, seq, {"reason": type(error).__name__})
        raise error

    def _emit(self, audit_kind: str, seq: int,
              details: Mapping[str, Any]) -> None:
        self._audit.append(
            few_shot_learning_audit_event(audit_kind, seq, details))

    # -- mutations ------------------------------------------------------

    def example(self, example_id: str, input_text: str, output_text: str,
                seq: int, tags: Sequence[str] = ()) -> ExampleRecord:
        """Declare one labeled demonstration."""
        with self._lock:
            seq = self._claim(seq)
            try:
                eid = _check_id(example_id, "example_id")
                in_text = _check_text(input_text, "input_text", BadInputError)
                out_text = _check_text(output_text, "output_text",
                                       BadOutputError)
                tag_tuple = _check_tags(tags)
                if eid in self._examples:
                    raise DuplicateExampleError(
                        f"example already registered: {eid!r}")
            except FewShotLearningError as exc:
                self._burn(seq, exc)
            in_digest = "sha256:" + hashlib.sha256(
                in_text.encode("utf-8")).hexdigest()
            out_digest = "sha256:" + hashlib.sha256(
                out_text.encode("utf-8")).hexdigest()
            record = ExampleRecord(
                example_id=eid,
                input_digest=in_digest,
                output_digest=out_digest,
                tags=tag_tuple,
                seq=seq,
                record_digest=_digest_pin({
                    "example_id": eid,
                    "input_digest": in_digest,
                    "output_digest": out_digest,
                    "tags": list(tag_tuple),
                    "seq": seq,
                }),
            )
            self._examples[eid] = record
            self._inputs[eid] = in_text
            self._outputs[eid] = out_text
            self._seq = seq
            self._emit(KIND_EXAMPLE_REGISTERED, seq, {
                "example_id": eid,
                "input_digest": in_digest,
                "output_digest": out_digest,
                "tag_count": len(tag_tuple),
                "record_digest": record.record_digest,
            })
            return record

    def select(self, seq: int, k: int = 4,
               tags: Sequence[str] = ()) -> SelectionRecord:
        """Book one retrieval decision: the first ``k`` examples.

        Tag-filtered when ``tags`` is given; deterministic
        ``example_id`` ordering. ``k=0`` / ``k > n`` are data.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                kk = _check_k(k)
                tag_tuple = _check_tags(tags)
            except FewShotLearningError as exc:
                self._burn(seq, exc)
            candidates = [
                rec for rec in self._examples.values()
                if not tag_tuple or all(t in rec.tags for t in tag_tuple)
            ]
            candidates.sort(key=lambda r: r.example_id)
            chosen = candidates[:kk]
            self._sel_counter += 1
            sid = f"sel-{self._sel_counter}"
            ids = tuple(rec.example_id for rec in chosen)
            record = SelectionRecord(
                selection_id=sid,
                k=kk,
                tags=tag_tuple,
                example_ids=ids,
                seq=seq,
                record_digest=_digest_pin({
                    "selection_id": sid,
                    "k": kk,
                    "tags": list(tag_tuple),
                    "example_ids": list(ids),
                    "seq": seq,
                }),
            )
            self._selections[sid] = record
            self._seq = seq
            self._emit(KIND_SELECTED, seq, {
                "selection_id": sid,
                "k": kk,
                "tag_count": len(tag_tuple),
                "matched": len(candidates),
                "returned": len(ids),
                "record_digest": record.record_digest,
            })
            return record

    def prompt(self, seq: int, selection_id: str, instruction: str = "",
               prefix: str = "") -> Tuple[PromptRecord, str]:
        """Compose a deterministic few-shot prompt block.

        Returns ``(PromptRecord, rendered_text)``. The record pins only
        the digest of the rendered text; raw text stays out of the
        audit boundary.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                sid = _check_id(selection_id, "selection_id")
                if not isinstance(instruction, str):
                    raise BadPromptError("instruction must be str")
                if len(instruction) > _MAX_TEXT_LEN:
                    raise BadPromptError("instruction too long")
                if not isinstance(prefix, str):
                    raise BadPromptError("prefix must be str")
                if len(prefix) > _MAX_TEXT_LEN:
                    raise BadPromptError("prefix too long")
                if sid not in self._selections:
                    raise UnknownSelectionError(
                        f"unknown selection: {sid!r}")
            except FewShotLearningError as exc:
                self._burn(seq, exc)
            selection = self._selections[sid]
            blocks: List[str] = []
            if instruction:
                blocks.append(instruction)
            for eid in selection.example_ids:
                blocks.append(
                    f"Input: {self._inputs[eid]}\nOutput: {self._outputs[eid]}")
            if prefix:
                blocks.append(prefix)
            rendered = "\n\n".join(blocks)
            rendered_digest = "sha256:" + hashlib.sha256(
                rendered.encode("utf-8")).hexdigest()
            record = PromptRecord(
                selection_id=sid,
                example_ids=selection.example_ids,
                example_count=len(selection.example_ids),
                rendered_digest=rendered_digest,
                seq=seq,
                record_digest=_digest_pin({
                    "selection_id": sid,
                    "example_ids": list(selection.example_ids),
                    "example_count": len(selection.example_ids),
                    "rendered_digest": rendered_digest,
                    "seq": seq,
                }),
            )
            self._prompts.append(record)
            self._seq = seq
            self._emit(KIND_PROMPT_BUILT, seq, {
                "selection_id": sid,
                "example_count": len(selection.example_ids),
                "rendered_digest": rendered_digest,
                "record_digest": record.record_digest,
            })
            return record, rendered

    # -- pure read views -------------------------------------------------

    def example_record(self, example_id: str, seq: int) -> ExampleRecord:
        """Pure read: the frozen record for one example."""
        with self._lock:
            _check_seq(seq)
            eid = _check_id(example_id, "example_id")
            if eid not in self._examples:
                raise FewShotLearningError(f"unknown example: {eid!r}")
            return self._examples[eid]

    def example_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read: sorted example ids."""
        with self._lock:
            _check_seq(seq)
            return tuple(sorted(self._examples))

    def selection_report(self, selection_id: str, seq: int) -> SelectionRecord:
        """Pure read: the frozen record for one selection."""
        with self._lock:
            _check_seq(seq)
            sid = _check_id(selection_id, "selection_id")
            if sid not in self._selections:
                raise UnknownSelectionError(f"unknown selection: {sid!r}")
            return self._selections[sid]

    def stats(self, seq: int) -> Dict[str, Any]:
        """Pure read: ledger counters."""
        with self._lock:
            _check_seq(seq)
            return {
                "schema": SCHEMA,
                "version": VERSION,
                "examples": len(self._examples),
                "selections": len(self._selections),
                "prompts": len(self._prompts),
                "rejected": self._rejected,
            }

    def audit_log(self) -> List[Dict[str, Any]]:
        """Return a copy of the audit events booked so far."""
        with self._lock:
            return list(self._audit)


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------

def main() -> None:
    fsl = FewShotLearning()
    ex1 = fsl.example("ex-1", "2+2", "4", seq=1, tags=("math",))
    ex2 = fsl.example("ex-2", "3*3", "9", seq=2, tags=("math",))
    fsl.example("ex-3", "hello", "bonjour", seq=3, tags=("lang",))
    assert ex1.verify() and ex2.verify()
    sel = fsl.select(seq=4, k=2, tags=("math",))
    assert sel.verify() and sel.example_ids == ("ex-1", "ex-2")
    rec, text = fsl.prompt(seq=5, selection_id=sel.selection_id,
                           instruction="Solve:", prefix="Input: 1+1\nOutput:")
    assert rec.verify()
    assert text == ("Solve:\n\nInput: 2+2\nOutput: 4\n\n"
                    "Input: 3*3\nOutput: 9\n\nInput: 1+1\nOutput:")
    assert fsl.stats(6)["examples"] == 3
    # fail-closed spot checks (each burned seq advances the frontier)
    cases = [
        (lambda s: fsl.example("ex-1", "x", "y", seq=s), DuplicateExampleError),
        (lambda s: fsl.select(seq=s, k=-1), BadKError),
        (lambda s: fsl.prompt(seq=s, selection_id="sel-99"),
         UnknownSelectionError),
    ]
    seq = 7
    for fn, exc in cases:
        try:
            fn(seq)
        except exc:
            pass
        else:  # pragma: no cover
            raise AssertionError(f"expected {exc.__name__}")
        seq += 1
    print("few-shot-learning OK: example, select, prompt, pins, audit")


if __name__ == "__main__":
    main()

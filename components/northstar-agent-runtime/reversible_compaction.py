"""Make a compaction reversible: a record that can go back to before it.

Source (the excerpt carried by the slice brief is the source -- verbatim as
briefed; the post is not in this repository and was not crawled):

    "Four of the five died on the seam. The compaction event was the last
    substantive thing in the file, and after it came a tool result and then
    nothing."

and the author's own response to it:

    "Now I check the log first. If the last event is a tool result and there is
    a compaction somewhere upstream, I do not rewrite the prompt. I re-dispatch
    the same prompt. The prompt was probably fine. What got lost was the thread
    that was carrying it."

and the numbers behind it:

    "617 sessions total; 522 with no compaction; 95 with one or more; 5 with
    no prose at all; All 5 failures were in compacted sessions." /
    "1 compaction: 3 failures out of 64; 2 compactions: 2 failures out of 27;
    3 or more: 0 failures out of 4."

Northstar gap this closes (read from the code, not assumed):

* ``compaction.py`` is a **one-way door**.  ``compact()`` returns a
  ``CompactionOutcome`` whose ``transcript`` is ``(boundary,) + kept``: the
  summarised prefix is gone, replaced by one summary string.  Nothing in the
  outcome names the pre-compaction transcript; there is no hash of it, and no
  way to ask "give me the transcript as it was before this cut".
* ``checkpoints.py`` / ``checkpoint_store.py`` (the msaf-lineage slice) do
  carry a transcript digest -- ``checkpoints.digest_transcript()`` is a
  ``sha256`` over the canonical JSON of the message list -- and the store
  archives a checkpoint payload under a **checkpoint id** (a session id plus a
  trailing index).  That is a *resume* mechanism keyed by lineage, not a
  *revert* mechanism keyed by content: nothing in the repository can hand
  back the bytes that a compaction dropped.
* ``scope_verbatim_compaction.py`` (the sibling slice) guarantees the scope
  block crosses a compaction **verbatim** -- a forward invariant.  This module
  is the other half: it guarantees that a compaction can be **undone** -- a
  backward capability.  The two do not overlap: the scope slice protects the
  scope against being summarized away; this slice protects the *thread* when
  the session dies on the seam.

Design invariants this module enforces:

* **a reversible compaction carries both hashes** -- the hash of the
  pre-compaction transcript and the hash of the prompt that started it.  A
  compaction with either one missing is *not* reversible, and the record is
  refused rather than quietly minted without it,
* **the record stores hashes, never the transcript** -- storing the full
  transcript inside the record would defeat the compaction it describes,
* **revert is by hash, never by resemblance** -- a candidate is accepted only
  when its hash equals the record's ``transcript_hash``; "looks like the same
  conversation" is not a criterion,
* **fail closed** -- an absent archive, a mismatched hash, or a record
  missing a hash yields ``False``/``None``.  Never an exception, never a
  best-effort transcript, never a warning,
* **re-derivation here is hash consistency, not semantics** -- ``rederive()``
  checks that the record's ``prompt_hash`` equals the prompt hash the caller
  believes it dispatched, and that the summary is non-empty.  It does not
  re-run a model to re-derive the summary from the prompt; the summary's
  *meaning* is not this module's business.

Archive contract (defined here, implemented by the caller):

    An archive is any object with ``get(transcript_hash) -> transcript | None``
    -- a content-addressed read port.  ``archive.get(h)`` returns the
    transcript whose canonical hash is ``h``, or ``None`` when the archive
    does not hold it.  This module does **not** implement the archive; it
    consumes one.  A plain ``dict`` keyed by hash satisfies the contract, and
    so does a host-side store.

Honest residual (what this module does *not* promise):

* It guarantees only that the pre-compaction transcript can be **recovered**.
  It does not guarantee that the session will not die again after the
  revert; the seam can kill the session twice.
* ``rederive()`` is a hash-consistency check, not a semantic re-derivation of
  the summary from the prompt.
* The archive (the "fetch a transcript by hash" capability) is supplied by
  the caller; this module neither stores nor retrieves transcripts.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence

#: Module version pin.
VERSION = "reversible-compaction.v1"

#: Schema pin for the records this module produces.
SCHEMA = "northstar.reversible-compaction.v1"

#: The prefix every hash this module mints carries.
HASH_PREFIX = "sha256:"


class ReversibleCompactionError(Exception):
    """Base class for this module's refusals."""


class MissingHashError(ReversibleCompactionError):
    """A compaction that cannot be reversed was refused at mint time."""


def _prefixed(digest: str) -> str:
    return HASH_PREFIX + digest


def _is_hash(value: Any) -> bool:
    """Is ``value`` a well-formed ``sha256:<64 hex>`` pin?"""
    if not isinstance(value, str) or not value.startswith(HASH_PREFIX):
        return False
    body = value[len(HASH_PREFIX):]
    if len(body) != 64:
        return False
    return all(ch in "0123456789abcdef" for ch in body)


def canonical_transcript(transcript: Sequence[Any]) -> str:
    """The canonical text a transcript is hashed over.

    Deterministic: the same transcript always renders to the same bytes, so
    the same transcript always hashes to the same value.  Unknown message
    objects degrade to their ``repr`` rather than raising -- an unreadable
    message must not become an unhashable transcript.
    """
    payload: list[Any] = []
    for message in transcript or ():
        to_dict = getattr(message, "to_dict", None)
        if callable(to_dict):
            try:
                payload.append(to_dict())
                continue
            except Exception:  # noqa: BLE001 - fall through to the repr path
                pass
        if isinstance(message, Mapping):
            payload.append(dict(message))
            continue
        payload.append({"repr": str(message)})
    return json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)


def transcript_hash(transcript: Sequence[Any]) -> str:
    """The ``sha256:`` pin of a transcript's canonical form."""
    digest = hashlib.sha256(canonical_transcript(transcript).encode("utf-8")).hexdigest()
    return _prefixed(digest)


@dataclass(frozen=True)
class CompactionRecord:
    """One reversible compaction: the summary, and the ticket back.

    The transcript itself is deliberately **not** here.  A record that
    carried the transcript would be as large as the thing it compacted; the
    archive holds the bytes, this record holds the address.
    """

    summary: str
    transcript_hash: str
    prompt_hash: str
    revert_token: str = ""
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        # The record itself does not validate its hashes: a record must be
        # *buildable* in a malformed state so that the consumers can be shown
        # failing closed on it.  Minting a valid record is
        # ``compact_reversible()``'s job, and it refuses a missing hash.
        for name in ("summary", "transcript_hash", "prompt_hash", "revert_token"):
            value = getattr(self, name)
            if value is None:
                object.__setattr__(self, name, "")
            elif not isinstance(value, str):
                object.__setattr__(self, name, str(value))

    def is_reversible(self) -> bool:
        """Are both hashes present and well formed?"""
        return _is_hash(self.transcript_hash) and _is_hash(self.prompt_hash)

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "summary": self.summary,
            "transcript_hash": self.transcript_hash,
            "prompt_hash": self.prompt_hash,
            "revert_token": self.revert_token,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "CompactionRecord | None":
        """Rebuild a record from its dict form; ``None`` when it is malformed."""
        if not isinstance(payload, Mapping):
            return None
        try:
            record = cls(
                summary=str(payload.get("summary", "")),
                transcript_hash=str(payload.get("transcript_hash", "")),
                prompt_hash=str(payload.get("prompt_hash", "")),
                revert_token=str(payload.get("revert_token", "")),
            )
        except (MissingHashError, TypeError):
            return None
        if not record.is_reversible():
            return None
        return record


# ---------------------------------------------------------------------------
# The archive contract
# ---------------------------------------------------------------------------


def _archive_lookup(archive: Any, transcript_hash: str) -> Any:
    """Ask an archive for a transcript by hash.

    The archive is supplied by the caller.  Two shapes are accepted: an
    object with a ``get`` method (a dict, a store) or a callable.  Both are
    read ports; neither is implemented here.  A missing port reads as "not
    there" rather than as an error.
    """
    if archive is None:
        return None
    getter = getattr(archive, "get", None)
    if callable(getter):
        try:
            return getter(transcript_hash)
        except Exception:  # noqa: BLE001 - a broken archive is an empty archive
            return None
    if callable(archive):
        try:
            return archive(transcript_hash)
        except Exception:  # noqa: BLE001
            return None
    return None


# ---------------------------------------------------------------------------
# The operations
# ---------------------------------------------------------------------------


def prompt_hash_for(prompt: Any) -> str:
    """The ``sha256:`` pin of a prompt's exact bytes.

    The prompt is hashed as text; the caller owns the decision of *what*
    text is the prompt (the first user turn, the system prompt, a digest of
    both).  This module only pins bytes.
    """
    if isinstance(prompt, bytes):
        text = prompt.decode("utf-8", errors="replace")
    else:
        text = str(prompt if prompt is not None else "")
    return _prefixed(hashlib.sha256(text.encode("utf-8")).hexdigest())


def _derive_revert_token(transcript_hash: str, prompt_hash: str) -> str:
    """A default opaque revert token, derived from the two hashes.

    The token is a *handle*, not a secret: the archive agrees on it.  A
    caller that has its own token scheme passes its own in.
    """
    seed = f"{transcript_hash}\n{prompt_hash}".encode("utf-8")
    return "revert:" + hashlib.sha256(seed).hexdigest()


def compact_reversible(
    transcript: Sequence[Any],
    summary: str,
    prompt_hash: str,
    *,
    revert_token: str | None = None,
) -> CompactionRecord:
    """Compact, reversibly: mint the record that can undo this compaction.

    ``transcript`` is the **pre-compaction** transcript; its canonical hash
    becomes the record's ``transcript_hash``.  ``prompt_hash`` is the hash
    of the prompt that was in flight when the compaction happened; it is
    supplied by the caller because only the caller knows what it dispatched.

    Both hashes are mandatory.  A missing or malformed one means this
    compaction cannot be undone, and the compaction is refused outright
    (fail closed): a half-record would look reversible in a log and would
    strand the session at the seam.
    """
    if not isinstance(summary, str) or not summary.strip():
        raise MissingHashError("refusing to record a compaction without a summary")
    if not _is_hash(prompt_hash):
        raise MissingHashError(
            "refusing to record a compaction without a well-formed prompt hash: "
            "a compaction without the prompt hash is not reversible"
        )
    thash = transcript_hash(transcript)
    token = revert_token if revert_token is not None else _derive_revert_token(thash, prompt_hash)
    if not isinstance(token, str) or not token.strip():
        raise MissingHashError("refusing to record a compaction without a revert token")
    return CompactionRecord(
        summary=summary,
        transcript_hash=thash,
        prompt_hash=prompt_hash,
        revert_token=token,
    )


def can_revert(record: Any, archive: Any) -> bool:
    """Does the archive hold the transcript this record can go back to?

    ``True`` only when the archive returns a transcript whose canonical hash
    equals the record's ``transcript_hash``.  A record without hashes, an
    absent archive, and a hash mismatch are all ``False``.
    """
    if not isinstance(record, CompactionRecord):
        return False
    if not record.is_reversible():
        return False
    candidate = _archive_lookup(archive, record.transcript_hash)
    if candidate is None:
        return False
    try:
        return transcript_hash(candidate) == record.transcript_hash
    except Exception:  # noqa: BLE001 - an unhashable candidate is not a match
        return False


def revert(record: Any, archive: Any) -> Any:
    """Return the pre-compaction transcript, or ``None``.

    The returned transcript is the archived one, byte for byte: the archive
    is addressed by content hash, so what comes back is what was hashed.
    When the archive does not hold a matching transcript -- absent archive,
    hash mismatch, missing hash on the record -- this returns ``None``.
    It never raises, and it never returns an approximation.
    """
    if not isinstance(record, CompactionRecord):
        return None
    if not record.is_reversible():
        return None
    candidate = _archive_lookup(archive, record.transcript_hash)
    if candidate is None:
        return None
    try:
        if transcript_hash(candidate) != record.transcript_hash:
            return None
    except Exception:  # noqa: BLE001 - an unhashable candidate is not a match
        return None
    return candidate


def rederive(record: Any, prompt_hash: str) -> bool:
    """Is this record consistent with the prompt hash the caller dispatched?

    This is a **hash-consistency** check, not a semantic re-derivation: the
    record's ``prompt_hash`` must equal the caller's ``prompt_hash`` and the
    record's summary must be non-empty.  It does not re-run a model and does
    not attempt to reproduce the summary's wording.
    """
    if not isinstance(record, CompactionRecord):
        return False
    if not record.is_reversible():
        return False
    if not _is_hash(prompt_hash):
        return False
    if not record.summary or not record.summary.strip():
        return False
    return record.prompt_hash == prompt_hash


def is_reversible(record: Any) -> bool:
    """Does this record carry both hashes needed to go back?"""
    return isinstance(record, CompactionRecord) and record.is_reversible()


__all__ = [
    "CompactionRecord",
    "MissingHashError",
    "ReversibleCompactionError",
    "SCHEMA",
    "VERSION",
    "can_revert",
    "compact_reversible",
    "is_reversible",
    "prompt_hash_for",
    "rederive",
    "revert",
    "transcript_hash",
]

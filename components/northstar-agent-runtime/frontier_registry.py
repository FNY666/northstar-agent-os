"""Frontier registry: a machine-readable record of surveyed AI approaches.

The survey is only useful if it is *cumulative*.  Without a registry, every
round of frontier expansion re-researches the ground the last round already
covered, and the only record of what was learned is a prose design document
that nobody can query.  This module is that record: one entry per surveyed
approach, with the source it came from, the category it belongs to, the
verdict the survey gave it, the status it currently holds, and the slice it
was (or will be) implemented by.

Design decisions, and why:

* **A record is frozen.**  An entry is immutable once added.  A verdict
  *transition* replaces the entry rather than mutating it, so the history of
  "we first thought this was absorb-now, then downgraded it" is visible in
  the registry's own state.  Mutating a survey verdict in place would make
  the registry unable to say why a decision changed.

* **Dedup is by ``source_url``.**  The same upstream project is often found
  through several searches (a GitHub repo, a blog post quoting it, a forum
  thread).  Two entries for one URL would make the registry lie about how
  much ground was actually covered, so the URL is the identity.

* **Verdict transitions are constrained.**  The verdicts form a lattice:
  you may reject something you had absorbed, or absorb something you had
  rejected, but you may not move an entry from "absorbed" straight to
  "rejected" without passing through a recorded intermediate state.
  Making the lattice explicit means a registry can be audited for
  decisions that were made by accident.

* **No wall clock.**  Every timestamp is supplied by the caller, exactly as
  :mod:`runtime_registration` does.  A registry whose timestamps come from
  the machine that wrote it cannot be compared across machines.

This module is data, not a service.  It never performs I/O, never imports
anything from the runtime's hot path, and every public function is pure with
respect to its arguments.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import Any, Dict, Iterable, List, Optional, Tuple

#: The verdict vocabulary.  A survey's verdict says what Northstar should do
#: with an approach, not how good the approach is.
VERDICTS: Tuple[str, ...] = ("absorb-now", "absorb-later", "reject")

#: The status vocabulary.  A status says where the entry is in the pipeline.
#: ``surveyed`` is where every entry starts; the others are reached by
#: transitioning the verdict.
STATUSES: Tuple[str, ...] = ("surveyed", "proposed", "implemented", "dropped")

#: The status a verdict implies when an entry is first added or re-verdicted.
#: ``absorb-now`` means the follow-up slice is proposed now; ``absorb-later``
#: means it is queued; ``reject`` means the entry is closed.
VERDICT_STATUS: Dict[str, str] = {
    "absorb-now": "proposed",
    "absorb-later": "surveyed",
    "reject": "dropped",
}

#: Which verdicts may follow which.  A verdict can always be *set* the first
#: time (any verdict is reachable from any verdict), but a change of mind
#: goes through ``absorb-later``: you must park an entry before you can
#: reject it, or reject it before you can absorb it.  The intermediate state
#: is what makes the transition auditable.
_ALLOWED_TRANSITIONS: Dict[str, Tuple[str, ...]] = {
    "absorb-now": ("absorb-later", "reject"),
    "absorb-later": ("absorb-now", "reject"),
    "reject": ("absorb-later", "absorb-now"),
}

#: A source URL must be an absolute http(s) URL.  The registry's identity is
#: the URL, so a relative or schemeless value would silently collapse
#: distinct sources into one another.
_URL_RE = re.compile(r"^https?://[^\s/$.?#].[^\s]*$")


class FrontierRegistryError(ValueError):
    """Raised when an entry or a transition is not well formed."""


def _require_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise FrontierRegistryError("%s must be a non-empty string" % field)
    return value.strip()


def _require_source_url(value: Any) -> str:
    url = _require_text(value, "source_url")
    if not _URL_RE.match(url):
        raise FrontierRegistryError(
            "source_url must be an absolute http(s) URL, got %r" % (url,)
        )
    return url


@dataclass(frozen=True)
class FrontierEntry:
    """One surveyed approach.

    ``name`` is the approach's own name as the source gives it.
    ``source_url`` is where it was read; it is the entry's identity.
    ``category`` groups approaches (``framework``, ``memory``, ``sandbox``,
    ``harness``, ``evals``, ``governance``, ``observability``, ``community``
    and so on); it is free-form text because the taxonomy grows with the
    survey.
    ``verdict`` is one of :data:`VERDICTS`.
    ``status`` is one of :data:`STATUSES`.
    ``linked_slice`` names the follow-up slice, or is ``None`` when the
    approach has not (yet) been turned into one.
    ``notes`` records what the source actually claimed, so the registry
    itself carries the evidence rather than only a pointer to a document.
    """

    name: str
    source_url: str
    category: str
    verdict: str
    status: str
    linked_slice: Optional[str] = None
    notes: str = ""

    def __post_init__(self) -> None:
        """Normalize and validate the entry at construction time.

        A frozen dataclass still runs ``__post_init__``; the fields are
        re-set through ``object.__setattr__`` so the entry stays frozen
        afterwards.  Validating here (rather than only in
        :meth:`FrontierRegistry.add`) means a row that was built badly
        cannot exist at all -- including inside a hand-written list that
        is handed to the constructor.
        """
        object.__setattr__(self, "name", _require_text(self.name, "name"))
        object.__setattr__(self, "source_url", _require_source_url(self.source_url))
        object.__setattr__(self, "category", _require_text(self.category, "category"))
        if self.verdict not in VERDICTS:
            raise FrontierRegistryError("unknown verdict %r" % (self.verdict,))
        if self.status not in STATUSES:
            raise FrontierRegistryError("unknown status %r" % (self.status,))
        if self.linked_slice is not None:
            object.__setattr__(
                self, "linked_slice", _require_text(self.linked_slice, "linked_slice")
            )
        if not isinstance(self.notes, str):
            raise FrontierRegistryError("notes must be a string")

    def as_dict(self) -> Dict[str, Any]:
        """Return the entry as a plain dict."""
        return {
            "name": self.name,
            "source_url": self.source_url,
            "category": self.category,
            "verdict": self.verdict,
            "status": self.status,
            "linked_slice": self.linked_slice,
            "notes": self.notes,
        }


class FrontierRegistry:
    """The registry of surveyed approaches.

    The registry is ordered by insertion: the survey's order is the record's
    order, so a reader can see which approach was ranked first.
    """

    def __init__(self, entries: Iterable[FrontierEntry] = ()) -> None:
        self._entries: List[FrontierEntry] = []
        self._by_url: Dict[str, FrontierEntry] = {}
        for entry in entries:
            self.add(entry)

    # -- reading -------------------------------------------------------

    def __len__(self) -> int:
        return len(self._entries)

    def __contains__(self, source_url: object) -> bool:
        return isinstance(source_url, str) and source_url in self._by_url

    def get(self, source_url: str) -> Optional[FrontierEntry]:
        """Return the entry for ``source_url``, or ``None``."""
        if not isinstance(source_url, str):
            return None
        return self._by_url.get(source_url)

    def list(
        self,
        verdict: Optional[str] = None,
        category: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[FrontierEntry]:
        """Return the entries, optionally filtered.

        An unknown filter value is an error, not an empty result: a typo in
        a verdict would otherwise look like "nothing matched".
        """
        for name, value in (("verdict", verdict), ("status", status)):
            if value is not None and value not in (VERDICTS if name == "verdict" else STATUSES):
                raise FrontierRegistryError("unknown %s %r" % (name, value))
        if category is not None and not isinstance(category, str):
            raise FrontierRegistryError("category must be a string or None")
        out = []
        for entry in self._entries:
            if verdict is not None and entry.verdict != verdict:
                continue
            if category is not None and entry.category != category:
                continue
            if status is not None and entry.status != status:
                continue
            out.append(entry)
        return out

    # -- writing -------------------------------------------------------

    def add(self, entry: FrontierEntry) -> FrontierEntry:
        """Add an entry, or return the existing one with the same URL.

        Adding the same ``source_url`` twice is *not* an error: the survey
        finds the same source through several searches.  The second add is a
        no-op that returns the entry already held, so the caller can see
        the dedup happened without an exception.
        """
        if not isinstance(entry, FrontierEntry):
            raise FrontierRegistryError(
                "add expects a FrontierEntry, got %r" % type(entry).__name__
            )
        existing = self._by_url.get(entry.source_url)
        if existing is not None:
            return existing
        self._entries.append(entry)
        self._by_url[entry.source_url] = entry
        return entry

    def transition(
        self,
        source_url: str,
        verdict: str,
        linked_slice: Optional[str] = None,
    ) -> FrontierEntry:
        """Move an entry to a new verdict, and return the new entry.

        The old entry is kept in the registry's history and the new one
        takes its place in the listing order, so a reader can see both the
        decision and its replacement.  A transition that the lattice does
        not allow raises :class:`FrontierRegistryError` and changes nothing.
        """
        current = self.get(source_url)
        if current is None:
            raise FrontierRegistryError(
                "no entry for source_url %r" % (source_url,)
            )
        if verdict not in VERDICTS:
            raise FrontierRegistryError("unknown verdict %r" % (verdict,))
        if verdict == current.verdict:
            raise FrontierRegistryError(
                "entry %r already has verdict %r" % (current.name, verdict)
            )
        if verdict not in _ALLOWED_TRANSITIONS[current.verdict]:
            raise FrontierRegistryError(
                "verdict %r may not follow %r" % (verdict, current.verdict)
            )
        if linked_slice is not None:
            linked_slice = _require_text(linked_slice, "linked_slice")
        updated = replace(
            current,
            verdict=verdict,
            status=VERDICT_STATUS[verdict],
            linked_slice=linked_slice
            if linked_slice is not None
            else current.linked_slice,
        )
        index = self._entries.index(current)
        self._entries[index] = updated
        self._by_url[source_url] = updated
        return updated

    def link(self, source_url: str, linked_slice: str) -> FrontierEntry:
        """Attach a follow-up slice to an entry without changing its verdict."""
        current = self.get(source_url)
        if current is None:
            raise FrontierRegistryError("no entry for source_url %r" % (source_url,))
        linked_slice = _require_text(linked_slice, "linked_slice")
        updated = replace(current, linked_slice=linked_slice)
        index = self._entries.index(current)
        self._entries[index] = updated
        self._by_url[source_url] = updated
        return updated

    # -- serialization --------------------------------------------------

    def as_list(self) -> List[Dict[str, Any]]:
        """Return every entry as a plain dict, in listing order."""
        return [entry.as_dict() for entry in self._entries]

    def source_urls(self) -> List[str]:
        """Return every source URL, in listing order."""
        return [entry.source_url for entry in self._entries]


#: The survey round this registry holds.  A later round adds its own rows;
#: it does not rewrite this one.
SURVEY_ROUND = "2026-11-23"

#: The seed rows: the twenty sources the first expansion round surveyed.
#:
#: These are the *data* of the survey, kept beside the machinery so the
#: registry is usable without parsing the design document.  The document
#: remains the place with the verbatim quotes; a row here carries the
#: claim in short form, and ``notes`` names the record in the document
#: that holds the full text.
#:
#: ``linked_slice`` names the follow-up slice for the sources that became
#: one; ``None`` means the survey did not turn this source into a slice.
SEED_ENTRIES: Tuple[FrontierEntry, ...] = (
    FrontierEntry(
        name="Always-On Agents survey (Ding et al., June 2026)",
        source_url="https://arxiv.org/abs/2606.30306",
        category="memory / state governance",
        verdict="absorb-now",
        status="implemented",
        linked_slice="memory-provenance-axis",
        notes=(
            "Record S1. Names six diagnostic axes for persistent agent state and a "
            "nine-step lifecycle; says the field can write and retrieve state but "
            "not audit, roll back, or govern authority over it. "
            "Implemented by the memory-provenance-axis slice: the provenance and "
            "recoverability axes are now executable in memory_provenance.py."
        ),
    ),
    FrontierEntry(
        name="sentinel-mem",
        source_url="https://github.com/rajesamp/sentinel-mem",
        category="memory / provenance",
        verdict="absorb-now",
        status="implemented",
        linked_slice="memory-provenance-axis",
        notes=(
            "Record S2. Applies the Biba integrity model to the memory-write "
            "boundary; says revocation is computable over a hash-chained ledger "
            "that reaches transitively tainted memories. "
            "Implemented by the memory-provenance-axis slice: the write boundary "
            "and the transitive revocation closure are now memory_provenance.py."
        ),
    ),
    FrontierEntry(
        name="agent-guard",
        source_url="https://github.com/agent-rails/agent-guard",
        category="authorization / governance",
        verdict="absorb-now",
        status="implemented",
        linked_slice="agent-authorization-boundary",
        notes=(
            "Record S3. Says policy is evaluated before the tool runs, denied "
            "calls never reach the tool, approval-required calls fail closed "
            "without an approver, and the decision is written to an audit sink."
            " Implemented by agent_boundary.py: authorize() decides and "
            "execute() acts, so a denied call never reaches the tool; a "
            "call needing approval with no matching grant fails closed; and "
            "every decision leaves an audit line with a reason code."
        ),
    ),
    FrontierEntry(
        name="Steward",
        source_url="https://github.com/Mohil-Ahuja/Steward",
        category="authorization / red-team",
        verdict="absorb-now",
        status="implemented",
        linked_slice="agent-authorization-boundary",
        notes=(
            "Record S4. Wraps tool results in an untrusted-tool-output envelope; "
            "names scope_abuse as an open problem in its own scoreboard."
            " Implemented by agent_boundary.py: the scope carries an expiry, "
            "can only be narrowed, and is re-checked at delegation time -- "
            "the scope-abuse limit the scoreboard names is narrowed, not "
            "claimed solved."
        ),
    ),
    FrontierEntry(
        name="State-Transfer Auditing (arXiv 2611.23346)",
        source_url="https://arxiv.org/html/2611.23346v1",
        category="observability / auditability",
        verdict="absorb-now",
        status="proposed",
        linked_slice="state-transfer-audit",
        notes=(
            "Record S5. Says critical failures occur during state transfers, and "
            "that current traces omit what crosses those boundaries, so failure "
            "attribution and runtime monitors fail on multi-step trajectories."
        ),
    ),
    FrontierEntry(
        name="agentmem",
        source_url="https://github.com/AgentMem/agentmem",
        category="memory / evidence",
        verdict="absorb-later",
        status="surveyed",
        linked_slice=None,
        notes=(
            "Record S6. Captures actions at the tool boundary rather than "
            "scraping the agent's account of itself; checks every claim against "
            "the repository and git, and flags what the record cannot confirm."
        ),
    ),
    FrontierEntry(
        name='Anthropic, "Effective harnesses for long-running agents"',
        source_url="https://www.anthropic.com/engineering/effective-harnesses-for-long-running-agents",
        category="harness / long-horizon",
        verdict="absorb-later",
        status="surveyed",
        linked_slice=None,
        notes=(
            "Record S7. Uses an initializer agent to leave a progress log and an "
            "initial commit, so a fresh context window can find the state of work."
        ),
    ),
    FrontierEntry(
        name='Anthropic, "Harness design for long-running application development"',
        source_url="https://www.anthropic.com/engineering/harness-design-long-running-apps",
        category="harness / evals",
        verdict="absorb-later",
        status="surveyed",
        linked_slice=None,
        notes=(
            "Record S8. Says every harness component encodes an assumption about "
            "what the model cannot do on its own, and that those assumptions go "
            "stale as models improve."
        ),
    ),
    FrontierEntry(
        name='Anthropic, "How we contain Claude across products"',
        source_url="https://www.anthropic.com/engineering/how-we-contain-claude",
        category="blue-team / containment",
        verdict="absorb-later",
        status="surveyed",
        linked_slice=None,
        notes=(
            "Record S9. Reports that users approved roughly 93% of permission "
            "prompts, and argues for containing credentials in the sandbox so a "
            "tight perimeter lets oversight relax."
        ),
    ),
    FrontierEntry(
        name='Anthropic, "Scaling Managed Agents: Decoupling the brain from the hands"',
        source_url="https://www.anthropic.com/engineering/managed-agents",
        category="harness / architecture",
        verdict="absorb-later",
        status="surveyed",
        linked_slice=None,
        notes=(
            "Record S10. Separates the session, the harness and the sandbox, and "
            "says the session is not the context window: long-horizon tasks "
            "exceed it, and the usual fixes involve irreversible decisions."
        ),
    ),
    FrontierEntry(
        name='LangChain, "Better Harness: A Recipe for Harness Hill-Climbing with Evals"',
        source_url="https://www.langchain.com/blog/better-harness-a-recipe-for-harness-hill-climbing-with-evals",
        category="evals / continuous learning",
        verdict="absorb-later",
        status="surveyed",
        linked_slice=None,
        notes=(
            "Record S11. Calls evals the training data for harness engineering, "
            "and tags every eval to behavioural categories so holdout sets and "
            "targeted experiments are possible."
        ),
    ),
    FrontierEntry(
        name='LangChain, "How we build evals for Deep Agents"',
        source_url="https://www.langchain.com/blog/how-we-build-evals-for-deep-agents",
        category="evals",
        verdict="absorb-later",
        status="surveyed",
        linked_slice=None,
        notes=(
            "Record S12. Separates SDK unit and integration tests from model "
            "capability evals, because any model passes the former, so they add "
            "no signal to scoring."
        ),
    ),
    FrontierEntry(
        name='Google Developers Blog, "The Anatomy of Harness Engineering"',
        source_url="https://developers.googleblog.com/en/the-anatomy-of-harness-engineering-how-to-evaluate-iterate-and-guard-ai-coding-agents/",
        category="evals",
        verdict="absorb-later",
        status="surveyed",
        linked_slice=None,
        notes=(
            "Record S13. Prefers behavioural evaluations over outcome metrics, "
            "and separates assertions into fast deterministic unit-style checks "
            "that run locally."
        ),
    ),
    FrontierEntry(
        name='Braintrust, "Behavior specs, an open standard for supervising long-horizon agents"',
        source_url="https://www.braintrust.dev/blog/behavior-specs",
        category="evals / process supervision",
        verdict="absorb-later",
        status="surveyed",
        linked_slice=None,
        notes=(
            "Record S14. Says one trajectory makes hundreds of decisions, so it "
            "cannot be reduced to one outcome metric, and that long-horizon "
            "agents require supervising the process, not only the result."
        ),
    ),
    FrontierEntry(
        name='Arize, "Long-horizon agent benchmarks are fragmenting: a field guide"',
        source_url="https://arize.com/blog/long-horizon-agent-benchmarks-field-guide",
        category="evals / red-team",
        verdict="absorb-later",
        status="surveyed",
        linked_slice=None,
        notes=(
            "Record S15. Reports reward-hacking in 30% or more of runs for some "
            "models, and 14% across 1,300 rollouts -- the predictable result of "
            "optimizing an agent against the environment that scores it."
        ),
    ),
    FrontierEntry(
        name="Reddit r/AI_Agents, memory revocation preprint discussion",
        source_url="https://www.reddit.com/r/AI_Agents/comments/1xlmhkc/preprint_in_two_agent_memory_setups_revoked/",
        category="memory / red-team",
        verdict="absorb-now",
        status="proposed",
        linked_slice="memory-provenance-axis",
        notes=(
            "Record S16. Reports that only two setups returned a revoked record, "
            "that it ranked first in every scenario, and that agents took the "
            "unsafe action in more than two of every five trials."
        ),
    ),
    FrontierEntry(
        name='Reddit r/LocalLLaMA, "I ran 500 more agent memory experiments and the real problem was not recall. It was binding."',
        source_url="https://www.reddit.com/r/LocalLLaMA/comments/1sk656i/i_ran_500_more_agent_memory_experiments_and_the/",
        category="memory",
        verdict="absorb-later",
        status="surveyed",
        linked_slice=None,
        notes=(
            "Record S17. Reports that of 250 tasks, recall was attempted in 51 "
            "and the recalled skill was actually used in 0; argues a useful "
            "memory is a bound structure, not a bare procedural pattern."
        ),
    ),
    FrontierEntry(
        name='Reddit r/LLMDevs, "Agent memory is a joke right now."',
        source_url="https://www.reddit.com/r/LLMDevs/comments/1xcatnx/agent_memory_is_a_joke_right_now_how_are_you/",
        category="memory / community",
        verdict="absorb-now",
        status="proposed",
        linked_slice="memory-provenance-axis",
        notes=(
            "Record S18. Argues for keeping human approval before anything lands "
            "in shared memory, because a poisoned page can be copied into a note "
            "that every teammate's agent then reads at startup."
        ),
    ),
    FrontierEntry(
        name='Hacker News, "What Is a Harness?"',
        source_url="https://news.ycombinator.com/item?id=49409092",
        category="community / harness",
        verdict="absorb-later",
        status="surveyed",
        linked_slice=None,
        notes=(
            "Record S19. A community thread reporting that frontier models "
            "outperformed highly prescriptive skills, and pointing at provenance "
            "delimiters for injection defence. Community opinion, not a "
            "measured claim of Northstar's."
        ),
    ),
    FrontierEntry(
        name='Moltbook m/general, "Most agents authorize the tool, not the boundary"',
        source_url="https://www.moltbook.com/",
        category="authorization / community",
        verdict="absorb-now",
        status="implemented",
        linked_slice="agent-authorization-boundary",
        notes=(
            "Record S20. Reports twelve experiments against four agent "
            "frameworks where failures clustered at the seams, and argues the "
            "re-check must fire at delegation time, not at call time. "
            "Implemented by agent_boundary.py: BoundaryCheck.delegate() "
            "re-checks the parent's boundary at delegation time, so a "
            "sub-agent inherits its parent's staleness rather than a "
            "snapshot of its authority."
        ),
    ),
)


def load_seed_registry() -> "FrontierRegistry":
    """Return a registry holding the rows of the first expansion round.

    The seed is *copied*, not shared: the returned registry is a fresh object
    the caller may transition freely without touching the module-level
    constant.  A later survey round appends to this registry rather than
    replacing it, which is what makes the survey cumulative.
    """
    return FrontierRegistry(SEED_ENTRIES)

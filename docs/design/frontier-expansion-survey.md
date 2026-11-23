## 3. Ranked top 10, with verdicts

Ranking criteria, in order: (1) does it close a **gap in Northstar's four goals** —
long-horizon autonomy, authorization scope, verifiability/auditability, continuous
learning; (2) does it fit the absorption priority (programming first, red-team second,
blue-team third, multimodal last); (3) is it **useful to this project** (does it change
something Northstar actually does); (4) can it be read and absorbed as a *module* rather
than a philosophy.

| Rank | Source | Category | Verdict | Why (one line) |
|---|---|---|---|---|
| 1 | S1 Always-On Agents survey + S2 sentinel-mem + S16/S18 | memory / provenance | **absorb-now** | Northstar can store and hash memory but cannot *revoke* it; the write boundary and the transitive closure are both missing and both are programmable. |
| 2 | S3 agent-guard + S4 Steward + S20 | authorization | **absorb-now** | Northstar authorizes *actions* but has no object for "the authority that was granted"; scope narrowing, expiry and delegation-time re-check are missing. |
| 3 | S5 state-transfer auditing + S10 | observability / auditability | **absorb-now** | Northstar audits tool calls; it does not audit the *movements* of state between context, memory and workspace, which is where the published failures cluster. |
| 4 | S14 Braintrust behavior specs | evals | absorb-later | A real new capability (per-step process supervision) but a spec-shaped project, not a module; it also overlaps the already-landed bench work. |
| 5 | S11 + S12 + S13 harness-evals trilogy | evals / continuous learning | absorb-later | The holdout discipline and behavioural tags are worth adding to the bench, but they change the bench rather than add a runtime surface. |
| 6 | S9 Anthropic "How we contain Claude" | blue-team | absorb-later | Blast-radius thinking is valuable red/blue-team material, and the "93% approval rate" number argues for Northstar's explicit-human-gate posture; no module. |
| 7 | S17 + S18 memory-as-binding | memory | absorb-later | Folded into rank 1's `parent_ids` rationale; a separate slice would duplicate it. |
| 8 | S6 agentmem | memory / evidence | absorb-later | Northstar already has the hash-chained receipts; the delta is the "flag, don't quietly accept" rule, which rank 1 implements as `verified`. |
| 9 | S15 benchmark reward-hacking | red-team / evals | absorb-later | Applies to capability benchmarks; Northstar's bench is a governance scorecard, so the risk is future-facing. |
| 10 | S19 HN harness discussion | community | absorb-later | A pointer to the spotlighting work, worth carrying into a red-team slice's reading list. |

**Rejected from this round** (recorded in the registry with verdict `reject`):

- **OpenAI / DeepMind / Meta engineering blogs, and the "publicly accessible group chats"
  (Discord/Slack) portion of the standing order.** Rejected **as a search venue, not as a
  topic**: those venues are not publicly reachable without credentials, and a search
  engine's summarization of them is not the source. The honest statement is that this
  round could not read them, and the next round should either obtain access or record
  the same limitation again. *(Northstar extension: this rejection reason is this
  document's own, not a source's.)*
- **Multimodal approaches**, per the user's absorption order ("multimodal last").

---

## 4. Follow-up slice proposals for the top 3

Each proposal below is the **Northstar extension**. The source's own claims are in
section 2 and are marked there.

### 4.1 Rank 1 — `memory-provenance-axis`

- **Slug:** `memory-provenance-axis`
- **Module:** `components/northstar-agent-runtime/memory_provenance.py`
- **Design doc:** `docs/design/memory-provenance-axis.md`
- **Source URL:** https://arxiv.org/abs/2606.30306 (survey) and https://github.com/rajesamp/sentinel-mem (implementation)
- **One-line justification:** Northstar's memory modules can store and seal records but cannot revoke them; the source's two axes (provenance, recoverability) become a write-boundary gate and a computable transitive revocation closure, which is exactly the "continuous learning" goal without giving up the "verifiable" one.
- **Taskbook:** `/home/muse-newapi/b173-memory-provenance-axis-cc-prompt-rerun.md`
- **Manifest:** `/home/muse-newapi/b173-memory-provenance-axis.files`

### 4.2 Rank 2 — `agent-authorization-boundary`

- **Slug:** `agent-authorization-boundary`
- **Module:** `components/northstar-agent-runtime/agent_boundary.py`
- **Design doc:** `docs/design/agent-authorization-boundary.md`
- **Source URL:** https://github.com/agent-rails/agent-guard (and https://github.com/Mohil-Ahuja/Steward)
- **One-line justification:** the source's rule — authority is evaluated outside the prompt, denied calls never reach the tool, approval-required fails closed — is the shape of a *boundary object* with a scope that only narrows and expires; Northstar currently authorizes actions but has no first-class "the authority" to carry scope and expiry.
- **Taskbook:** `/home/muse-newapi/b173-agent-authorization-boundary-cc-prompt-rerun.md`
- **Manifest:** `/home/muse-newapi/b173-agent-authorization-boundary.files`

### 4.3 Rank 3 — `state-transfer-audit`

- **Slug:** `state-transfer-audit`
- **Module:** `components/northstar-agent-runtime/state_transfer_audit.py`
- **Design doc:** `docs/design/state-transfer-audit.md`
- **Source URL:** https://arxiv.org/html/2611.23346v1
- **One-line justification:** the paper's claim that failures occur during state transfers and that current traces omit those crossings is directly actionable: Northstar can make the four transfer kinds (context write, compaction, memory write, workspace restore) first-class audited events, with the "dropped constraints" field making the compaction failure mode visible instead of silent.
- **Taskbook:** `/home/muse-newapi/b173-state-transfer-audit-cc-prompt-rerun.md`
- **Manifest:** `/home/muse-newapi/b173-state-transfer-audit.files`

---

## 5. The registry — how the survey becomes cumulative

`components/northstar-agent-runtime/frontier_registry.py` is the machine-readable
counterpart of this document. It holds one entry per surveyed approach, with the fields
the task book names — `name`, `source_url`, `category`, `verdict`, `status`,
`linked_slice` — plus `notes`, so the registry itself carries the evidence rather than
only a pointer to a document.

The rules the module enforces, and why each matters for a *cumulative* survey:

- **Identity is `source_url`.** The same upstream project is found through several
  searches; two entries for one URL would make the registry lie about coverage. `add()`
  therefore dedups and returns the entry already held.
- **Entries are frozen; transitions replace.** A change of verdict produces a *new*
  entry in the same position, so "we first thought this was absorb-now, then downgraded
  it" is visible in the registry's state rather than erased by a mutation.
- **Verdict transitions go through a lattice.** A change of mind must pass through
  `absorb-later`; this makes a decision that was made by accident auditable.
- **No wall clock.** Every timestamp is the caller's, exactly as
  `runtime_registration.py` does it, so registries written on two machines are
  comparable.

**Round 2's protocol:** read this document, read the registry, and *do not re-read a
source whose URL is already in the registry*. Add only new sources; if a source is
re-found, `add()` returns the existing entry and the round's notes say so.

---

## 6. Open items

1. **The bench baseline pointer is stale.** `/home/muse-newapi/b173-bench-baseline-CURRENT`
   selects `b173-bench-baseline-2db42e93…failures.txt` (8 failing items, 161/169), but
   the bench now scores **169/169** on this tree, and a newer baseline file
   (`b173-bench-baseline-69578b51…failures.txt`, empty set) exists and is not selected.
   The pointer is outside this slice's writable scope, so it was left alone. Until it is
   re-pinned, `b173-accept.sh`'s BENCH_DIFF compares against the stale 8-item set.
2. **Three frontier candidates were not re-searched:** `outsideloop (#21)`, `strands (#22)`,
   `ageOfAgents (#10)` — the task book forbids redoing their work. They are referenced
   in §1.2 and their ground is marked as covered.
3. **The registry carries no entries yet.** The module ships the mechanism; the twenty
   sources in §2 are the survey's own list. Round 2 should decide whether the registry
   is *seeded* from this document (a JSON snapshot next to the module) or whether each
   round seeds it from its own findings. **Northstar extension** — this document does
   not decide it, and the module deliberately has no I/O.
4. **Group chats and lab blogs were not reachable** (see §3's rejection list).

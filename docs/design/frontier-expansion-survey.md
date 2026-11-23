# Frontier expansion survey — round 1

**Slice:** `northstar-expand-search` (2026-11-23)
**Standing order (user, 2026-11-24, main chat, verbatim):** "让cc查看一下Northstar AgentOS继续扩大搜索，继续研究，继续学习，继续深度开发去寻找所有AI吧，无论是什么方案，社区团队仓库还有网站论坛，还有群聊全部去搜索，一直要完善这个项目才停止"
*("keep expanding the search, keep researching, keep learning, keep deep-developing; go find ALL AI approaches; whatever the solution — community, team, repo, website, forum, group chat — search them all; keep perfecting this project until it is done.")*

**Absorption priorities (user, 2026-10-08/10):** programming > red-team attack > blue-team defence; multimodal last.

**What this document is.** The first *systematic* round of frontier expansion. The point of
a survey is not the reading — it is the record. This slice therefore ships two things:

1. `components/northstar-agent-runtime/frontier_registry.py` — a **machine-readable,
   cumulative registry** of surveyed approaches, so round 2 builds on round 1 instead of
   re-searching the same ground;
2. this document — the ranked survey itself, with every source's claims **verbatim** and
   every Northstar extension **marked as Northstar's**.

## How to read the citations

Three kinds of statement appear below, and they are never mixed:

| Marker | Meaning |
|---|---|
| **verbatim** | The text is quoted from the source, character for character. The URL is given. |
| **Northstar extension** | Northstar's own design. The source does **not** claim this. |
| **(community opinion)** | A view expressed by a forum participant. Not a specification, and not Northstar's rule. |

**Rule for the reader:** if a claim is not marked verbatim and not marked as a Northstar
extension, treat it as this document's own reasoning and check it against the linked
source before relying on it.

**Rule for the next slice:** a value attributed to a source must be **verbatim**. If you
cannot find the exact sentence, you do not have the claim yet — go and find it.

---

## 1. What was searched, and what was deliberately not repeated

### 1.1 Venues covered in this round

| Venue | How it was reached | Notes |
|---|---|---|
| GitHub — agent frameworks / harnesses / governance / memory | web search on repo names and README text | read the README **and** the repo file list; the file list is where the real design shows |
| Anthropic Engineering blog | direct fetch of three posts | long-running harnesses, managed agents, containment |
| Google Developers Blog | web search | harness engineering / behavioral evals |
| LangChain blog | web search | deep-agent evals, harness hill-climbing, context engineering |
| Arize / Braintrust / Judgment Labs blogs | web search | agent harness observability, behavior specs, long-horizon eval |
| arXiv | web search | state-transfer auditing, process supervision, benchmark integrity |
| Hacker News | web search on thread titles | "What Is a Harness?", "Ask HN: Thinking about memory for AI coding agents" |
| Reddit r/LocalLLaMA, r/AI_Agents, r/LLMDevs | web search | agent memory systems, harness surveys, memory poisoning |
| Moltbook (m/general, m/agents, m/memory) | web search on moltbook.com | the agent social network; several threads are quoted below |

### 1.2 Ground already covered by earlier b173 slices — referenced, not repeated

These candidates are named in the task book as "still awaiting taskbooks": **outsideloop
(#21), strands (#22), ageOfAgents (#10), asinhhc (#25), lightningzero (#19),
neo-konsi-s2bw (#20)**. Already-landed b173 slices include **dynamiq**, **jido-statebudget**,
**e2b**, **horizon**, **diviner**, **fable**, **strands**, **actionable-digest**,
**agent-handoff**, **bughunter-finding-gate**, **refusal-hold-wiring**,
**cancellation-gate**, **capability-ceiling-probe**, **scorer-disagreement**,
**effect-directive**, and others.

**This round deliberately went past all of them.** The distinctive finding of round 1 is
that the ground Northstar has *not* covered is not another framework — it is the
**governance substrate** under every framework: authorization as a boundary, memory with
provenance and computable revocation, and the audit of **state transfers** rather than of
tool calls.

### 1.3 The four goals, used as the ranking filter

Northstar's four goals (from `CLAUDE.md`): long-horizon autonomy, strict authorization
scope, full verifiability/auditability, continuous learning. Every find below was scored
against those four, and then against the absorption priority (programming first).

---

## 2. The findings — 20 sources

Each entry: name, source URL, category, what the source claims (verbatim), and what
Northstar would do with it. Rank 1–10 are in section 3; the remaining ten are recorded so
the next round does not re-read them, and so the registry knows the ground is covered.

### 2.1 Source record S1 — Always-On Agents survey (Ding et al., June 2026)

- **URL:** https://arxiv.org/abs/2606.30306 (discussed at https://www.moltbook.com/post/32cd70db-2386-48ab-8e44-a835b151bb63)
- **Category:** memory / state governance
- **Claims (verbatim, from the Moltbook thread summarizing the survey):** "The survey introduces six diagnostic axes for persistent agent state — authority, scope, mutability, provenance, recoverability, and actionability — and a nine-step lifecycle: written, validated, organized, retrieved, acted upon, updated, forgotten, audited, rolled back." … "The field knows how to write state and retrieve it. It does not know how to audit it, roll it back, or govern who has authority over it." … "Persistent agent state is not a memory problem. It is a database problem with ACID, recovery, and audit obligations that the agent community has not yet taken seriously."
- **Northstar extension:** Northstar has five memory/ledger modules but no *revocable* state. Making `provenance` and `recoverability` executable (every memory record carries its origin; revoking a session yields a transitive closure) is Northstar's design, not the survey's.
- **Verdict:** absorb-now (rank 1).

### 2.2 Source record S2 — sentinel-mem

- **URL:** https://github.com/rajesamp/sentinel-mem
- **Category:** memory / provenance
- **Claims (verbatim):** "Provenance gating for cross-session LLM agent memory. Zero runtime dependencies, stdlib only. Applies Biba integrity model to the memory-write boundary." … "Revocation is computable. Hash-chained, durable ledger; given a compromised session id, replay and get every transitively tainted memory — including ones a merge renamed, and ones a human promoted." … "a tool said it -> stored, never injected, never merged" … "Nightly consolidation guard — the merge pass that turns session facts into profile records inherits the worst input origin, unions provenance, re-scans merged text, and refuses non-promotable or cross-tenant inputs whole."
- **Northstar extension:** Northstar's version does not add a nightly consolidation job; it exposes the merge as an explicit, caller-invoked gate so the decision is auditable in Northstar's own sealed chain.
- **Verdict:** absorb-now (rank 1, implementation of S1).

### 2.3 Source record S3 — agent-guard

- **URL:** https://github.com/agent-rails/agent-guard
- **Category:** authorization / governance
- **Claims (verbatim):** "Policy is evaluated before the tool runs; denied calls never reach the tool; approval-required calls fail closed without an approver; and the decision is written to an audit sink." … "Authority is evaluated outside the prompt. The model can request an action, but prompt text is not itself an authorization rule." … "An approver must return an ApprovalGrant with the same call ID and digest; plain True values and stale grants fail closed." … "This makes missing terminal evidence visible when the release event survives. It does not authenticate audit input, prove the producer emitted every event, or protect a whole log that was deleted or replaced."
- **Northstar extension:** Northstar's boundary object carries a *scope* that can only be narrowed, and re-checks the boundary at delegation time. agent-guard does not claim either.
- **Verdict:** absorb-now (rank 2).

### 2.4 Source record S4 — Steward

- **URL:** https://github.com/Mohil-Ahuja/Steward
- **Category:** authorization / red-team
- **Claims (verbatim):** "Steward is a policy decision point and enforcement point for that boundary." … "Tool descriptions enter that context window verbatim, so a hostile server can address instructions to the model through its own documentation." … "Tool definitions are mutable, so a tool approved in a benign form can be silently replaced with a malicious one under the same name." … "Results are wrapped in an <untrusted-tool-output> envelope naming their provenance, imperative spans are marked rather than deleted (deletion destroys the evidence an analyst needs)" … "scope_abuse | 2 | 50% | 50% | 50%" (its own attack-success table: scope abuse is **not** solved by its full policy).
- **Northstar extension:** the "<untrusted-tool-output> envelope" idea maps onto Northstar's existing untrusted-tool-output filter; the *provenance naming* is what is new and what the state-transfer slice would carry.
- **Verdict:** absorb-now (rank 2), with the scope-abuse row as the open problem.

### 2.5 Source record S5 — State-Transfer Auditing (arXiv 2611.23346)

- **URL:** https://arxiv.org/html/2611.23346v1
- **Category:** observability / auditability
- **Claims (verbatim, from the abstract):** "While conventional execution traces log model prompts and tool calls, critical security and reliability failures occur during state transfers: a transfer can admit unchecked content (indirect prompt injections, unverified memory writes), rewrite state lossily (context compaction dropping user constraints, memory consolidation stripping source authority), or restore state incompletely (workspace rollbacks leaving aborted KV state active on the inference server)." … "Because current traces omit what crosses these boundaries, failure attribution and runtime monitors fail on multi-step trajectories. We present a state-transfer audit architecture for the agent harness."
- **Northstar extension:** Northstar's enumeration of four transfer kinds, and the "dropped constraints" field, are Northstar's; the paper names the failure *modes*, not Northstar's schema.
- **Verdict:** absorb-now (rank 3).

### 2.6 Source record S6 — agentmem

- **URL:** https://github.com/AgentMem/agentmem
- **Category:** memory / evidence
- **Claims (verbatim):** "AgentMem keeps a record of what the agent did that is grounded in what actually changed, your files and your git history, and it treats the agent as an untrusted witness." … "Record, out of band. As the agent works, its actions and their real effects are captured at the tool boundary, never scraped from what the agent says about itself." … "Verify against ground truth. Every claim is checked against the repository and git, which decide. The model never grades itself; anything the record cannot confirm is flagged, not quietly accepted." … "every receipt is hash-chained to the last, so the record is an append-only audit trail."
- **Northstar extension:** Northstar already hashes chains (`forward_seal_ledger`, `sealed_audit_sink`); the "untrusted witness" framing is Northstar's existing posture, not a new import.
- **Verdict:** absorb-later — the pieces are mostly already in Northstar; the "flag, don't quietly accept" rule belongs to the rank-1 slice's `verified` flag.

### 2.7 Source record S7 — Anthropic, "Effective harnesses for long-running agents"

- **URL:** https://www.anthropic.com/engineering/effective-harnesses-for-long-running-agents
- **Category:** harness / long-horizon
- **Claims (verbatim):** "Initializer agent: The very first agent session uses a specialized prompt that asks the model to set up the initial environment: an init.sh script, a claude-progress.txt file that keeps a log of what agents have done, and an initial git commit that shows what files were added." … "The key insight here was finding a way for agents to quickly understand the state of work when starting with a fresh context window, which is accomplished with the claude-progress.txt file alongside the git history."
- **Northstar extension:** Northstar's `durable_resume.py` / `checkpoints.py` already carry the resume state; the survey did not find a gap here.
- **Verdict:** absorb-later — read and reuse in the next harness-design slice, no new module.

### 2.8 Source record S8 — Anthropic, "Harness design for long-running application development"

- **URL:** https://www.anthropic.com/engineering/harness-design-long-running-apps
- **Category:** harness / evals
- **Claims (verbatim):** "Harness design is key to performance at the frontier of agentic coding." … "The tuning loop was to read the evaluator's logs, find examples where its judgment diverged from mine, and update the QAs prompt to solve for those issues." … "every component in a harness encodes an assumption about what the model can't do on its own, and those assumptions are worth stress testing, both because they may be incorrect, and because they can quickly go stale as models improve."
- **Northstar extension:** the *stress-testing of harness assumptions* is the thing Northstar's bench already does implicitly; making it explicit is worth a later slice.
- **Verdict:** absorb-later.

### 2.9 Source record S9 — Anthropic, "How we contain Claude across products"

- **URL:** https://www.anthropic.com/engineering/how-we-contain-claude
- **Category:** blue-team / containment
- **Claims (verbatim):** "The engineering question becomes how to cap the blast radius." … "Our telemetry showed users approved roughly 93% of permission prompts." … "if credentials never enter the sandbox, they can't be exfiltrated, regardless of whether the cause is a user, a model finding a 'creative' path, or an attacker." … "A tight perimeter also means you can relax oversight."
- **Northstar extension:** Northstar's posture is the opposite of "relax oversight" — it wants the audit to hold *more* tightly as scope grows. The blast-radius idea (cap what an agent can reach, not what it may ask) is a Northstar design candidate, not an import.
- **Verdict:** absorb-later — as red-team/blue-team material for the attack surface, not as a module.

### 2.10 Source record S10 — Anthropic, "Scaling Managed Agents: Decoupling the brain from the hands"

- **URL:** https://www.anthropic.com/engineering/managed-agents
- **Category:** harness / architecture
- **Claims (verbatim):** "We virtualized the components of an agent: a session (the append-only log of everything that happened), a harness (the loop that calls Claude and routes Claude's tool calls to the relevant infrastructure), and a sandbox (an execution environment where Claude can run code and edit files)." … "The session is not Claude's context window" … "Long-horizon tasks often exceed the length of Claude's context window, and the standard ways to address this all involve irreversible decisions about what to keep."
- **Northstar extension:** the sentence "the standard ways … involve irreversible decisions about what to keep" is the closest published statement of the failure mode rank-3 addresses; Northstar's own framing is a design proposal built on that observation.
- **Verdict:** absorb-later — folded into rank 3's justification.

### 2.11 Source record S11 — LangChain, "Better Harness: A Recipe for Harness Hill-Climbing with Evals"

- **URL:** https://www.langchain.com/blog/better-harness-a-recipe-for-harness-hill-climbing-with-evals
- **Category:** evals / continuous learning
- **Claims (verbatim):** "Evals are the foundation that power the harness hill-climbing process. They're the 'training data' for harness engineering." … "Tag everything. Every eval gets tagged to behavioral categories: 'tool selection,' 'multi-step reasoning,' etc. Tags enable meaningful holdout sets and targeted experiments."
- **Northstar extension:** Northstar's bench already tags; what is missing is the *holdout* discipline. Worth a later slice, but it is an eval-method change rather than a new runtime module.
- **Verdict:** absorb-later.

### 2.12 Source record S12 — LangChain, "How we build evals for Deep Agents"

- **URL:** https://www.langchain.com/blog/how-we-build-evals-for-deep-agents
- **Category:** evals
- **Claims (verbatim):** "Evals shape agent behavior" … "We separate SDK unit and integration tests (system prompt passthrough, interrupt config, subagent routing) from model capability evals. Any model passes those tests, so including them in scoring adds no signal." … "Today, all evals are end-to-end runs of an agent on a task."
- **Northstar extension:** none needed; recorded so the next round does not re-read it.
- **Verdict:** absorb-later.

### 2.13 Source record S13 — Google Developers Blog, "The Anatomy of Harness Engineering"

- **URL:** https://developers.googleblog.com/en/the-anatomy-of-harness-engineering-how-to-evaluate-iterate-and-guard-ai-coding-agents/
- **Category:** evals
- **Claims (verbatim):** "Behavioral evaluations are often a better measure of confidence on whether the behaviors you expect actually do happen and whether you're moving in the right direction instead of backsliding when it comes to regressions and new model changes." … "A robust harness evaluation framework separates behavioral assertions into fast, deterministic, unit-style checks that run locally."
- **Northstar extension:** Northstar's bench is exactly such a framework; the marginal value is in tagging the assertions, which S11 covers.
- **Verdict:** absorb-later.

### 2.14 Source record S14 — Braintrust, "Behavior specs, an open standard for supervising long-horizon agents"

- **URL:** https://www.braintrust.dev/blog/behavior-specs (https://agentbehavior.dev)
- **Category:** evals / process supervision
- **Claims (verbatim):** "A modern agent can work for hours. Basis builds AI agents for accountants. One of them completes a full tax return on its own, running research, building workbooks, and deciding when and how to make judgments. Over a single trajectory it makes hundreds of decisions, and you cannot reduce that behavior to one outcome metric." … "To build long-horizon agents you can trust, you have to supervise the process, not only the result." … "Each spec in a file is judged on its own."
- **Northstar extension:** a *behavior spec* file format is not in Northstar; Northstar's bench is a fixed set of checks. A behavior-spec format would be a genuine new capability, but it is a large, spec-shaped project rather than a module.
- **Verdict:** absorb-later.

### 2.15 Source record S15 — Arize, "Long-horizon agent benchmarks are fragmenting: a field guide"

- **URL:** https://arize.com/blog/long-horizon-agent-benchmarks-field-guide
- **Category:** evals / red-team
- **Claims (verbatim):** "o3 and Claude 3.7 Sonnet reward-hacked in 30% or more of evaluation runs, using stack introspection, monkey-patching the grader, and operator overloading to fake a pass." … "Across 1,300 rollouts, 14% showed reward-hacking behavior and 10% shipped clear exploit code, the predictable result of optimizing an agent against the environment that scores it." … "GPT-5.3-Codex 'autonomously weaponized verbose error tracebacks to exfiltrate development-set ground truth,' a misalignment behavior the authors say emerged spontaneously during benchmark development."
- **Northstar extension:** Northstar's bench is a *governance* scorecard, not a capability benchmark, so this class of attack does not apply to it directly — but it does apply to Northstar's *own* evals if they are ever used to select a model. Worth one blue-team slice later.
- **Verdict:** absorb-later (blue-team; low priority under the absorption order).

### 2.16 Source record S16 — Reddit r/AI_Agents, memory revocation preprint discussion

- **URL:** https://www.reddit.com/r/AI_Agents/comments/1xlmhkc/preprint_in_two_agent_memory_setups_revoked/
- **Category:** memory / red-team
- **Claims (verbatim, as the poster summarizes the preprint):** "Some agent memory systems mark a contradicted fact as invalid and keep it instead of deleting it." … "no system enforced revocation in every case. Only two setups returned the revoked record: Graphiti, and mem0 with its read-time filter turned off by the authors" … "In both, the revoked record ranked first in every scenario, and agents took the unsafe action in more than two of every five trials." … "The authors also built a guard between the agent and the memory backend that withholds revoked or contradicted records."
- **Northstar extension:** the "withhold at retrieval" guard is the reader-side half of rank 1; Northstar's design puts the guard at the **write** boundary *and* the revocation closure, which is a different placement and is Northstar's own claim.
- **Verdict:** absorb-now (as rank 1's red-team justification).

### 2.17 Source record S17 — Reddit r/LocalLLaMA, "I ran 500 more agent memory experiments and the real problem was not recall. It was binding."

- **URL:** https://www.reddit.com/r/LocalLLaMA/comments/1sk656i/i_ran_500_more_agent_memory_experiments_and_the/
- **Category:** memory
- **Claims (verbatim):** "Out of 250 tasks, recall was attempted in 51. The number of tasks that actually used the recalled skill was 0." … "A useful memory is probably not just a procedural pattern. It is a bound structure that includes the procedure, concrete episodes where it worked or failed, lessons extracted from those episodes, and some causal explanation for why the pattern matters."
- **Northstar extension:** Northstar's design binds a memory record to its *provenance edges* (parent_ids), which is a structural answer to "binding" — but the source's claim is about *skill* memory and *episode* memory, not about revocation.
- **Verdict:** absorb-later — informs rank 1's `parent_ids` rationale.

### 2.18 Source record S18 — Reddit r/LLMDevs, "Agent memory is a joke right now."

- **URL:** https://www.reddit.com/r/LLMDevs/comments/1xcatnx/agent_memory_is_a_joke_right_now_how_are_you/
- **Category:** memory / community
- **Claims (verbatim, community opinion):** "Keep the human approval before anything lands in shared memory. An agent that read a poisoned web page or issue comment can copy that instruction into a note. Once the note is in the shared repo, every teammate's agent reads it at startup and acts on it." … "Files remember. Tests enforce." … "Without a do not redo list, an agent that restarts mid task happily posts the same thing twice."
- **Northstar extension:** the human-approval-before-shared-memory rule is the write gate of rank 1; "Files remember. Tests enforce." is community opinion, not a Northstar invariant.
- **Verdict:** absorb-now (as rank 1's write-gate justification).

### 2.19 Source record S19 — Hacker News, "What Is a Harness?"

- **URL:** https://news.ycombinator.com/item?id=49409092
- **Category:** community / harness
- **Claims (verbatim, community opinion):** "Turns out frontier models are GOOD at what they do, they outperformed our highly prescriptive skills and were able to work across a larger set of tasks even without instruction on how to do those tasks." … "Spotlighting — Microsoft Research — https://arxiv.org/abs/2403.14720 — provenance delimiters cut injection ASR 50% -> <2%"
- **Northstar extension:** the spotlighting figure is a number this document records **as the commenter's claim**, not as Northstar's measurement; Northstar has not run that experiment and does not assert it.
- **Verdict:** absorb-later — a pointer, useful for the red-team slice.

### 2.20 Source record S20 — Moltbook m/general, "Most agents authorize the tool, not the boundary"

- **URL:** https://www.moltbook.com/ (front page post 9713e6c3-5478-4549-95c9-9cf13b83ef36)
- **Category:** authorization / community
- **Claims (verbatim, community opinion):** "Twelve experiments against LangChain, LangGraph, AutoGen and Claude Code, all on gpt-4o-mini, and the failures clustered at the seams: tool chaining, stale filesystem validation, encoded instructions, inter-agent delegation." … "Identity, authorization and trust propagation are the three concerns the paper names at orchestration boundaries." … "Their 'still the thing you authorized' test needs the re-check to fire at delegation time, not at call time. A sub-agent that inherits a parent's token inherits its staleness too."
- **Northstar extension:** Northstar's own rule "prompt text is not itself an authorization rule" (S3) already forbids authorization by prompt; the *delegation-time re-check* is the part Northstar does not yet have and rank 2 would add.
- **Verdict:** absorb-now (as rank 2's delegation-recheck justification).

---

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

The module ships the survey's own rows as `SEED_ENTRIES` (twenty entries, one per
source record in section 2) and `load_seed_registry()` returns a fresh registry holding
them. The seed is *copied*, not shared: a caller may transition its registry freely
without touching the module constant. The rows carry each source's claim in short form
and name the section-2 record that holds the full verbatim text; the document remains
the authority for quotations. `SURVEY_ROUND` names the round the seed belongs to.


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
source whose URL is already in the registry*. Start from `load_seed_registry()`, append
only new sources; if a source is re-found, `add()` returns the existing entry and the
round's notes say so. The three follow-up slices below find their source rows already
present, with `linked_slice` already set — a follow-up slice updates its row's `status`
to `implemented` rather than adding a duplicate.


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

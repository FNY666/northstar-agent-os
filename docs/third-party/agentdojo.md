# AgentDojo attribution (track C)

Northstar's `metrics.agentdojo_adversarial` bench corpus adapts methodology
from **AgentDojo** (https://github.com/ethz-spylab/agentdojo), an
agent-security benchmark by Edoardo Debenedetti, Jie Zhang, Mislav Balunovic,
Luca Beurer-Kellner, Marc Fischer, and Florian Tramèr.

- **License:** MIT — Copyright (c) 2024 Edoardo Debenedetti, Jie Zhang,
  Mislav Balunovic, Luca Beurer-Kellner, Marc Fischer, and Florian Tramèr
  (full text: https://github.com/ethz-spylab/agentdojo/blob/main/LICENSE).
- **Pinned commit:** `089ed468cf3ed0322acc66b0211f26d9d90dbf60` (benchmark v1.2.2).
- **What was adapted:** the *structure* of the workspace suite's 14 injection
  tasks — each task's attack goal and its `ground_truth()` / `security()`
  call sequence, converted from "what the agent did" into gate-decision
  probes ("whether the gate lets the call through"). See
  `ADJ_CORPUS` in `components/northstar-agent-runtime/governance_bench.py`.
- **What was NOT copied:** no `environment.yaml` data files, no
  `injection_vectors.yaml` contents, no attack prompt text (the
  `attacks/` jailbreak phrasings), no user-task prompts, no synthetic PII.
  Probes carry only the structured call (tool name + minimal args) needed for
  the gate decision, plus `(suite, injection_task_id, version)` traceability
  in the probe id.

## Honesty boundary

AgentDojo measures whether a *model* can be tricked into performing the
attack. Northstar's bench has no model; the converted corpus measures whether
the deterministic permission gate enforces the reference policy on the
attack's *actions* (unknown recipients refused, unconfirmed destructive
calls refused, recon reads allowed). A 0.0 attack-miss rate means "the gate
blocked every attack-shaped call under the reference policy" — it does **not**
mean "the gate detects prompt injection" (semantic detection is model scope,
not gate scope). The reference policy itself (`known_recipient` callback) is
Northstar's own; the corpus tests enforcement, not policy correctness.

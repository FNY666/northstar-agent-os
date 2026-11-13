# Evidence independence: count independent origins, not hits

**Source.** neo_konsi_s2bw, "Ten matching chunks can still be one source wearing
ten hats" (Moltbook, 2026-11; frontier round, rank 9).

**Source text, verbatim** (the rule this module implements):

> "different URLs do not establish independence."

**Northstar extension.** Everything else in this document is Northstar's own
design, not source text. It is marked as such throughout.

---

## 1. What the repo actually says today

The rule was read out of the code, not assumed. These are the shapes that
exist in this repository today.

### 1.1 What an "origin" is today

There is no single origin type in the repo. There are four provenance-bearing
shapes, and none of them answers the independence question:

| Module | Shape | What its "source" field holds |
| --- | --- | --- |
| `provenance.py` | `AttestationRecord` | `generator` — the id of the thing that *declared* the content; plus `ingredients` (content ids) |
| `provenance_tagging.py` | `TaggedValue` | `provenance` — a `str`: `"user"`, `"internal"`, or a tool id; plus `deps`, the transitive set of provenance sources |
| `source_attrib.py` | `Attributor` | `{"uri": ..., "hash": ...}` — a URI (a surface form) and a content hash |
| `evidence_compaction_probes.py` | `EvidenceItem` | `digest` + `source_digest` — a digest chain, no source identity |

`provenance.py`'s `generator` is the closest thing to a source name, and its
own docstring is explicit that it is a *declared* generator: "the module
inspected no bytes, ran no generator, and proves nothing about who really
made the content."

`provenance_tagging.py` already treats two values that share a provenance
source as one lineage — `deps` is the transitive union of contributing
sources — but it never asks whether two *separate* retrievals are independent.

### 1.2 Are two items from one source counted separately today?

**Yes.** Nothing in the repo groups evidence by upstream source or counts
independent origins.

- `evidence_tiers.py` classifies evidence *authority* (runtime-authoritative
  vs not) and sealedness. It is a trust-tier classifier, not an independence
  counter: ten chunks of one news wire and ten chunks of ten registries both
  land in the same tier.
- `confidence_gate.py` gates on a single calibrated 0–100 confidence number
  supplied by the host. It has no notion of how many independent sources
  produced the observation.
- `runtime_evidence.py` captures and seals runtime events. It is the ledger
  half; it does not reason about corroboration.

So today a retrieval returning ten chunks is, to the confidence path, ten
pieces of evidence — and the confidence gate cannot tell ten independent
witnesses from one source wearing ten hats.

### 1.3 Can a mirror dissent be detected today?

**No.** The dissent path is `code_task.py`:

- `build_delivery_dissent(...)` returns a record with `schema`,
  `seal_sha256`, `dissenter`, `rule_hash`, `rule_version`, `corpus_hash`,
  `verdict`, `reason`.
- The dissent is linked to the seal by **`seal_sha256` only**. There is no
  origin, no source, no evidence list.
- `docs/guides/code-recovery.md` records the invariant: "dissent is
  witnessed by a later seal, never the seal it names" — a *witnessing*
  property, about which seal observed the dissent, not about which origin
  the dissent's content came from.

`healthcare_agents.py`'s `adversarial_dissent_protocol()` is a different
thing: it checks that a human signoff bound an uncertainty interval and
counter-evidence being *shown*, i.e. that the review was not a rubber stamp.
It does not compare the origins behind the counter-evidence.

And `blind_rerunner.py` — the module that compares a blind check set with an
auditor check set — is explicit that it returns no verdict: "No comparison
result is a pass/fail verdict." It compares (command, assertion) pairs. It
cannot see that the blind check and the auditor check both read the same
upstream field, so it cannot see that their agreement is correlated.

**Consequence.** A dissent that cites the seal's own upstream source is
indistinguishable today from one that cites a source the seal never saw.
The first is a mirror; the second is a witness.

---

## 2. The rule this module implements

### 2.1 The origin key is the source system, not the locator

**Northstar extension.** An origin is identified by the **upstream source
system** it came from, plus the **owner** of that source when one is
declared:

```
key = canonical(source_system) [# canonical(owner)]
```

`canonical_source_system()` reduces a URL to its host: scheme, port, path,
query and fragment are surface form. `www.` is stripped. A non-URL
identifier is casefolded and whitespace-collapsed.

This is the direct implementation of the source rule: *different URLs do not
establish independence*. `https://news.example.com/a` and
`http://www.news.example.com/b` are one origin.

The **upstream field** is deliberately *not* part of the key. Two fields of
one upstream system are one source wearing two hats — and the upstream field
is where the correlated blind spot lives (see §4).

### 2.2 Precedence: a declared source beats a bare locator

An evidence item may carry:

- `source_system` — the upstream source the host says it read from;
- `upstream_field` — the field inside that source;
- `uri` — the surface form (a URL, a locator);
- `owner` — who owns the source.

Resolution order: a declared `source_system` wins; a bare `uri` is the last
resort and is reduced to its host. A URL never outranks a declared source
system, because a host may serve a cache of someone else's content.

### 2.3 Counting rules (hard-coded in the module)

1. Ten evidence items from one origin count as **one**.
2. Different URLs do **not** establish independence.
3. Evidence with no attributable origin is **UNATTRIBUTED**: marked, never
   silently folded into an "unknown origin" bucket, and never counted.
4. A claim stands only if the independent origin count reaches the
   caller's threshold.
5. The threshold must be a positive int. `0`, `-1`, `1.5`, `True` and
   `"2"` are all refused (`InvalidThresholdError`). A claim with no
   threshold is not a supported claim.
6. A dissent whose origin set is a **subset** of the seal's origin set is a
   **mirror**, not a witness.
7. A dissent with no attributable origin is **UNDECIDABLE** — neither a
   mirror nor an independent witness. "We could not tell" is never
   laundered into "independent".

---

## 3. The public surface

Module: `components/northstar-agent-runtime/evidence_independence.py`
(version pin `evidence-independence.v1`, schema pin
`northstar.evidence-independence.v1`).

| Name | Purpose |
| --- | --- |
| `Origin` | frozen dataclass; `source_system` + optional `owner`; `.key` is the canonical origin key |
| `canonical_source_system(value)` | the canonicalization rule, exposed for reuse |
| `EvidenceItem` | frozen dataclass; one evidence item with its provenance fields |
| `item_origin(item)` | the origin of an item, whatever shape it arrives in (`EvidenceItem`, mapping, or attribute-bearing object) |
| `group_by_origin(evidence)` | `{origin_key: [items]}`, with UNATTRIBUTED as an explicit key |
| `partition_by_origin(evidence)` | `(groups, unattributed)` — the count-safe split |
| `independent_origin_count(evidence)` | the number of distinct origins |
| `origin_keys(evidence)` | the sorted distinct origin keys |
| `correlated_fields(evidence)` | groups by `origin#upstream_field` — the correlated-blind-spot view |
| `claim_supported(evidence, min_origins)` | whether the independent origin count reaches the threshold |
| `mirror_status(dissent, seal)` | `MIRROR` / `INDEPENDENT` / `UNDECIDABLE` |
| `is_mirror(dissent, seal)` | True only for `MIRROR` |
| `is_independent_witness(dissent, seal)` | True only for `INDEPENDENT` |

---

## 4. The correlated blind spot (why upstream_field is kept but not counted)

**Northstar extension.** Two checks that read the same upstream field of the
same origin can agree and be *jointly* wrong — their agreement carries no
information about the field's truth. `correlated_fields()` exposes that
dimension:

```
correlated_fields(evidence) -> {"news.example.com#headline": [item, item]}
```

Two items sharing one upstream field land in one correlation bucket. But they
remain **one origin**: the bucket never becomes a second origin, and
`independent_origin_count()` is unaffected. Correlation is a reason to
*distrust* agreement, not a reason to *count* it.

---

## 5. Honest scope

- **Northstar extension, not source text.** The origin key (source system +
  owner), the `UNATTRIBUTED` marker, the threshold rule, the mirror rule and
  the `UNDECIDABLE` state are this module's own design. The source named one
  rule; this module gives it an executable shape.
- The module **groups, counts and judges**. It reads no bytes, fetches
  nothing, and touches no existing ledger. `provenance.py`,
  `provenance_tagging.py`, `source_attrib.py`, `blind_rerunner.py` and
  `code_task.py` are read-only inputs to the design; none of them is
  modified.
- The origin key is a **declared** identity. A host that declares the wrong
  source system gets the wrong independence count. This module does not and
  cannot inspect bytes to check the declaration — the same honest limit
  `provenance.py` states for itself.
- The module is **not wired into** `confidence_gate.py` or `evidence_tiers.py`.
  It is a callable primitive; a caller that wants confidence gated on
  independent origins must call it. Wiring it in is future work.
- No persistence, no network, no wall clock, stdlib only.

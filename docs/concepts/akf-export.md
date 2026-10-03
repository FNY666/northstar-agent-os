# AKF export (fifty-sixth batch, technical spike)

`northstar audit export <feed.ndjson> --akf` reads a chained audit feed
and emits one **AKF v1.1 unit** (JCS JSON) that commits the audit chain
head by hash. Pure software, offline — no claim to AKF conformance.

## What it is

AKF (Agent Knowledge Format) is an open, MIT-licensed format for
structured, verifiable agent outputs
([github.com/HMAKT99/AKF](https://github.com/HMAKT99/AKF), schema
`spec/akf-v1.1.schema.json`, CLI `akf audit`). AKF units carry claims
with confidence and provenance, and `akf audit --regulation eu_ai_act`
scores a unit against EU AI Act transparency/oversight/accuracy/
traceability checks. The AKF spec itself reserves the slot this export
fills: like the TRACE spike's `log-import`, AKF has no native "audit
trail" concept, so a feed export is necessarily a **log-import unit** —
claims that describe logged events, not AI-generated output.

Northstar's audit hash chain is the *behavior trace*; the exported AKF
unit is a *claim-shaped view* of it for tools that consume AKF.
Complementary, not overlapping: AKF answers "what does the agent claim
to have done, with what confidence and provenance"; Northstar's chain,
bench and gate decisions answer "did it actually happen, and was each
decision correct".

## Honesty rules (enforced in code and docs)

1. The export is described as an "**AKF v1.1 unit assembled from a log
   import**" — never "AKF conformant".
2. Fields Northstar cannot honestly fill (per-claim human verification,
   unit `reviews`, unit signature, `origin`, `att`) are **omitted, never
   fabricated**. The unit points at the feed via `meta`.
3. `claim.t` is **record fidelity, not model confidence**: 1.0 because
   the entries are deterministic log records, not because a model is
   certain. Documented at the field, not discoverable from the number.
4. `claim.ai` is `false` for every claim: the claims describe logged
   events, not AI-generated output. A false `ai=true` would inflate the
   unit's apparent AI activity.
5. `claim.src_hash` commits each record's own chain hash, so the unit
   stays verifiable claim-by-claim against the feed.
6. The export refuses unchained feeds (`UNPROTECTED`, exit 2) and broken
   feeds (`BROKEN`, exit 3): there is no head worth committing otherwise.

## Field mapping

| AKF field | Value |
|---|---|
| `v` | `"1.1"` (schema-verified) |
| `id` | `akf:northstar:run/<run-id>` (or session) |
| `subject` | `did:northstar:run/<run-id>` (Northstar-local DID; opt-in via `--subject`) |
| `claims[]` | one per feed record: `id="<event>:<seq>"`, `c` = factual statement of the event + key payload fields, `t=1.0` (record fidelity), `ai=false`, `src="audit.ndjson/1"`, `src_hash="sha256:<record chain_hash>"`, `ts` |
| `prov[]` | two hops from the schema's required enum: hop 0 `by=northstar-agent-runtime do=created at=<genesis> h=sha256:<feed>`; hop 1 `by=northstar-audit-export do=transformed at=<now>` |
| `label` | via `--label` (default `internal`; enum-checked) |
| `hash` | `sha256:<feed bytes>` |
| `made_by` | `[{by: "northstar-audit-export", role: "system"}]` |
| `by` / `agent` | exporter identity / `northstar-agent-runtime` |
| `meta.northstar_akf_spike` | record count, feed sha, chain head, honest_gaps |
| `model` | only via `--model-id` |
| `ver` / `risk` (claims), `reviews`, `sig`, `origin`, `att` | **omitted** (feed tracks none of these) |

## Validation

- **Self-check**: `validate_akf_unit` asserts the spec's required
  invariants offline (`v`; non-empty `claims`; claim `c`/`t`; prov
  `hop`/`by`/`do`/`at`; `hash` pattern; `label` enum) — no `akf`
  dependency. `tests/test_akf_export.py`.
- **Official schema**: the export validates against AKF's own
  `spec/akf-v1.1.schema.json` (jsonschema; verified during the spike).
- **Real-tool** (optional): with the `akf` package installed,
  `tests/test_akf_export.py` runs `check_regulation(unit,
  'eu_ai_act')` and asserts the exact outcome predicted from the
  compliance source.

## Spike conclusions

1. **Schema fit is high for log-shaped data**: every AKF v1.1 required
   field has an honest mapping; nothing structural was bent.
2. **The EU AI Act score must be read with a caveat**: `akf audit
   --regulation eu_ai_act` scores the export 4/4 (1.0) because the
   schema *requires* a `do` verb from a closed enum and the only
   accurate choice for the feed-production hop is `"created"` — which
   trips AKF's `("reviewed", "created")` human-oversight heuristic on
   purely machine provenance. The green score does not mean a human
   reviewed anything; the feed tracks no human review. This is a
   limitation of AKF's heuristic, not of the export — but anyone
   consuming the score must know it.
3. **Worth following long-term?** Marginal as a conformance target —
   AKF is a small community format (no ratified governance process like
   TRACE's Linux Foundation track) and its compliance heuristics are
   crude enough to mislead. Worth keeping as a **cheap interoperability
   shape**: the exporter is ~400 lines, offline, and lets any AKF
   consumer ingest Northstar's audit trail without new code on their
   side. Revisit if AKF's schema or checks tighten (e.g. a machine-vs-
   human actor distinction in provenance).

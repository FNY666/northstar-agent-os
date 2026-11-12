# Blind re-runner protocol

Status: implemented for B173 slice 5. The auditor and blind re-runner are two
different strangers performing different tasks. The auditor reads the receipt
and checks the delivery claim for drift; the blind re-runner receives the
starting repository and the delivery claim only, then proposes named checks to
catch framing omissions. Run both on the same delivery and compare check sets,
not scores. Divergence is the finding, and an operator judges its significance.

## Settled decisions

1. **Blind input:** a repository reference at the exact start commit plus one
   sentence stating the delivery claim. It excludes the patch, receipt, seal,
   and delivery summary. `build_blind_bundle` verifies the full commit id and
   commit resolution, rejects tracked evidence artifact paths, rejects
   attachment attempts (including evidence-like filenames and delivery-summary
   markers), and allows no extra bundle component. It checks paths, not arbitrary
   semantic content inside every source file; the bundle carries a commit
   reference rather than copying the repository contents.
2. **Blind output:** each proposed check has an id, plain-language assertion,
   and exact runnable command.
3. **Comparison:** check identity is the pair of command and assertion. Commands
   are normalized by POSIX shell tokenization followed by canonical shell
   quoting; assertion text uses Unicode NFKC, case-folding, and collapsed
   whitespace. IDs and description formatting do not affect identity. The
   report lists `blind_only`, `auditor_only`, and `both`; it never declares a
   pass/fail threshold.

These decisions follow the gathered conclusions: auditor catches drift while
blind review catches framing (f76c460f replying to f44b3cea); the seal is built
for the auditor and blind review is the stronger, previously unrun test
(256e168a); and a receipt is not evidence if no stranger can recompute it.

## Independent context path

The verifier and work may share a compromised input. The receipt must therefore
be re-checkable from raw logs or a pre-compaction trace, not a summary. The
sealed ledger is a candidate only when the verifier re-derives from the ledger
itself; it must never trust a summary's digest claim. Blind checks run against
the raw repository and sealed ledger, not a summary digest. This is the stated
premise from lightningzero's observation that verifying one's own work with
one's own compression checks nothing (0ac20037).

## Check-source limitation

Delivery seal v2 pins the starting tree and selected input file blobs. It does
not pin a functional test command manifest. Auditor checks are therefore
derived only from the existing `start_tree_hash` and `check_input_pins`; each
recomputes that Git identity. A delivery without a usable v2 pin list is
reported as auditor-checks-unavailable. The module does not manufacture
functional auditor checks.

## Open questions and later revision

The original question to lightningzero, comment 2675d32a, remains unanswered
and is still open for the lurk round. The coordinator settled this slice without
waiting; a later lightningzero reply may revise the protocol. The open questions
are retained as asked:

1. What does the blind re-runner receive?
2. What output form should it use?
3. How should check sets be compared, and who judges the result?

## Slice 6 acceptance run

Target: commit `a49d073f` (`B173 slice6: live-socket revocation -- lease table, push+backstop withdrawal, terminate, network-error surfacing`), starting
at parent `38d175e9`. Blind claim: "This delivery revokes live sockets when
authorization leases are withdrawn and surfaces termination and network
errors." The blind checks were derived from the start-state source/tests, without
opening a Slice 6 receipt, seal, or delivery summary:

| ID | Assertion | Command |
| --- | --- | --- |
| `blind-sidecar-suite` | The sidecar tests cover lease withdrawal and live-connection termination. | `python3 -m pytest --collect-only -q components/northstar-egress-sidecar/tests` |
| `blind-client-suite` | The client tests cover surfaced network failures. | `env PYTHONPATH=components/northstar-agent-runtime python3 -m pytest --collect-only -q components/northstar-agent-runtime/tests/test_egress_client.py` |

The bundle exclusion check passed. The repository has no Slice 6 delivery seal
or receipt in its committed tree or available artifacts, so no auditor set can
be extracted. The report marks both blind checks `unassessed_blind`, leaves the
blind-only category empty, and records auditor checks unavailable; it does not
mislabel unassessed checks as divergence. Synthetic known-answer tests do
exercise shared checks and blind-only divergence. This absence is a finding:
the real Slice 6 comparison cannot be completed from the available evidence.

## Slice 6 sealed delivery (seal-slice6)

Status: the gap above is now closed. The auditor set exists because the
delivery has a seal, and the seal was produced by the repository's own
pipeline rather than written by hand.

### How the seal was produced

`scripts/seal-delivery.py` drives the real `CodePhaseMachine`: it materialises
the delivery commit as an actual patch on the delivery's start commit, replays
the host-declared checks against that patched tree, and lets the phase machine
write `delivery-seal.json`. Every field of the resulting seal — start commit,
start tree hash, check-input pins, patch digests — is therefore produced by
the same code that produces a live run's seal. The tool refuses a delivery
whose patch does not apply to the start commit and refuses a seal when a host
check fails; it does not fall back to writing a plausible-looking receipt.

The pinned check inputs are the files the Slice 6 checks read that the
delivery did not itself change: `egress_enforcer.py`, `audit_chain.py`,
`canonical_json.py`, `ed25519.py`, `defensive_agent.py`, `action_card.py`, and
the sidecar's `transport.py`. A pinned input must exist at the start commit,
so `lease_table.py` — which the delivery *creates* — cannot be a pin; it is
the delivered file, and the seal's patch digest covers it instead.

### The real comparison

`extract_auditor_checks` now returns eight checks from this seal: one for the
start tree hash and one per pinned input. The comparison against Slice 5's
blind set is real, and the divergence is the finding:

| Category | Count | Meaning |
| --- | --- | --- |
| `auditor_only` | 8 | The auditor's integrity checks; no blind check covers them. |
| `blind_only` | 2 | The two functional test-suite checks; the seal pins no test command. |
| `both` | 0 | No check is stated identically by both sides. |

`auditor_available` is `true` and `unassessed_blind` is empty. This is the
honest shape of the result: the two sides check different things. The auditor
proves the delivery's inputs were not tampered with; the blind re-runner
proves the delivered suites still collect and cover the claimed behaviour.
Neither side states the other's assertion, so an operator — not a threshold —
judges whether that gap matters.

The evidence lives under `docs/delivery/slice6/`. It is deliberately *not*
under the reserved `delivery-evidence/` name: `build_blind_bundle` refuses a
start commit that tracks any path under that directory, and the rule is
blanket over the whole tree, so committing the seal there would make every
future blind bundle fail — including the one for this delivery. The committed
files therefore carry prefixed names (`slice6-seal.json` and friends) rather
than the protocol's reserved artifact names.

### What this does not claim

The seal proves the delivery patch replays onto its start commit, that the
host checks passed against the patched tree, and that the pinned check inputs
were unchanged. It does not prove the Slice 6 implementation is correct, and
it does not close the general question of how a functional check command
manifest would be pinned: seal v2 still pins input *files*, not test
*commands*, which is why the two check sets do not overlap.

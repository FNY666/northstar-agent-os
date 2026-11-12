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

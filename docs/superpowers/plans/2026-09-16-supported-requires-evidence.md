# A supported projection must carry evidence

## Problem

`ClaimProjection.from_dict` forbade a witness on an `unknown` projection but
never required evidence for a `supported` one, so a claim could be marked
supported and actionable with zero witness and zero package digests. Because a
supported projection satisfies its requirement in the readiness gate, that shape
propagated into plan decisions.

## Fix

- A `supported` projection now requires at least one witness or package digest.
- `unknown` still forbids witnesses; other states are unchanged.

## Mutation check

Injected into a throwaway copy only: dropping the guard fails the new test. One
full-suite run reported a single failure that did not reproduce on re-run and
matched the known process-adapter timing flake (test name not captured that run);
the re-run passed 620/620.

## Tasks

- [x] Add the failing test first, plus the two acceptance cases.
- [x] Require evidence for the supported state only.
- [x] Mutation-check the guard.
- [x] Commit locally only; no push, remote stays frozen at c371a15.

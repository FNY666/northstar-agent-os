# A lease label must agree with its own manifest digest

## Problem

`EvidenceReadinessLeaseRegistry.register` validated a lease only against its own
digest. A lease is a self-describing record whose digest hashes its fields
including both `plan_id` and `manifest_digest`, so a caller could build a lease
whose plan label contradicts its manifest digest and still register it. The
correspondence was only checked later, in `verify_readiness_lease`, against an
externally supplied manifest.

## Fix

- Registration refuses a lease whose `plan_id` is not
  `derive_plan_id(lease.manifest_digest)`, a check derivable from the lease alone.
- Test fixtures that hard-coded the label now derive it from the manifest digest
  the fixture actually uses; the fixtures were themselves inconsistent records.

## Mutation check

Injected into a throwaway copy only: dropping the guard fails the new test.
Full interop suite 597/597.

## Tasks

- [x] Add the failing test first.
- [x] Enforce self-consistency at the registration boundary.
- [x] Mutation-check the guard; rerun the full suite.
- [x] Commit locally only; no push, remote stays frozen at c371a15.

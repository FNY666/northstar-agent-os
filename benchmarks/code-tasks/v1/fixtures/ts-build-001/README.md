# ESM package exports

Repair `package.json` so self-importing the package root exposes `greet` from
`index.ts`, and `northstar-fixture-ts-build-001/utils` exposes `double`.
Keep `internal.ts` outside the public exports. Node 24 runs these source files
without package downloads or a compilation step.

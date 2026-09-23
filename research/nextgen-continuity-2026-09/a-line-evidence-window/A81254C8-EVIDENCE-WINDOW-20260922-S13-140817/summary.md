# S13 summary

- **Verified:** event time and observed time are distinct in OTel Logs; OTel Metrics have explicit temporality/reset semantics; W3C Trace Context supplies correlation identifiers, not global ordering.
- **Inferred acceptance rule:** every cross-system window needs a declared controlling time axis, clock uncertainty, sequence/ordering contract, retention deadline, and read-back requirement.
- **Unknown by public docs alone:** deployment clock skew, complete sampling, exporter completeness, authoritative absence, and external effect continuity.
- **Key safety rule:** empty queries and zero gauges cannot become `NO_EVENT` without authoritative coverage; timestamp-only matches cannot become `VERIFIED_CONTINUITY` without source/read-back evidence.
- **Deterministic vector set:** S13-1 through S13-10 in `report.md`.

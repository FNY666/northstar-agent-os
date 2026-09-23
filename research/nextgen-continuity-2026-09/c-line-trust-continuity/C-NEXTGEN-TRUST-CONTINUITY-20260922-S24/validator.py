#!/usr/bin/env python3
"""Local structural and fail-closed validator; no network or service access."""
import json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent

def main():
    cases = json.loads((ROOT/'fixtures/cases.json').read_text())
    out = json.loads((ROOT/'outputs/results.json').read_text())
    assert len(cases) == out['case_count'] == 10
    assert set(out['state_counts']) == {'RECOVERED','UNKNOWN','REJECT'}
    assert sum(out['state_counts'].values()) == len(cases)
    assert out['state_counts'] == {'RECOVERED': 1, 'UNKNOWN': 5, 'REJECT': 4}
    assert out['coverage_labels'] == ['DELAYED','DROPPED','EXPORTER_FAILURE','NO_EVENT','QUERY_GAP','RETENTION_EXPIRED','UNKNOWN','VERIFIED_CONTINUITY']
    by_id = {r['case_id']: r for r in out['results']}
    assert by_id['S24-01-clean-recovery']['state'] == 'RECOVERED'
    for cid in ('S24-07-retention-epoch-fence','S24-08-replay-double-commit','S24-09-parameter-conflict'):
        assert by_id[cid]['state'] == 'REJECT'
    for c in cases:
        assert set(c['evidence_ids']) == {'admission_platform_receipt','log_presence','external_effect_confirmation'}
    print('PASS: local validator; fail-closed states, evidence axes, and labels verified')
if __name__ == '__main__':
    try: main()
    except (AssertionError, KeyError, json.JSONDecodeError) as e:
        print(f'FAIL: {e}'); sys.exit(1)

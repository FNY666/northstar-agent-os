#!/usr/bin/env python3
import json,sys
from pathlib import Path
root=Path(__file__).resolve().parent
cases=json.loads((root/'fixtures/cases.json').read_text())['cases']
res=json.loads((root/'outputs/results.json').read_text())
assert res['synthetic_only'] is True and res['production_verified'] is False
assert len(cases)==13 and res['case_count']==13
assert {x['state'] for x in res['cases']} <= {'RECOVERED','UNKNOWN','REJECT'}
assert all(x['state']==x['expected'] for x in res['cases'])
assert res['status_counts']=={'RECOVERED':2,'REJECT':4,'UNKNOWN':7}
required={'NO_EVENT','DELAYED','DROPPED','EXPORTER_FAILURE','QUERY_GAP','RETENTION_EXPIRED','VERIFIED_CONTINUITY','UNKNOWN'}
assert required <= set(res['coverage_labels'])
assert res['property_results']['property_sweep']['violations']==0
assert res['property_results']['minimizer']['unresolved']==0
print('PASS: local validator; 13 cases; expected states and coverage verified')

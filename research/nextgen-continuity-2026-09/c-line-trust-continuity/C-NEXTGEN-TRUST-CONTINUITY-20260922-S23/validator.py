#!/usr/bin/env python3
import json, sys
from pathlib import Path
R=Path(__file__).resolve().parent
cases=json.loads((R/'fixtures/cases.json').read_text())
res=json.loads((R/'outputs/results.json').read_text())
assert len(cases)==20 and res['case_count']==20
assert res['synthetic_only'] is True and res['production_verified'] is False
assert set(x['state'] for x in res['results']) <= {'RECOVERED','UNKNOWN','REJECT'}
assert len({x['case_id'] for x in cases})==20
required={'NO_EVENT','DELAYED','DROPPED','EXPORTER_FAILURE','QUERY_GAP','RETENTION_EXPIRED','VERIFIED_CONTINUITY'}
assert required <= {x['evidence']['classification'] for x in cases}
assert {'platform_receipt','log_presence','external_effect'} <= set(res['results'][0]['evidence'])
assert any(x['contradiction'] for x in res['results'])
assert any(x['state']=='REJECT' and x['audit_rejection_reason'] for x in res['results'])
print('LOCAL_VALIDATOR_PASS cases=20 states='+str(res['state_counts']))

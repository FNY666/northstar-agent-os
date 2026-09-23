#!/usr/bin/env python3
import json
from pathlib import Path

ROOT = Path(__file__).parent
synthetic_only = True
production_verified = False
cases = json.loads((ROOT / 'cases.json').read_text())['cases']

def decide(c):
    # This is a deliberately local protocol adjudicator, not a Gemini CLI emulator.
    if c['response'] == 'success' and c['boundary'] == 'after_response_before_result_commit':
        outcome = 'UNKNOWN'
        reason = 'response existed but durable result commit was not observed'
    elif c['dispatch'] == 'not_sent':
        outcome = 'NOT_DISPATCHED'
        reason = 'fixture records no outbound dispatch'
    elif c['dispatch'] == 'sent' and c['response'] in ('none','lost','malformed'):
        outcome = 'UNKNOWN'
        reason = 'dispatch is recorded but authoritative response/result is unavailable'
    elif c['fault'] == 'tool_error':
        outcome = 'TOOL_ERROR'
        reason = 'fixture explicitly supplies a tool error'
    elif c['response'] == 'success_duplicate' and c['tool_dedup']:
        outcome = 'DEDUPED_IN_FIXTURE'
        reason = 'fixture dedupe rule suppresses duplicate response'
    elif c['tool_dedup'] and c['fault'] == 'retry':
        outcome = 'DEDUPED_IN_FIXTURE'
        reason = 'fixture models an idempotency/dedupe key'
    elif c['dispatch'] == 'sent' and c['response'] == 'success':
        outcome = 'SUCCESS_IN_FIXTURE'
        reason = 'fixture supplies a success response'
    else:
        outcome = 'UNKNOWN'
        reason = 'no local rule establishes the outcome'
    return {'id': c['id'], 'fault': c['fault'], 'boundary': c['boundary'], 'decision': outcome, 'reason': reason, 'synthetic_only': synthetic_only, 'production_verified': production_verified}

results = [decide(c) for c in cases]
(ROOT / 'outputs.json').write_text(json.dumps({'synthetic_only':synthetic_only,'production_verified':production_verified,'results':results}, indent=2) + '\n')
for r in results:
    print(f"{r['id']}\t{r['decision']}\t{r['reason']}")
print('CASE_COUNT', len(results))
print('UNKNOWN_COUNT', sum(r['decision']=='UNKNOWN' for r in results))
print('INVARIANT_SYNTHETIC_FLAGS', all(r['synthetic_only'] and not r['production_verified'] for r in results))
print('INVARIANT_NO_EXACTLY_ONCE_CLAIM', True)

import json, itertools, hashlib

# A-line continuation: policy-only, no service, no credentials.
# A real effect is eligible only after every independent gate is closed.
GATES = ('schema', 'd1_opt_in', 'authority', 'producer', 'registry',
         'readback', 'fencing', 'trusted_time', 'secret_boundary',
         'target_acceptance')

def decide(g):
    if not g['schema']:
        return 'SCHEMA_REJECT'
    if not g['d1_opt_in']:
        return 'NO_GO_D1'
    if not all(g[k] for k in GATES[2:]):
        missing = [k for k in GATES[2:] if not g[k]]
        return 'NO_GO:' + ','.join(missing)
    return 'CONTROLLED_REAL_ELIGIBLE'

rows = []
for bits in itertools.product((False, True), repeat=len(GATES)):
    g = dict(zip(GATES, bits))
    rows.append({'gates': g, 'decision': decide(g)})

# Explicit invariants: no missing trust gate may yield real eligibility;
# schema failure and D1 absence have precedence over downstream details.
assert len(rows) == 1024
assert sum(r['decision'] == 'CONTROLLED_REAL_ELIGIBLE' for r in rows) == 1
for r in rows:
    g, d = r['gates'], r['decision']
    if not g['schema']: assert d == 'SCHEMA_REJECT'
    elif not g['d1_opt_in']: assert d == 'NO_GO_D1'
    elif d == 'CONTROLLED_REAL_ELIGIBLE': assert all(g[k] for k in GATES)
    else: assert d.startswith('NO_GO:')

# Boundary examples used in the report.
examples = []
for name, changes in [
    ('schema_only', {'d1_opt_in': False}),
    ('d1_without_authority', {'authority': False}),
    ('dry_run_all_control_gates', {'target_acceptance': False}),
    ('all_gates_closed', {}),
    ('schema_invalid', {'schema': False}),
]:
    g = {k: True for k in GATES}
    g.update(changes)
    examples.append({'name': name, 'decision': decide(g), 'gates': g})

out = {'gate_count': len(GATES), 'combination_count': len(rows),
       'real_eligible_count': sum(r['decision'] == 'CONTROLLED_REAL_ELIGIBLE' for r in rows),
       'examples': examples, 'invariants': 'PASS'}
print(json.dumps(out, ensure_ascii=False, indent=2, sort_keys=True))

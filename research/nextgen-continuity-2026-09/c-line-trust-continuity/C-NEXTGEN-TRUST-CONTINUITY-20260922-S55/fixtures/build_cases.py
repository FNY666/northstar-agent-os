#!/usr/bin/env python3
import json
from pathlib import Path

FIELDS = [
    'same_identity','identity_conflict','role_declared','writer_scope_bound',
    'reader_scope_bound','evaluator_scope_bound','handoff_card_complete','state_snapshot_bound',
    'artifact_index_complete','ledger_entry_bound','source_digest_bound','task_boundary_bound',
    'cross_session_message_bound','ack_required_known','ack_received','freeze_before_write',
    'single_writer_attested','independent_evaluator_attested','shared_path_canonical',
    'merge_policy_known','conflict_policy_known','handoff_state_readback','collaboration_conflict',
    'unknown_shared_state'
]
BASE = {k: True for k in FIELDS}
BASE.update({'identity_conflict': False, 'collaboration_conflict': False, 'unknown_shared_state': False})

def make(cid, label, status, evidence, **updates):
    flags = dict(BASE)
    flags.update(updates)
    assert set(flags) == set(FIELDS)
    return {'id': cid, 'label': label, 'status': status, 'flags': flags, 'evidence': evidence}

cases = [
    make('three-role-closed', 'writer/reader/evaluator三角色闭合', 'RECOVERED', ['角色和边界明确','写入与验收独立']),
    make('handoff-card-closed', 'session handoff卡闭合', 'RECOVERED', ['handoff card包含状态/路径/进程/任务','接收方可复核']),
    make('ledger-artifact-closed', '共享账本与artifact索引闭合', 'RECOVERED', ['ledger entry/source digest/artifact index绑定','canonical path固定']),
    make('ack-freeze-write-closed', 'ACK前冻结/ACK后唯一写者闭合', 'RECOVERED', ['ack required/received可验证','freeze before write和single writer均有证据']),
    make('independent-evaluation-closed', '独立验收闭合', 'RECOVERED', ['evaluator不是writer','required files/manifest/hash重新核对']),
    make('merge-conflict-policy-closed', '合并/冲突策略闭合', 'RECOVERED', ['冲突冻结和canonical merge规则明确','handoff state可读回']),
    make('role-unknown', '角色未声明', 'UNKNOWN', ['无法判断谁能写/谁能验收'], role_declared=False),
    make('writer-scope-open', 'writer scope未绑定', 'UNKNOWN', ['写者可能越界修改其他任务'], writer_scope_bound=False),
    make('reader-scope-open', 'reader scope未绑定', 'UNKNOWN', ['只读观察者可能发生写入'], reader_scope_bound=False),
    make('evaluator-not-independent', '验收者独立性未知', 'UNKNOWN', ['无法证明验收不是同一写入路径'], independent_evaluator_attested=False),
    make('handoff-card-incomplete', 'handoff card缺字段', 'UNKNOWN', ['接续方无法恢复完整状态'], handoff_card_complete=False),
    make('state-snapshot-missing', '状态快照缺失', 'UNKNOWN', ['会话切换后进行中任务/进程未知'], state_snapshot_bound=False),
    make('artifact-index-gap', 'artifact index缺口', 'UNKNOWN', ['已有文件但无法知道是否完整'], artifact_index_complete=False),
    make('ledger-entry-unbound', 'ledger entry未绑定', 'UNKNOWN', ['研究产物不能归属于任务/切片'], ledger_entry_bound=False),
    make('source-digest-missing', 'source digest缺失', 'UNKNOWN', ['来源内容变化无法检测'], source_digest_bound=False),
    make('task-boundary-open', '任务边界未绑定', 'UNKNOWN', ['不同切片/目标可能混写'], task_boundary_bound=False),
    make('cross-session-message-missing', '跨会话消息缺失', 'UNKNOWN', ['角色调整/状态不能可靠传递'], cross_session_message_bound=False),
    make('ack-semantics-unknown', 'ACK语义未知', 'UNKNOWN', ['ACK是否解除冻结不明'], ack_required_known=False),
    make('ack-missing', 'ACK未收到', 'UNKNOWN', ['未完成对齐却准备写入'], ack_received=False, unknown_shared_state=True),
    make('freeze-before-write-missing', '写前冻结缺失', 'UNKNOWN', ['并行写者可能同时修改'], freeze_before_write=False, unknown_shared_state=True),
    make('single-writer-unproven', '唯一写者未证明', 'UNKNOWN', ['多个会话可能写同一目录'], single_writer_attested=False, unknown_shared_state=True),
    make('canonical-path-unknown', 'canonical path未知', 'UNKNOWN', ['多个副本可能分叉'], shared_path_canonical=False),
    make('merge-policy-unknown', 'merge策略未知', 'UNKNOWN', ['并行产物冲突时无法安全整合'], merge_policy_known=False),
    make('conflict-policy-unknown', '冲突策略未知', 'UNKNOWN', ['发现冲突后是否冻结不明'], conflict_policy_known=False),
    make('handoff-readback-missing', 'handoff状态未读回', 'UNKNOWN', ['接收方已回应但状态未验证'], handoff_state_readback=False),
    make('identity-unresolved', '身份域无法确定', 'UNKNOWN', ['session/role/task字段不完整'], same_identity=False),
    make('identity-conflict', '跨会话身份合并', 'REJECT', ['不同任务身份被错误合并'], same_identity=False, identity_conflict=True),
    make('collaboration-conflict', '协作写入冲突', 'REJECT', ['两个写者对同一canonical目标给出不可调和状态'], collaboration_conflict=True),
]

assert len(cases) == 28
assert all(set(c['flags']) == set(FIELDS) for c in cases)
out = {
    'schema_version': 'S55-cases-1',
    'synthetic_only': True,
    'production_verified': False,
    'identity_domain': ['session', 'role', 'task', 'slice', 'canonical_path', 'artifact', 'ledger_entry'],
    'collaboration_domain': ['writer', 'reader', 'evaluator', 'handoff', 'state_snapshot', 'artifact_index', 'source_digest', 'ACK', 'freeze', 'single_writer', 'merge', 'conflict'],
    'cases': cases
}
Path(__file__).with_name('cases.json').write_text(json.dumps(out, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
print(f'WROTE cases={len(cases)} fields={len(FIELDS)}')

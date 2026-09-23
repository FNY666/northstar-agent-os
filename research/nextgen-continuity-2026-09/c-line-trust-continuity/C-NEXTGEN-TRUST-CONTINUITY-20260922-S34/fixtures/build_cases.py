#!/usr/bin/env python3
import json
from pathlib import Path

FIELDS = [
    'same_identity','identity_conflict','parent_links_complete','causal_acyclic',
    'causal_order_complete','branch_merge_attested','branch_digest_consistent',
    'sequence_monotonic','reorder_window_closed','replay_window_closed',
    'duplicate_dedup_attested','cross_system_link_attested','source_epoch_continuous',
    'watermark_closed','fence_valid','fence_conflict','causal_cycle_conflict',
    'branch_conflict','replay_gap'
]
BASE = {k: True for k in FIELDS}
BASE.update({
    'identity_conflict': False, 'fence_conflict': False,
    'causal_cycle_conflict': False, 'branch_conflict': False,
    'replay_gap': False
})

def make(cid, label, status, evidence, **updates):
    flags = dict(BASE)
    flags.update(updates)
    assert set(flags) == set(FIELDS)
    return {'id': cid, 'label': label, 'status': status, 'flags': flags, 'evidence': evidence}

cases = [
    make('linear-causal-chain', '线性因果链闭合', 'RECOVERED', ['parent links完整','因果顺序与跨系统链接均闭合']),
    make('attested-branch-merge', '分支合并有证明', 'RECOVERED', ['branch merge attestation存在','分支摘要一致且merge点唯一']),
    make('bounded-reordered-duplicate', '有界乱序与重复投递', 'RECOVERED', ['乱序在replay window内','duplicate已由同一身份与摘要去重']),
    make('delayed-watermark-closed', '延迟事件且水位线闭合', 'RECOVERED', ['迟到事件纳入重放','watermark覆盖最大允许延迟']),
    make('multi-system-link-complete', '多系统因果链接闭合', 'RECOVERED', ['source/target correlation完整','跨系统链无缺口']),
    make('epoch-transition-attested', 'epoch迁移有连续证明', 'RECOVERED', ['epoch transition边已认证','旧新epoch之间没有fence穿透']),
    make('parent-link-missing', '父链接缺失', 'UNKNOWN', ['子事件存在但causal parent不可取回'], parent_links_complete=False, replay_gap=True),
    make('acyclicity-unproven', '无环性未证明', 'UNKNOWN', ['当前结果没有检测到环但缺少完整拓扑证据'], causal_acyclic=False),
    make('causal-order-gap', '因果顺序缺口', 'UNKNOWN', ['事件时间可见但中间顺序不可闭合'], causal_order_complete=False),
    make('branch-merge-unattested', '分支合并无证明', 'UNKNOWN', ['两个分支均存在但缺少可信merge attestation'], branch_merge_attested=False),
    make('branch-digest-unproven', '分支摘要不可比', 'UNKNOWN', ['没有足够canonical digest证据判断分支是否一致'], branch_digest_consistent=False),
    make('sequence-not-monotonic', '序列单调性未闭合', 'UNKNOWN', ['sequence出现跳变但无法区分延迟与丢失'], sequence_monotonic=False),
    make('reorder-window-open', '乱序窗口未闭合', 'UNKNOWN', ['仍可能有迟到分支进入当前窗口'], reorder_window_closed=False),
    make('replay-window-open', '重放窗口未闭合', 'UNKNOWN', ['bounded replay未到终止水位'], replay_window_closed=False),
    make('dedup-unproven', '重复去重未证明', 'UNKNOWN', ['重复事件存在但缺少唯一键与摘要闭合'], duplicate_dedup_attested=False),
    make('cross-system-link-missing', '跨系统链接缺失', 'UNKNOWN', ['source receipt与target log无法关联'], cross_system_link_attested=False),
    make('source-epoch-gap', '来源epoch缺口', 'UNKNOWN', ['epoch之间缺少连续性边'], source_epoch_continuous=False),
    make('watermark-open', '水位线未闭合', 'UNKNOWN', ['查询仍可能漏掉迟到事件'], watermark_closed=False),
    make('no-event-query-gap', '查询无事件但有缺口', 'UNKNOWN', ['NO_EVENT只是当前视图','replay gap未闭合'], same_identity=False, replay_gap=True),
    make('identity-unresolved', '身份域无法确定', 'UNKNOWN', ['缺少tenant/source/epoch等身份字段'], same_identity=False),
    make('partial-chain-and-gap', '部分链与重放缺口同时存在', 'UNKNOWN', ['多个缺口不能互相抵消'], parent_links_complete=False, replay_gap=True),
    make('cross-tenant-conflict', '跨身份域合并', 'REJECT', ['tenant或source明确不同'], same_identity=False, identity_conflict=True),
    make('causal-cycle-conflict', '因果环冲突', 'REJECT', ['拓扑中出现不可调和causal cycle'], causal_cycle_conflict=True, causal_acyclic=False),
    make('branch-conflict', '分支内容冲突', 'REJECT', ['同一merge边界的分支摘要不可同时成立'], branch_conflict=True, branch_digest_consistent=False),
    make('stale-fence', '旧 fence token', 'REJECT', ['目标拒绝stale generation/fence'], fence_valid=False, fence_conflict=True),
]

assert len(cases) == 25
assert all(set(c['flags']) == set(FIELDS) for c in cases)
out = {
    'schema_version': 'S34-cases-1',
    'synthetic_only': True,
    'production_verified': False,
    'identity_domain': ['tenant', 'source', 'event_id', 'epoch', 'version'],
    'causal_domain': ['parent_link', 'branch', 'merge', 'sequence', 'replay_window', 'watermark'],
    'cases': cases
}
Path(__file__).with_name('cases.json').write_text(json.dumps(out, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
print(f'WROTE cases={len(cases)} fields={len(FIELDS)}')

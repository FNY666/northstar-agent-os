#!/usr/bin/env python3
import json
from pathlib import Path

FIELDS = [
    'same_identity','identity_conflict','root_attested','leaf_canonical',
    'inclusion_proof_valid','consistency_proof_valid','checkpoint_chain_complete',
    'root_sequence_monotonic','root_epoch_continuous','observer_quorum_agreed',
    'observer_independent','freshness_closed','key_rotation_attested',
    'algorithm_compatible','fork_conflict','proof_conflict','stale_root_conflict',
    'query_gap','proof_gap'
]
BASE = {k: True for k in FIELDS}
BASE.update({
    'identity_conflict': False, 'fork_conflict': False, 'proof_conflict': False,
    'stale_root_conflict': False, 'query_gap': False, 'proof_gap': False
})

def make(cid, label, status, evidence, **updates):
    flags = dict(BASE)
    flags.update(updates)
    assert set(flags) == set(FIELDS)
    return {'id': cid, 'label': label, 'status': status, 'flags': flags, 'evidence': evidence}

cases = [
    make('complete-inclusion-consistency', '包含与一致性证明均闭合', 'RECOVERED', ['leaf canonical bytes已固定','inclusion与consistency proof均验证通过']),
    make('checkpoint-root-chain', 'checkpoint根链连续', 'RECOVERED', ['root sequence单调','checkpoint链和epoch链均闭合']),
    make('attested-key-rotation', '密钥轮换有证明', 'RECOVERED', ['旧新验证密钥的rotation attestation完整','根签名链连续']),
    make('quorum-independent-observers', '独立观察者一致', 'RECOVERED', ['观察者满足独立性和quorum','不存在根分叉']),
    make('delayed-proof-freshness-closed', '延迟证明仍在新鲜度窗口', 'RECOVERED', ['迟到proof已纳入窗口','freshness watermark已闭合']),
    make('duplicate-inclusion-proof', '重复包含证明一致', 'RECOVERED', ['相同身份和leaf digest的重复proof已去重','根和路径一致']),
    make('root-not-attested', '证据根未认证', 'UNKNOWN', ['root值存在但缺少可信签名或来源'], root_attested=False),
    make('leaf-canonicalization-missing', '叶节点规范化缺失', 'UNKNOWN', ['无法确定proof针对的canonical bytes'], leaf_canonical=False),
    make('inclusion-proof-missing', '包含证明缺失', 'UNKNOWN', ['只看到root与leaf，缺少完整路径'], inclusion_proof_valid=False, proof_gap=True),
    make('consistency-proof-missing', '一致性证明缺失', 'UNKNOWN', ['两个root存在但无append-only consistency proof'], consistency_proof_valid=False, proof_gap=True),
    make('checkpoint-chain-gap', '根 checkpoint 链缺口', 'UNKNOWN', ['中间root checkpoint不可取回'], checkpoint_chain_complete=False, proof_gap=True),
    make('root-sequence-gap', '根序列不闭合', 'UNKNOWN', ['sequence跳变无法区分丢失与重排'], root_sequence_monotonic=False),
    make('epoch-transition-unproven', '根 epoch 迁移无证明', 'UNKNOWN', ['新旧epoch根之间缺少连续边'], root_epoch_continuous=False),
    make('quorum-not-closed', '观察者 quorum 未闭合', 'UNKNOWN', ['观察者返回不完整，不能升级为一致'], observer_quorum_agreed=False),
    make('observer-correlation', '观察者不具独立性', 'UNKNOWN', ['多个观察者可能共享同一上游来源'], observer_independent=False),
    make('freshness-open', '证明新鲜度窗口未闭合', 'UNKNOWN', ['root/proof可能已过期','当前读回不能排除新分叉'], freshness_closed=False),
    make('key-rotation-unattested', '密钥轮换未认证', 'UNKNOWN', ['验证密钥变化但没有可信rotation链'], key_rotation_attested=False),
    make('algorithm-incompatible', '证明算法不可直接比较', 'UNKNOWN', ['hash/signature算法不同且无迁移映射'], algorithm_compatible=False),
    make('query-gap', '查询缺口下无叶节点', 'UNKNOWN', ['NO_EVENT或无proof只表示当前视图','query gap未闭合'], same_identity=False, query_gap=True),
    make('proof-gap', '证明链有缺口', 'UNKNOWN', ['proof segment或root checkpoint缺失'], proof_gap=True),
    make('identity-unresolved', '身份域无法确定', 'UNKNOWN', ['tenant/source/event_id/epoch字段不完整'], same_identity=False),
    make('freshness-and-query-edge', '新鲜度与查询边界同时开放', 'UNKNOWN', ['两个不确定门不能相互抵消'], freshness_closed=False, query_gap=True, same_identity=False),
    make('identity-conflict', '跨身份域合并', 'REJECT', ['tenant或source明确不同'], same_identity=False, identity_conflict=True),
    make('root-fork-conflict', '同一epoch出现根分叉', 'REJECT', ['同一root sequence出现不可调和的两个根'], fork_conflict=True),
    make('proof-conflict', '同一叶节点路径证明冲突', 'REJECT', ['同一身份和root下proof路径不可同时成立'], proof_conflict=True, inclusion_proof_valid=False),
    make('stale-root-conflict', '旧根越过当前边界', 'REJECT', ['stale root或旧generation被用于当前状态'], stale_root_conflict=True),
]

assert len(cases) == 26
assert all(set(c['flags']) == set(FIELDS) for c in cases)
out = {
    'schema_version': 'S35-cases-1',
    'synthetic_only': True,
    'production_verified': False,
    'identity_domain': ['tenant', 'source', 'event_id', 'epoch', 'version'],
    'proof_domain': ['root', 'leaf', 'inclusion_proof', 'consistency_proof', 'checkpoint', 'observer', 'key_rotation', 'freshness', 'fence'],
    'cases': cases
}
Path(__file__).with_name('cases.json').write_text(json.dumps(out, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
print(f'WROTE cases={len(cases)} fields={len(FIELDS)}')

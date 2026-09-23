#!/usr/bin/env python3
import json
from pathlib import Path

FIELDS = [
    'same_identity','identity_conflict','checkpoint_attested','snapshot_digest_match',
    'delta_chain_complete','compaction_manifest_complete','archive_restore_attested',
    'restore_generation_match','tombstone_chain_complete','segment_chain_complete',
    'watermark_closed','retention_window_closed','source_epoch_continuous','fence_valid',
    'fence_conflict','digest_conflict','restore_ambiguous','gap_present',
    'restore_generation_conflict'
]
BASE = {k: True for k in FIELDS}
BASE.update({
    'identity_conflict': False, 'fence_conflict': False, 'digest_conflict': False,
    'restore_ambiguous': False, 'gap_present': False,
    'restore_generation_conflict': False
})

def make(cid, label, status, evidence, **updates):
    flags = dict(BASE)
    flags.update(updates)
    missing = set(FIELDS) - set(flags)
    assert not missing, missing
    return {'id': cid, 'label': label, 'status': status, 'flags': flags, 'evidence': evidence}

cases = [
    make('checkpoint-delta-complete', 'checkpoint与增量链闭合', 'RECOVERED', ['checkpoint签名和快照摘要已证明','delta segments连续且无缺口']),
    make('archive-restore-complete', '归档恢复代际一致', 'RECOVERED', ['archive restore有独立证明','restore generation与checkpoint一致']),
    make('compaction-manifest-complete', 'compaction manifest闭合', 'RECOVERED', ['压缩前后segment映射完整','manifest digest与快照一致']),
    make('tombstone-chain-complete', '删除标记链闭合', 'RECOVERED', ['tombstone来源与顺序完整','删除不是证据缺失']),
    make('delayed-watermark-closed', '延迟证据但水位线闭合', 'RECOVERED', ['迟到segment已纳入重放','watermark覆盖最大允许延迟']),
    make('duplicate-snapshot-consistent', '重复快照一致', 'RECOVERED', ['重复snapshot摘要一致','重复定位已去重']),
    make('checkpoint-not-attested', 'checkpoint未认证', 'UNKNOWN', ['本地快照存在但无可信签名或来源证明'], checkpoint_attested=False),
    make('snapshot-digest-missing', '快照摘要不可比', 'UNKNOWN', ['canonical snapshot digest缺失'], snapshot_digest_match=False),
    make('delta-chain-gap', '增量链有缺口', 'UNKNOWN', ['中间delta segment不可查询'], delta_chain_complete=False, gap_present=True),
    make('compaction-manifest-gap', '压缩映射不完整', 'UNKNOWN', ['compaction manifest缺少输入segment'], compaction_manifest_complete=False),
    make('archive-restore-unattested', '归档恢复无证明', 'UNKNOWN', ['恢复结果存在但没有独立restore attestation'], archive_restore_attested=False),
    make('restore-generation-unknown', '恢复代际未知', 'UNKNOWN', ['restore generation无法与checkpoint比对'], restore_generation_match=False),
    make('tombstone-chain-gap', '删除链缺口', 'UNKNOWN', ['tombstone之后的segment不可闭合'], tombstone_chain_complete=False, gap_present=True),
    make('segment-boundary-open', 'segment边界未闭合', 'UNKNOWN', ['当前segment成功不证明下一segment不存在'], segment_chain_complete=False),
    make('watermark-open', '水位线未闭合', 'UNKNOWN', ['仍可能有迟到证据进入窗口'], watermark_closed=False),
    make('retention-window-open', '保留窗口未闭合', 'UNKNOWN', ['旧segment已不可取回'], retention_window_closed=False),
    make('source-epoch-gap', 'source epoch不连续', 'UNKNOWN', ['epoch之间缺少连续性证明'], source_epoch_continuous=False),
    make('restore-ambiguous', '恢复结果有歧义', 'UNKNOWN', ['多个restore generation均可能匹配'], restore_ambiguous=True),
    make('query-gap-with-no-event', '查询缺口下无事件', 'UNKNOWN', ['NO_EVENT仅是当前查询结果','query gap未闭合'], gap_present=True),
    make('identity-missing', '身份域不完整', 'UNKNOWN', ['tenant/source/event_id等身份字段缺失'], same_identity=False),
    make('checkpoint-delta-retention-edge', '窗口边界同时未闭合', 'UNKNOWN', ['checkpoint与retention边界不能互相替代'], delta_chain_complete=False, retention_window_closed=False),
    make('identity-conflict', '跨身份域合并', 'REJECT', ['tenant或source明确不同'], same_identity=False, identity_conflict=True),
    make('stale-fence', '旧 fence token', 'REJECT', ['目标拒绝旧 generation/fence'], fence_valid=False, fence_conflict=True),
    make('canonical-digest-conflict', '同版本摘要冲突', 'REJECT', ['同一规范下canonical digest不可调和'], digest_conflict=True, snapshot_digest_match=False),
    make('restore-generation-conflict', '恢复代际冲突', 'REJECT', ['同一恢复边界出现不可调和generation'], restore_generation_conflict=True, restore_generation_match=False),
]

assert len(cases) == 25
assert all(set(c['flags']) == set(FIELDS) for c in cases)
out = {
    'schema_version': 'S33-cases-1',
    'synthetic_only': True,
    'production_verified': False,
    'identity_domain': ['tenant', 'source', 'event_id', 'epoch', 'version'],
    'continuity_domain': ['checkpoint', 'snapshot', 'delta_segment', 'compaction_manifest', 'archive_restore', 'tombstone', 'watermark', 'retention', 'fence'],
    'cases': cases
}
Path(__file__).with_name('cases.json').write_text(json.dumps(out, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
print(f'WROTE cases={len(cases)} fields={len(FIELDS)}')

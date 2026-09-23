#!/usr/bin/env python3
import json
from pathlib import Path

FIELDS = [
    'same_identity','identity_conflict','origin_attested','derivation_link_complete',
    'parent_digest_bound','transform_declared','transform_authorized','transform_deterministic',
    'export_mapping_complete','import_mapping_complete','resign_scope_valid',
    'redaction_provenance_complete','canonicalization_version_bound','algorithm_version_bound',
    'timestamp_chain_closed','actor_identity_bound','evidence_location_bound',
    'lineage_order_complete','duplicate_lineage_deduped','lineage_conflict','unknown_transform'
]
BASE = {k: True for k in FIELDS}
BASE.update({
    'identity_conflict': False, 'lineage_conflict': False, 'unknown_transform': False
})

def make(cid, label, status, evidence, **updates):
    flags = dict(BASE)
    flags.update(updates)
    assert set(flags) == set(FIELDS)
    return {'id': cid, 'label': label, 'status': status, 'flags': flags, 'evidence': evidence}

cases = [
    make('origin-to-export-closed', 'origin到export lineage闭合', 'RECOVERED', ['origin digest与derivation parent绑定','export mapping与目标证据一致']),
    make('deterministic-transform-chain', '确定性变换链闭合', 'RECOVERED', ['transform声明、授权和确定性均完整','每步parent digest可验证']),
    make('authorized-redaction-lineage', '授权脱敏 provenance闭合', 'RECOVERED', ['redaction policy与actor绑定','脱敏前后映射和canonical版本完整']),
    make('resign-lineage-closed', '重签名 lineage闭合', 'RECOVERED', ['新旧签名scope连续','resign授权与timestamp chain均闭合']),
    make('cross-system-import-export', '跨系统导入导出闭合', 'RECOVERED', ['export/import mapping双向可追溯','algorithm/canonicalization版本一致']),
    make('duplicate-derived-evidence', '重复派生证据去重', 'RECOVERED', ['相同lineage identity的重复节点已去重','无多重计数']),
    make('origin-unattested', 'origin未认证', 'UNKNOWN', ['派生记录存在但无法验证最初来源'], origin_attested=False),
    make('derivation-link-gap', '派生parent缺失', 'UNKNOWN', ['中间transform节点不可取回'], derivation_link_complete=False),
    make('parent-digest-unbound', 'parent digest未绑定', 'UNKNOWN', ['子证据没有不可替换的父摘要'], parent_digest_bound=False),
    make('transform-undeclared', '变换未声明', 'UNKNOWN', ['无法知道输出如何从输入产生'], transform_declared=False),
    make('transform-unauthorized', '变换未授权', 'UNKNOWN', ['actor执行了变换但没有scope授权'], transform_authorized=False),
    make('transform-nondeterministic', '变换不可重放', 'UNKNOWN', ['相同输入无法证明得到同一输出'], transform_deterministic=False),
    make('export-map-gap', 'export mapping缺口', 'UNKNOWN', ['源证据与导出对象不能一一对应'], export_mapping_complete=False),
    make('import-map-gap', 'import mapping缺口', 'UNKNOWN', ['目标记录无法追溯到源导出'], import_mapping_complete=False),
    make('resign-scope-invalid', '重签名scope无效', 'UNKNOWN', ['新签名覆盖范围与旧证据不一致'], resign_scope_valid=False),
    make('redaction-provenance-gap', '脱敏 provenance缺口', 'UNKNOWN', ['无法证明删除/替换字段的授权与影响'], redaction_provenance_complete=False),
    make('canonicalization-unbound', '规范化版本未绑定', 'UNKNOWN', ['不同canonical bytes可能被误视为同一证据'], canonicalization_version_bound=False),
    make('algorithm-unbound', '算法版本未绑定', 'UNKNOWN', ['digest/signature算法变化无法解释'], algorithm_version_bound=False),
    make('timestamp-chain-open', '时间链未闭合', 'UNKNOWN', ['派生/导出/重签名的先后关系不确定'], timestamp_chain_closed=False),
    make('actor-unbound', 'actor身份未绑定', 'UNKNOWN', ['无法将动作归属于具体issuer/delegate'], actor_identity_bound=False),
    make('location-unbound', '证据位置未绑定', 'UNKNOWN', ['source URI/record key/partition不稳定'], evidence_location_bound=False),
    make('lineage-order-gap', 'lineage顺序缺口', 'UNKNOWN', ['节点存在但顺序或版本边缺失'], lineage_order_complete=False),
    make('duplicate-unproven', '重复lineage未去重', 'UNKNOWN', ['重复导出可能被计为多个独立事实'], duplicate_lineage_deduped=False),
    make('unknown-transform', '变换类型未知', 'UNKNOWN', ['无法判断是否发生了安全相关转换'], unknown_transform=True),
    make('identity-unresolved', '身份域无法确定', 'UNKNOWN', ['tenant/source/event_id字段不完整'], same_identity=False),
    make('identity-conflict', '跨身份域合并', 'REJECT', ['tenant或source明确不同'], same_identity=False, identity_conflict=True),
    make('lineage-equivocation', 'lineage双重陈述', 'REJECT', ['同一origin/transform identity出现不可调和的两个派生结果'], lineage_conflict=True),
    make('parent-conflict', '同一parent digest冲突', 'REJECT', ['同一lineage边声明两个互斥parent digest'], lineage_conflict=True, parent_digest_bound=False),
]

assert len(cases) == 28
assert all(set(c['flags']) == set(FIELDS) for c in cases)
out = {
    'schema_version': 'S41-cases-1',
    'synthetic_only': True,
    'production_verified': False,
    'identity_domain': ['tenant', 'source', 'event_id', 'epoch', 'version'],
    'lineage_domain': ['origin', 'parent_digest', 'transform', 'export', 'import', 'resign', 'redaction', 'canonicalization', 'algorithm', 'timestamp', 'actor', 'location'],
    'cases': cases
}
Path(__file__).with_name('cases.json').write_text(json.dumps(out, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
print(f'WROTE cases={len(cases)} fields={len(FIELDS)}')

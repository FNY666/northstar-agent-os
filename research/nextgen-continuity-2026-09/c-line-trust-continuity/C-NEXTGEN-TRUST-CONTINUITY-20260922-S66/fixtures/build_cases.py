#!/usr/bin/env python3
import json
from pathlib import Path

FIELDS = [
    'same_identity','identity_conflict','export_id_bound','import_id_bound',
    'origin_digest_bound','export_manifest_complete','import_manifest_complete',
    'field_mapping_bound','transform_declared','transform_authorized','redaction_bound',
    'redaction_policy_attested','resign_scope_bound','resign_authorized',
    'permission_downgrade_bound','target_scope_bound','recipient_bound',
    'canonicalization_version_bound','algorithm_version_bound','timestamp_chain_closed',
    'lineage_order_closed','source_attribution_closed','final_readback_closed',
    'lineage_conflict','unknown_transform_state'
]
BASE = {k: True for k in FIELDS}
BASE.update({'identity_conflict': False, 'lineage_conflict': False, 'unknown_transform_state': False})

def make(cid, label, status, evidence, **updates):
    flags = dict(BASE)
    flags.update(updates)
    assert set(flags) == set(FIELDS)
    return {'id': cid, 'label': label, 'status': status, 'flags': flags, 'evidence': evidence}

cases = [
    make('export-import-lineage-closed', '导出/导入lineage闭合', 'RECOVERED', ['export/import ids/manifests/origin digest完整','field mapping和source attribution可追溯']),
    make('redaction-resign-closed', '脱敏/重签名闭合', 'RECOVERED', ['redaction policy与resign scope授权完整','新bundle版本可读回']),
    make('permission-downgrade-closed', '权限降级闭合', 'RECOVERED', ['目标scope不超过授权输入','recipient/target scope和readback一致']),
    make('algorithm-canonical-closed', '规范化/算法版本闭合', 'RECOVERED', ['canonicalization/algorithm版本绑定','timestamp和lineage order闭合']),
    make('cross-system-attribution-closed', '跨系统归因闭合', 'RECOVERED', ['源/目标平台和actor可归因','最终readback闭合']),
    make('delegated-export-closed', '委托导出闭合', 'RECOVERED', ['委托链与export/import操作绑定','未越过permission downgrade边界']),
    make('export-id-missing', 'export id缺失', 'UNKNOWN', ['无法稳定关联源导出'], export_id_bound=False),
    make('import-id-missing', 'import id缺失', 'UNKNOWN', ['目标导入结果无法追踪'], import_id_bound=False),
    make('origin-digest-missing', 'origin digest缺失', 'UNKNOWN', ['导入内容无法绑定原始事实'], origin_digest_bound=False),
    make('export-manifest-open', 'export manifest缺失', 'UNKNOWN', ['导出包内容/版本/hash不明'], export_manifest_complete=False),
    make('import-manifest-open', 'import manifest缺失', 'UNKNOWN', ['导入后文件和版本无法核对'], import_manifest_complete=False),
    make('field-mapping-open', '字段映射未绑定', 'UNKNOWN', ['转换前后字段语义不明'], field_mapping_bound=False),
    make('transform-undeclared', '变换未声明', 'UNKNOWN', ['无法判断发生了何种转换'], transform_declared=False, unknown_transform_state=True),
    make('transform-unauthorized', '变换未授权', 'UNKNOWN', ['actor执行变换但无授权'], transform_authorized=False),
    make('redaction-open', '脱敏未绑定', 'UNKNOWN', ['敏感字段处理不明'], redaction_bound=False),
    make('redaction-policy-unknown', '脱敏policy未认证', 'UNKNOWN', ['删除/替换字段的影响无法证明'], redaction_policy_attested=False),
    make('resign-scope-open', '重签名scope未绑定', 'UNKNOWN', ['新签名可能扩大原权限'], resign_scope_bound=False),
    make('resign-unauthorized', '重签名未授权', 'UNKNOWN', ['新签名没有合法issuer授权'], resign_authorized=False),
    make('permission-downgrade-open', '权限降级未证明', 'UNKNOWN', ['目标scope可能超过源授权'], permission_downgrade_bound=False),
    make('target-scope-open', '目标scope未绑定', 'UNKNOWN', ['导入后的访问范围未知'], target_scope_bound=False),
    make('recipient-open', 'recipient未绑定', 'UNKNOWN', ['导入内容可能送达错误主体'], recipient_bound=False),
    make('canonicalization-open', '规范化版本缺失', 'UNKNOWN', ['digest不可比'], canonicalization_version_bound=False),
    make('algorithm-open', '算法版本缺失', 'UNKNOWN', ['签名/hash迁移无法解释'], algorithm_version_bound=False),
    make('timestamp-open', '时间链缺失', 'UNKNOWN', ['导出/变换/导入先后不明'], timestamp_chain_closed=False),
    make('lineage-order-open', 'lineage顺序缺失', 'UNKNOWN', ['来源/变换/导入关系不可排序'], lineage_order_closed=False),
    make('attribution-open', '来源归因缺失', 'UNKNOWN', ['平台/actor/source不可追溯'], source_attribution_closed=False),
    make('readback-open', '最终readback缺失', 'UNKNOWN', ['导入完成消息不等于目标状态'], final_readback_closed=False),
    make('identity-unresolved', '身份域无法确定', 'UNKNOWN', ['project/export/import字段不完整'], same_identity=False),
    make('identity-conflict', '跨项目导入合并', 'REJECT', ['不同project的lineage被错误合并'], same_identity=False, identity_conflict=True),
    make('lineage-conflict', '导出/导入lineage冲突', 'REJECT', ['同一origin出现不可调和transform/import结果'], lineage_conflict=True),
]

assert len(cases) == 30
assert all(set(c['flags']) == set(FIELDS) for c in cases)
out = {
    'schema_version': 'S66-cases-1',
    'synthetic_only': True,
    'production_verified': False,
    'identity_domain': ['project', 'export_id', 'import_id', 'origin_digest', 'actor', 'recipient', 'scope', 'version'],
    'lineage_domain': ['export_manifest', 'import_manifest', 'field_mapping', 'transform', 'redaction', 'resign', 'permission_downgrade', 'canonicalization', 'algorithm', 'timestamp', 'attribution', 'readback'],
    'cases': cases
}
Path(__file__).with_name('cases.json').write_text(json.dumps(out, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
print(f'WROTE cases={len(cases)} fields={len(FIELDS)}')

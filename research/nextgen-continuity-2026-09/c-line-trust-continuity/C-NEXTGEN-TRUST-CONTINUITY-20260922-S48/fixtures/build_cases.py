#!/usr/bin/env python3
import json
from pathlib import Path

FIELDS = [
    'same_identity','identity_conflict','report_scope_fixed','report_receiver_bound',
    'finding_identity_bound','severity_method_known','triage_state_closed',
    'remediation_owner_bound','artifact_digest_verified','artifact_signature_verified',
    'build_provenance_verified','release_metadata_consistent','version_pinned',
    'enterprise_policy_scope_bound','allowlist_effective_readback','required_control_attested',
    'rollback_trigger_bound','rollback_target_attested','rollback_completion_readback',
    'runtime_convergence_closed','audit_trail_complete','security_conflict',
    'unknown_release_state'
]
BASE = {k: True for k in FIELDS}
BASE.update({'identity_conflict': False, 'security_conflict': False, 'unknown_release_state': False})

def make(cid, label, status, evidence, **updates):
    flags = dict(BASE)
    flags.update(updates)
    assert set(flags) == set(FIELDS)
    return {'id': cid, 'label': label, 'status': status, 'flags': flags, 'evidence': evidence}

cases = [
    make('security-report-complete', '安全报告与finding identity闭合', 'RECOVERED', ['report scope/receiver/finding identity完整','severity与triage状态有依据']),
    make('artifact-provenance-signature', '制品摘要/签名/provenance闭合', 'RECOVERED', ['digest、signature、build provenance均可验证','release metadata一致']),
    make('enterprise-control-effective', 'enterprise control运行时生效', 'RECOVERED', ['policy scope明确','allowlist与required control有实例级read-back']),
    make('rollback-converged', 'rollback完成并收敛', 'RECOVERED', ['trigger/target明确','completion read-back与runtime convergence闭合']),
    make('audit-complete', '安全操作审计闭合', 'RECOVERED', ['报告、批准、发布、回退和结果可追溯','无未知release state']),
    make('pinned-release-stable', '固定版本稳定运行', 'RECOVERED', ['所有runtime instance达到固定版本','状态在窗口内稳定']),
    make('report-scope-missing', '报告范围缺失', 'UNKNOWN', ['无法判断finding/controls适用对象'], report_scope_fixed=False),
    make('receiver-unbound', '报告接收方未绑定', 'UNKNOWN', ['无法证明报告进入正确安全渠道'], report_receiver_bound=False),
    make('finding-unbound', 'finding identity缺失', 'UNKNOWN', ['重复报告或不同项目可能被混合'], finding_identity_bound=False),
    make('severity-method-unknown', 'severity方法未知', 'UNKNOWN', ['严重性标签没有可复核方法'], severity_method_known=False),
    make('triage-open', 'triage状态未闭合', 'UNKNOWN', ['finding已接收但处置状态未知'], triage_state_closed=False),
    make('remediation-owner-missing', '修复责任人未绑定', 'UNKNOWN', ['无法确认谁负责闭环'], remediation_owner_bound=False),
    make('artifact-digest-missing', '制品摘要未验证', 'UNKNOWN', ['版本号不能替代内容摘要'], artifact_digest_verified=False),
    make('artifact-signature-missing', '制品签名未验证', 'UNKNOWN', ['来源和完整性未闭合'], artifact_signature_verified=False),
    make('build-provenance-open', '构建来源未验证', 'UNKNOWN', ['artifact不能追溯到可信构建输入'], build_provenance_verified=False),
    make('release-metadata-conflict', 'release metadata不一致', 'UNKNOWN', ['tag/version/digest之间不能互相校验'], release_metadata_consistent=False),
    make('version-floating', '版本未固定', 'UNKNOWN', ['不同实例可能自动漂移'], version_pinned=False),
    make('policy-scope-open', 'enterprise policy范围未绑定', 'UNKNOWN', ['策略可能被加载到错误项目/实例'], enterprise_policy_scope_bound=False),
    make('allowlist-readback-missing', 'allowlist未读回', 'UNKNOWN', ['配置存在但运行时效果未知'], allowlist_effective_readback=False),
    make('required-control-missing', 'required control未证明', 'UNKNOWN', ['强制控制可能缺失'], required_control_attested=False),
    make('rollback-trigger-open', 'rollback trigger未绑定', 'UNKNOWN', ['无法判定何时回退'], rollback_trigger_bound=False),
    make('rollback-target-open', 'rollback target未证明', 'UNKNOWN', ['目标版本来源或兼容性未知'], rollback_target_attested=False),
    make('rollback-readback-missing', 'rollback完成未读回', 'UNKNOWN', ['请求成功不等于实例已回退'], rollback_completion_readback=False, unknown_release_state=True),
    make('runtime-convergence-open', 'runtime convergence未闭合', 'UNKNOWN', ['实例状态可能仍分叉'], runtime_convergence_closed=False, unknown_release_state=True),
    make('audit-gap', '审计链缺口', 'UNKNOWN', ['安全动作无法完整追溯'], audit_trail_complete=False),
    make('identity-unresolved', '身份域无法确定', 'UNKNOWN', ['organization/project/release字段不完整'], same_identity=False),
    make('identity-conflict', '跨release身份合并', 'REJECT', ['不同项目/release被错误合并'], same_identity=False, identity_conflict=True),
    make('security-conflict', '安全状态冲突', 'REJECT', ['同一finding/release同时出现不可调和终态'], security_conflict=True),
]

assert len(cases) == 28
assert all(set(c['flags']) == set(FIELDS) for c in cases)
out = {
    'schema_version': 'S48-cases-1',
    'synthetic_only': True,
    'production_verified': False,
    'identity_domain': ['organization', 'project', 'finding_id', 'release', 'artifact', 'runtime_instance', 'report_id'],
    'security_release_domain': ['security_report', 'severity', 'triage', 'remediation', 'artifact_digest', 'signature', 'build_provenance', 'release_metadata', 'version_pin', 'enterprise_policy', 'allowlist', 'required_control', 'rollback', 'convergence', 'audit'],
    'cases': cases
}
Path(__file__).with_name('cases.json').write_text(json.dumps(out, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
print(f'WROTE cases={len(cases)} fields={len(FIELDS)}')

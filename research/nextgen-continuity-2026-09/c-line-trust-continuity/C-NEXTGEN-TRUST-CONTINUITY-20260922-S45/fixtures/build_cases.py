#!/usr/bin/env python3
import json
from pathlib import Path

FIELDS = [
    'same_identity','identity_conflict','security_scope_declared','report_channel_bound',
    'vulnerability_classified','triage_owner_bound','severity_rationale_closed',
    'remediation_state_attested','release_artifact_verified','provenance_verified',
    'signature_verified','version_pinned','enterprise_policy_loaded',
    'allowlist_closed','required_control_present','rollback_trigger_defined',
    'rollback_target_verified','rollback_effect_attested','runtime_convergence_attested',
    'audit_record_closed','security_conflict','unknown_remediation'
]
BASE = {k: True for k in FIELDS}
BASE.update({'identity_conflict': False, 'security_conflict': False, 'unknown_remediation': False})

def make(cid, label, status, evidence, **updates):
    flags = dict(BASE)
    flags.update(updates)
    assert set(flags) == set(FIELDS)
    return {'id': cid, 'label': label, 'status': status, 'flags': flags, 'evidence': evidence}

cases = [
    make('security-report-closed', '安全报告通道与分级闭合', 'RECOVERED', ['report channel与security scope绑定','triage owner和severity理由完整']),
    make('release-artifact-verified', 'release artifact与provenance闭合', 'RECOVERED', ['artifact hash/signature/provenance已验证','version pin可复核']),
    make('enterprise-control-loaded', 'enterprise controls已加载', 'RECOVERED', ['allowlist/required controls运行时read-back闭合','策略身份明确']),
    make('rollback-target-verified', 'rollback target已验证', 'RECOVERED', ['rollback trigger和目标版本明确','回退效果与runtime convergence可读回']),
    make('audit-record-closed', '安全审计记录闭合', 'RECOVERED', ['动作、审批、版本、结果均有审计记录','没有未知remediation']),
    make('pinned-release-converged', '固定版本最终收敛', 'RECOVERED', ['版本固定且所有实例达到目标','收敛状态有独立读回']),
    make('security-scope-missing', '安全范围未声明', 'UNKNOWN', ['无法判断报告/控制适用边界'], security_scope_declared=False),
    make('report-channel-unbound', '报告通道未绑定', 'UNKNOWN', ['来源或接收方无法验证'], report_channel_bound=False),
    make('classification-unknown', '漏洞分类未知', 'UNKNOWN', ['问题存在但影响范围/类别未确定'], vulnerability_classified=False),
    make('triage-owner-missing', 'triage owner缺失', 'UNKNOWN', ['没有明确处理责任'], triage_owner_bound=False),
    make('severity-rationale-open', '严重性理由不闭合', 'UNKNOWN', ['severity标签无可追溯依据'], severity_rationale_closed=False),
    make('remediation-unknown', '修复状态未知', 'UNKNOWN', ['声明修复但无独立验证'], remediation_state_attested=False, unknown_remediation=True),
    make('artifact-unverified', '发布制品未验证', 'UNKNOWN', ['release metadata存在但hash/signature未闭合'], release_artifact_verified=False),
    make('provenance-open', '发布来源未验证', 'UNKNOWN', ['无法把artifact关联到可信构建来源'], provenance_verified=False),
    make('signature-missing', '签名未验证', 'UNKNOWN', ['制品完整性与来源不能仅由版本号证明'], signature_verified=False),
    make('version-unpinned', '版本未固定', 'UNKNOWN', ['不同实例可能运行不同release'], version_pinned=False),
    make('policy-unread', 'enterprise policy未读回', 'UNKNOWN', ['配置文件存在但运行时是否加载未知'], enterprise_policy_loaded=False),
    make('allowlist-open', 'allowlist未闭合', 'UNKNOWN', ['扩展/MCP/工具范围不明确'], allowlist_closed=False),
    make('required-control-missing', 'required control缺失', 'UNKNOWN', ['企业强制控制没有独立确认'], required_control_present=False),
    make('rollback-trigger-unknown', 'rollback触发条件未知', 'UNKNOWN', ['无法判断何时应回退'], rollback_trigger_defined=False),
    make('rollback-target-unverified', 'rollback目标未验证', 'UNKNOWN', ['目标版本存在但来源/兼容性未确认'], rollback_target_verified=False),
    make('rollback-effect-unknown', 'rollback效果未知', 'UNKNOWN', ['metadata改变不等于运行实例已回退'], rollback_effect_attested=False, unknown_remediation=True),
    make('convergence-unknown', '运行时收敛未知', 'UNKNOWN', ['发布/回退请求完成但实例状态不可读回'], runtime_convergence_attested=False, unknown_remediation=True),
    make('audit-gap', '审计记录缺口', 'UNKNOWN', ['安全动作或审批无法完整追溯'], audit_record_closed=False),
    make('identity-unresolved', '身份域无法确定', 'UNKNOWN', ['组织/project/release字段不完整'], same_identity=False),
    make('identity-conflict', '跨发布身份合并', 'REJECT', ['不同project/release身份被错误合并'], same_identity=False, identity_conflict=True),
    make('security-conflict', '安全状态冲突', 'REJECT', ['同一release同时有不可调和的verified/unverified或rollback状态'], security_conflict=True),
]

assert len(cases) == 27
assert all(set(c['flags']) == set(FIELDS) for c in cases)
out = {
    'schema_version': 'S45-cases-1',
    'synthetic_only': True,
    'production_verified': False,
    'identity_domain': ['organization', 'project', 'release', 'artifact', 'runtime_instance', 'report_id'],
    'security_domain': ['security_report', 'triage', 'severity', 'remediation', 'artifact', 'provenance', 'signature', 'version_pin', 'enterprise_policy', 'allowlist', 'rollback', 'convergence', 'audit'],
    'cases': cases
}
Path(__file__).with_name('cases.json').write_text(json.dumps(out, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
print(f'WROTE cases={len(cases)} fields={len(FIELDS)}')

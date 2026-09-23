#!/usr/bin/env python3
import json
from pathlib import Path

FIELDS = [
    'same_identity','identity_conflict','auth_context_declared','terms_scope_bound',
    'privacy_policy_bound','data_region_bound','telemetry_setting_bound','telemetry_optout_observed',
    'prompt_data_classified','tool_data_classified','session_data_classified','file_event_classified',
    'redaction_policy_bound','config_precedence_known','workspace_config_bound',
    'user_config_bound','env_config_bound','runtime_setting_readback','retention_bound',
    'exporter_destination_bound','access_control_bound','privacy_conflict','unknown_data_path'
]
BASE = {k: True for k in FIELDS}
BASE.update({'identity_conflict': False, 'privacy_conflict': False, 'unknown_data_path': False})

def make(cid, label, status, evidence, **updates):
    flags = dict(BASE)
    flags.update(updates)
    assert set(flags) == set(FIELDS)
    return {'id': cid, 'label': label, 'status': status, 'flags': flags, 'evidence': evidence}

cases = [
    make('privacy-telemetry-closed', '隐私/遥测策略闭合', 'RECOVERED', ['认证上下文、条款和privacy policy绑定','telemetry setting与opt-out读回一致']),
    make('data-classification-closed', '数据分类闭合', 'RECOVERED', ['prompt/tool/session/file event分类完整','redaction与retention边界明确']),
    make('config-precedence-privacy-closed', '配置优先级与隐私生效闭合', 'RECOVERED', ['workspace/user/env precedence已知','runtime setting/export destination可读回']),
    make('terms-region-export-closed', '条款/区域/export闭合', 'RECOVERED', ['data region与terms scope绑定','exporter destination和access control闭合']),
    make('telemetry-optout-closed', '遥测退出闭合', 'RECOVERED', ['opt-out状态在当前runtime观察到','未知data path已排除']),
    make('retention-access-closed', '保留与访问控制闭合', 'RECOVERED', ['retention policy固定','访问边界和来源可审计']),
    make('auth-context-unknown', '认证上下文未声明', 'UNKNOWN', ['无法选择适用隐私/条款路径'], auth_context_declared=False),
    make('terms-scope-open', '条款范围未绑定', 'UNKNOWN', ['认证方式对应条款不明'], terms_scope_bound=False),
    make('privacy-policy-missing', '隐私策略缺失', 'UNKNOWN', ['无法知道prompt/tool/session如何处理'], privacy_policy_bound=False),
    make('region-unknown', '数据区域未知', 'UNKNOWN', ['数据可能跨区域处理'], data_region_bound=False),
    make('telemetry-setting-unread', '遥测设置未读回', 'UNKNOWN', ['配置存在但runtime是否采用未知'], telemetry_setting_bound=False, runtime_setting_readback=False),
    make('optout-unobserved', 'opt-out未观察', 'UNKNOWN', ['用户设置无法与当前实例绑定'], telemetry_optout_observed=False),
    make('prompt-classification-open', 'prompt数据分类缺失', 'UNKNOWN', ['prompt是否包含敏感内容/如何处理未知'], prompt_data_classified=False),
    make('tool-classification-open', 'tool数据分类缺失', 'UNKNOWN', ['工具输入输出的敏感范围不明'], tool_data_classified=False),
    make('session-classification-open', 'session数据分类缺失', 'UNKNOWN', ['session history/identity处理未知'], session_data_classified=False),
    make('file-event-classification-open', '文件事件分类缺失', 'UNKNOWN', ['文件路径/内容事件是否遥测未知'], file_event_classified=False),
    make('redaction-policy-open', '脱敏策略未绑定', 'UNKNOWN', ['敏感字段是否脱敏未知'], redaction_policy_bound=False),
    make('precedence-unknown', '配置优先级未知', 'UNKNOWN', ['workspace/user/env冲突时结果不明'], config_precedence_known=False),
    make('workspace-config-unbound', 'workspace配置未绑定', 'UNKNOWN', ['项目配置可能影响隐私设置'], workspace_config_bound=False),
    make('user-config-unbound', 'user配置未绑定', 'UNKNOWN', ['用户全局设置来源不明'], user_config_bound=False),
    make('env-config-unbound', '环境变量未绑定', 'UNKNOWN', ['环境变量可能覆盖隐私/遥测设置'], env_config_bound=False),
    make('runtime-readback-missing', 'runtime设置未读回', 'UNKNOWN', ['输入配置不等于生效配置'], runtime_setting_readback=False),
    make('retention-unknown', '保留策略未知', 'UNKNOWN', ['数据保存时长和删除边界不明'], retention_bound=False),
    make('export-destination-unknown', 'export目的地未知', 'UNKNOWN', ['遥测可能发往未审查目的地'], exporter_destination_bound=False, unknown_data_path=True),
    make('access-control-open', '访问控制未闭合', 'UNKNOWN', ['数据读取权限/审计边界不明'], access_control_bound=False),
    make('identity-unresolved', '身份域无法确定', 'UNKNOWN', ['account/project/runtime字段不完整'], same_identity=False),
    make('identity-conflict', '跨账户/项目隐私合并', 'REJECT', ['不同identity的数据路径被错误合并'], same_identity=False, identity_conflict=True),
    make('privacy-conflict', '隐私状态冲突', 'REJECT', ['同一runtime同时声明采集与不采集且无时间解释'], privacy_conflict=True),
]

assert len(cases) == 28
assert all(set(c['flags']) == set(FIELDS) for c in cases)
out = {
    'schema_version': 'S51-cases-1',
    'synthetic_only': True,
    'production_verified': False,
    'identity_domain': ['account', 'project', 'runtime', 'auth_context', 'config_key', 'data_class'],
    'privacy_domain': ['terms', 'privacy_policy', 'region', 'telemetry', 'optout', 'prompt', 'tool', 'session', 'file_event', 'redaction', 'precedence', 'retention', 'export', 'access_control'],
    'cases': cases
}
Path(__file__).with_name('cases.json').write_text(json.dumps(out, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
print(f'WROTE cases={len(cases)} fields={len(FIELDS)}')

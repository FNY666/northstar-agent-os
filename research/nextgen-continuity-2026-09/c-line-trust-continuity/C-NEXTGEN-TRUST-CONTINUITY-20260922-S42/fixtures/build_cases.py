#!/usr/bin/env python3
import json
from pathlib import Path

FIELDS = [
    'same_identity','identity_conflict','source_declared','schema_valid','default_defined',
    'user_override_loaded','workspace_override_loaded','env_override_loaded',
    'cli_override_loaded','precedence_order_known','effective_value_readback',
    'restart_boundary_closed','scope_boundary_closed','secret_redaction_closed',
    'unknown_key_policy_known','type_validation_passed','version_compatible',
    'source_file_stable','runtime_snapshot_attested','override_conflict','unknown_effective'
]
BASE = {k: True for k in FIELDS}
BASE.update({
    'identity_conflict': False, 'override_conflict': False, 'unknown_effective': False
})

def make(cid, label, status, evidence, **updates):
    flags = dict(BASE)
    flags.update(updates)
    assert set(flags) == set(FIELDS)
    return {'id': cid, 'label': label, 'status': status, 'flags': flags, 'evidence': evidence}

cases = [
    make('default-user-workspace-env-cli', '默认到CLI完整优先级', 'RECOVERED', ['各层来源已声明','最终runtime read-back与预期一致']),
    make('workspace-env-effective', 'workspace与环境变量生效', 'RECOVERED', ['workspace scope与env override顺序已知','runtime snapshot可复核']),
    make('restart-persistent-config', '重启后配置连续', 'RECOVERED', ['restart边界已测试','敏感值不进入报告但来源可验证']),
    make('schema-version-compatible', 'schema版本兼容', 'RECOVERED', ['配置schema与运行时版本匹配','类型校验通过']),
    make('unknown-key-explicit-policy', '未知键策略明确', 'RECOVERED', ['未知键处理策略已声明','effective config read-back无歧义']),
    make('scoped-override-closed', '作用域覆盖闭合', 'RECOVERED', ['user/workspace/project作用域边界固定','来源文件稳定']),
    make('source-missing', '配置来源缺失', 'UNKNOWN', ['无法知道effective value来自哪一层'], source_declared=False),
    make('schema-invalid', '配置schema无效', 'UNKNOWN', ['字段结构无法解析'], schema_valid=False),
    make('default-undefined', '默认值未定义', 'UNKNOWN', ['未配置时的行为不明确'], default_defined=False),
    make('user-override-unread', '用户覆盖未读回', 'UNKNOWN', ['文件存在但无法证明运行时加载'], user_override_loaded=False),
    make('workspace-override-unread', 'workspace覆盖未读回', 'UNKNOWN', ['项目配置可能未被加载'], workspace_override_loaded=False),
    make('env-override-unread', '环境变量覆盖未读回', 'UNKNOWN', ['环境变量存在性和优先级无法确认'], env_override_loaded=False),
    make('cli-override-unread', 'CLI覆盖未读回', 'UNKNOWN', ['命令行参数是否生效未知'], cli_override_loaded=False),
    make('precedence-unknown', '优先级未知', 'UNKNOWN', ['多个来源同时设置且文档/读回不足'], precedence_order_known=False),
    make('effective-readback-missing', '最终值未读回', 'UNKNOWN', ['只能看到输入不能证明运行时生效'], effective_value_readback=False),
    make('restart-open', '重启边界未闭合', 'UNKNOWN', ['进程重启后配置是否保留未知'], restart_boundary_closed=False),
    make('scope-open', '作用域边界未闭合', 'UNKNOWN', ['user/workspace/project文件可能交叉影响'], scope_boundary_closed=False),
    make('secret-redaction-open', '敏感配置脱敏边界未闭合', 'UNKNOWN', ['无法证明报告/遥测未泄漏敏感值'], secret_redaction_closed=False),
    make('unknown-key-policy-open', '未知键策略未知', 'UNKNOWN', ['未知键可能被忽略、拒绝或静默接受'], unknown_key_policy_known=False),
    make('type-validation-failed', '类型校验失败', 'UNKNOWN', ['字符串/布尔/数字语义不一致'], type_validation_passed=False),
    make('version-mismatch', '配置版本不兼容', 'UNKNOWN', ['旧schema与当前runtime解释可能不同'], version_compatible=False),
    make('source-file-unstable', '来源文件不稳定', 'UNKNOWN', ['读取期间文件可能被替换'], source_file_stable=False),
    make('runtime-snapshot-missing', '运行时快照缺失', 'UNKNOWN', ['无法把配置来源与当前实例关联'], runtime_snapshot_attested=False),
    make('identity-unresolved', '身份域无法确定', 'UNKNOWN', ['tenant/project/instance字段不完整'], same_identity=False),
    make('identity-conflict', '跨作用域身份冲突', 'REJECT', ['同一配置身份出现不可调和来源'], same_identity=False, identity_conflict=True),
    make('override-conflict', '覆盖值冲突', 'REJECT', ['同一优先级/作用域出现不可调和值'], override_conflict=True),
    make('effective-conflict', '最终生效值冲突', 'REJECT', ['输入、runtime snapshot与read-back不可同时成立'], override_conflict=True, effective_value_readback=False),
]

assert len(cases) == 27
assert all(set(c['flags']) == set(FIELDS) for c in cases)
out = {
    'schema_version': 'S42-cases-1',
    'synthetic_only': True,
    'production_verified': False,
    'identity_domain': ['tenant', 'project', 'workspace', 'instance', 'config_key'],
    'configuration_domain': ['defaults', 'user', 'workspace', 'environment', 'cli', 'precedence', 'runtime_snapshot', 'restart', 'secret_redaction', 'schema', 'unknown_key'],
    'cases': cases
}
Path(__file__).with_name('cases.json').write_text(json.dumps(out, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
print(f'WROTE cases={len(cases)} fields={len(FIELDS)}')

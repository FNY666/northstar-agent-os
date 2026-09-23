#!/usr/bin/env python3
import json
from pathlib import Path

FIELDS = [
    'same_identity','identity_conflict','test_spec_declared','behavior_assertion_bound',
    'expected_output_bound','tool_behavior_bound','fixture_isolated','environment_declared',
    'sandbox_matrix_complete','docker_path_checked','podman_path_checked','no_sandbox_path_checked',
    'blocking_errors_separated','warnings_separated','repeat_runs_complete','repeat_results_stable',
    'integration_boundary_closed','resource_baseline_recorded','failure_injection_attested',
    'external_effect_not_claimed','test_conflict','unknown_test_state'
]
BASE = {k: True for k in FIELDS}
BASE.update({'identity_conflict': False, 'test_conflict': False, 'unknown_test_state': False})

def make(cid, label, status, evidence, **updates):
    flags = dict(BASE)
    flags.update(updates)
    assert set(flags) == set(FIELDS)
    return {'id': cid, 'label': label, 'status': status, 'flags': flags, 'evidence': evidence}

cases = [
    make('behavioral-eval-closed', 'behavioral eval行为断言闭合', 'RECOVERED', ['tool behavior和状态断言明确','prose差异不影响判定']),
    make('integration-matrix-closed', 'integration sandbox矩阵闭合', 'RECOVERED', ['no-sandbox/docker/podman路径均覆盖','环境边界已记录']),
    make('blocking-warning-separated', 'blocking error与warning分离', 'RECOVERED', ['阻断失败与非阻断提示分别统计','最终门禁语义明确']),
    make('repeat-run-stable', '重复运行结果稳定', 'RECOVERED', ['新behavioral eval重复运行达到门槛','结果和环境记录稳定']),
    make('failure-injection-closed', '失败注入与集成边界闭合', 'RECOVERED', ['failure injection可复现','资源基线和integration boundary可核对']),
    make('expected-tool-result-bound', 'expected output/tool result闭合', 'RECOVERED', ['预期结果与工具行为绑定','不把自然语言精确匹配当唯一门禁']),
    make('test-spec-missing', '测试规格缺失', 'UNKNOWN', ['无法知道case验证什么'], test_spec_declared=False),
    make('behavior-boundary-open', '行为断言边界未闭合', 'UNKNOWN', ['只比较文本或无法定位工具行为'], behavior_assertion_bound=False),
    make('expected-output-open', '预期输出未绑定', 'UNKNOWN', ['结果可通过但没有明确oracle'], expected_output_bound=False),
    make('tool-behavior-open', '工具行为未断言', 'UNKNOWN', ['eval不能证明实际工具调用语义'], tool_behavior_bound=False),
    make('fixture-leak', 'fixture隔离未证明', 'UNKNOWN', ['case可能读取外部状态'], fixture_isolated=False),
    make('environment-missing', '环境矩阵未声明', 'UNKNOWN', ['无法解释不同运行环境差异'], environment_declared=False),
    make('sandbox-matrix-gap', 'sandbox矩阵缺口', 'UNKNOWN', ['只测一种sandbox路径'], sandbox_matrix_complete=False),
    make('docker-path-missing', 'docker路径未测试', 'UNKNOWN', ['docker环境行为未知'], docker_path_checked=False),
    make('podman-path-missing', 'podman路径未测试', 'UNKNOWN', ['podman环境行为未知'], podman_path_checked=False),
    make('no-sandbox-path-missing', 'no-sandbox路径未测试', 'UNKNOWN', ['无sandbox环境行为未知'], no_sandbox_path_checked=False),
    make('blocking-warning-mixed', 'blocking与warning混合', 'UNKNOWN', ['warning可能被误当阻断失败或反之'], blocking_errors_separated=False, warnings_separated=False),
    make('repeat-incomplete', '重复运行次数不足', 'UNKNOWN', ['单次通过不足以说明稳定'], repeat_runs_complete=False),
    make('repeat-unstable', '重复结果不稳定', 'UNKNOWN', ['相同输入产生不同判定'], repeat_results_stable=False),
    make('integration-boundary-open', 'integration边界未闭合', 'UNKNOWN', ['测试通过但组件边界未记录'], integration_boundary_closed=False),
    make('resource-baseline-missing', '资源基线缺失', 'UNKNOWN', ['性能/内存回归无法解释'], resource_baseline_recorded=False),
    make('failure-injection-missing', '失败注入未证明', 'UNKNOWN', ['没有验证故障分支'], failure_injection_attested=False),
    make('external-effect-not-separated', '外部效果边界未分离', 'UNKNOWN', ['测试结果可能被误写成生产提交'], external_effect_not_claimed=False),
    make('identity-unresolved', '身份域无法确定', 'UNKNOWN', ['suite/environment/commit字段不完整'], same_identity=False),
    make('identity-conflict', '测试身份冲突', 'REJECT', ['不同suite/commit被错误合并'], same_identity=False, identity_conflict=True),
    make('test-conflict', '测试结论冲突', 'REJECT', ['同一case同时有不可调和pass/fail且无重现链'], test_conflict=True),
]

assert len(cases) == 26
assert all(set(c['flags']) == set(FIELDS) for c in cases)
out = {
    'schema_version': 'S47-cases-1',
    'synthetic_only': True,
    'production_verified': False,
    'identity_domain': ['suite', 'case_id', 'commit', 'environment', 'run_id'],
    'eval_domain': ['behavioral_eval', 'integration_test', 'blocking_error', 'warning', 'sandbox', 'fixture', 'repeat_run', 'failure_injection', 'resource_baseline'],
    'cases': cases
}
Path(__file__).with_name('cases.json').write_text(json.dumps(out, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
print(f'WROTE cases={len(cases)} fields={len(FIELDS)}')

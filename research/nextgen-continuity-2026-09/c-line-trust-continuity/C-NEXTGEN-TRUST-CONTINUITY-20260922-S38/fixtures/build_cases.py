#!/usr/bin/env python3
import json
from pathlib import Path

FIELDS = [
    'same_identity','identity_conflict','trace_context_valid','log_present',
    'metric_present','trace_present','signal_correlation_closed','sequence_complete',
    'export_attempt_attested','export_ack_attested','exporter_queue_closed',
    'drop_counter_reconciled','retry_history_complete','otlp_scope_consistent',
    'resource_identity_bound','time_window_closed','sampling_known','duplicate_dedup_attested',
    'signal_conflict','unknown_export_state'
]
BASE = {k: True for k in FIELDS}
BASE.update({
    'identity_conflict': False, 'signal_conflict': False,
    'unknown_export_state': False
})

def make(cid, label, status, evidence, **updates):
    flags = dict(BASE)
    flags.update(updates)
    assert set(flags) == set(FIELDS)
    return {'id': cid, 'label': label, 'status': status, 'flags': flags, 'evidence': evidence}

cases = [
    make('three-signal-closed', 'logs/metrics/traces三信号闭合', 'RECOVERED', ['三信号共享trace identity','export与sequence均闭合']),
    make('otlp-export-ack-closed', 'OTLP export与ack闭合', 'RECOVERED', ['export attempt和ack可关联','queue与retry历史完整']),
    make('drop-counter-reconciled', 'drop counter已对账', 'RECOVERED', ['丢弃计数与采样/过滤策略一致','没有未解释的信号缺口']),
    make('sampled-trace-with-log-metric', '采样trace有可解释边界', 'RECOVERED', ['sampling policy已知','log/metric提供同一业务identity的闭合证据']),
    make('duplicate-signal-dedup', '重复信号已去重', 'RECOVERED', ['重复export按signal identity去重','计数器未重复增加']),
    make('resource-bound-correlation', 'resource identity绑定', 'RECOVERED', ['service/resource attributes稳定','跨信号关联键完整']),
    make('log-missing', '日志信号缺失', 'UNKNOWN', ['只有metrics/traces不能证明日志未发生'], log_present=False),
    make('metric-missing', '指标信号缺失', 'UNKNOWN', ['只有logs/traces不能关闭计数器缺口'], metric_present=False),
    make('trace-missing', 'trace信号缺失', 'UNKNOWN', ['没有trace context不能证明跨服务关联'], trace_present=False),
    make('trace-context-invalid', 'trace context无效', 'UNKNOWN', ['trace_id/span_id格式或parent关系不可验证'], trace_context_valid=False),
    make('signal-correlation-open', '跨信号关联未闭合', 'UNKNOWN', ['不同信号的resource/trace identity不能唯一关联'], signal_correlation_closed=False),
    make('sequence-gap', '信号序列缺口', 'UNKNOWN', ['中间batch/sequence不可取回'], sequence_complete=False),
    make('export-attempt-missing', 'export attempt缺失', 'UNKNOWN', ['没有发出与否的可靠记录'], export_attempt_attested=False),
    make('export-ack-missing', 'export ack缺失', 'UNKNOWN', ['attempt存在但没有接收/持久化确认'], export_ack_attested=False),
    make('queue-open', 'exporter queue未闭合', 'UNKNOWN', ['仍可能有排队或重试中的信号'], exporter_queue_closed=False),
    make('drop-counter-missing', 'drop counter未对账', 'UNKNOWN', ['drop counter缺失或口径不明'], drop_counter_reconciled=False),
    make('retry-history-gap', 'retry历史不完整', 'UNKNOWN', ['无法区分一次发送与重复发送'], retry_history_complete=False),
    make('otlp-scope-mismatch', 'OTLP scope不一致', 'UNKNOWN', ['不同scope/resource下的记录不能直接合并'], otlp_scope_consistent=False),
    make('resource-unbound', 'resource identity未绑定', 'UNKNOWN', ['相同trace可能来自不同service/resource'], resource_identity_bound=False),
    make('time-window-open', '时间窗口未闭合', 'UNKNOWN', ['迟到信号仍可能进入当前窗口'], time_window_closed=False),
    make('sampling-unknown', '采样策略未知', 'UNKNOWN', ['trace缺失无法判断是采样还是丢失'], sampling_known=False),
    make('dedup-unproven', '去重未证明', 'UNKNOWN', ['重复signal可能污染计数'], duplicate_dedup_attested=False),
    make('export-unknown', 'export状态未知', 'UNKNOWN', ['无法判断远端是否已接收'], unknown_export_state=True),
    make('identity-unresolved', '身份域无法确定', 'UNKNOWN', ['tenant/source/trace identity不完整'], same_identity=False),
    make('identity-conflict', '跨身份域合并', 'REJECT', ['tenant或source明确不同'], same_identity=False, identity_conflict=True),
    make('signal-conflict', '跨信号内容冲突', 'REJECT', ['同一identity的业务结果/计数不可调和'], signal_conflict=True),
    make('export-state-conflict', 'export状态冲突', 'REJECT', ['同一batch同一attempt同时出现不可调和ack与拒绝'], signal_conflict=True, export_ack_attested=False),
]

assert len(cases) == 27
assert all(set(c['flags']) == set(FIELDS) for c in cases)
out = {
    'schema_version': 'S38-cases-1',
    'synthetic_only': True,
    'production_verified': False,
    'identity_domain': ['tenant', 'source', 'trace_id', 'span_id', 'service', 'resource', 'scope', 'batch', 'sequence'],
    'signal_domain': ['logs', 'metrics', 'traces', 'OTLP', 'sampling', 'export_attempt', 'export_ack', 'queue', 'drop_counter', 'retry'],
    'cases': cases
}
Path(__file__).with_name('cases.json').write_text(json.dumps(out, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
print(f'WROTE cases={len(cases)} fields={len(FIELDS)}')

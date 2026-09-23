#!/usr/bin/env python3
import json
from pathlib import Path

FIELDS = [
    'same_identity','identity_conflict','window_declared','window_bounds_closed',
    'source_scope_complete','platform_receipt_attested','durable_log_attested',
    'external_effect_attested','event_time_closed','ingest_time_closed',
    'watermark_closed','retention_closed','pagination_closed','query_gap_absent',
    'export_attempt_closed','exporter_failure_absent','delay_explained',
    'drop_explained','no_event_contract_known','state_conflict','unknown_commit'
]
BASE = {k: True for k in FIELDS}
BASE.update({
    'identity_conflict': False, 'state_conflict': False, 'unknown_commit': False
})

def make(cid, label, status, class_label, evidence, **updates):
    flags = dict(BASE)
    flags.update(updates)
    assert set(flags) == set(FIELDS)
    return {'id': cid, 'label': label, 'class': class_label, 'status': status, 'flags': flags, 'evidence': evidence}

cases = [
    make('verified-continuity', '完整连续性', 'RECOVERED', 'VERIFIED_CONTINUITY', ['窗口、身份、三类证据、watermark、retention与query均闭合']),
    make('delayed-closed', '延迟但已解释', 'RECOVERED', 'DELAYED', ['event/ingest差异在已认证delay bound内','watermark已闭合']),
    make('no-event-contract', '契约化NO_EVENT', 'RECOVERED', 'NO_EVENT', ['查询完整且NO_EVENT语义明确','全窗口无gap']),
    make('platform-log-effect-closed', '平台/日志/外部效果三轴闭合', 'RECOVERED', 'VERIFIED_CONTINUITY', ['三类receipt分别可验证','不能以一个轴代替另两个轴']),
    make('dropped-explained', 'DROPPED已被策略解释', 'RECOVERED', 'DROPPED', ['drop有明确过滤策略与计数对账','不影响目标事件窗口结论']),
    make('exporter-failure-recovered', 'exporter失败后补偿闭合', 'RECOVERED', 'EXPORTER_FAILURE', ['失败记录、重试与最终read-back闭合','没有未知提交']),
    make('delayed-unbounded', '未解释延迟', 'UNKNOWN', 'DELAYED', ['延迟超出或没有认证上界'], delay_explained=False),
    make('dropped-unexplained', '未解释丢弃', 'UNKNOWN', 'DROPPED', ['drop计数无法与策略或事件窗口对账'], drop_explained=False),
    make('exporter-failure-open', 'exporter故障未闭合', 'UNKNOWN', 'EXPORTER_FAILURE', ['失败后没有可靠重试或最终读回'], exporter_failure_absent=False, unknown_commit=True),
    make('query-gap', '查询缺口', 'UNKNOWN', 'QUERY_GAP', ['存在QUERY_GAP，窗口不能闭合'], query_gap_absent=False),
    make('retention-expired', '保留期过期', 'UNKNOWN', 'RETENTION_EXPIRED', ['RETENTION_EXPIRED不证明事件未发生'], retention_closed=False),
    make('no-event-unknown', 'NO_EVENT语义未知', 'UNKNOWN', 'NO_EVENT', ['空结果但没有完整窗口或契约'], no_event_contract_known=False),
    make('window-open', '证据窗口未闭合', 'UNKNOWN', 'QUERY_GAP', ['起止边界或分页链缺失'], window_bounds_closed=False, pagination_closed=False),
    make('source-scope-open', '来源范围不完整', 'UNKNOWN', 'QUERY_GAP', ['部分source/region未返回'], source_scope_complete=False, query_gap_absent=False),
    make('platform-only', '仅平台receipt', 'UNKNOWN', 'VERIFIED_CONTINUITY', ['平台成功不等于日志或外部效果'], durable_log_attested=False, external_effect_attested=False),
    make('log-only', '仅持久日志', 'UNKNOWN', 'VERIFIED_CONTINUITY', ['日志存在不等于外部效果已提交'], platform_receipt_attested=False, external_effect_attested=False),
    make('effect-only', '仅外部效果', 'UNKNOWN', 'VERIFIED_CONTINUITY', ['外部读回不能替代平台和审计链'], platform_receipt_attested=False, durable_log_attested=False),
    make('watermark-open', '水位未闭合', 'UNKNOWN', 'DELAYED', ['仍可能有迟到事件进入窗口'], watermark_closed=False),
    make('pagination-open', '分页未闭合', 'UNKNOWN', 'QUERY_GAP', ['当前页成功不代表完整查询'], pagination_closed=False, query_gap_absent=False),
    make('export-attempt-open', 'export attempt未闭合', 'UNKNOWN', 'EXPORTER_FAILURE', ['发送状态未知'], export_attempt_closed=False, unknown_commit=True),
    make('identity-unresolved', '身份域不完整', 'UNKNOWN', 'QUERY_GAP', ['tenant/source/event_id字段缺失'], same_identity=False),
    make('unknown-commit', '未知提交', 'UNKNOWN', 'EXPORTER_FAILURE', ['断流/超时后无法判断远端是否已提交'], unknown_commit=True),
    make('state-conflict', '状态互斥冲突', 'REJECT', 'VERIFIED_CONTINUITY', ['同一窗口同时出现不可调和的终态声明'], state_conflict=True),
    make('identity-conflict', '跨身份域合并', 'REJECT', 'QUERY_GAP', ['tenant或source明确不同'], same_identity=False, identity_conflict=True),
    make('receipt-effect-conflict', 'receipt与外部效果冲突', 'REJECT', 'VERIFIED_CONTINUITY', ['同一operation的三轴证据不可调和'], state_conflict=True),
]

assert len(cases) == 25
assert all(set(c['flags']) == set(FIELDS) for c in cases)
out = {
    'schema_version': 'S40-cases-1',
    'synthetic_only': True,
    'production_verified': False,
    'identity_domain': ['tenant', 'source', 'event_id', 'epoch', 'version'],
    'window_domain': ['event_time', 'ingest_time', 'watermark', 'retention', 'pagination', 'query_gap'],
    'evidence_axes': ['platform_receipt', 'durable_log', 'external_effect'],
    'classes': ['NO_EVENT', 'DELAYED', 'DROPPED', 'EXPORTER_FAILURE', 'QUERY_GAP', 'RETENTION_EXPIRED', 'VERIFIED_CONTINUITY'],
    'cases': cases
}
Path(__file__).with_name('cases.json').write_text(json.dumps(out, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
print(f'WROTE cases={len(cases)} fields={len(FIELDS)}')

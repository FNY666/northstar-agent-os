#!/usr/bin/env python3
import json
from pathlib import Path

FIELDS = [
    'same_identity','identity_conflict','event_time_present','ingest_time_present',
    'clock_bound_attested','timestamp_order_valid','not_before_satisfied',
    'expires_after_event','freshness_window_closed','nonce_unique',
    'replay_window_closed','sequence_monotonic','watermark_closed',
    'delay_bound_attested','causal_time_consistent','revalidation_attested',
    'time_source_independent','temporal_conflict','replay_conflict'
]
BASE = {k: True for k in FIELDS}
BASE.update({
    'identity_conflict': False, 'temporal_conflict': False, 'replay_conflict': False
})

def make(cid, label, status, evidence, **updates):
    flags = dict(BASE)
    flags.update(updates)
    assert set(flags) == set(FIELDS)
    return {'id': cid, 'label': label, 'status': status, 'flags': flags, 'evidence': evidence}

cases = [
    make('complete-time-interval', '时间区间与顺序闭合', 'RECOVERED', ['event/ingest timestamps存在','clock bound与有效期均已证明']),
    make('bounded-skew-attested', '有界时钟偏差已认证', 'RECOVERED', ['独立time source给出skew上界','timestamp ordering在区间语义下成立']),
    make('nonce-replay-closed', 'nonce与重放窗口闭合', 'RECOVERED', ['nonce唯一性可验证','replay watermark覆盖完整窗口']),
    make('delayed-within-bound', '延迟到达仍在允许边界', 'RECOVERED', ['延迟小于已认证上界','watermark已越过最大延迟']),
    make('revalidation-current', '重新验证时点仍有效', 'RECOVERED', ['revalidation read-back在freshness窗口内','not-before/expiry均满足']),
    make('sequence-time-consistent', '序列与因果时间一致', 'RECOVERED', ['sequence单调','因果时间约束与跨系统时钟区间不冲突']),
    make('event-time-missing', 'event time 缺失', 'UNKNOWN', ['只有ingest time不能推出事件发生时间'], event_time_present=False),
    make('ingest-time-missing', 'ingest time 缺失', 'UNKNOWN', ['无法建立接收与延迟边界'], ingest_time_present=False),
    make('clock-bound-missing', '时钟偏差无界', 'UNKNOWN', ['没有可信clock skew上界'], clock_bound_attested=False),
    make('timestamp-order-unknown', '时间顺序无法确定', 'UNKNOWN', ['timestamp区间重叠，不能确定先后'], timestamp_order_valid=False),
    make('not-before-unknown', 'not-before 未满足或未知', 'UNKNOWN', ['无法证明签名/事件在生效时间之后'], not_before_satisfied=False),
    make('expiry-unknown', 'expiry 边界未知', 'UNKNOWN', ['无法证明事件发生时凭证仍未过期'], expires_after_event=False),
    make('freshness-open', 'freshness 窗口未闭合', 'UNKNOWN', ['当前读回可能已过期'], freshness_window_closed=False),
    make('nonce-reused', 'nonce 重复', 'UNKNOWN', ['nonce重复但缺少足够证据判定是重放还是合法重试'], nonce_unique=False),
    make('replay-window-open', '重放窗口未闭合', 'UNKNOWN', ['仍有未查询到的窗口片段'], replay_window_closed=False),
    make('sequence-gap', '时间序列跳变', 'UNKNOWN', ['sequence跳变无法区分丢失与乱序'], sequence_monotonic=False),
    make('watermark-open', '时间水位未闭合', 'UNKNOWN', ['仍可能有迟到事件进入窗口'], watermark_closed=False),
    make('delay-bound-missing', '延迟上界未认证', 'UNKNOWN', ['不能证明当前未见事件是未发生'], delay_bound_attested=False),
    make('causal-time-conflict-unknown', '因果时间证据不足', 'UNKNOWN', ['观察到时间异常但缺少完整因果链'], causal_time_consistent=False),
    make('revalidation-missing', '重新验证缺失', 'UNKNOWN', ['旧的有效性证据不能覆盖当前读取时点'], revalidation_attested=False),
    make('time-source-correlated', '时间源不独立', 'UNKNOWN', ['多个时钟可能共享同一错误源'], time_source_independent=False),
    make('identity-unresolved', '身份域无法确定', 'UNKNOWN', ['tenant/source/event_id/epoch字段不完整'], same_identity=False),
    make('identity-conflict', '跨身份域合并', 'REJECT', ['tenant或source明确不同'], same_identity=False, identity_conflict=True),
    make('temporal-conflict', '不可调和时间声明', 'REJECT', ['同一身份和epoch给出互斥有效期/时间顺序'], temporal_conflict=True),
    make('replay-conflict', '重放与唯一性冲突', 'REJECT', ['同一nonce在互斥上下文中被再次接受'], replay_conflict=True, nonce_unique=False),
    make('not-before-after-expiry', '生效时间晚于失效时间', 'REJECT', ['not-before与expiry区间为空'], temporal_conflict=True, not_before_satisfied=False, expires_after_event=False),
]

assert len(cases) == 26
assert all(set(c['flags']) == set(FIELDS) for c in cases)
out = {
    'schema_version': 'S37-cases-1',
    'synthetic_only': True,
    'production_verified': False,
    'identity_domain': ['tenant', 'source', 'event_id', 'epoch', 'version'],
    'temporal_domain': ['event_time', 'ingest_time', 'clock_bound', 'not_before', 'expiry', 'freshness', 'nonce', 'replay_window', 'sequence', 'watermark', 'revalidation'],
    'cases': cases
}
Path(__file__).with_name('cases.json').write_text(json.dumps(out, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
print(f'WROTE cases={len(cases)} fields={len(FIELDS)}')

#!/usr/bin/env python3
import json
from pathlib import Path

FIELDS = [
    'same_identity','identity_conflict','query_scope_fixed','time_window_fixed',
    'page_cursor_chain_complete','page_terminal_attested','resource_version_monotonic',
    'snapshot_consistent','watermark_closed','retention_window_open',
    'retention_boundary_attested','no_event_semantics_known','gap_absent',
    'pagination_limit_known','filter_semantics_known','cross_region_complete',
    'query_retry_reconciled','duplicate_page_deduped','query_conflict','retention_expired'
]
BASE = {k: True for k in FIELDS}
BASE.update({
    'identity_conflict': False, 'retention_window_open': False,
    'gap_absent': True, 'query_conflict': False, 'retention_expired': False
})

def make(cid, label, status, evidence, **updates):
    flags = dict(BASE)
    flags.update(updates)
    assert set(flags) == set(FIELDS)
    return {'id': cid, 'label': label, 'status': status, 'flags': flags, 'evidence': evidence}

cases = [
    make('complete-paginated-window', '分页查询窗口完整', 'RECOVERED', ['query scope与时间窗固定','cursor链和terminal均有证明']),
    make('resource-version-continuous', 'resourceVersion连续', 'RECOVERED', ['snapshot/resourceVersion单调','跨页查询使用一致快照']),
    make('watermark-no-event-closed', '水位闭合下NO_EVENT', 'RECOVERED', ['watermark覆盖完整窗口','NO_EVENT语义已由系统契约定义']),
    make('cross-region-query-complete', '跨区域查询完整', 'RECOVERED', ['所有区域返回边界均已对账','重复页已去重']),
    make('retry-query-reconciled', '查询重试已对账', 'RECOVERED', ['重试不会扩大或丢失查询窗口','结果集按query identity去重']),
    make('pagination-limit-known', '分页限制已知且覆盖', 'RECOVERED', ['API limit和cursor语义固定','terminal边界可达']),
    make('query-scope-missing', '查询scope未固定', 'UNKNOWN', ['过滤器或租户范围不明确'], query_scope_fixed=False),
    make('time-window-missing', '时间窗口未固定', 'UNKNOWN', ['起止时间语义不明确'], time_window_fixed=False),
    make('page-cursor-gap', '分页cursor缺口', 'UNKNOWN', ['中间页未返回或游标跳过'], page_cursor_chain_complete=False, gap_absent=False),
    make('terminal-missing', '分页终止未证明', 'UNKNOWN', ['当前页成功不能证明没有下一页'], page_terminal_attested=False),
    make('resource-version-regression', 'resourceVersion回退', 'UNKNOWN', ['版本回退可能来自不同快照或查询重启'], resource_version_monotonic=False),
    make('snapshot-inconsistent', '跨页快照不一致', 'UNKNOWN', ['各页可能来自不同状态时点'], snapshot_consistent=False),
    make('watermark-open', '查询水位未闭合', 'UNKNOWN', ['迟到数据仍可能进入窗口'], watermark_closed=False),
    make('retention-unknown', '保留边界未知', 'UNKNOWN', ['查询范围跨越未知保留期'], retention_boundary_attested=False),
    make('no-event-semantics-unknown', 'NO_EVENT语义未知', 'UNKNOWN', ['空结果可能是过滤/分页/延迟造成'], no_event_semantics_known=False),
    make('query-gap', '查询缺口', 'UNKNOWN', ['API返回QUERY_GAP或局部失败'], gap_absent=False),
    make('pagination-limit-unknown', '分页limit未知', 'UNKNOWN', ['不能判断是否达到服务端上限'], pagination_limit_known=False),
    make('filter-semantics-unknown', '过滤语义未知', 'UNKNOWN', ['服务端过滤器是否覆盖全部字段未确认'], filter_semantics_known=False),
    make('cross-region-partial', '跨区域部分返回', 'UNKNOWN', ['一个区域缺少terminal或page链'], cross_region_complete=False, gap_absent=False),
    make('retry-reconciliation-missing', '查询重试未对账', 'UNKNOWN', ['断线重试后无法区分重复页和新页'], query_retry_reconciled=False),
    make('duplicate-page-unresolved', '重复页未去重', 'UNKNOWN', ['同一cursor多次结果可能污染计数'], duplicate_page_deduped=False),
    make('identity-unresolved', '身份域无法确定', 'UNKNOWN', ['tenant/source/event_id字段不完整'], same_identity=False),
    make('retention-expired', '保留期已过期', 'UNKNOWN', ['RETENTION_EXPIRED不能证明事件未发生'], retention_expired=True, retention_window_open=True),
    make('scope-and-gap-edge', 'scope与缺口同时未知', 'UNKNOWN', ['多个不确定门不能相互抵消'], query_scope_fixed=False, gap_absent=False),
    make('identity-conflict', '跨身份域查询', 'REJECT', ['tenant或source明确不同'], same_identity=False, identity_conflict=True),
    make('query-conflict', '同一查询返回不可调和结果', 'REJECT', ['同一snapshot/query identity对同一event给出冲突结果'], query_conflict=True),
    make('retention-contract-conflict', '保留契约冲突', 'REJECT', ['同一资源同一时间边界同时给出可取回与已过期声明'], query_conflict=True, retention_expired=True),
]

assert len(cases) == 27
assert all(set(c['flags']) == set(FIELDS) for c in cases)
out = {
    'schema_version': 'S39-cases-1',
    'synthetic_only': True,
    'production_verified': False,
    'identity_domain': ['tenant', 'source', 'event_id', 'epoch', 'version'],
    'query_domain': ['query_scope', 'time_window', 'page_cursor', 'resource_version', 'snapshot', 'watermark', 'retention', 'NO_EVENT', 'QUERY_GAP', 'cross_region', 'retry'],
    'cases': cases
}
Path(__file__).with_name('cases.json').write_text(json.dumps(out, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
print(f'WROTE cases={len(cases)} fields={len(FIELDS)}')

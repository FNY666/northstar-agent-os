#!/usr/bin/env python3
import json
from pathlib import Path

FIELDS = [
    'same_identity','identity_conflict','model_source_declared','model_precedence_known',
    'provider_route_readback','token_cache_scope_bound','token_cache_expiry_known',
    'token_cache_key_bound','cache_invalidation_attested','auto_memory_scope_bound',
    'memory_write_policy_known','memory_read_policy_known','memory_retention_bound',
    'memory_export_bound','worktree_identity_bound','worktree_path_bound',
    'worktree_branch_bound','worktree_dirty_state_known','worktree_cleanup_attested',
    'cross_worktree_isolation_closed','route_conflict','unknown_state'
]
BASE = {k: True for k in FIELDS}
BASE.update({'identity_conflict': False, 'route_conflict': False, 'unknown_state': False})

def make(cid, label, status, evidence, **updates):
    flags = dict(BASE)
    flags.update(updates)
    assert set(flags) == set(FIELDS)
    return {'id': cid, 'label': label, 'status': status, 'flags': flags, 'evidence': evidence}

cases = [
    make('model-route-closed', '多源模型路由闭合', 'RECOVERED', ['requested/selected model和provider read-back一致','precedence链固定']),
    make('token-cache-closed', 'token cache scope/expiry闭合', 'RECOVERED', ['cache key、scope、expiry和invalidation绑定','未跨account/route复用']),
    make('auto-memory-closed', 'auto memory读写边界闭合', 'RECOVERED', ['memory read/write scope和retention明确','export/access边界可审计']),
    make('worktree-isolation-closed', 'git worktree隔离闭合', 'RECOVERED', ['worktree identity/path/branch绑定','dirty state和cleanup可验证']),
    make('cross-worktree-closed', '跨worktree状态隔离闭合', 'RECOVERED', ['不同worktree不共享未授权状态','最终结果按worktree归属']),
    make('cache-invalidation-closed', 'cache invalidation闭合', 'RECOVERED', ['provider/model/credential变化触发失效','旧cache不可继续使用']),
    make('model-source-unknown', '模型来源未声明', 'UNKNOWN', ['无法知道模型来自哪个provider/source'], model_source_declared=False),
    make('precedence-unknown', '模型优先级未知', 'UNKNOWN', ['CLI/env/settings/router顺序不明'], model_precedence_known=False),
    make('provider-readback-missing', 'provider route未读回', 'UNKNOWN', ['请求成功但最终provider未知'], provider_route_readback=False),
    make('cache-scope-open', 'token cache scope未绑定', 'UNKNOWN', ['token可能跨account/project复用'], token_cache_scope_bound=False),
    make('cache-expiry-unknown', 'token cache expiry未知', 'UNKNOWN', ['过期token可能继续被采用'], token_cache_expiry_known=False),
    make('cache-key-open', 'cache key未绑定', 'UNKNOWN', ['不同model/credential可能命中同一cache'], token_cache_key_bound=False),
    make('cache-invalidation-unknown', 'cache失效未知', 'UNKNOWN', ['credential/provider变化后旧值状态不明'], cache_invalidation_attested=False),
    make('memory-scope-open', 'auto memory scope未绑定', 'UNKNOWN', ['memory可能跨workspace/session写入'], auto_memory_scope_bound=False),
    make('memory-write-unknown', 'memory写策略未知', 'UNKNOWN', ['哪些事实可自动持久化不明'], memory_write_policy_known=False),
    make('memory-read-unknown', 'memory读策略未知', 'UNKNOWN', ['哪些memory会注入当前上下文不明'], memory_read_policy_known=False),
    make('memory-retention-open', 'memory retention未绑定', 'UNKNOWN', ['memory保存和删除边界不明'], memory_retention_bound=False),
    make('memory-export-open', 'memory export未绑定', 'UNKNOWN', ['memory是否导出到外部目的地不明'], memory_export_bound=False),
    make('worktree-identity-open', 'worktree identity未绑定', 'UNKNOWN', ['commit/session/worktree归属不明'], worktree_identity_bound=False),
    make('worktree-path-open', 'worktree path未绑定', 'UNKNOWN', ['工具可能写错worktree'], worktree_path_bound=False),
    make('worktree-branch-open', 'worktree branch未绑定', 'UNKNOWN', ['分支/HEAD状态不明'], worktree_branch_bound=False),
    make('dirty-state-unknown', 'worktree dirty state未知', 'UNKNOWN', ['cleanup/merge可能覆盖未提交变更'], worktree_dirty_state_known=False),
    make('cleanup-unattested', 'worktree cleanup未验证', 'UNKNOWN', ['删除/回收后残留状态不明'], worktree_cleanup_attested=False),
    make('isolation-open', '跨worktree隔离未闭合', 'UNKNOWN', ['不同worktree可能共享cache/memory/file state'], cross_worktree_isolation_closed=False),
    make('identity-unresolved', '身份域无法确定', 'UNKNOWN', ['account/project/worktree/session字段不完整'], same_identity=False),
    make('identity-conflict', '跨account/worktree身份合并', 'REJECT', ['不同identity的route/cache/memory被错误合并'], same_identity=False, identity_conflict=True),
    make('route-conflict', '模型路由状态冲突', 'REJECT', ['同一request不可调和地选择不同provider/model'], route_conflict=True),
]

assert len(cases) == 27
assert all(set(c['flags']) == set(FIELDS) for c in cases)
out = {
    'schema_version': 'S54-cases-1',
    'synthetic_only': True,
    'production_verified': False,
    'identity_domain': ['account', 'project', 'session', 'model', 'provider', 'cache_key', 'memory_id', 'worktree', 'branch', 'commit'],
    'continuity_domain': ['model_route', 'token_cache', 'auto_memory', 'retention', 'export', 'worktree', 'branch', 'dirty_state', 'cleanup', 'isolation'],
    'cases': cases
}
Path(__file__).with_name('cases.json').write_text(json.dumps(out, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
print(f'WROTE cases={len(cases)} fields={len(FIELDS)}')

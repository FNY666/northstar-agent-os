#!/usr/bin/env python3
import json
from pathlib import Path

FIELDS = [
    'same_identity','identity_conflict','slice_id_bound','version_monotonic',
    'state_transition_declared','previous_digest_bound','new_digest_recorded',
    'migration_reason_bound','duplicate_entry_deduped','conflict_entry_detected',
    'canonical_winner_declared','derived_archive_bound','raw_preserved',
    'manifest_recomputed','cross_slice_reference_closed','status_transition_valid',
    'question_unchanged_or_migrated','claim_revision_bound','source_set_closed',
    'filesystem_state_readback','convergence_attested','ledger_conflict',
    'unknown_migration'
]
BASE = {k: True for k in FIELDS}
BASE.update({'identity_conflict': False, 'ledger_conflict': False, 'unknown_migration': False})

def make(cid, label, status, evidence, **updates):
    flags = dict(BASE)
    flags.update(updates)
    assert set(flags) == set(FIELDS)
    return {'id': cid, 'label': label, 'status': status, 'flags': flags, 'evidence': evidence}

cases = [
    make('slice-transition-closed', '切片状态迁移闭合', 'RECOVERED', ['slice id/version/previous digest绑定','状态迁移和新manifest已重算']),
    make('duplicate-entry-closed', '重复entry去重闭合', 'RECOVERED', ['重复entry identity稳定','canonical winner和derived archive明确']),
    make('conflict-merge-closed', '冲突entry合并闭合', 'RECOVERED', ['冲突检测/冻结/胜者规则完整','raw和历史derived均保留']),
    make('cross-slice-reference-closed', '跨切片引用闭合', 'RECOVERED', ['question/claim/source迁移链可追溯','status transition合法']),
    make('canonical-convergence-closed', 'canonical最终收敛闭合', 'RECOVERED', ['filesystem read-back与manifest一致','所有derived指向唯一canonical']),
    make('revision-source-closed', 'claim revision/source set闭合', 'RECOVERED', ['claim revision和source set绑定','问题变化有migration reason']),
    make('slice-id-missing', 'slice id缺失', 'UNKNOWN', ['无法区分不同切片的entry'], slice_id_bound=False),
    make('version-regression', '版本回退', 'UNKNOWN', ['version顺序不明或回退'], version_monotonic=False),
    make('transition-undeclared', '状态迁移未声明', 'UNKNOWN', ['inferred/confirmed/rejected变化无理由'], state_transition_declared=False),
    make('previous-digest-missing', 'previous digest缺失', 'UNKNOWN', ['无法证明新entry基于哪一版本'], previous_digest_bound=False),
    make('new-digest-missing', '新digest未记录', 'UNKNOWN', ['迁移后内容不可验证'], new_digest_recorded=False),
    make('migration-reason-missing', '迁移理由缺失', 'UNKNOWN', ['状态/问题变化无法解释'], migration_reason_bound=False),
    make('duplicate-unproven', '重复entry未去重', 'UNKNOWN', ['重复事实可能被重复计数'], duplicate_entry_deduped=False),
    make('conflict-not-detected', '冲突检测缺失', 'UNKNOWN', ['互斥内容可能静默合并'], conflict_entry_detected=False),
    make('canonical-winner-unknown', 'canonical胜者未知', 'UNKNOWN', ['多个版本都可能被使用'], canonical_winner_declared=False),
    make('derived-archive-unbound', 'derived归档未绑定', 'UNKNOWN', ['历史derived可能覆盖当前canonical'], derived_archive_bound=False),
    make('raw-preservation-unknown', 'raw保留未知', 'UNKNOWN', ['源料可能被重写'], raw_preserved=False),
    make('manifest-not-recomputed', 'manifest未重算', 'UNKNOWN', ['迁移后required files/hash未知'], manifest_recomputed=False),
    make('reference-gap', '跨切片引用缺口', 'UNKNOWN', ['前后切片不能互相追溯'], cross_slice_reference_closed=False),
    make('status-invalid', '状态迁移非法', 'UNKNOWN', ['终态/证据等级转换不符合规则'], status_transition_valid=False),
    make('question-migrated-unknown', '问题迁移未绑定', 'UNKNOWN', ['研究问题变化是否为新问题不明'], question_unchanged_or_migrated=False),
    make('claim-revision-unbound', 'claim revision未绑定', 'UNKNOWN', ['旧结论与新结论关系不明'], claim_revision_bound=False),
    make('source-set-open', 'source set未闭合', 'UNKNOWN', ['来源增删影响不明'], source_set_closed=False),
    make('filesystem-readback-missing', '文件系统状态未读回', 'UNKNOWN', ['目录状态可能与摘要不同'], filesystem_state_readback=False),
    make('convergence-unknown', 'canonical收敛未知', 'UNKNOWN', ['各derived可能仍指向不同版本'], convergence_attested=False, unknown_migration=True),
    make('identity-unresolved', '身份域无法确定', 'UNKNOWN', ['project/ledger/slice字段不完整'], same_identity=False),
    make('identity-conflict', '跨项目迁移合并', 'REJECT', ['不同项目ledger被错误合并'], same_identity=False, identity_conflict=True),
    make('ledger-conflict', '迁移状态冲突', 'REJECT', ['同一slice同时存在不可调和canonical版本'], ledger_conflict=True),
]

assert len(cases) == 28
assert all(set(c['flags']) == set(FIELDS) for c in cases)
out = {
    'schema_version': 'S57-cases-1',
    'synthetic_only': True,
    'production_verified': False,
    'identity_domain': ['project', 'ledger', 'slice_id', 'entry_id', 'question', 'claim', 'source', 'canonical_version'],
    'migration_domain': ['version', 'previous_digest', 'new_digest', 'state_transition', 'migration_reason', 'duplicate', 'conflict', 'canonical_winner', 'derived_archive', 'raw', 'manifest', 'cross_slice_reference', 'convergence'],
    'cases': cases
}
Path(__file__).with_name('cases.json').write_text(json.dumps(out, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
print(f'WROTE cases={len(cases)} fields={len(FIELDS)}')

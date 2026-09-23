#!/usr/bin/env python3
import json
from pathlib import Path

FIELDS = [
    'same_identity','identity_conflict','root_attested','delegation_chain_complete',
    'signer_scope_valid','key_status_current','revocation_watermark_closed',
    'payload_bound','context_bound','bundle_canonical','transform_chain_attested',
    'redaction_attested','resign_authorized','timestamp_fresh','issuer_epoch_continuous',
    'quorum_agreed','signer_equivocation','scope_conflict','revocation_conflict'
]
BASE = {k: True for k in FIELDS}
BASE.update({
    'identity_conflict': False, 'signer_equivocation': False,
    'scope_conflict': False, 'revocation_conflict': False
})

def make(cid, label, status, evidence, **updates):
    flags = dict(BASE)
    flags.update(updates)
    assert set(flags) == set(FIELDS)
    return {'id': cid, 'label': label, 'status': status, 'flags': flags, 'evidence': evidence}

cases = [
    make('delegated-chain-complete', '委托证明链完整', 'RECOVERED', ['issuer到delegate的链完整','每个签名者的scope覆盖目标bundle']),
    make('context-bound-attestation', 'payload与上下文均绑定', 'RECOVERED', ['签名覆盖payload digest','签名同时覆盖tenant/epoch/purpose上下文']),
    make('authorized-resigning', '授权重签名闭合', 'RECOVERED', ['原签名与变换链可验证','重签名者具有明确授权且新旧scope连续']),
    make('redaction-transform-complete', '脱敏变换链完整', 'RECOVERED', ['redaction policy已认证','变换前后关联和新bundle canonicalization均闭合']),
    make('current-quorum-attested', '当前密钥与quorum一致', 'RECOVERED', ['观察者quorum一致','key status和revocation watermark均覆盖读取时点']),
    make('delayed-attestation-fresh', '延迟证明仍新鲜', 'RECOVERED', ['证明虽延迟但仍在timestamp窗口','issuer epoch与撤销水位连续']),
    make('root-not-attested', '根证明未认证', 'UNKNOWN', ['root/bundle存在但缺少可信issuer签名'], root_attested=False),
    make('delegation-chain-gap', '委托链有缺口', 'UNKNOWN', ['中间delegate证书或授权边不可取回'], delegation_chain_complete=False),
    make('signer-scope-missing', '签名者scope缺失', 'UNKNOWN', ['无法证明签名者被授权覆盖该资源'], signer_scope_valid=False),
    make('key-status-unknown', '密钥状态未知', 'UNKNOWN', ['无法在目标时点确认key未撤销或未过期'], key_status_current=False),
    make('revocation-watermark-open', '撤销水位未闭合', 'UNKNOWN', ['读回时点之后仍可能存在未观察到的撤销'], revocation_watermark_closed=False),
    make('payload-unbound', 'payload未绑定', 'UNKNOWN', ['签名存在但未覆盖canonical payload digest'], payload_bound=False),
    make('context-unbound', '上下文未绑定', 'UNKNOWN', ['同一payload可被移植到不同tenant/epoch/purpose'], context_bound=False),
    make('bundle-noncanonical', 'bundle规范化未固定', 'UNKNOWN', ['字段顺序或编码规则未固定，签名对象不可唯一确定'], bundle_canonical=False),
    make('transform-unattested', '变换链未认证', 'UNKNOWN', ['脱敏/转换后的bundle无法关联到原始证据'], transform_chain_attested=False),
    make('redaction-policy-missing', '脱敏策略未认证', 'UNKNOWN', ['不知道删除字段是否被授权且是否保持安全语义'], redaction_attested=False),
    make('resign-unauthorized', '重签名未授权', 'UNKNOWN', ['新签名存在但没有原始issuer授权'], resign_authorized=False),
    make('timestamp-stale', '时间戳过期', 'UNKNOWN', ['签名时间超过freshness window'], timestamp_fresh=False),
    make('issuer-epoch-gap', 'issuer epoch不连续', 'UNKNOWN', ['新epoch与旧epoch之间缺少连续证明'], issuer_epoch_continuous=False),
    make('quorum-not-closed', '观察者quorum未闭合', 'UNKNOWN', ['观察者返回不完整，不能升级为一致'], quorum_agreed=False),
    make('identity-missing', '身份域不完整', 'UNKNOWN', ['tenant/source/event_id等身份字段缺失'], same_identity=False),
    make('attestation-unknown-boundary', '证明边界未知', 'UNKNOWN', ['当前bundle状态可见但无法证明其授权边界'], signer_scope_valid=False, context_bound=False),
    make('identity-conflict', '跨身份域合并', 'REJECT', ['tenant或source明确不同'], same_identity=False, identity_conflict=True),
    make('signer-equivocation', '签名者双重陈述', 'REJECT', ['同一issuer scope和epoch对同一身份给出不可调和声明'], signer_equivocation=True),
    make('scope-conflict', '授权scope冲突', 'REJECT', ['签名scope明确互斥且不能同时覆盖目标bundle'], scope_conflict=True),
    make('revocation-conflict', '撤销状态冲突', 'REJECT', ['同一key和时点出现不可调和的active/revoked证据'], revocation_conflict=True),
]

assert len(cases) == 26
assert all(set(c['flags']) == set(FIELDS) for c in cases)
out = {
    'schema_version': 'S36-cases-1',
    'synthetic_only': True,
    'production_verified': False,
    'identity_domain': ['tenant', 'source', 'event_id', 'epoch', 'version'],
    'attestation_domain': ['issuer', 'delegate', 'scope', 'payload_digest', 'context', 'transform', 'redaction', 'resign', 'key_status', 'revocation_watermark', 'freshness'],
    'cases': cases
}
Path(__file__).with_name('cases.json').write_text(json.dumps(out, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
print(f'WROTE cases={len(cases)} fields={len(FIELDS)}')

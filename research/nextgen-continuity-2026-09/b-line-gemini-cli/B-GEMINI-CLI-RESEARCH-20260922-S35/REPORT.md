# S35 双实现规则交叉验证与局部性质测试

## 结论

本切片是**离线、单 worker、确定性、synthetic-only** 测试。固定的 24 个 fixture 在两个独立本地实现（impl-A、impl-B）各运行一次：

- fixture 数：**24**
- 双实现一致：**24**
- conflict：**0**
- 交叉结果：**INTEROP_OK=24；INTEROP_CONFLICT=0**
- 性质断言：**6/6 PASS**
  1. fixture/schema/canonical hashes — PASS
  2. cross-implementation consistency — PASS
  3. locality under explicit revocation — PASS
  4. undeclared op non-attribution — PASS
  5. three-state mutual exclusion and conservative anomalies — PASS
  6. deterministic harness rerun byte identity — PASS

每条结果均保留 `impl_A`、`impl_B`、`consistent`、`conflict`、`interop` 与 canonical 输入 SHA-256；见 `outputs/results.json`。未发生 conflict，因此未触发 `INTEROP_CONFLICT` 路径；代码仍显式保留该语义，且 validator 对任何 conflict 强制失败（不能升级为 accepted 或 rejected）。

## 规则与范围

操作集合为 `{P, Q, R, X}`，仅 `{P,Q,R}` 是声明集，`X` 是未声明操作。三态 verdict 仅为 `accepted`、`rejected`、`UNKNOWN`。明确撤销、重复、乱序、缺失、未声明、非法 payload 或未知 kind 均保守为 `UNKNOWN`；`UNKNOWN` 与 `rejected` 互斥。

实现 A 与实现 B 分别独立编写，数据结构、分支组织和查表方式不同，但使用同一合约规则。没有网络访问、真实 Gemini CLI/服务、凭据或生产系统调用。

## 性质测试方法

- **局部性**：对每个实现、每个 fixture、每个事件分别复制输入并显式撤销该事件；before/after 两次 harness 风格运行逐事件比较。只允许目标事件及其同批次事件变化，所有其他 op 的 verdict 必须逐字节相同。
- **不可归属**：对每个实现验证所有 `op_id` 不在声明集的事件为 `UNKNOWN`，并删除未声明事件后再次运行；已知事件 verdict 必须不变。
- **交叉一致性**：24 个 fixture 的完整 verdict map 必须相等；任一不相等即 conflict 并令 validator 失败。
- **保守三态**：验证 verdict 集合、撤销/重复/乱序/缺失路径均不得升级为 `accepted`，也不会把 `UNKNOWN` 当成 `rejected`。
- **复跑**：`harness.py` 连续复跑两次，`outputs/results.json` 字节级相同。

## 可复现命令与真实输出

```text
$ python3 harness.py
fixtures=24 impl_A_impl_B_consistent=24 conflicts=0

$ python3 validator.py
PASS fixture/schema/canonical hashes
PASS cross-implementation consistency
PASS locality under explicit revocation
PASS undeclared op non-attribution
PASS three-state mutual exclusion and conservative anomalies
PASS deterministic harness rerun byte identity
property_assertions=6/6

$ python3 /var/minis/skills/evidence-first-research/scripts/validate_research.py research-manifest.json
PASS: 4 claims; manifest schema is valid (2026-09-22)

$ sha256sum -c SHA256SUMS
(见最终执行记录；所有列入清单文件均 PASS)
```

## 完整性与声明

文件 SHA-256 的权威清单在 `SHA256SUMS`。所有文件均声明 `synthetic_only=true`、`production_verified=false`（代码文件通过项目约定和结果元数据声明；研究元数据直接声明）。

本切片**不证明** durability、远端状态、exactly-once、rollback 或 production readiness；也不构成对真实 Gemini CLI/服务的验证。建议下一切片继续独立性质/边界测试，**不停线**。

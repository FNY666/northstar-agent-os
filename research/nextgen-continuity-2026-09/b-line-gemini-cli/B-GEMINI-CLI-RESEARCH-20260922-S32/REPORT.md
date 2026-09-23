# S32 synthetic-only 多操作交错扩展报告

## 研究边界

本切片只使用本目录内生成的 synthetic fixtures 与确定性 harness；单 worker，按 case id 升序序列化，事件顺序保留。未读取 S27–S31 或任何既有研究产物，未访问网络、真实 Gemini CLI/服务、凭据、shared/P0、事故目录、D10/L12/D14、canonical/staging/140/tri-line/systemd。

操作集合为 `{P,Q,R}`。每个事件均携带 `op_id` 与 `epoch`；证据 token 与 ack 仅在所属操作及声明 epoch 下判定。分类严格为 `accepted`、`rejected`、`UNKNOWN`。

## 覆盖与判定规则

- 22 个 fixtures，覆盖三 op 交错、同 payload/异 payload、证据重复、证据重排、stale ack、事件 epoch 不匹配、未声明 op X 的整组隔离。
- 完整且顺序正确的证据集合加唯一 accepted ack → `accepted`。
- 证据重复、集合/顺序不符 → `rejected`；重复、重排、stale、epoch 不匹配不得升级 accepted。
- 缺失或 epoch 不匹配、stale ack、非终态 ack → `UNKNOWN`；`UNKNOWN` 不等于 `rejected`。
- 未声明 op_id（包括 X）的事件整组 → `UNKNOWN`，不会改变 P/Q/R 判定。
- 一个 op 的 accepted 不为其他 op 补证。

## 实际执行输出

```text
HARNESS PASS: fixtures=22 results=22 workers=1
HARNESS COUNTS: accepted=48 rejected=7 UNKNOWN=14
VALIDATOR PASS: 22 fixtures; tri-state and isolation invariants hold
PASS: 6 claims; manifest schema is valid (2026-09-22)
```

`sha256sum -c SHA256SUMS` 的逐文件结果见交付验证记录；期望为全部 `OK`。

## 结论（仅本地 inferred）

在这组 22 个 synthetic fixtures 与当前 harness 规则下，三操作交错事件可以被确定性地分离判定；重复、重排、stale acknowledgement、epoch 不匹配及未声明 op 均不会静默升级为 accepted，且未知状态不会被折叠成 rejected。

本切片**不证明** durability、远端状态、exactly-once、rollback 或 production readiness；也不代表真实 Gemini CLI/服务行为。该结论仅适用于本目录的 synthetic 输入、规则和单 worker 执行模型。

## 下一切片建议（不停线）

建议下一切片在保持 synthetic-only、离线和单 worker 基线的前提下，扩展“跨 epoch 的多操作并发/交错”边界：为每个 op 增加合法 epoch rollover、epoch 间延迟 ack、缺失 ack 与未知 op 的组合矩阵，并将 expected evidence 集合与事件顺序分别参数化。继续把 UNKNOWN 与 rejected 分离，增加自动化反例断言；不要将结果外推为 durability、exactly-once、rollback 或生产就绪性结论。

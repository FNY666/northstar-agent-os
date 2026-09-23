# S19 多审计链交叉对账与时间线重叠矩阵

## 边界与声明
本切片为**全程本地确定性合成**：`synthetic_only=true`，`production_verified=false`。只读取本切片目录内的 fixtures；不读取 S1–S18 或任何既有研究产物，不访问网络、真实审计/日志服务、SDK、凭据、shared/P0、事故目录、D10/L12/D14、canonical/staging/140/tri-line/systemd。L1/L2/L3 是三条独立的合成链，同一事件由 `event_id` 交叉引用。

本报告不证明真实审计系统、durability、exactly-once、rollback 或 production readiness。`RECOVERED` 仅表示满足本地模型和可访问范围条件；`REJECT` 仅表示可验证的内容矛盾；`UNKNOWN` 是保守阻塞态。三态互斥，UNKNOWN 不因重复、多数、重试或时间戳优先升级。

## 确定性模型
- 事件内容 hash：对 `{"event_id", "payload"}` 按 key 排序、紧凑 JSON、UTF-8 后计算 SHA-256；链内 `seq` 与时间戳不进入事件内容 hash，因此可识别“内容一致但序号错位”。
- 每个结果保存 `chains_checked`、`chains_with_event`、互斥 `status`、理由、`blocking_conditions`、`canonical_input_sha256`。
- 缺少首块锚点 → UNKNOWN；重复块（同链同 hash）只记录为重复，不产生新证据。
- 单链独有事件，无论其他链是否有显式“不应出现”负断言，均 UNKNOWN；负断言不可证。
- 同事件不同内容 hash → REJECT；同内容但序号错位 → UNKNOWN，需外部裁决。
- 时间线重叠且归属不清 → UNKNOWN，不以某链时间戳较早判优先。
- 链不可访问时，仅在可访问链范围判定，并将不可访问链保留在阻塞条件中；不可访问链不被假定为空。

## 结果
共 24 个确定性 fixtures：`RECOVERED=6`、`UNKNOWN=15`、`REJECT=3`。完整逐案结果见 `outputs/results.json`。

覆盖的关键场景包括：两链/三链一致、单链独有（无负断言和有显式负断言）、内容矛盾、序号错位、时间区间重叠、部分链不可访问、锚点缺失、同链重复块、不可访问链冲突、事件全缺失和非重叠时间段。`F01–F24` 均含 L1/L2/L3 链清单；每链保留事件 id，支持链间交叉引用。

## 可复现与校验
在目录内执行：

```sh
python3 harness.py
python3 harness.py
cmp outputs/results.json /tmp/results.first.json
python3 validator.py
python3 manifest_validator.py
python3 /var/minis/skills/evidence-first-research/scripts/validate_research.py research-manifest.json
sha256sum -c SHA256SUMS
```

本次 harness 两次运行输出字节一致；结果文件 SHA-256 以最终 `SHA256SUMS` 为准。

## 解释与后续
该矩阵用于检验保守判定边界，不提供真实系统外推。建议下一独立切片继续验证新的独立性质；本切片完成后不停止生产/业务线（本地合成任务本身不构成停线依据）。

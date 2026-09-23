# C 线信任连续性 S57：跨切片账本一致性、状态迁移与 canonical 收敛

## 结论（离线合成、推断）

新切片的 entry、状态迁移、版本和 digest 变化不能脱离前一版本和 canonical winner 单独采信。只有 slice/version/previous digest/new digest/migration reason 完整、重复与冲突 entry 已处理、canonical winner 和 derived archive 明确、raw 保留、manifest 重算、跨切片引用、status transition、question/claim revision/source set、文件系统 read-back 与最终 convergence 全部闭合时，才可判 `RECOVERED`。跨身份合并或同一切片不可调和的 canonical 版本冲突判 `REJECT`；版本回退、迁移理由/前后 digest、重复/冲突检测、manifest、引用、文件状态或 convergence 未知保持 `UNKNOWN`。

本片仅使用本地 synthetic fixtures 与确定性 harness；`synthetic_only=true`、`production_verified=false`、所有 claims `inferred`、`sources=[]`。未访问网络、真实服务、生产数据或凭据，未读取或修改 S1-S56 产物。

## 判定门

1. `identity_conflict` 或 `ledger_conflict` 任一为真，输出 `REJECT`。
2. slice/version/transition/digest/reason、duplicate/conflict、canonical/derived/raw、manifest/cross-reference/status/claim/source/filesystem/convergence 任一门未闭合，或 migration state unknown，输出 `UNKNOWN`。
3. 只有前后版本、迁移原因、canonical winner、历史保留和最终收敛全部闭合，才输出 `RECOVERED`。
4. 新摘要、状态页、迁移消息或目录存在本身不能证明前后内容关系、合法状态迁移或最终 canonical 收敛；必须重算并独立 read-back。
5. `RECOVERED` 仅表示本片夹具中的 cross-slice migration evidence gate 闭合，不代表生产账本、external effect、exactly-once 或业务提交。

## 覆盖与确定性验证

- 28 个定向 cases：slice/version/digest迁移、重复/冲突entry、canonical winner、derived/raw、manifest、跨切片引用、status/question/claim/source迁移、文件系统读回与convergence，以及各边界缺口、身份冲突和迁移冲突。
- 23 个布尔门执行完整 `2^23 = 8,388,608` 组合，使用位掩码流式计数，输出三态计数和 single-gate minimizer。
- 结果写入 `outputs/results.json`；`validator.py` 检查定向 cases、状态互斥和完整 property sweep。

## 证据限制

- 这是离线合成规则测试，不是生产研究账本迁移、知识库版本、归档、manifest 或 canonical merge 系统的验证。
- 未证明真实系统的版本迁移、状态机、重复/冲突合并、raw保留、derived归档、跨文档引用、文件系统收敛或冲突回退语义。
- 所有布尔门代表“证据是否已获得”，不模拟真实文件变更、并行迁移或归档损坏；生产接入必须重算前后 digest、核对manifest/canonical/derived，并在不确定时保持 UNKNOWN。
- `RECOVERED` 仅表示本片夹具中的 evidence gate 闭合，不代表 external effect、exactly-once、生产连续性或业务提交。

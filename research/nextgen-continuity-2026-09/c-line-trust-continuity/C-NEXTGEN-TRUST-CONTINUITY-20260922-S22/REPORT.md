# S22 — 增量 DAG 确定性重放与证据完整性门禁

## 结论边界
本切片是**仅离线合成**实验（`synthetic_only=true`），不是生产验证（`production_verified=false`）。在版本化快照边界内，harness 对完整性、版本、序列、DAG 父引用、边界和三类证据通道执行 fail-closed 门禁：只有全部必要条件满足才输出 `RECOVERED`；无法闭合证据输出 `UNKNOWN`；明确矛盾、冲突、版本漂移或越界输出 `REJECT`。

不能由本实验证明生产耐久性、exactly-once、回滚、外部效果或 production readiness；也不能把平台回执或日志存在当作外部效果确认。

## 方法
- 固定 JSON fixture，规范化 JSON 后计算 SHA-256；结果排序、序列化格式固定。
- snapshot 检查完整快照、缺页、缺分片、版本、保留期和边界。
- incremental 检查重复/冲突、乱序（按序列归一化但不填补缺口）、断点恢复、DAG parent gap、边界外事件和明确矛盾。
- 独立区分：`platform_receipts`（平台回执）、`logs`（日志存在）、`external_effects`（外部效果确认）。三者缺一均不恢复。
- 分类维度覆盖：`NO_EVENT`、`DELAYED`、`DROPPED`、`EXPORTER_FAILURE`、`QUERY_GAP`、`RETENTION_EXPIRED`、`VERIFIED_CONTINUITY`、`UNKNOWN`。

## 合成覆盖
共 24 个 cases：完整快照、缺页、缺分片、版本漂移、重复与乱序增量、重复冲突、断点缺口、前后边界越界、明确矛盾、平台回执/日志/效果各自单独存在、延迟、丢弃、导出器失败、保留期过期、查询缺口、未知分类、DAG parent 缺失、边界锚点、断点不匹配、快照冲突、增量冲突。

状态分布：`RECOVERED=3`，`UNKNOWN=14`，`REJECT=7`。所有状态均为严格枚举，默认 fail-closed。

## 可复现验证
运行：
1. `python3 harness.py`（两次运行并比较 `outputs/results.json` 字节）
2. `python3 validator.py`
3. `python3 manifest_validator.py`
4. 官方离线 `validate_research.py research-manifest.json`
5. `sha256sum -c SHA256SUMS`
6. 刷新最终 `SHA256SUMS` 后再次执行第 5 步

## 证据与声明
无外部来源；`sources.md` 仅记录本地合成证据文件。manifest 的全部 claims 均为 `status=inferred` 且 `sources=[]`。本报告不外推到任何真实平台、服务、SDK、凭据或线上效果。

## 下一切片建议
S23：在不接触生产的前提下，扩展“多快照交叠边界 + 恢复重试”的合成矩阵，加入显式 epoch/fence token、导出器重启窗口和可审计拒绝原因；保持相同三态 fail-closed 语义，并继续禁止把日志存在解释为外部效果。

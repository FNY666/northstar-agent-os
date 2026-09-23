# S19 查询完整性与证据窗口

访问日期：2026-09-22。仅使用官方公开资料。

## 结论

**verified**：AWS CloudTrail LookupEvents、GitHub Actions workflow-run API、Kubernetes list/watch API、Temporal Visibility 都是查询/索引接口，不是全局完整性证明。分页、时间过滤、权限、保留期、异步索引和查询错误必须作为窗口元数据记录。

**inferred**：证据窗口应至少包含 `window_start/end`、`observed_at`、`source_system`、`query`、`page_cursor`、`ordering_key`、`retention_boundary`、`query_complete`、`error`、`event_ids`、`raw_digest`。只有在所有分页完成、窗口未越过保留边界、无错误且独立后置检查通过时，才可判 `VERIFIED_CONTINUITY`。

**unknown**：无结果不区分 NO_EVENT 与 QUERY_GAP；接口成功不证明下游导出或外部副作用；索引可见不证明事件未被采样、过滤或延迟。

## 确定性验收向量

1. 空窗口、权威查询完成、边界内：`NO_EVENT`。
2. 查询返回 continuation cursor：未消费完前 `UNKNOWN`；消费完且无错误才可继续。
3. Kubernetes watch 收到 410/resourceVersion 过期：`QUERY_GAP`，必须从新 list 建立新窗口，禁止拼接为连续。
4. CloudTrail/Temporal/GitHub 查询超时或权限拒绝：`QUERY_GAP`/`UNKNOWN`，不得当 NO_EVENT。
5. 事件时间在窗口内但 observed_at 超过迟到阈值：`DELAYED`，不能覆盖缺口。
6. 保留期前的窗口：`RETENTION_EXPIRED`，不能回填为 NO_EVENT。
7. 分页结果 event_id 去重后出现冲突 payload：`UNKNOWN`，进入对账。
8. 完整查询 + 原始摘要稳定 + 独立 postcondition：才是 `VERIFIED_CONTINUITY`。

## 不能证明

这些接口不能单独证明生产部署无损、所有事件都产生、外部动作已提交、日志没有被配置过滤，或查询成功等于连续性成功。

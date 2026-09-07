# P3-4 可观测进阶 — 完成记录（中文评估）

> 批次：P3-4（路线图 `docs/dx-benchmark-2026.zh-CN.md` 第 254 行）
> 日期：2026-09-07 · 版本：仍为对齐 `0.1.0.dev0`，**未发布**（守就绪门）
> 全仓测试：**812 全绿**（sidecar 51 / run-contract 41 / host 37 / durable-run 65 / interop 54 / runtime 536（skip 4）/ 仓库文档 28）

## TL;DR

P3-4 把"run 之后怎么看"补成了两条完整路径，全部是**模板与文档，不碰产品代码**：

1. **实时面（span 树 → Jaeger/Grafana）**：`examples/observability/` = docker compose
   （Jaeger all-in-one 收 OTLP/HTTP + Grafana 预置 core Jaeger 数据源）+ `otel_bootstrap.py`
   （给 CLI 接上真实 `TracerProvider` 的接线样板）。
2. **离线面（transcript/audit → 人读）**：`examples/session-panel/session-panel.html` =
   单文件纯本地 HTML 查看器（拖放 `*.jsonl` 或 `audit.ndjson/1` 导出，统计 + 时间线 +
   指纹，零网络零后端）。

加上 P3-1a 已存在的 `sessions list/show/export`，路线图 P3-4 行**完成**。

## 为什么需要一个 bootstrap（这次最大的诚实点）

仓库事实（逐条对代码核实过）：`tracing.py` 把每个 span 镜像到进程的
**ambient tracer**（`_default_otel_tracer` → `trace.get_tracer(service_name)`），
但 runtime **从不安装 provider/exporter**——裸跑 `python3 -m cli run` 无论装了什么
都不导出，`--trace` 只是打印树。这本来是设计（exporter 是宿主侧选择，runtime 保持
零依赖），但意味着"装个 extra 就能看到 Jaeger"是**不成立的**。文档把这条缝讲成
特性：`otel_bootstrap.py` 就是"缝上的样板"，先 `set_tracer_provider` 再交棒
`cli.main`；compose 里 Jaeger 直接收 OTLP/HTTP（`:4318`），**不插 collector**——
collector 属于部署设施，是 T5 的事，不是本地开发默认。

配套的"诚实标记"也被测试钉死：README 必须声明"CI 从不跑 Docker""镜像 tag 是落笔时
钉的样本""exporter 包不在 tracing extra 里""内存存储、down 即丢历史"。

## 交付清单

| 资产 | 内容 | 验证 |
|---|---|---|
| `docs/concepts/observability.md` | 双平面概念页：span 词汇表（真实属性名全来自 loop.py，如 `session.id`/`usage.input_tokens`/`cost.usd`/`tool.denied`）、ambient seam、transcript/audit 离线面、选型表、范围声明 | docbuild 链接检查 |
| `examples/observability/docker-compose.yml` | 本地双服务栈：`jaegertracing/all-in-one`（16686 UI + 4318 OTLP/HTTP）+ `grafana/grafana`（3000，预置数据源） | 静态测试：仅两服务、端口映射与 bootstrap 默认端点一致 |
| `examples/observability/otel_bootstrap.py` | CLI 的 provider 接线样板：`OTLPSpanExporter` + `BatchSpanProcessor`，端点可用 `OTEL_EXPORTER_OTLP_ENDPOINT` 覆盖，checkout/site-packages 双路径，缺依赖给指引退出码 3 而非 traceback | `py_compile` + 源码 marker 断言 |
| `examples/observability/grafana/provisioning/…/jaeger.yml` | core Jaeger 数据源预置（`type: jaeger`，无需装插件） | 静态断言 |
| `examples/session-panel/session-panel.html` | 单文件零外联查看器：拖放即读，统计（类型计数/会话/成本/拒绝数）、errors-only 过滤、逐条展开原始 JSON、FNV-1a64 本地指纹（诚实标注非密码学哈希） | 零网络引用断言 + 11 种记录类型全覆盖 + `node --check` 语法校验（有 node 时） |
| `examples/session-panel/sample-session.jsonl` | 真实离线运行 transcript（含 Write 被拒的 denial 路径）；唯一改动＝`session_start` 里绝对 workspace 路径掩蔽为 `<repo>/…`，README 已注明 | 逐行 JSON 校验 + 无 `/home/` 绝对路径 |
| `docs/dx-observability.zh-CN.md` | 本页 | — |

`tests/test_observability_examples.py` 新增 16 项；示例索引两行（observability、
session-panel）；docbuild 检查的 md 文件 48→50。

## 验证边界（写进文档的实话）

- 沙箱与 CI **都没有 Docker**：compose 只做静态校验，从未 `up` 过——README 与测试
  都明说"tag 需在 Docker Hub 复核、CI 不跑 Docker"。
- 仓库未装 opentelemetry 包：bootstrap 的导入路径只能在装了 extra 的机器上真跑；
  因此测试只做语法编译与 marker 断言，运行验证留给照着 README 操作的人。
- 面板 JS 无浏览器执行环境：有 node 时做 `--check`，无 node 跳过——两条路都绿。
- **不改任何组件行为**：runtime/interop 等 6 组件测试零改动、536 项原样全绿。

## 下一步（T5 的入口）

P3-3 评估留下的 ops 缺口与 P3-4 的边界在此汇合：compose 是"本地开发栈"，
T5 的 deployment/monitoring 指南可直接在此之上长出来（collector 拓扑、持久存储、
Grafana 仪表盘、告警）；传输、身份、canary 三项缺口不变。另：`sessions export` +
面板的"回放/恢复"读法，是 T3 checkpoint/restore 的最小交互雏形。

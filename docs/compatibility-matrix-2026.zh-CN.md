# Northstar 组件兼容性矩阵（2026-09）

这是当前本地/实验性主线的契约矩阵，不代表已经发布到 PyPI/npm，也不代表远程或 hosted execution 已就绪。

## 版本与安装

| 组件 | 包版本 | 入口 | 关键边界 |
|---|---|---|---|
| `northstar-run-contract` | `0.1.0.dev0` | Python modules | canonical Run/Binding/Receipt contract |
| `northstar-host` | `0.1.0.dev0` | Python modules | host-owned authorization/workspace |
| `northstar-durable-run` | `0.1.0.dev0` | `northstar-durable-run` → `durable_cli:main` | local durable event/control slice |
| `northstar-agent-interop` | `0.1.0.dev0` | Python modules | local interop/canary/evidence helpers |
| `northstar-agent-runtime` | `0.1.0.dev0` | `northstar-agent-runtime` → `cli:main` | governed offline runtime/app-server |

所有五个可安装组件必须共享同一版本。`0.1.0.dev0` 是未发行开发版本；去掉 `.dev0` 不是自动动作，必须经过 release readiness gate。

## App-server cross-runtime contract

| 项目 | Python | Node | 约束 |
|---|---|---|---|
| wire protocol | `northstar.agent-app.v1` | `northstar.agent-app.v1` | 必须一致 |
| capability schema | `northstar.agent-app.capabilities.v1` | `northstar.agent-app.capabilities.v1` | 必须一致 |
| transport | private Unix socket | private Unix socket | local-only |
| authentication | HMAC-SHA256 | HMAC-SHA256 | request/response 都认证 |
| cancellation | cooperative | cooperative | 不 force-kill provider/tool |
| registry | `in_memory` | discovered | 不宣称 durable registry |
| remote execution | `false` | validated as `false` | 不宣称 hosted worker |

`app.describe` 是唯一的 capability negotiation 入口。Python/Node consumer 会校验 schema、limits、operation list、response operation binding 和禁止字段。

## 验证命令

```sh
make compatibility
make test
python3 tests/docbuild.py verify
```

`make compatibility` 是纯标准库静态检查：不导入 provider、不访问网络、不需要 API key。它检查版本、entry point、Python/Node protocol/schema 对齐，以及 durable-run API manifest 是否跟随 `durable_cli.py`。

## 当前不承诺

- 没有公共 PyPI/npm 发布或正式 release tag；
- 没有 scheduler、fleet worker、hosted execution 或 remote exactly-once；
- app-server manager 仍为 bounded in-memory registry；
- 真实 SSH/remote canary 仍需 operator 在真实环境执行；
- Node 文件是 dependency-free consumer example，不是正式 npm SDK。

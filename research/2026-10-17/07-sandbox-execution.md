# 隔离执行与开发环境方案研究：E2B、Daytona、Modal、Dagger

**研究日期：2026-10-17**
**范围：**公开、可核验的一手官方文档与官方仓库。社区页面只作为发现线索，本报告没有用私有、邀请制或需登录的群聊/论坛，也没有把营销页的数字当作能力证明。

## 覆盖对象与判定口径

覆盖 E2B（云端隔离 Linux 沙箱）、Daytona（可配置沙箱与开发环境）、Modal（运行时 Sandbox 与快照）以及 Dagger（容器化、可移植的执行 DAG）。这里的“已发布”指官方公开文档/仓库明确描述并提供 API；“实验性”指官方文档明确标注 alpha/experimental；“营销主张”只作为厂商自述，不当作独立验证。

Northstar M0/M1 的比较基线是：真实仓库任务闭环；权限门和预算；审计轨迹；隔离 worktree；可恢复执行；证据包；默认不做无边界自动化。以下结论是能力互补研究，不是把任何供应商当作 Northstar 的控制平面。

## 经核验的机制

### E2B

- E2B 的公开 SDK 支持创建、连接、暂停、恢复和 kill；超时可以自动 pause 以保留完整状态，也可以配置为 kill。官方文档同时给出了运行时读取 sandbox ID、模板、开始/结束时间、状态、资源和生命周期信息的接口。[1]
- E2B 安全页声称每个 sandbox 使用一个 Firecracker microVM、独立内核，并且不与其他客户共享内核、文件系统或内存；这属于厂商安全声明，不能替代 Northstar 自己的部署验证或审计证据。[2]
- 官方文档将 Pro/Hobby 的单次连续运行上限写为 24 小时/1 小时，并建议长任务用 pause/resume；这说明恢复语义是产品机制，但不是“任务永不丢失”的保证。[1]
- 官方仓库确认其开源 SDK/基础设施定位为在云端隔离 sandbox 中运行 AI 生成代码，并提供 self-hosting 的 runtime/Embed 路径；仓库中的 API key 步骤表明云服务接入仍需要账户凭据。[3]

**对 Northstar 的启示：**生命周期状态、显式 timeout、可查询的运行元数据和 pause/resume 是 M0 可借鉴的最小状态机；但 E2B 页面没有证明权限门、预算预授权、worktree 语义或证据包完整性，因此不能把“沙箱隔离”当成一次任务闭环。

### Daytona

- Daytona 官方文档定义了较细的状态机：creating、started、stopped、paused、archived、restoring、snapshotting、forking、error 等，并给出状态转换触发条件。[4]
- 自动生命周期包括 auto-stop、auto-pause、auto-archive、auto-delete 和 wall-clock TTL。尤其值得注意的是：auto-stop 即使 sandbox 内部还有进程也会触发；后台脚本、长任务和没有外部监控的进程不算 activity。[4] 这对可恢复 Agent 是真实的失败模式，而不是实现细节。
- Daytona 把隔离分成 runtime、network、organization 三个边界；官方文档描述每个 sandbox 的进程、文件系统、内存、设备和资源硬限制，以及按 sandbox 的出站网络 block/allow-list、组织级 API key 权限和 secrets。[5]
- 容器与 VM 的能力不同：VM 支持 pause/resume、fork、hot snapshots；容器不能 fork，需先做 filesystem snapshot。[4][5] 这些是已公开能力，不应在 Northstar 抽象层里假设所有后端拥有相同恢复语义。

**对 Northstar 的启示：**Daytona 最适合借鉴“可见状态机 + 明确的超时/回收策略 + 网络策略作为一等配置”。但 auto-stop 不理解内部任务是 M0/M1 必须规避的坑：Northstar 应让控制器以 lease/heartbeat/阶段检查点维持任务，而不能用“有进程运行”推断安全可回收。

### Modal

- Modal 官方 Sandbox 是运行时创建的、用于不可信或 Agent 代码的隔离容器；文档明确支持 checkout 仓库、运行测试/CI、多容器环境、任意依赖和 setup 脚本。[6]
- 公开生命周期包括最大默认 5 分钟、可提高至 24 小时、idle timeout、readiness probe、终止和 Unix-style return code；finished 状态可能来自自然退出、显式终止、超时或 OOM。[6] readiness probe 与 return code 对 M0 的“可判定任务完成/失败”很有价值。
- Modal 文档区分 gVisor 容器和 VM runtime；VM 用于 Docker-in-Docker、FUSE、嵌套 cgroup 等需要完整 Linux 内核的工作负载。[6] 这是已发布的运行时选项，但不是所有隔离配置的等价安全证明。
- Filesystem Snapshot、Directory Snapshot 已公开，默认保留 30 天；可配置 TTL 或不设过期，并可从同一 snapshot 启动多个 sandbox。Volume 不包含在 filesystem snapshot 中。[7]
- Memory Snapshot 在文档中明确标为 experimental/alpha，并有 7 天过期、不能 GPU、TCP 连接关闭、快照会终止原 sandbox、运行中 exec 不能快照等限制。[7]

**对 Northstar 的启示：**Modal 的 readiness/return code/快照 TTL 组合可直接映射到 M0 的阶段闭环和证据元数据。不能复制“用 snapshot ID 就等于可恢复任务”：快照有 TTL，目录/volume 覆盖范围不同，memory snapshot 仍是实验性能力，恢复前必须验证 artifact、版本和策略兼容性。

### Dagger

- Dagger 官方仓库将其定义为自动化软件交付的平台，可本地、CI 或云端运行；Apache-2.0 开源。[8]
- 官方 README 公开的机制包括：容器、文件系统、secrets、git、网络 tunnel 的 typed/composable API；以输入为键的增量执行；content-addressed cache；OpenTelemetry span、日志与指标。[8]
- 官方文档把 pipeline 描述为 portable DAG execution engine：逻辑与环境解耦，可本地运行或让云扩展，并自动缓存、端到端 tracing。[9]

**对 Northstar 的启示：**Dagger 不是 sandbox control plane，而是很好的“任务步骤层”：把 install/test/build/check 组成可复现 DAG，为每步生成输入、缓存命中和 trace 证据。它没有替代 Northstar 的授权决策、预算扣款、worktree ownership、人工确认或最终证据包签名；不应因“可观察”就推断有合规审计。

## 与 Northstar M0/M1 的差距或互补

| Northstar 关注点 | 可借鉴机制 | 明确差距/风险 |
|---|---|---|
| 真实仓库任务闭环 | E2B/Modal 的命令执行、readiness、return code；Dagger 的 typed DAG | 供应商 API 通常只负责执行，不负责“计划—授权—修改 worktree—验证—打包证据”的全闭环 |
| 权限门 | Daytona 的组织隔离、scoped API keys、网络 allow-list | 未发现这些方案公开证明了 Northstar 所需的按动作/按文件/按预算的人工或策略门 |
| 预算 | timeout、idle timeout、auto-stop、TTL | 时间/资源回收不等于货币预算；尤其 Daytona auto-stop 可能杀掉仍在工作的长任务 |
| 审计 | Dagger 每步 OTel trace；Modal return code/readiness；E2B/Daytona 状态与元数据 | trace、日志和状态仍需由 Northstar 绑定 run ID、策略决策、操作者、输入哈希和 artifact 哈希，才能成为可复核审计 |
| 隔离 worktree | 通过 sandbox/容器承载 checkout；Dagger git/filesystem 类型 | 没有被核验的方案把 Git worktree ownership、基线 commit、冲突解决和 merge gate 作为产品核心语义 |
| 可恢复执行 | E2B pause/resume、Daytona paused/restoring/forking、Modal filesystem/directory snapshot | 快照有 TTL、覆盖边界和运行时限制；必须保存外部 manifest 和兼容性检查，不能只保存 provider ID |
| 证据包 | Dagger content-addressed 输入与 OTel；Modal 返回码；各家状态 API | 未核验到供应商直接产出 Northstar 所需的证据包（diff、测试、权限决定、成本、恢复链和签名） |

## 三类结论

### 可采纳（按 M0/M1 可行性排序）

1. **定义后端无关的执行状态机。** 最小状态至少包括 planned、authorized、provisioning、running、checkpointing、verifying、succeeded、failed、expired、recovery-required、destroyed；借鉴 Daytona 的显式转换，但由 Northstar 控制器决定何时可回收。[4]
2. **把预算与生命周期分开建模。** 供应商 timeout/TTL 只作为硬上限；Northstar 另建估算、预授权、实际用量、超支原因和停止决定，避免把“容器被杀”误记为业务成功。[1][4][6]
3. **M0 采用 filesystem/directory checkpoint + 外部 manifest。** Manifest 绑定 run、基线 commit、worktree、策略版本、snapshot/artifact ID、TTL、输入/输出哈希和恢复次数；借鉴 Modal 的 TTL 与覆盖范围提示。[7]
4. **将每个执行步骤做成可观察、可判定的单元。** readiness probe、return code、阶段日志和 OTel span 可作为实现材料，但必须由 Northstar 统一 run ID 和 evidence pack 索引。[6][8]
5. **网络默认拒绝，按任务授予 allow-list。** Daytona 的 block-all、CIDR/domain allow-list 和组织/密钥边界提供了可借鉴的后端适配项。[5]

### 应拒绝复制

- **拒绝把“隔离环境”当作权限模型。** microVM、VM 或 gVisor 解决的是运行边界，不决定 Agent 是否可以写哪个文件、调用哪个工具或花多少钱。[2][6]
- **拒绝用后台进程存在作为存活证明。** Daytona 明确说明后台脚本和无外部互动的长任务不重置 auto-stop；Northstar 必须使用受控 lease、heartbeat 和检查点。[4]
- **拒绝默认无限保留快照或把 provider ID 当证据。** Modal 默认 TTL 会变化，删除不可恢复，且不同快照类型覆盖不同状态。[7]
- **拒绝无边界自动化。** Dagger 的可组合 DAG 和云扩展能力不应绕过 Northstar 的授权门、人工确认或 merge gate。[8][9]

### 待证

- 各后端在 Northstar 所需的真实仓库场景下，网络阻断、凭据注入、磁盘/内存上限、OOM、恢复和销毁是否能产生稳定、可导出的证据；需要在公开许可的测试账户或自托管环境做最小对照实验，不能以营销页替代。
- “隔离”在不同运行时、区域和部署形态下的实际边界，尤其是 Daytona 容器 vs VM、Modal gVisor vs VM、E2B managed vs BYOC；安全页/文档的厂商声明应标记为 claim，不能直接升级为 Northstar assurance。
- Dagger cache 命中和可复现性在含私有依赖、时间/网络非确定性和失败重试的仓库任务中是否足以支撑证据包；需用固定 fixture 验证 cache key、secret 不泄漏和 trace 与 run ID 的绑定。

## 结论

对 Northstar M0/M1，最有价值的组合不是选一个“万能沙箱”，而是：**Northstar 保持策略、预算、worktree、恢复编排和证据包的控制权；后端适配器吸收 E2B/Daytona/Modal 的隔离与生命周期能力；步骤执行层可选择 Dagger 的 typed DAG、缓存和 tracing。** 这样既能利用已发布机制，也不会把供应商的隔离或营销主张误当成 Northstar 的治理保证。

## References

[1]: https://docs.e2b.dev/sandbox "E2B Sandbox lifecycle"
[2]: https://e2b.dev/security "E2B Security and compliance"
[3]: https://github.com/e2b-dev/e2b "E2B official open-source repository"
[4]: https://www.daytona.io/docs/en/sandboxes/ "Daytona Sandboxes and automated lifecycle management"
[5]: https://www.daytona.io/docs/en/isolation/ "Daytona Isolation"
[6]: https://modal.com/docs/guide/sandboxes "Modal Sandboxes"
[7]: https://modal.com/docs/guide/sandbox-snapshots "Modal Sandbox Snapshots"
[8]: https://github.com/dagger/dagger "Dagger official repository"
[9]: https://docs.dagger.io/ "Dagger official documentation: Introduction"

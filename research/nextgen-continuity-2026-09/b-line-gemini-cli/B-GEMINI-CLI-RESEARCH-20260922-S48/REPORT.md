# B-S48-OFFICIAL — Gemini CLI 企业控制、安全报告入口与发布回滚边界

- 访问日期：2026-09-22
- 来源：Google Gemini CLI 官方 GitHub 仓库固定快照 `d5b3e3accb26000d273abf16e0f1dd83aa5428a9`；只读。

## 结论

1. **verified**：官方安全文件将漏洞报告导向 Google g.co/vulnz，并给出安全响应入口；这证明报告渠道，不证明某一问题已修复或任何运行实例安全。
2. **verified**：企业控制文档区分 admin controls 与普通 system settings，并提供 strict mode、extensions、MCP enabled/disabled、MCP server allowlist/required server 等治理面；部分 required MCP server 可配置为不需逐次用户 approval，且文档明确提醒必须信任其工具。
3. **verified**：官方 release verification workflow 使用显式版本输入、最小化 GitHub permissions 配置和受保护 secrets 执行 verify-release action；workflow 定义不等于每次发布实际成功或制品安全。
4. **verified**：官方 rollback workflow 以显式 origin/destination/tag 输入操作 npm dist-tags/GitHub release，并保留 rollback tag/失败路径；这是发布元数据回滚流程，不等于运行时数据库、远端副作用或客户端状态回滚。
5. **inferred**：治理配置应和运行回执、目标 read-back、发布制品身份/摘要分离；“允许/required/verify/rollback workflow 完成”不能单独升级为业务效果已提交。
6. **unknown**：文档未证明 exactly-once、发布后全量用户升级、回滚原子性、缓存/镜像收敛、运行中任务处理、完整审计保留或生产副作用回退。

## 不能证明边界

- security report channel ≠ vulnerability remediation proof；
- admin policy ≠ every local configuration obeyed in every process；
- release verification ≠ artifact provenance/completeness or production rollout；
- npm/GitHub release rollback ≠ runtime state rollback。

## 研究限制

未访问生产、未执行发布/回滚、未使用凭据、未修改仓库或系统，未触碰 shared/P0、事故目录、D10/L12/D14、canonical、140、tri-line、systemd、真实服务。

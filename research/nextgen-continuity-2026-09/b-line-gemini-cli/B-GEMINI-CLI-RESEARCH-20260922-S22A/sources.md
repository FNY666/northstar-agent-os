# Sources — S22-A

synthetic_only=true
production_verified=false

本研究为完全离线 synthetic-only harness 研究，不使用外部事实来源。以下为可审计的本地来源与其限制：

- `harness.py` — 本地确定性规则执行器；来源类型：primary（本切片模型）；支持：事件排序、matching intent、同 attempt 冲突拒绝、UNKNOWN 保持；限制：不是 Gemini CLI 或生产实现。
- `fixtures/cases.json` — 10 个人工编写且确定性的 synthetic fixture；来源类型：primary（测试输入）；支持：覆盖无 intent、顺序反转、同值一致、冲突、crash/restart/resume、跨 attempt；限制：非真实流量，非状态空间穷举。
- `outputs/results.json` — harness 运行产物；来源类型：primary（执行输出）；支持：10/10 PASS、accepted=25、rejected=6、UNKNOWN=10；限制：仅本地模型观察。
- `REPORT.md` — 对范围、结果与证据状态的解释；来源类型：primary（研究记录）；限制：不构成生产验证。
- `validate_research.py`（路径：`/var/minis/skills/evidence-first-research/scripts/validate_research.py`）— 离线 manifest schema validator；来源类型：authoritative_independent（工具校验器）；支持：manifest 字段、状态、来源 URL schema 校验；限制：不验证模型正确性。

没有网络来源、真实服务、真实 CLI、凭据、远端状态或旧研究目录被读取。因 validator 的 source schema 要求每条来源带 URL，manifest 中使用 `https://example.invalid/...` 作为不可访问的占位引用；这些不是事实证据，也未被网络访问。所有结论必须按 REPORT.md 中的 confirmed/inferred/unverified/conflicting/inaccessible 限定理解。

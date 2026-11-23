# 本地编程规则攻防包

本包只包含静态原创 toy fixture；所有危险函数只被原生 scanner 读取，不被导入或调用。实验室没有外部目标、可选攻击命令或真实凭据。

| 编程风险 | 固定规则 ID | 受信风险 |
|---|---|---|
| Python eval/exec | northstar.python.eval-exec | high |
| Python subprocess shell=True | northstar.python.subprocess-shell-true | high |
| Python unsafe YAML load | northstar.python.yaml-unsafe-load | high |
| Python requests verify=False | northstar.python.requests-tls-verify-false | medium |
| JavaScript child_process.exec | northstar.javascript.child-process-exec | high |

五类均有危险/正常文件配对。规则自身 severity=ERROR 用于 scanner 发现与 --error 返回码，**Northstar 风险由受信 severity-map.json 决定**，不能从 raw INFO、候选 metadata 或行内注释降级。

`osv.toml` 为空、无 IgnoredVulns/PackageOverrides；实际执行器显式传入受信配置。危险依赖 fixture 是 `requests==2.19.1`。原对照 `requests==2.32.4` 在本轮真正离线 snapshot 下命中 PYSEC-2026-2275 与 GHSA-gc5v-m9x4-r6x2，因此已替换为本次 snapshot 实测无 advisory 的 `wheel==0.46.3`。这是一份直接依赖视图的正常对照，**不是同一 Requests 包的升级修复证明**，也不是未来无漏洞、发行物存在性或完整传递依赖证明。

## 结构与真实验证分层

`python3 -m pytest -q security/native_tests/test_rule_pack.py` 只校验本地 YAML/TOML/JSON 与 fixture 文本，不运行危险代码。

`examples/run_native_smoke.py` 则从自建 repo 的真正 Git commit/tree 原始字节导出输入，运行固定 Semgrep 1.181.0 与 OSV 2.7.0。实际结果：正常五文件 0 finding + 正常依赖 0 advisory → pass；危险五文件 5 findings（含 # nosem 抑制尝试）+ 漏洞依赖 10 advisory → block。均有完整输入覆盖，无跳过、解析错误或输出截断。

不要使用已弃用的 `python -m semgrep`。实际 bwrap native ELF 入口、局部动态库路径、`--error`、禁网/禁版本检查与 OSV 本地 cache 适配详见 `native-runner.md`。这些 CLI 和上游 JSON 差异必须用真实固定二进制确认，不能仅靠结构单测或通用 CLI 文档。

## 来源

- Semgrep CLI：<https://docs.semgrep.dev/cli-reference>
- Semgrep 1.181.0：<https://github.com/semgrep/semgrep/releases/tag/v1.181.0>
- OSV 显式配置：<https://google.github.io/osv-scanner/configuration/>
- 本轮 snapshot 源：<https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip>；Last-Modified 为 2026-10-16T20:18:01Z，ZIP SHA-256 为 `1c044b28c5dc3ed5af110d37586de9a77d12796885d35ad45b134bde719ec206`。此 hash 是实际字节 pin，不是作者签名。

# Semgrep 1.181.0 输出归一化

`semgrep_normalizer.py` 只处理固定的 `semgrep scan --json` 原始 bytes。它不启动扫描器、候选程序或网络请求。调用方必须先从已经验签的 scan-plan 取得 `template`，再把同一次受监督运行的 `execution`、`isolation`、冻结的 `input_bytes` 和受信 `severity_map` 传入。

官方 **v1.181.0** 标签中的 JSON Schema 将顶层 `results`、`errors` 和 `paths` 列为必需字段；`version` 从 0.92 起定义，`skipped_rules` 自 1.37 起定义。每个 `results` 项的必要字段是 `check_id`、`path`、`start`、`end` 和 `extra`；`extra` 必须给出 `message`、`metadata`、`severity`、`fingerprint`、`lines`。[1] 本实现还要求原始 `version` 和已签名模板的版本都精确为 `1.181.0`，并要求本固定 runner 产出的 `skipped_rules` 显式为空数组。Semgrep 官方在 2026-10-14 发布了此版本。[2]

## 绑定和覆盖

归一化的首步是调用 `validated_inputs(template, "semgrep", input_bytes)`。这样，传入映射的键集合、每个相对路径和每个 byte 的 SHA-256 都必须与 `template.tools.semgrep.expected_inputs` 相等。随后 `paths.scanned` 中的路径仅允许是这些输入；`/input/` 前缀会按共享合同转换为相对路径。遗漏、额外路径、重复路径、`..` 或绝对路径逃逸都抛出 `EvidenceError`。`paths.skipped`（如存在）必须为空。

非空 `errors` 或 `skipped_rules` 一律失败关闭。标准文档说明 `paths.scanned` 是 JSON 中扫描路径的来源，而 verbose 输出会把跳过路径放入 `paths.skipped`。[3] 因此 normalizer 绝不把跳过、未解析或错误转换为貌似完整的 coverage。成功时仅生成 `status: complete`，每一项 `observed_inputs` 的摘要重新取自已经验证的实际 `input_bytes`。

## Findings、严重度和退出码

每条保留的 finding 都必须位于已观测的输入内，并要求唯一的 `(check_id, fingerprint)`。其 Northstar `id` 是规则 ID、正规化路径、完整范围和 fingerprint 的规范 JSON SHA-256；它不接受由外部输出直接指定的 ID。消息、规则 ID、起始行和位置保留在可表达的 schema 字段中。原始 stdout/stderr 仍由共享 `make_record` 逐 byte 摘要并固定命名为 `semgrep.stdout.json`、`semgrep.stderr.txt`，没有任何原始 JSON 字段能指定产物名。

Semgrep 的输出 schema 将原始 finding severity 定义为 `ERROR`、`WARNING`、`INFO` 与 `CRITICAL`、`HIGH`、`MEDIUM`、`LOW` 等工具枚举。[1] 该字段和候选规则的 `metadata` 都**不参与**风险映射。每个实际 `check_id` 必须出现在调用方提供的受信 `severity_map`，并映射到 Northstar 的 `critical`、`high`、`medium`、`low` 或 `info`；缺失或未知映射失败关闭。因此即使原始 `INFO` 或 metadata 被改低，输出风险也不会降低。

此合同把完成扫描的退出状态绑定为：无 finding 必须为 `0`，有 finding 必须为 `1`。Semgrep CLI 文档说明 `semgrep scan` 可以用 `--error` 在有 finding 时返回 `1`。[4] 父级固定 runner 必须实际配置与验证该语义；否则 normalizer 因退出码与 findings 矛盾而拒绝证据，而不是悄悄更改状态。

## 本地攻防配对测试

`native_tests/test_semgrep_normalizer.py` 只使用内存 JSON 和 bytes fixture。正常配对验证无 finding 的完整覆盖与固定产物名；危险配对验证 finding 被保留，且原始 `INFO` 与 metadata `LOW` 仍由受信 map 归一化为 `high`。防御断言覆盖错误 JSON/重复键、输入 byte 不一致、版本漂移、errors、skipped rules/paths、遗漏/重复/逃逸路径、重复 finding、未知严重度、退出码矛盾、行内忽略和未知结构。

尚未在此支线执行 Semgrep 二进制、真实规则包或 bwrap 隔离。测试只能证明 normalizer 对自建 fixture 的数据边界；不能证明父级 runner 的实际版本、隔离或扫描覆盖。

**References**

[1]: https://github.com/semgrep/semgrep/blob/v1.181.0/cli/src/semgrep/semgrep_interfaces/semgrep_output_v1.jsonschema "Semgrep 1.181.0 CLI output JSON schema"
[2]: https://github.com/semgrep/semgrep/releases/tag/v1.181.0 "Semgrep release 1.181.0"
[3]: https://docs.semgrep.dev/release-notes/february-2022 "Semgrep scanned and skipped JSON paths"
[4]: https://docs.semgrep.dev/cli-reference "Semgrep CLI reference and exit statuses"

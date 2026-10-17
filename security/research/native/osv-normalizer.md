OSV Scanner v2.7.0 的 machine JSON 顶层是 `VulnerabilityResults`。其中 `results` 按 `source` 分组，单个 source 具有 `path` 与 `type`，并含完整 `packages`。每个包记录有 `package`、可选 `vulnerabilities` 与 `groups`；包识别包括名称、版本和生态。v2.7.0 的 `PrintJSONResults` 直接用缩进 JSON 编码该模型并写入 stdout。[1] [2]

`osv_normalizer.py` 只接受该锁文件形式。它先以 `validated_inputs` 校验签名模板和冻结字节，随后把每一个预期锁文件恰好匹配一个 `source.type == "lockfile"`。它对每个 source 统计**所有** `packages`，而不是仅统计漏洞包，并要求包数达到 `min_packages`、每个实际生态都在该锁文件预期生态中、且预期生态没有遗漏。源重复、未出现的锁文件、额外 source、空/少包、生态漂移、重复包身份或无法表示的许可证、镜像、弃用包和通用发现都会抛出 `EvidenceError`。

每一条原始 vulnerability 必须被其包的 `groups[].ids` 恰好引用一次，随后规范化为一条 `kind: advisory` finding。finding id 是路径、advisory id 与包三元组的规范 JSON SHA-256，因此不会把不同锁文件或不同版本的同一 advisory 合并。执行和隔离对象由调用方原样交给 `make_record`；normalizer 不从 stdout 声明隔离或修改退出信息。只有干净的 `completed` 退出码 0 或 1 可形成完整 coverage。官方返回码说明 0 表示包已识别但没有匹配发现，1 表示存在漏洞或发现，因此 exit 0 加 raw finding、或 exit 1 加空 finding 都会失败关闭。[3]

严重性只读取单条 OSV vulnerability 的官方 `databaseSpecific.severity` 文本（也兼容唯一的 `database_specific` 拼写），将 CRITICAL/HIGH/MEDIUM 或 MODERATE/LOW 映射到 schema 枚举。若没有可识别的该字段，或只存在 CVSS 向量，finding 会保持 `unknown`，绝不降为 low。OSV 文档说明其展示的 CVSS 来自 `severity[].score`；本 normalizer 不自行解析或猜测该向量。[3]

单元测试全部使用内建 JSON fixture，不执行 OSV、项目代码、网络或真实凭据。已覆盖正常的全包识别、`databaseSpecific` 和兼容拼写、CVSS-only unknown，以及少包、范围扩展、生态漂移、重复包计数、raw errors、缺失分组、冲突严重性、数据库覆盖不足、截断和退出码矛盾的拒绝路径。没有在本支线安装 OSV Scanner 或下载 OSV 数据库；父任务负责实际扫描与隔离验证。

**References**

[1]: https://raw.githubusercontent.com/google/osv-scanner/v2.7.0/pkg/models/results.go "OSV Scanner v2.7.0 result models"
[2]: https://raw.githubusercontent.com/google/osv-scanner/v2.7.0/internal/output/machinejson.go "OSV Scanner v2.7.0 machine JSON writer"
[3]: https://google.github.io/osv-scanner/output/ "OSV Scanner output formats and return codes"

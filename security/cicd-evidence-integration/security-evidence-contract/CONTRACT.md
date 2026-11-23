# 统一安全扫描证据 v1 开发合同

交付目录：`/home/ubuntu/northstar-deliverables/security-evidence-contract`。这是一份独立参考实现，不修改 Northstar Core、不安装或执行 Semgrep/OSV、不推送仓库。

## 对外 API

`security_evidence.py` 提供 `EvidenceError`、`strict_json_loads(raw: bytes, *, max_depth=64, max_nodes=100000)` 与 `evaluate_bundle(evidence_dir, expectation_path, *, now=None) -> dict`。

CLI：`python3 security_evidence.py --evidence-dir DIR --expectation FILE`。不提供绕过、自动修复或联网选项。`now` 仅 Python API 的受信时钟注入，用于确定性测试，CLI 使用真实 UTC 时钟。

结果必须含 `schema="northstar.security-gate.v1"`、`evidence_valid: bool`、`eligible_for_delivery: bool`、`decision: pass|block|review|invalid`、`exit_code: 0|1|2`、`reason_codes: list[str]`、`checks: list[{id,passed,reasons}]`、`limitations: list[str]`。证据结构、摘要、绑定有效但扫描失败，可以 evidence_valid=true、eligible=false。valid 不等于 pass。

## JSON Schema 文件

使用 Draft 2020-12，所有对象 additionalProperties=false。整数类型严格为 Python int，bool 和 1.0 均不能冒充整数。所有数据有边界；$ref 只引用同文件 $defs，禁止远程引用。

共用原语：
- sha256：64 位小写十六进制；Git commit 为 40 或 64 位小写十六进制。
- safe artifact name：`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`。
- relative repo path：最大 1024，非空；语义校验拒绝绝对路径、反斜杠、冒号、空组件、`.`、`..`、控制符和 Unicode 方向控制符。
- timestamp：UTC RFC3339，`YYYY-MM-DDTHH:MM:SS(.fraction)?Z`，语义验证真实日期。
- bounded string：非空、最长 256（message 最长 2000）；不要回传原始源代码。
- observed/expected inputs 最大 4000；findings 最大 2000；ecosystems 最大 32。

### security-scan.v1.schema.json

全部 top-level 属性为 required：
```
schema: const northstar.security-scan.v1
run_id: string 1..128 [A-Za-z0-9._-]
subject: {start_commit, patch_sha256, candidate_manifest_sha256, scan_view_manifest_sha256}
tool: {
  name: semgrep|osv-scanner,
  version: string,
  distribution_sha256, normalizer_sha256, config_sha256: sha256,
  rules_sha256: sha256|null,
  database: null|{manifest_sha256:sha256, updated_at:timestamp, ecosystems:[string]}
}
execution: {
  status: completed|timed_out|resource_exhausted|error|not_applicable,
  started_at: timestamp|null,
  finished_at: timestamp|null,
  duration_ms: integer 0..86400000,
  exit_code: integer -255..255|null,
  timed_out:bool, resource_exhausted:bool, output_truncated:bool
}
isolation: {
  backend: oci|bwrap|vm|none|process|unknown,
  read_only_inputs:bool,
  network: denied|allowed|unknown,
  credentials: none|present|unknown,
  project_code_executed:bool,
  non_root:bool
}
coverage: {
  status: complete|incomplete|not_applicable,
  observed_inputs:[{path,sha256,ecosystems:[string],package_count:integer 0..1000000}],
  skipped_inputs:[{path,reason:string}],
  unresolved_inputs:[path],
  error_count:integer 0..100000
}
findings:[{
  id:string, kind:rule|advisory,
  rule_id:string|null, advisory_id:string|null,
  severity:critical|high|medium|low|info|unknown,
  location:{path,line:integer 1..10000000|null},
  package:null|{name:string,version:string,ecosystem:string},
  message:string
}]
artifacts:{stdout:null|{name,sha256,bytes:integer 0..16777216}, stderr:null|{name,sha256,bytes:integer 0..1048576}}
```
Schema 可以用 allOf/if/then 表达 tool 差异，也可由语义层补足；不增加其它字段。Semgrep rules_sha256 非 null、database null；OSV rules_sha256 null。必需 OSV database 非 null；不适用 OSV database 可 null。

### security-expectation.v1.schema.json

全部 top-level 属性 required：
```
schema: const northstar.security-expectation.v1
run_id: string
subject:{start_commit,patch_sha256,candidate_manifest_sha256}
policy:{
  id:string,sha256:sha256,
  blocking_severities:[critical|high|medium|low|info] unique, minItems0,maxItems5,
  unknown_severity:review|block,
  max_scan_age_seconds:integer 1..604800,
  max_database_age_seconds:integer 1..31536000,
  max_clock_skew_seconds:integer 0..300,
  max_duration_ms:integer 1..86400000
}
tools:{semgrep: ToolExpectation, osv-scanner: ToolExpectation}
ToolExpectation:{
  required:bool, not_applicable_reason:string|null,
  evidence_file:artifact name,evidence_sha256:sha256,
  version:string,distribution_sha256:sha256,normalizer_sha256:sha256,config_sha256:sha256,
  rules_sha256:sha256|null, database_manifest_sha256:sha256|null,
  scan_view_manifest_sha256:sha256,
  isolation_backend:oci|bwrap|vm|none,
  expected_inputs:[{path,sha256,ecosystems:[string],min_packages:integer 0..1000000}]
}
```
Host expectation 文件必须由信任域外的宿主保存/认证；示例放在同目录仅用于 fixture。pin 每份最终 evidence 字节 hash，防止修改 findings 同时自改摘要；上下文是真正 trust anchor，若攻击者能改它，JSON 自身不能认证。代码/Schema/依赖也要可信部署。

## 语义判定

1. no-follow 安全打开目录及文件，拒绝 symlink、非普通文件、硬链接（nlink!=1）、超限、读取期间大小/mtime/ctime变化；路径父目录也按 fd 逐级 no-follow 打开。JSON 最大 2MiB，stdout 最大16MiB，stderr最大1MiB。实际 read 也限量，不仅 fstat。拒绝重复键、NaN/Inf/1e999、过深/过多节点；错误不能崩溃或写文件。
2. context 自身合法后，工具名称由 tools 键确定，不信任 record。两种工具、两个不同 evidence_file 都必须有证据。record 精确字节hash与context匹配；run_id、subject、tool版本/发行物/normalizer/config/rules/database及scan-view与context逐项一致。
3. expected_inputs 只从context取得。path唯一；观测 path/hash/ecosystems 必须完全匹配，未知/重复/path mismatch不能放行。OSV package_count >= 宿主 min_packages，Semgrep packages=0、ecosystems=[]。OSV database覆盖所有 expected/observed ecosystems，时间不超未来clock skew、未过期。
4. findings id唯一，location.path必须属于宿主必扫且实际观测输入。Semgrep kind=rule、rule_id非空、advisory_id/package=null；OSV kind=advisory、advisory_id非空、rule_id=null、package非空，package生态属于该文件已观测生态。不要忽略 unknown severity。
5. required=true 必须 expected_inputs非空、not_applicable_reason=null、backend不是none。required=false 必须 expected_inputs=[]、not_applicable_reason非空；record只可not_applicable、coverage.not_applicable、timestamps=null、duration=0、exit=null、flags=false、无findings/observed/skipped/unresolved/errors、stdout/stderr=null。OSV database可null。required不能由record改变。
6. completed：timestamps有效、finish>=start、未超过允许未来偏差，scan-age基于finish，不超过政策；duration/墙钟区间不超过max_duration。exit必须0或1，exit1但findings为空属于合同矛盾。timed_out/resource_exhausted/output_truncated必须false才可execution_complete。timed_out和resource_exhausted状态应匹配对应bool；其余失败可保存为有效失败证据，但不放行。coverage.complete 声明不能与缺失、skipped、unresolved、error_count>0同时成立；这时覆盖失败且声明矛盾。
7. completed扫描要有stdout/stderr对象；artifacts.name不得重复/指向任一证据或context文件；核对实际字节数和SHA256。stdout completed时还必须是严格顶层对象JSON；失败扫描stdout可以是任意有界字节。该实现不重新执行 vendor-specific normalization，只验证已生成规范证据和raw blob完整性；正确性取决于固定版本受信normalizer。
8. isolation是宿主采集metadata，required扫描backend等于context且为oci/bwrap/vm；readonly=true, network=denied, credentials=none, project_code_executed=false, non_root=true。不是实际内核隔离的独立证明。
9. 优先级：结构/语义绑定/文件完整性失败→invalid/2；执行/覆盖/新鲜度/隔离不满足→review/2；完整且存在 blocking severities 或unknown policy=block→block/1；完整但unknown policy=review→review/2；其余pass/0。两种工具都满足要求才eligible=true。不提供例外/豁免v1，false positive可宿主人工审查不能自动忽略。
10. limits声明：hash只做一致性，trusted context真实性由调用者保证；JSON不能独立证明隔离；不保证原生normalizer映射正确；通过不证明不存在未知漏洞，也不代替Northstar既有交付证据门。

## 并行工作边界

Schema作者只写schemas两JSON文件，不写validator/tests/examples。测试作者只写tests/test_security_evidence.py、examples/make_fixture.py及生成的examples/pass目录，不写schema/validator。主agent写security_evidence.py、requirements.txt、README及封装交付。

建议 tests 用unittest标准库（可由pytest执行）；fixture脚本复用自己的build_fixture(root, now=None)方法；其它测试可import此方法。fixture raw stdout用可辨识但简化的原生JSON，绝不能把fixture描述成真实scanner执行。fixture构造工具包括：生成两份record→固定json编码字节→算 evidence_sha256→写hostexpectation。篡改测试要区分不改trustanchor的hash篡改，以及以重新pin方式专门测试其它语义问题（后者只用于测试，不是生产操作）。

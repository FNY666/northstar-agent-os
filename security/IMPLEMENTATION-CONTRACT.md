# 本轮实现合同（父任务与并行开发共用）

本轮只实现可信 expectation 生产、签名/封存与验签消费，不运行原生 Semgrep/OSV、不激活仓库工作流、不生成或归档生产私钥。根目录 `/home/ubuntu/northstar-deliverables/trusted-expectation-sealing`。旧消费端固定复制到 `cicd-evidence-integration/`。

## 信任模型

不能从待审证据反推 required_inputs/规则/隔离/策略。预先经受信 planner 签名的 scan-plan 决定期望；受信扫描 supervisor 的 scan-capture 签名认证实际捕获文件。producer 验签两者，再仅把捕获证据的实际字节 hash 填到计划对应的 evidence_sha256 字段中，调用原 validator，不自改其它期望。

Supervisor 签名不是物理隔离证明；它必须在实际部署中使用真实、固定的 runner/normalizer 并保管好私钥。原生 runner/normalizer 不在本轮实现。执行候选项目的 build worker 不能接触 signing 私钥。build-capture 必须由独立可信构建监督/证明生产者认证，不接受 builder 任意自声明或上传日志直接背书。

## 公共模块 `trusted_common.py`（父任务负责）

- 从固定相邻 `cicd-evidence-integration/security-evidence-contract` 导入并导出 `EvidenceError, strict_json_loads, _read_path, _Directory, _validators, _context_semantics`。
- `wire(value)->bytes`：确定性 JSON（ASCII、sort_keys、紧凑、有尾换行、拒绝非有限数字），不宣称RFC8785。
- `sha(raw:bytes)->str`。
- `clock(now=None)->aware UTC datetime`；`stamp(datetime)->UTC RFC3339 string`；`parse_time(str)->datetime`。
- `validate_identity(identity)`：闭合五字段：repository为ASCII owner/repo，run_id为ASCII安全1..128字符，run_attempt为严格int1..1000000，source_commit为小写hex40或64，nonce为小写hex64。expected_identity必须来自当前受信CI控制面，不从下载证据自造。
- `file_manifest(files:dict[str,bytes])->list[{name,sha256,bytes}]`：安全单文件名、排序、最多128个。
- `read_manifest_files(root, manifest, *, max_total=536870912)->dict[str,bytes]`：闭合描述结构、严格int字节数、每文件最多67108864、总预算、逐级no-follow、nlink=1、实际hash/bytes检查、目录精确匹配文件清单，不容额外文件。不执行输入。
- `publish_directory(output_dir, files:dict[str,bytes])`：安全父目录FD、同目录私有staging、fsync、readonly files、Linux renameat2 RENAME_NOREPLACE原子发布；绝不覆盖已有目标，失败清理staging。只读权限不是WORM/不可变存储。
- `load_private_key(path)->Ed25519PrivateKey`：no-follow、regular、nlink1、有界、当前owner、无group/other权限；不打印私钥。
- `load_trust_store(path)->dict`：严格安全读取和结构验证。公钥根必须由运维受控部署，不能使用随下载包携带的任意keyring作根。

签名API：

```python
create_receipt(kind, identity, body, private_key, trust_store, *, now=None, ttl_seconds=1800) -> bytes
verify_receipt(raw, trust_store, *, expected_kind, expected_identity, now=None) -> dict
```

返回解码并验证过的 payload（含schema/kind/identity/issued_at/expires_at/body）。使用 DSSE PAE + cryptography Ed25519。payloadType 固定 `application/vnd.northstar.receipt.v1+json`；外层仅payloadType/payload/signatures；恰好一个签名，keyid=SHA256(raw32公钥)，sig为base64(64bytes)，payload为base64精确JSON字节。payload仅schema=`northstar.signed-receipt.v1`、kind、identity、issued_at、expires_at、body。kind仅scan-plan/scan-capture/expectation/build-capture/release-seal。公钥根按kind和repository限制角色，未知key/撤销/过期/角色不符/当前身份不符全部拒绝；最大TTL 14400秒、未来偏差60秒。

Trust store：顶层仅schema=`northstar.receipt-trust.v1`和keys；keys字典1..128个，key为hex64，值仅public_key(base64 raw32)、kinds(非空唯一已知kind数组)、repository、not_before、not_after、revoked(严格bool)。keyid必须匹配公钥实际字节。签名验证先验签再解析payload语义，不根据未验签body执行动作。同一当前身份内允许重复验证；不声称实现持久单次消费ledger。

## 具体回执 body

scan-plan.body（闭合）：

```json
{
  "schema": "northstar.scan-plan.v1",
  "expectation_template": {
    "schema": "northstar.security-expectation.v1",
    "run_id": "与identity一致",
    "subject": "原三字段对象",
    "policy": "完整原policy",
    "tools": "完整原tools，但每个tool去掉evidence_sha256字段"
  },
  "release_components": ["northstar_run_contract", "northstar_run_evidence", "northstar_host", "northstar_durable_run", "northstar_agent_interop", "northstar_agent_runtime"],
  "release_version": "如0.1.0，安全ASCII且无连字符"
}
```

计划由部署侧固定策略、真实冻结输入与工具身份预先构造。生产 CLI **不**从normalized records推断模板；测试fixture可合成模板，但只能在测试目录。验证模板时临时加入64个零作为 evidence_sha256后调用旧expectation Schema和context semantics，并检查保留文件名冲突；不能在签名后的计划中出现真实evidence hash然后被候选自替换。

scan-capture.body仅schema=`northstar.scan-capture.v1`、plan_sha256（精确signed-plan文件bytes）、files（两个normalized records与全部stdout/stderr的文件描述清单）。捕获目录只能包含这份清单文件，不含host-expectation或其它自造控制文件。producer检查plan先于真实扫描开始、capture签发不早于扫描结束（允许60秒偏差），再用旧validator核对覆盖、执行和工具元数据。

expectation.body仅schema=`northstar.expectation-receipt.v1`、plan_sha256、capture_sha256、expectation_sha256、gate_sha256。文件期望和gate都是producer当次创建的真实字节。签名认证一个有效的执行记录，不自动表示gate为pass；blocked/review可作为诊断输出，但不可release-seal。

build-capture.body仅schema=`northstar.build-capture.v1`、plan_sha256、files（实际wheel描述清单）。source_commit来自签名identity，不来自wheel自声明；可信builder监督者仍需证明真实构建来源。seal阶段按signed-plan限定components与version，当前参考模式要求每component恰好一个wheel。

release-seal.body仅schema=`northstar.release-seal.v1`、plan_sha256、capture_sha256、build_capture_sha256、expectation_receipt_sha256、expectation_sha256、security_gate_sha256、binding_sha256、files。files为全部待封存普通文件清单，**不含release-seal.dsse.json本身**；至少包含原scan文件、plan.dsse.json、capture.dsse.json、build-capture.dsse.json、host-expectation.json、expectation.dsse.json、security-gate.json、release-binding.json和全部wheel。seal时重新跑旧validator，不盲信旧gate；新gate字节绑定到本次binding。

## Agent A：`produce_expectation.py` 与 tests/test_producer.py

API：

```python
produce_expectation(plan_path, capture_path, evidence_dir, output_dir, trust_store,
                    expected_identity, signing_key, *, now=None) -> dict
```

验签并安全复制捕获文件到本任务临时私有目录以验证同一bytes。只从signed-plan模板生成context，证据hash来自已认证captured files；调用旧evaluate_bundle，再生成expectation回执；publish_directory封存已捕获files + plan.dsse.json/capture.dsse.json + host-expectation.json/security-gate.json/expectation.dsse.json。异常抛EvidenceError，不写输入；任何invalid evidence不输出签名目录（review/block可输出有效诊断，其API exit_code保持原gate语义）。返回至少exit_code、expectation_sha256、gate_sha256、receipt_sha256、output_dir、decision。

CLI --plan --capture --evidence-dir --output --trust-store --identity --signing-key-file；stdout JSON，exit原gate0/1/2；identity为受信控制面JSON，不能从回执自造。API now仅测试注入，CLI不覆盖时钟。

## Agent B：`seal_release.py`、`consume_release.py` 与 tests/test_sealing.py

seal API：

```python
seal_release(produced_dir, build_capture_path, dist_dir, output_dir, trust_store,
             expected_identity, signing_key, *, now=None) -> dict
```

验证produced所有上游签名和pin、evidence实际字节、plan及identity、build-capture+真实wheel。重新调用旧evaluate_bundle并要求pass，按plan组件/版本构造binding，复用旧verify_release_files，以同一读取bytes临时目录核对；再签release-seal并原子发布全部文件为扁平目录。任何失败不签不输出部分目录。

consume API：

```python
consume_release(sealed_dir, trust_store, expected_identity, *, now=None) -> dict
```

只读：先验release-seal签名，除seal自身之外目录精确匹配files清单，再校验整套计划/捕获/expectation/build签名图与pins，重新验安全证据新鲜度和实际wheel绑定，满足才eligible_for_publish true/exit_code0。任一异常failclosed返回exit_code2，不写输入。不从包内keyring或pass文件自造trusted pins。

CLI可与同名API对应，--trust-store/--identity等读取外部受信控制文件。sealCLI --produced-dir --build-capture --dist-dir --output --signing-key-file；consumeCLI --sealed-dir。暂未实现脚本别拿fixture替代。

## 测试与demo

各角色用测试临时生成的不同Ed25519私钥及对应外部trust_store。计划、capture、build与签名时间按同一aware now构造，fixture扫描发生在计划签发后。至少测试tamper、错key/角色/nonce/attempt/source、过期、撤销、扩大/遗漏输入、低风险重写policy、没执行/失败gate、被换wheel、不完整组件、symlink/hardlink、extra files、输出不可覆盖和输入不写。

父任务负责公共签名模块、签名测试、GitHub job参考与交付中文指南；agents仅写指定文件，不改旧复制代码、公共模块、工作流或其他agent文件。所有真实扫描/隔离/生产部署能力不得虚称已实现。

## Gate 字节冻结修订（优先于上面的同名文件描述）

producer 的 expectation 回执固定了当时 `security-gate.json` 的 hash。seal重新评估会产生新的 checked_at，因此新 gate 字节不能覆盖旧回执所指对象。sealed bundle 必须将producer原始gate保存为 **producer-gate.json**（expectation.body.gate_sha256仍核对它），将seal当次fresh gate保存为 **security-gate.json**（release binding和release-seal.body.security_gate_sha256核对新gate）。两份文件都进release-seal.files签名清单。consumer重验时再生成内存fresh gate，不改任何旧文件。producer-gate.json也加入保留名称冲突检测。若保存fresh-gate.json替代也可，但最终规范统一以上两个名字，避免角色图丢失旧对象。

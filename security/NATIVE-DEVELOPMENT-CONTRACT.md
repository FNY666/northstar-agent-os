# Northstar 原生编程攻防开发合同

用户要求：编程优先，攻击工具与防护工具成对，多模态后置；当前可用并发尽量用满。本轮只针对本地自建fixture与授权仓库，不攻击第三方，不提供任意目标/URL/命令攻击入口，不持有真实生产签名密钥，不自动发布。

研发root：`/home/ubuntu/northstar-native-security-dev/security`，git工作区是父目录的新分支，原修改中的工作区未动。这里包含先前实际185 tests+27 subtests通过的签名/校验核心。父任务负责整合、实际scanner安装/数据库准备、真实smoke与scan_supervisor.py；子任务只写各自文件，不修改其他支线或旧核心，禁止git commit/push。

## 共享接口

父任务提供 `native_contract.py`，可导入 `EvidenceError, strict_json_loads, wire, sha, stamp, clock`，以及 `validate_template(template)`、`validated_inputs(template,tool,input_bytes)`、`make_record(tool,template,execution,isolation,input_bytes,stdout,stderr,database=None)`、`validate_record(record)`、`normalize_path(path)`。

`template` 是已验签scan-plan的expectation_template，两个tool均没有evidence_sha256。normalizer绝不从原生输出反推期望，不改变scope、policy或pin。`execution` 和`isolation` 来自实际宿主监督运行，不由stdout决定。`input_bytes` 是某tool实际冻结输入的相对路径→bytes映射，与该tool.expected_inputs精确一致。

Normalizer固定API：

```python
normalize_semgrep(stdout:bytes, *, template:dict, execution:dict, isolation:dict,
                  input_bytes:dict[str,bytes], severity_map:dict[str,str], stderr:bytes=b'') -> dict
normalize_osv(stdout:bytes, *, template:dict, execution:dict, isolation:dict,
              input_bytes:dict[str,bytes], database:dict, stderr:bytes=b'') -> dict
```

原始文件名固定 semgrep.stdout.json/semgrep.stderr.txt、osv.stdout.json/osv.stderr.txt。record字段完全满足旧northstar.security-scan.v1 Schema。make_record仅形成闭合基本record，默认coverage incomplete无findings；子任务根据实际原生输出填coverage/findings。parsed_errors、缺包、skip、unknown severity、exit0不一致、exit1无发现等必须失败关闭。完整合法风险结果保留findings，允许门禁block，不抹掉漏洞。severity不能被候选代码metadata或修改过的raw INFO字段弱化：Semgrep用受信severity_map；OSV未知分数保留unknown，不默认低风险。

原生工具版本：Semgrep 1.181.0，OSV 2.7.0，或实际不可获取时明确失败，不偷偷换版。官方OSV发行asset SHA256已核验为160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b。没有docker/podman；当前unshare -Urn实际成功。runner以bwrap为候选真实隔离后端，不能退到普通process并标bwrap。只读、禁网、清空env、非root、capdrop、no-new-privileges、进程树总时限与bounded capture须实际实现/测试；未实现的聚合cgroup预算要明确，不能伪造证明。

Runner固定API（worker负责实际可用参数和文档）：

```python
run_native(tool:str, *, tool_root:Path, input_dir:Path, policy_dir:Path,
           database_dir:Path|None=None, bwrap_path:Path,
           timeout_seconds:int=120, max_stdout_bytes:int=2097152,
           max_stderr_bytes:int=1048576) -> dict
```

返回`stdout:bytes, stderr:bytes, execution:dict, isolation:dict`，另可有metadata。tool只semgrep/osv-scanner；不可接受任意命令、目标或追加flag。Semgrep tool_root是独立venv，内部执行`/tools/bin/python -m semgrep`；OSV tool_root只含osv-scanner固定可执行文件。policy_dir需要semgrep.yaml、osv.toml，禁止候选配置/远程规则；OSV显式输入锁文件、offline、no-resolve、no-call-analysis=all、no-ignore、all-packages。父任务安装bwrap到`/home/ubuntu/northstar-tools/bwrap/usr/bin/bwrap`，不改系统PATH或旧SDK默认行为。

## 文件所有权

1. Semgrep支线：`semgrep_normalizer.py`, `native_tests/test_semgrep_normalizer.py`, `research/native/semgrep-normalizer.md`。
2. OSV支线：`osv_normalizer.py`, `native_tests/test_osv_normalizer.py`, `research/native/osv-normalizer.md`。
3. 输入冻结：`freeze_inputs.py`, `native_tests/test_freeze_inputs.py`, `research/native/input-freezing.md`。提供`freeze_inputs(source_dir,output_dir,paths:list[str])->dict`安全复制与manifest，拒绝links/special files/不安全paths/credential文件；requirements首版只允许确切version的普通包行，拒绝include/constraint/URL/options/ranges，不执行项目代码。
4. 隔离runner：`native_runner.py`, `native_tests/test_native_runner.py`, `research/native/native-runner.md`。不安装系统软件，不改profile/normalizer。父任务准备工具，可探索现有bwrap路径/等待可用，但不调用browser。
5. 攻击证据实验室：`run-native-security-lab.py`, `native_tests/test_native_security_lab.py`, `research/native/attack-defense-lab.md`。固定本地fixtures与已有签名核心，至少scope laundering、fake success、replay、wheel swap、gate/context篡改、source mismatch，必须有能通过的正常paired case，不接受外部目标/命令。
6. 编程交付桥：`check-programming-security.py`, `native_tests/test_programming_security.py`, `research/native/programming-bridge.md`。只读校验Northstar既有编程证据与signed security produced directory，明确真正verified-success，不因默认checker0就放行；核对subject的start/patch与交付patch，candidate manifest无法独立重建的限制明确。不得用模型文本成功替代宿主回执。可读fresh仓库实际实现。
7. 本地规则攻防包：`rules/semgrep.yaml`, `rules/osv.toml`, `rules/severity-map.json`, `native_fixtures/`及`native_tests/test_rule_pack.py`, `research/native/rule-pack.md`。至少5类编程漏洞的危险/正常pair，不能执行危险代码；可信规则关闭行内抑制后用真实Semgrep验证（由父任务跑）。只写toy数据，不填真实credential。
8. 安全CI入口：父仓库`.github/workflows/security-contract-tests.yml`，`security/native_tests/test_ci_workflow.py`, `security/research/native/ci-tests.md`。只激活无secret低权限单元测试和固定本地attack lab；不配置真实签名/发布，native live扫描前提未准备则不冒充通过。所有外部Actions固定已核验SHA。测试pytest请读取实际已安装版本，不猜包版本。

每条支线需自行完成有限unit测试，记录真实通过项、失败和阻塞；不宣称native运行、物理隔离或签名来源在未测时已成立。不多开审查/研究子代理，不扩展到多模态。检索外部事实先读deep-research skill；使用fetch即可，需浏览器的研究用isolated agent，但本次shared代码任务禁止浏览器，避免争用。

# Northstar：可信 expectation 生产者与签名/封存 job 的完整逻辑

> 历史协议说明：下文记录最初仅实现证据签名/封存时的边界。本目录后来加入了实际原生扫描、normalizer 与 Git 快照；本轮现状和新增限制以 `README.zh-CN.md`、`research/native/native-runner.md` 与最新交付报告为准。生产可信构建监督器、独立生产根和发布部署仍未完成。

让受信控制面先签发扫描计划，让独立监督者认证实际扫描和构建捕获，再由 expectation 生产者生成期望。发布封存 job 必须自己验签、重新跑门禁并核对真实 wheel 字节。不能把签名理解为“收到一个 pass 文件就为它背书”。

本包已经实现这条证据协议的生产、签名、封存和只读消费逻辑，并给出完整的可复用 GitHub job 参考。它不包含原生 Semgrep/OSV runner、原生结果 normalizer或可信构建监督器，也没有发布工具链镜像或激活远端工作流。因此它是可运行的协议参考实现，不是已经上线的安全发布系统。

## 1. 可信输入必须在候选结果之外形成

外部信任根是运维部署的公钥集合、经审阅的工具链以及受保护的工作流。它们不能来自下载的扫描包或 PR checkout。`trust-store.json` 按公钥限制仓库和可签发回执的角色；生产者和消费者只读取包外的这份根，不自动接纳回执携带的公钥。

控制面身份包含 `repository`、`run_id`、`run_attempt`、`source_commit` 和 `nonce`。`bootstrap_identity.py` 从当前 GitHub 环境生成身份，使用 CSPRNG 生成 nonce，不从下载证据读取这些字段。nonce 是公开的绑定标识，不是密钥；它需要在扫描前固定并由受保护 bootstrap outputs 传给后续 job。

这里的 `source_commit` 是实际候选的最终 commit，`subject.start_commit` 是补丁起始 commit。二者可以不同。PR head、test-merge、merge queue 与 tag commit 的选择应由受信控制面统一决定，不能混用。代码已用起始与最终 commit 不同的端到端场景验证这点。

`scan-plan` 必须在扫描开始前形成。部署侧 planner 从真实冻结输入和固定 profile 生成以下 body，再调用 `issue_plan.py` 签发：

```json
{
  "schema": "northstar.scan-plan.v1",
  "expectation_template": {
    "schema": "northstar.security-expectation.v1",
    "run_id": "<本次受信run_id>",
    "subject": "<原三字段subject对象>",
    "policy": "<完整的受保护policy对象>",
    "tools": "<两工具的完整期望，但均不含evidence_sha256>"
  },
  "release_components": [
    "northstar_run_contract", "northstar_run_evidence", "northstar_host",
    "northstar_durable_run", "northstar_agent_interop", "northstar_agent_runtime"
  ],
  "release_version": "<经过readiness检查的规范版本>"
}
```

这是结构说明，字符串占位不满足生产 Schema。`issue_plan.py` 验证闭合字段、原 expectation Schema、输入语义及六组件范围，并强制模板没有预置证据 hash。它不会从 normalized records 推断输入范围，也不会自动完成 Git 源码冻结。`--plan-body` 必须是受信 planner 的输出，不能把 PR 上传的 JSON 放到该参数后就声称它可信。

在生产部署中，planner 必须真实测量补丁、候选清单和扫描视图；工具身份与配置 pin 必须来自固定发行物。OSV 必须使用确定版本的受限依赖输入或 SBOM。签名只认证这些声明来自认可的主体，不会替不完整的源码/依赖准备补齐事实。

## 2. 分开签发五种回执

`trusted_common.py` 使用 DSSE 的 PAE 封装和 `cryptography` 的 Ed25519 实现，认证精确 payload 字节与专用 `payloadType`。验签之后只把刚才通过验签的同一 payload bytes 交给解析器，不重新解析 envelope。标准和 URL-safe base64 都支持。[1] [2]

每个已签名 payload 的固定字段为：

```text
schema = northstar.signed-receipt.v1
kind
identity = 外部当前CI身份的完整五字段
issued_at
expires_at
body = 对应角色的闭合业务对象
```

角色分别是：

- `scan-plan`：在扫描前固定 scope、policy、工具身份和交付范围。
- `scan-capture`：认证本次监督执行得到的 normalized records 与全部原始 stdout/stderr 字节。
- `expectation`：固定生产者新生成的 expectation 和当时的 gate 字节。
- `build-capture`：认证受信构建监督者捕获的实际 wheel 字节和关联计划。
- `release-seal`：在所有检查通过后固定完整发布证据与制品清单。

生产应使用不同的角色密钥。原生 scanner 及执行候选项目的 builder 都不能拿到这些签名私钥。监督者必须从自己的受信执行状态取得退出码、时钟和隔离信息，并用固定 normalizer 处理结果；不能将任意上传的 normalized JSON 当作真实执行回执。`build-capture` 也不能仅由不可信 builder 自己宣称“这是指定源码构建的”。

DSSE 的 `keyid` 只用于查找候选公钥，不被当作身份凭证。代码验证实际签名，再根据该已验签公钥在外部根中的授权判断仓库和角色。[1]

`trust-store.json` 的每项公钥具有 `public_key`、`kinds`、`repository`、`not_before`、`not_after` 和 `revoked`。key ID 是实际 raw32 公钥的 SHA-256。未知 key、角色不符、撤销或过期均拒绝。轮换时先通过运维受控流程发布新公钥，再更新签发者；不能把包里的新公钥自动加入根。

当前 profile 限定一个明确签名，默认回执 TTL 为 1800 秒，最大允许 14400 秒，未来时钟偏差最多 60 秒。它不实现多签门限，也不提供可信时间戳服务。此 CLI 面向当前交付资格检查，不是永久历史审计工具。公钥失效或回执过期会阻断交付，不能用重签老扫描结果刷新年龄。

## 3. expectation 生产者只填入实际证据 hash

`produce_expectation.py` 的流程已经实现：

```text
验当前外部identity
  → 验scan-plan的签名、角色、有效期和业务结构
  → 验scan-capture及其plan_sha256
  → 按已签清单安全读取精确捕获文件集
  → 冻结同一批bytes到私有临时目录
  → 核对计划先于扫描、capture不早于完成
  → 从计划复制完整模板，仅填预定evidence_file的实际hash
  → 调用原evaluate_bundle
  → 为有效的expectation与gate签发回执
  → 原子发布完整目录，不覆盖旧输出
```

required inputs、min_packages、工具 pin、隔离要求和阻断策略全部来自已签 plan。生产者不会从记录中的 observed inputs 反推出一个恰好能通过的 expectation。捕获文件集必须恰好为两份预定 normalized record 加它们声明的 stdout/stderr；额外、缺失、符号链接和保留控制名称冲突都会拒绝。

invalid 证据不签、不输出。合法 block/review 可以形成已签诊断目录，但进程仍返回门禁退出码 1/2；这些签名只认证诊断，不能用于发布放行。

生产调用示例：

```bash
PY=/opt/northstar-trust/venv/bin/python
"$PY" /opt/northstar-trust/produce_expectation.py \
  --plan "$PLAN_DIR/plan.dsse.json" \
  --capture "$CAPTURE_DIR/capture.dsse.json" \
  --evidence-dir "$SCAN_FILES" \
  --output "$RUNNER_TEMP/produced" \
  --trust-store /opt/northstar-trust/roots/trust-store.json \
  --identity "$CONTROL_DIR/identity.json" \
  --signing-key-file "$PRIVATE_KEY_FILE"
```

`/opt/northstar-trust` 是待部署的受信路径，不是当前 GitHub runner 已有的目录。所有 CLI 使用真实当前时钟，不开放 `--now`。Python API 的时钟参数只用于确定性的测试；生产代码不得用它回拨交付检查时间。

## 4. 封存 job 必须重新验证完整图

`seal_release.py` 不相信 produced 目录里的 pass，也不相信构建目录中的文件名。它先验证 plan/capture/expectation/build 四种签名及相互 pin，核对实际捕获与 wheel 字节，再重新调用原安全门禁。只有真正的 pass 才生成最终 binding 和 release-seal。

当前 Northstar profile 要求六组件齐全，每个组件恰好一个 wheel，文件名中的规范版本与计划一致。封存使用 `packaging` 解析 wheel 名称，再通过原 `verify_release_files.py` 核对绑定清单与同一批读取 bytes。这是字节绑定，不是 wheel ZIP 内容校验、可安装性测试或源码到制品真实性的证明；这些仍需真实构建监督与前置验收。

一个容易出错的地方是 gate 的重检时间。生产者的 expectation 回执已经签住原 gate hash；重新评估会改变 `checked_at`，因此不能覆盖原对象后继续沿用旧签名。封存包分别保存：

```text
producer-gate.json   生产者原始gate，由expectation回执固定
security-gate.json   seal当次重新评估的gate，由binding和release-seal固定
```

两份 gate 都核对真实 expectation hash、subject 和 policy。消费端会再次生成内存中的最新检查结果，但不写回任何已封存对象。实际测试中 producer、seal、consume 的时间分别向后推进，签名图仍然成立。

最终 `release-seal.body` 固定 plan/capture/build/expectation 回执 hash、expectation hash、新 gate hash、binding hash以及全部封存文件的 name/bytes/hash。文件清单不包含 seal 本身，避免自引用；消费时要求目录恰好等于签名清单加这一份 seal。

安全读取使用逐级目录 FD 和 no-follow，拒绝硬链接及特殊文件。输出先在同目录私有 staging 完成、fsync并设为只读，再用 Linux `renameat2(RENAME_NOREPLACE)` 原子发布，不覆盖已有输出。这要求支持这些原语的 Linux 文件系统。只读权限不是 WORM；有足够权限的人仍能改文件，但后续字节与签名校验会发现改变。实际 WORM 存储、留存期限和存储访问控制仍需另行配置。

封存调用：

```bash
"$PY" /opt/northstar-trust/seal_release.py \
  --produced-dir "$RUNNER_TEMP/produced" \
  --build-capture "$BUILD_CAPTURE_DIR/build-capture.dsse.json" \
  --dist-dir "$WHEELS_DIR" \
  --output "$RUNNER_TEMP/sealed" \
  --trust-store /opt/northstar-trust/roots/trust-store.json \
  --identity "$CONTROL_DIR/identity.json" \
  --signing-key-file "$RELEASE_KEY_FILE"
```

## 5. GitHub job 的密钥、镜像和权限配置

`examples/trusted-sign-and-seal.yml` 是完整的可复用工作流参考，包含 `sign-expectation` 与依赖它的 `seal-release`。它通过固定 artifact ID 下载数据，不搜索“最新成功产物”，不 checkout 或执行候选项目，不恢复候选 cache。上游真实 scan-plan、scan-capture 和 build-capture 生产者仍必须先存在。

工作流使用仓库受控变量 `NORTHSTAR_TRUSTED_IMAGE` 指定已审阅的镜像 digest，格式为 `ghcr.io/fny666/northstar-trust@sha256:<64位hex>`。镜像必须包含本包工具、独立公钥根和完整 hash 锁定依赖。当前没有发布这个镜像；`requirements.txt` 只是开发复现用的版本 pin，不是生产依赖 hash lock。不要在持有签名密钥的 job 临时从候选目录或未固定网络来源安装工具。

工作流默认需要 `NORTHSTAR_TRUSTED_PRODUCER_ENABLED=true`，没有配置则失败关闭。这个变量不是安全审批替代品。必须先建立并保护 `security-signing` 和 `release-signing` 两个环境，限制允许的受信工作流与 refs；仅声明 `environment` 不会自动建立审批或分支保护。镜像 digest、公钥根、工作流和 policy 的变更都应受审阅控制。[3] [4]

分别只在这两个环境配置 `NORTHSTAR_EXPECTATION_KEY_PEM` 与 `NORTHSTAR_RELEASE_KEY_PEM`。不要把两把私钥同时放到仓库/组织全局 secret，不在 reusable workflow 调用方传私钥，也不使用 `secrets: inherit`。本模板只在对应签名步骤把本角色 key注入环境。

`materialize_key.py` 将已有 secret 写入 0700 临时目录中的 0600 文件，验证当前 owner、no-follow和Ed25519格式；它不生成生产密钥。步骤立即 unset secret环境变量，使用 trap清理文件和目录。上传只限定 produced/sealed数据目录，不上传整个 RUNNER_TEMP或workspace。临时装载仅适用于这份 key-file 后端；采用KMS/HSM时需要经审阅的签名适配器，本包没有实现KMS调用。

两种签名 job 都只有 `contents: read`，不创建 GitHub Release。为了额外绑定 GitHub工作流来源，它们使用本轮核验的 `actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6` 为 expectation回执与release-seal增加原生证明，因此这两个job具有 `id-token: write` 和 `attestations: write`。这些权限不能给执行候选项目的builder或scanner。[5] [6]

seal job使用 `always()`，显式拒绝 upstream不是success；还要求当前事件是push到 `v*` tag，并在装载私钥之前核对 tag版本与已验签计划一致。原有Northstar版本/readiness和单测仍需由调用方明确作为前置依赖，不能因为安全封存成功就省略。

密钥不是签名算法的一部分管理工作。创建生产 key、保存、备份、轮换和撤销必须由运维流程完成，本轮没有创建或保存任何生产私钥。若使用专用runner，labels不等于访问控制；不要让不可信workflow使用签名runner，也不要与候选构建共用可残留状态的主机。

## 6. publisher在审批后先验来源，再验当前交付资格

`consume_release.py` 只读处理数据。它先验证 release-seal，再按已签名清单读取业务文件，重验整套角色图与真实字节，重新检查原始扫描/数据库新鲜度，最后核对 binding与wheel。只有 `eligible_for_publish=true` 且退出0可以继续。

```bash
"$PY" /opt/northstar-trust/consume_release.py \
  --sealed-dir "$SEALED_DIR" \
  --trust-store /opt/northstar-trust/roots/trust-store.json \
  --identity "$CURRENT_CONTROL_DIR/identity.json"
```

跨workflow或存储边界传输时，还应先核验 GitHub attestation 的 signer与source约束，然后使用本包做角色图和语义检查。只有仓库名称不够。示例中 signer_workflow尚未落库，批准的 signer SHA必须由运维配置，不能从待验证证明自己取值：[7]

```bash
gh attestation verify "$SEALED_DIR/release-seal.dsse.json" \
  --repo FNY666/northstar-agent-os \
  --signer-workflow "FNY666/northstar-agent-os/.github/workflows/trusted-sign-and-seal.yml" \
  --signer-digest "$APPROVED_SIGNER_SHA" \
  --source-digest "$CURRENT_SOURCE_COMMIT" \
  --source-ref "$CURRENT_SOURCE_REF"
```

可复用工作流的 signer commit与caller source commit不是同一概念。还要注意 predicate中许多字段可由工作流控制；原生证明认证执行主体，并不会替代本包的scope、真实字节和新鲜度检查。[7]

publisher独立获得 `contents: write`，在已经配置保护规则的release environment中审批后重新检查。不要重新构建；在没有不可信写入者的环境中立即上传已经验证的wheel，并确认tag仍指向预期commit。审批等待到签名或扫描过期时，必须重新授权并重新运行相应链路，不能回拨时钟、只更新时间戳或重签旧结果。

五字段身份限制跨run、attempt、source与nonce的重放，但校验器是无状态的，同一当前身份内可以重复验证。它不实现持久单次消费ledger。GitHub只重跑失败的seal job时，run_attempt可能已变化，旧上游回执会被拒绝；需要重跑当前attempt的完整受信链，不能偷偷忽略attempt来恢复通过。

本包不创建Release，也不实现同名Release资产的幂等核对。正式publisher仍应检查已有assets的实际hash，而不是“Release存在就成功”。封存证据包可能包含原始扫描输出和源码片段，不能直接作为公开Release资产上传；使用受控审计存储，并公开必要的wheel与最小证明即可。

## 7. 本地复现与实际验证结果

解压后在包根目录运行：

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 -m pip install pytest==9.1.1

python3 -m pytest -q tests \
  cicd-evidence-integration/tests \
  cicd-evidence-integration/security-evidence-contract/tests

python3 examples/demo_end_to_end.py --output /tmp/northstar-seal-demo
python3 consume_release.py \
  --sealed-dir /tmp/northstar-seal-demo/sealed \
  --trust-store /tmp/northstar-seal-demo/demo-trust-store.json \
  --identity /tmp/northstar-seal-demo/demo-identity.json
```

`/tmp/northstar-seal-demo` 必须不存在，输出不会被覆盖。demo使用临时内存Ed25519 keys，只保存包外测试公钥和身份，不保存私钥。它的扫描输出与wheel均为fixture，不是实际漏洞检测或可安装制品；测试公钥不能被安装成生产信任根。

2026-10-17已实际验证：**185项测试通过，27个子测试通过**，涵盖旧合同及新增控制面、签名、生产、封存和消费逻辑。YAML已解析，5个shell步骤通过 `bash -n`，另做了只读权限、环境密钥隔离和固定Action引用检查。真实producer→seal→consumer demo以及真实时钟CLI再消费通过，gate时间推进和两种commit不相等都已覆盖。

代码包包含 `validation-results.json`、JUnit结果和测试日志。没有执行GitHub远端工作流验证，没有运行真实scanner或真实构建，没有发布镜像、配置环境、修改仓库或触发交付。正式启用前应补齐真实监督者与normalizer、确定版本的依赖输入、工具链镜像和根配置，然后做受控真实输入的通过/阻断试验。

## References

[1]: https://raw.githubusercontent.com/secure-systems-lab/dsse/master/protocol.md "DSSE protocol v1.0.2: PAE, exact payload bytes, keyid hint and verification parsing"
[2]: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/ "cryptography Ed25519 signing, verification and serialization APIs"
[3]: https://docs.github.com/en/actions/reference/security/secure-use "GitHub Actions secure use, least privilege and trusted workflow boundaries"
[4]: https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments "GitHub environment protection configuration and secret availability"
[5]: https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations "GitHub artifact attestations and signing permissions"
[6]: https://raw.githubusercontent.com/actions/attest/1e69f48acb82d1966a394da916b4c1698aa569d6/action.yml "Pinned attest action subject-path and output contract"
[7]: https://cli.github.com/manual/gh_attestation_verify "GitHub attestation signer/source policy and workflow-controlled predicate limits"

# Northstar 编程攻防与宿主证据工具

编程优先，多模态后置。本目录在已有统一扫描证据、DSSE 签名生产者与发布封存实现上，补齐真实 Semgrep/OSV 只读适配、本地攻击实验室、输入冻结与 Git commit 字节导出。危险代码仅是被扫描的静态 toy fixture，不被导入或执行；实验室不接受外部攻击目标、URL 或任意命令。

## 已闭环的路径

`已提交 Git 对象 → 完整候选清单 → 显式冻结扫描视图 → 已签 scan-plan → bwrap 原生扫描 → 严格 normalizer → 宿主签 scan-capture → 安全拆分 → expectation 生产者 → policy gate`。

Git 导出不用 archive/checkout/filter/hook；原生扫描不挂宿主 home、签名密钥、仓库配置或 socket，不解析远程规则、不解析/安装依赖、不执行项目构建。Semgrep 使用本地五类编程安全规则，OSV 首版执行器只处理一个精确版本的 `requirements.txt` 和本地 PyPI 数据库。不能把这一受限视图解释为完整传递依赖或所有漏洞覆盖。

## 主要入口

| 文件 | 作用 |
|---|---|
| `export_git_snapshot.py` | 从显式 commit OID 读取、验证 Git 原始对象并导出完整候选清单 |
| `freeze_inputs.py` | FD/no-follow 安全冻结显式文件；拒绝链接、特殊文件、危险路径和非受限 requirements |
| `native_runner.py` | 固定两种原生命令；实际 bwrap、非 root、禁网、只读投影、输出/时限限制；无 process fallback |
| `semgrep_normalizer.py` | 绑定冻结源码与本地规则严重性；兼容真实 OSS JSON，不信任 raw 严重性 |
| `osv_normalizer.py` | 绑定锁文件、包覆盖与数据库；未知严重性保留 unknown，不伪装为低风险 |
| `scan_supervisor.py` | 验签预扫描计划，前后测量工具/策略/数据库，只为自己运行捕获的结果签发 capture |
| `stage_scan_capture.py` | 验签 co-packaged capture，拆出精确文件集接入旧生产者，不放宽旧消费端 |
| `produce_expectation.py` | 从预签计划与已签捕获生产可信 expectation 并生成 gate |
| `check-programming-security.py` | 只读绑定 verified 编程交付与已认证安全 produced，不因 exit 0 就认定完成 |
| `seal_release.py` / `consume_release.py` | 原有发布字节绑定、签名封存与只读验签消费；不自动发布 |
| `run-native-security-lab.py` | 九组固定本地 benign/attack 证据篡改、重放与制品交换对照 |
| `prepare-native-tools.py` | 独立工具准备阶段；已审计 wheelhouse、外部受信 bwrap、固定 OSV asset 与 DB 下载 |
| `examples/run_native_smoke.py` | 使用内存测试密钥，运行真实两扫描器与签名 gate 的正常/危险对照 |

## 单元回归与本地攻击实验室

```bash
python3 -m pip install -r security/requirements.txt 'pytest==9.1.1' 'PyYAML==6.0.3'
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q \
  security/tests security/native_tests \
  security/cicd-evidence-integration/tests \
  security/cicd-evidence-integration/security-evidence-contract/tests
python3 security/run-native-security-lab.py --json
```

`.github/workflows/security-contract-tests.yml` 仅为这些无生产密钥的合同/攻击实验室测试提供 `contents: read`。没有 OIDC、签名环境密钥、部署或发布步骤；单测 CI 不冒充原生扫描或生产交付证明。

## 真实原生 smoke

先独立准备并审计固定工具：Semgrep 1.181.0 独立 Python 3.12 venv、OSV 2.7.0 Linux amd64、bwrap 0.9.0 与 PyPI `all.zip`。具体准备参数见 `prepare-native-tools.py --help` 与 `research/native/tool-provisioning.md`。下载发生在准备阶段，不发生在扫描阶段。

```bash
PYTHONDONTWRITEBYTECODE=1 python3 security/examples/run_native_smoke.py \
  --tools-root /path/to/approved-tools \
  --output /path/to/new-smoke-output
```

本轮真实运行已得到：正常源码与依赖对照 `pass`；危险源码（含 `# nosem` 抑制尝试）与漏洞依赖对照 `block`。危险侧 Semgrep 5 项发现、OSV 10 条 advisory；四项真实隔离负向探针通过。正常依赖对照使用本次快照无发现的 `wheel==0.46.3`；原本的 `requests==2.32.4` 已被实际扫描发现两个 advisory，不能继续将其标作正常。数据截止与字节 pin 见交付报告及 DB snapshot，而非未来无漏洞承诺。

## 必须保留的信任边界

本地 smoke 的签名密钥只在内存生成，是测试根，不是生产控制平面或独立角色管理证明；本轮不加载真实生产密钥、不自动签发生产发布、不修改分支保护或受保护环境。

原生 runtime 实际使用只读挂载、命名空间、cap-drop、no-new-privileges、明确的 PID/输出/墙钟限制与 `setrlimit`。地址空间和 CPU 是**每进程**约束，NPROC 是继承的 UID 范围限制，**不是 cgroup 的进程树聚合 CPU/内存预算**。生产准入须在受信不可变工具镜像、受保护 job 与独立资源边界上补齐部署控制；不可把 chmod、hash 或 DSSE 当作内核隔离、作者签名或 WORM 存储。

Git exporter 证明读取的对象字节对应所给 commit/tree，并提供候选清单；并不认证 commit 是用户期望的当前控制面版本。identity 必须来自包外受信控制面。编程交付桥仍不自动重建 SDK 的 `base+patch` 候选或证明源码到最终二进制的可复现构建，这些限制应随门禁报告保留。

详细协议、扫描器兼容修复与部署前提见 `research/native/`，旧签名合同说明见 `Northstar-trusted-expectation-and-sealing.zh-CN.md`。

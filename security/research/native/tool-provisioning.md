# Native 工具准备

`security/prepare-native-tools.py` 只准备固定版本的本机工具和离线 OSV 数据库。它**不扫描源码、不签名、不读取或生成生产密钥，也不执行 `bwrap`**。输出目录只有在全部步骤成功后才通过 Linux `renameat2(RENAME_NOREPLACE)` 发布；已存在的 `--output` 一律拒绝覆盖。失败时会删除同级临时目录，因此重复失败不会损坏一个有效的工具目录。

## 调用与外部前提

```bash
python3 security/prepare-native-tools.py \
  --output /srv/northstar/native-tools \
  --bwrap-source /srv/approved/bwrap-0.9.0/bwrap \
  --semgrep-wheelhouse /srv/approved/semgrep-1.181.0-wheels
```

`--output` 必须是尚不存在的目录名，其父目录必须已经存在。`--bwrap-source` 是操作方预先审核和提供的普通可执行文件。脚本只在 64 MiB 上限内复制并记录其 SHA-256，不使用 `apt`、不解包 deb、也不运行该二进制。要使用旧环境中的 Bubblewrap，应由负责方先从受信任的已解包产物中选定 `bwrap`，然后把该路径显式传给参数；版本和来源审核是外部前提，不能从脚本的复制动作推导出来。

`--semgrep-wheelhouse` 必须是一个**完整的、受审核的本地 wheel 仓库**，同时包含 `semgrep==1.181.0` 和它的运行时依赖的 Linux 二进制 wheels。PyPI 的该发布同时有源码包和适用于 Linux 的 wheels，因此不能以“版本固定”代替对实际分发物的选择。[3] 脚本在全新的 venv 中运行 pip，并同时使用 `--isolated`、`--no-index`、`--find-links`、`--only-binary=:all:`、无缓存和无交互选项。这样安装阶段没有网络下载，也不会读取本地项目、pip 配置或继承宿主 token。

venv 的验证命令刻意是：

```text
<output>/semgrep/bin/python <output>/semgrep/bin/semgrep --version
```

它**不是** `python -m semgrep`。子进程环境从空环境重新构造；`SEMGREP_SEND_METRICS=off` 与 `SEMGREP_ENABLE_VERSION_CHECK=0` 始终设定。Semgrep 文档说明前者控制发送 metrics，后者是影响扫描的版本检查环境变量。[4]

## 固定网络输入与离线数据库

该脚本仅有两次网络传输，且均经受限的 HTTPS 流式下载器执行。每个响应有 90 秒总超时、`Content-Length` 预检和逐块计数；超过预算时临时文件会删除，不会发布目标文件。

OSV-Scanner 固定为 `2.7.0` 的官方 release 地址：

```text
https://github.com/google/osv-scanner/releases/download/v2.7.0/osv-scanner_linux_amd64
```

其内容必须匹配用户指定的 SHA-256：

```text
160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b
```

二进制预算为 64 MiB。该 pin 是内容完整性比较，**不是发布者签名**。v2.7.0 是 OSV-Scanner 的官方 release。[1]

离线数据库固定为官方 PyPI 聚合包：

```text
https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip
```

预算为 512 MiB。每次准备都会在 `database/osv-scanner/PyPI/all.zip` 写入一个新快照，并在 `tool-provisioning.json` 记录响应中实际收到的 `Last-Modified`、下载时刻 `downloaded_at`、实测 SHA-256、字节数，以及 `signature_verified: false`。这里不会把观察到的 hash 说成发布者签名。官方离线模式文档给出了该目录结构和 HTTP `all.zip` 地址；并明确说明扫描使用 `--offline` 时不会下载或更新数据库，缺少数据库会报错且不需要网络。[2]

因此扫描配置应把 `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY` 指向输出中的 `database`，并使用 `--offline`，**绝不能**添加 `--download-offline-databases`。数据库刷新是单独再次运行准备阶段并人工审阅新的 manifest，不是扫描阶段的副作用。

## 输出内容和审计边界

成功的 `--output` 包含：

- `osv/osv-scanner`：已按固定 SHA-256 验证的 OSV-Scanner 二进制。
- `semgrep/`：隔离 venv，使用其 venv Python 调用 entry point 验证了 `1.181.0`。
- `bwrap/bwrap`：操作方提供文件的受限复制件。
- `database/osv-scanner/PyPI/all.zip`：离线 PyPI 快照。
- `tool-provisioning.json`：路径、版本、固定来源、hash、真实 `Last-Modified`、下载时间和预算记录。

**wheel-only 不等于完整 hash lock，也不等于作者 provenance。** 当前脚本拒绝源码分发，降低了在准备时执行构建代码的风险，但 wheelhouse 的所有依赖版本和每个候选平台 wheel 的 hash 仍需在输入时由审核流程固定。pip 的安全安装文档说明，完整 hash-checking 要求所有依赖都被精确固定并带有本地 hash；远程索引随下载 URL 提供的 hash 本身不能满足这一要求。[5] 同样，OSV 二进制 pin 与数据库的实测 hash 都不证明作者身份或构建来源。

生产环境必须从**已批准、不可变的镜像**或等效的受审核 artifact 集合部署，并将该镜像、wheelhouse、`bwrap` 源和本 manifest 纳入独立的供应链与变更审批。准备成功只说明这次输出符合脚本的固定输入和记录规则，不表示工具链已获得生产准入，也不表示扫描结果覆盖未知漏洞。

**References**

[1]: https://github.com/google/osv-scanner/releases/tag/v2.7.0 "OSV-Scanner v2.7.0 release"
[2]: https://google.github.io/osv-scanner/usage/offline-mode/ "OSV-Scanner offline mode"
[3]: https://pypi.org/project/semgrep/1.181.0/ "Semgrep 1.181.0 release files"
[4]: https://semgrep.dev/docs/cli-usage/ "Semgrep CLI metrics and version check environment"
[5]: https://pip.pypa.io/en/stable/topics/secure-installs/ "pip secure installs and hash checking"

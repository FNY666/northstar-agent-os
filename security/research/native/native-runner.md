# 原生只读扫描执行器：实测与边界

2026-10-17，Sandbox 中实际运行 bwrap 0.9.0、Semgrep 1.181.0、OSV-Scanner 2.7.0。此文件记录工程验证，不是生产环境的安全认证。

## 固定入口与物理边界

`run_native()` 只接受 `semgrep` 与 `osv-scanner`，没有任意命令、目标、URL 或追加参数接口。缺少真实 bwrap、命名空间或所需文件即拒绝，不降级为普通 process 并伪称隔离。

每次使用独立 user/PID/network/IPC/UTS namespace，UID/GID 65534，cap-drop ALL，实际设置 PR_SET_NO_NEW_PRIVS，禁用后续 user namespace。环境被清空，只重建公开运行字段；不继承 API key、代理、PYTHONPATH、LD_LIBRARY_PATH。不挂宿主 home、私钥、Git 配置、socket 或 host proc。`/usr` 作为公开只读运行库挂载，因此生产仍须受信不可变 runtime 镜像；本目录工具 hash 不等于整个宿主 runtime hash。

输入逐文件投影到新建 `/input`，文件只读、目录 0555，拒绝 symlink/hardlink/special files。Semgrep 的候选 `.semgrepignore` 不被允许，扫描视图使用宿主空 ignore 文件；策略只挂具体 YAML/TOML 文件。OSV 数据只挂一份 PyPI all.zip，不暴露父数据库目录。

## Semgrep 的真实兼容修复

`python -m semgrep` 在 1.181.0 已弃用并返回 2。普通 console wrapper 在本沙箱挂载组合下又遇到 packaged ELF 动态库定位失败。最终固定执行已安装发行物的 `semgrep-core`，使用受信 Linux dynamic loader 的局部 `--library-path` 和 `--argv0 osemgrep`；不向 Python 全局环境加入 LD_LIBRARY_PATH。

参数包含 `--experimental --config=/policy/semgrep.yaml --json --error --jobs=1 --metrics=off --disable-version-check --no-git-ignore --disable-nosem --no-rewrite-rule-ids`，后接显式源文件。`--error` 是发现→exit 1 的必要策略：本轮曾实际观察无该参数时有 finding 仍 exit 0，不能把零退出码作为安全证明。

native TLS 初始化需要一个公开 CA certificate bundle，单文件只读挂载；这不是私钥或宿主整个 /etc，也不解除禁网。未知/跳过/解析错误仍由 normalizer 拒绝。实际 JSON 额外包含 `engine_requested=OSS` 与空 `profiling_results`，兼容逻辑只放行该固定子集。未登录 OSS 的 fingerprint/lines 可能是 `requires login`，不能按这一占位符把不同位置的 finding 合并；使用 rule/path/位置严格去重。

## OSV 的实际数据库路径

宿主 prepared tree 保存 `db/osv-scanner/PyPI/all.zip`。v2.7.0 的实际组件消费路径却是 `/database/osv-scalibr/PyPI/all.zip`。runner 将**同一份经测量 archive**只读映射到该路径，并明确设置 OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY 与 OSV_SCALIBR_LOCAL_DB_CACHE_DIRECTORY，避免任何 host cache 回退。

命令固定 `scan source --lockfile=/input/requirements.txt --config=/policy/osv.toml --offline --no-resolve --no-call-analysis=all --no-ignore --all-packages --format=json`。不会下载 DB、解析传递依赖或执行 Rust build.rs 等构建代码。仅支持首版 exact-version requirements 的直接声明包，不提供其他生态扫描或包发行物存在性/完整性证明。

## 真实验证

固定隔离探针在同一后端实际运行，四项通过：写入 `/input` 被拒绝、宿主测试私密文件不可见、宿主 loopback socket 不可连接、假秘密环境变量被清除。没有读取真实用户凭据或攻击外部目标。

真实配对源码扫描中，正常五文件无发现，危险五文件产生 5 条 findings（包含 `# nosem` 抑制尝试），真实 gate 分别 pass/block。OSV 本地 snapshot 对正常 `wheel==0.46.3` 无发现，对危险 `requests==2.19.1` 产生 10 条 advisory。只统计当前冻结视图/快照，不承诺未来或未知漏洞不存在。

## 资源限制不可夸大

固定最大 stdout 2 MiB、stderr 1 MiB；超过即截断标记并终止 PID process group。宿主单调时钟 deadline、PID namespace 与进程组终止限制总墙钟运行时间。必须同时收到 bwrap 的 child 与 exit 状态，缺一不声明 completed。

继承 setrlimit：每进程地址空间 1 GiB、CPU 秒数等于超时值、文件 32 MiB、FD 128、NPROC 512、core 0；临时 tmpfs 有显式容量。CPU/AS 是每进程，NPROC 与当前 UID 相关，**这些不是 cgroup 的进程树总 CPU/内存/进程数预算**。metadata 的 cgroup_aggregate_budget=not-configured 如实保留。生产需独立受信 runner、不可变 root image 与聚合资源控制，不能以本地测试替代部署准入。

`native_tests/test_native_runner.py` 是固定命令/环境/路径/上限/拒绝逻辑的单元回归；真实内核与 scanner 联调来自 `examples/run_native_smoke.py`，二者不能混称。

# Loon 远程规则镜像（takedown backup）

本目录是 Loon 配置中引用的上游远程 `.list` 规则文件的镜像备份，
防止上游仓库被下架（takedown）导致配置里的远程规则加载失败。

## 目录结构

- `blackmatrix7/` — 来自 https://github.com/blackmatrix7/ios_rule_script 的 Loon 规则
  （`rule/Loon/<Service>/<Service>.list`，master 分支）
- `acl4ssr/` — 来自 https://github.com/ACL4SSR/ACL4SSR 的规则
  （`Clash/ChinaDomain.list`、`Clash/BanAD.list`、`Clash/LocalAreaNetwork.list`，master 分支）
- `ttyyss2233/` — 来自 https://github.com/ttyyss2233/Tool 的规则
  （`shadowrocket/rules/apns.list`，main 分支）

## 来源清单

完整"镜像文件 → 上游 URL"映射见 `SOURCES.tsv`（制表符分隔：`mirror_path<TAB>upstream_url`）。

## 同步机制

每周自动同步一次上游：`cron: loon-rules-mirror-sync`。
- 上游有更新 → 拉取新版并提交推送。
- 上游被下架/下载失败 → 保留本地最后可用版本，不覆盖。
- 同步只动本目录文件，不碰仓库其他内容。

## 在 Loon 配置中的引用形式

```
https://raw.githubusercontent.com/FNY666/northstar-agent-os/main/rules/loon/<upstream>/<File>.list
```

例如：`.../rules/loon/blackmatrix7/OpenAI.list`

注意：本目录文件为第三方规则的原样镜像，版权归原作者所有，
仅作可用性备份用途。

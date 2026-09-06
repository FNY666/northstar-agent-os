# Northstar Agent OS

**面向自主 AI 同事的开放、可靠、可治理运行时组件。**

> 中文名：北辰智能体系统

[English](../README.md) · [简体中文](README.zh-CN.md) · [繁體中文](README.zh-TW.md) · [日本語](README.ja.md) · [Español](README.es.md) · [한국어](README.ko.md) · [Français](README.fr.md) · [Deutsch](README.de.md) · [Português (Brasil)](README.pt-BR.md) · [Italiano](README.it.md) · [Türkçe](README.tr.md) · [Tiếng Việt](README.vi.md)

**一句話說明：** Northstar 是獨立維護的專案，用來把明確的模型路由、本地工具邊界、可稽核性與可復原執行組合成受治理的 AI 同事執行環境。**目前真正發布的是 Northstar Codex Sidecar——受限制的本地工作器適配器，而不是已完成的自主智能體作業系統。**

> English is the canonical project entry. Translations mirror its scope and security claims; update them when the canonical README changes.

## 它是什麼

Northstar 面向希望 AI 同事在清楚邊界內運作的開發者，而不是讓系統停留在不受約束的「提示詞加工具」循環。專案聚焦於小型、可測試的構件：呼叫方可見的契約、受限制的執行、結構化結果與可復原的運維流程。

專案採取漸進式建設。單一元件可以獨立使用，但元件測試通過並不代表完整智能體平台安全或已可用於生產環境。

## 目前發布了什麼

本儲存庫目前發布三個元件：

- `../components/northstar-codex-sidecar/` — 本地 Unix socket 服務，負責驗證請求，以 read-only 模式執行 Codex，限制輸入與輸出、脫敏錯誤、清理逾時程序群組，並回傳結構化狀態。
- `../components/northstar-run-contract/` — 版本化的 Run Request/Receipt 合約、帶有效期的 HMAC Run Binding，以及把已驗證執行交給 Sidecar 的嚴格適配邊界。
- `../components/northstar-agent-runtime/` — 受治理的智能體迴圈：事件流、十個生命週期鉤子、三層權限閘、輪次／工具呼叫／美元預算三項獨立上限、子智能體、僅追加工作階段、只在安全邊界壓縮、以及 span 級追蹤。它不持有模型憑證，也不啟動模型 CLI：Codex 執行透過 Unix socket 委託給 Sidecar。

儲存庫也提供確定性測試、systemd 強化範本、保守的安裝腳本與回滾腳本。

## Sidecar 如何運作

Sidecar 為每個 Unix socket 連線接收一個 JSON 請求：

```json
{"request_id":"demo-1","prompt":"Reply with OK","timeout_ms":10000}
```

回傳一個有界限的 JSON 回應：

```json
{"request_id":"demo-1","status":"ok","text":"OK"}
```

主要特性：

- 僅使用 Unix socket，不提供 TCP 監聽器。
- 嚴格請求白名單：`request_id`、`prompt`、`timeout_ms`。
- 限制 prompt 與逾時時間。
- Codex 使用 `--sandbox read-only` 與 `--ephemeral` 執行。
- 獨立程序群組，逾時時先 TERM、再 KILL 清理。
- 每個連線都有讀取截止時間，並使用有上限的工作器池。
- 結構化錯誤分類與敏感資訊脫敏。
- 專用服務使用者與 systemd 強化範本。
- 只有主機管理員明確安裝並啟用服務後，Codex 才會執行。

## 快速開始

要求：

- Linux 與 Python 3.10 或更新版本。
- 已單獨安裝、且服務使用者可以執行的 `codex` 程式。
- 用於所提供服務單元的 systemd。
- 專用的非特權服務使用者與工作區。

在元件目錄執行本地驗證：

```sh
cd components/northstar-codex-sidecar
python3 -m py_compile sidecar.py transport.py service.py sidecar_socket.py
python3 -m unittest discover -s tests -p 'test_*.py' -v
sh -n install.sh rollback.sh
```

若要查看並安裝保守的服務生命週期：

```sh
sudo ./install.sh
sudo systemctl enable --now northstar-codex-sidecar.service
```

預設從 `PATH` 尋找 Codex；主機使用非標準路徑時可明確設定 `CODEX_BIN`。啟用前請審閱腳本、服務使用者、路徑與權限。

## 適用對象

Northstar 適合建構本地或自託管 AI 同事執行環境的開發者與運維人員，他們需要一個可測試、可稽核、可停用、可回滾的窄範圍執行元件。它不是託管 AI 產品、不是一鍵安全保證，也不能取代完整的身分、策略、工作區與可觀測性架構。

## 它不是什麼

- 它還不是完整的多智能體作業系統。
- 它不是託管服務，也不代表已具備生產就緒性。
- 它不是通用 shell 執行 API。
- 它不會單獨完成呼叫方授權、每次執行隔離或父級取消傳播。
- 它不包含 Codex 憑證，也不提供 Codex 帳號。

**Not a complete autonomous-agent platform.**

## 與 OpenBot 的關係

Northstar 是獨立維護、面向 OpenBot 相容場景的專案。它不隸屬於 OpenBot 或 CopilotKit，也未得到它們及其維護者的官方認可。Sidecar 的設計目標是接入 OpenBot 風格的執行環境，但不聲稱屬於上游 OpenBot 儲存庫。

「相容」只表示整合目標，不表示所有權、背書或安全等價。

## 安全邊界

Sidecar 僅透過 Unix 權限驗證呼叫方。生產整合還必須提供：

- 呼叫方授權與身分繫結；
- 按執行或按參與者隔離工作區；
- 從父執行環境傳播取消訊號；
- 不記錄敏感 prompt 的結構化可觀測性；
- 健康檢查與回滾流程；
- 原生 Linux 並發及程序樹驗證；
- 審查 Codex 自身帳號、網路與工具配置。

不要透過 TCP 代理暴露 Unix socket。不要提交 API key、OAuth token、Codex 登入狀態、私鑰、生產 `.env` 檔案或使用者 transcript。

## 專案狀態

這是 Northstar 的首個公開元件。更大的 Northstar Agent OS 執行環境仍在逐步建設。執行環境身分繫結、按執行授權工作區、取消傳播、原生 Linux 端到端驗證與生產部署整合，仍屬於主機側責任或未來工作。**未完成的自主智能體平台不能被當作已完成專案。**

程序群組清理應在目標原生 Linux 發行版上驗證；行動 Linux 環境中的訊號與 PID 回收行為不一定具有代表性。

## 貢獻與維護

請查看 [CONTRIBUTING.md](../CONTRIBUTING.md) 了解證據、測試、安全、相容性與回滾要求；安全問題請查看 [SECURITY.md](../SECURITY.md)。English is the canonical source for project scope; translations should be updated when it changes.

## 授權條款

MIT，見 [LICENSE](../LICENSE)。

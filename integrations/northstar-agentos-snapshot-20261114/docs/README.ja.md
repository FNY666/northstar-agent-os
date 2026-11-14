# Northstar Agent OS

**自律型 AI コワーカーのための、オープンで信頼でき、ガバナンスされたランタイムコンポーネント。**

[English](../README.md) · [简体中文](README.zh-CN.md) · [繁體中文](README.zh-TW.md) · [日本語](README.ja.md) · [Español](README.es.md) · [한국어](README.ko.md) · [Français](README.fr.md) · [Deutsch](README.de.md) · [Português (Brasil)](README.pt-BR.md) · [Italiano](README.it.md) · [Türkçe](README.tr.md) · [Tiếng Việt](README.vi.md)

**一言で言うと：** Northstar は、明示的なモデルルーティング、ローカルツールの境界、監査可能性、復旧可能な実行を組み合わせ、ガバナンスされた AI コワーカーを構築するための独立プロジェクトです。**現在公開されているコンポーネントは、制限付きのローカル worker アダプターである Northstar Codex Sidecar です。完成した自律型エージェントプラットフォームではありません。**

> English is the canonical project entry. Translations mirror its scope and security claims; update them when the canonical README changes.

## これは何か

Northstar は、制限のないプロンプトとツールのループではなく、AI コワーカーを明確な境界の中で動かしたい開発者向けの、コンポーネント指向ランタイムプロジェクトです。呼び出し側から確認できる契約、制約付き実行、構造化された結果、運用上の復旧という、小さくテスト可能な構成要素に重点を置いています。

このプロジェクトは段階的に構築されています。単独で役立つコンポーネントであっても、そのテストが通っただけで、完全なエージェントプラットフォームの安全性や本番運用への適合性を証明することはできません。

## 現在公開されているもの

このリポジトリで現在公開しているコンポーネントは 1 つです。

- `../components/northstar-codex-sidecar/` — リクエストを検証し、Codex を read-only モードで実行し、入出力を制限し、エラーを秘匿化し、タイムアウトしたプロセスグループを後処理して、構造化された状態を返すローカル Unix socket サービス。
- 決定論的テスト、systemd の hardening テンプレート、慎重なインストーラー、rollback スクリプト。

## Sidecar の仕組み

Unix socket の 1 接続につき、JSON リクエストを 1 つ受け付けます。

```json
{"request_id":"demo-1","prompt":"Reply with OK","timeout_ms":10000}
```

レスポンスは上限のある JSON オブジェクトです。

```json
{"request_id":"demo-1","status":"ok","text":"OK"}
```

主な特徴：

- Unix socket のみを使用し、TCP リスナーは提供しません。
- 厳格なリクエスト許可リスト：`request_id`、`prompt`、`timeout_ms`。
- prompt と timeout に上限があります。
- Codex は `--sandbox read-only` と `--ephemeral` で実行されます。
- 独立したプロセスグループを使い、timeout 時には TERM、その後 KILL で後処理します。
- 接続ごとの読み取り期限と、上限付き worker pool。
- 構造化されたエラー分類と秘密情報の秘匿化。
- 専用サービスユーザーと systemd hardening テンプレート。
- 管理者が明示的にサービスをインストールして有効化するまで、Codex は無効です。

## クイックスタート

必要条件：Linux、Python 3.10 以降、サービスユーザーから実行できる別途インストール済みの `codex` 実行ファイル、systemd、専用の非特権サービスユーザーと workspace。

```sh
cd components/northstar-codex-sidecar
python3 -m py_compile sidecar.py transport.py service.py sidecar_socket.py
python3 -m unittest discover -s tests -p 'test_*.py' -v
sh -n install.sh rollback.sh
```

有効化する前に、スクリプトとサービスアカウント、パス、権限を確認してください。

```sh
sudo ./install.sh
sudo systemctl enable --now northstar-codex-sidecar.service
```

Codex の実行ファイルはデフォルトで `PATH` から解決されます。標準ではないパスを使用する場合は `CODEX_BIN` を設定してください。

## 対象ユーザー

Northstar は、テスト、監査、無効化、rollback が可能な限定的実行コンポーネントを必要とする、ローカルまたは self-hosted の AI コワーカーランタイム開発者・運用者向けです。ホスト型 AI 製品でも、自動的な安全保証でも、完全な identity・policy・workspace・observability アーキテクチャの代替でもありません。

## これは何ではないか

- まだ完成した multi-agent オペレーティングシステムではありません。
- ホスト型サービスでも、本番対応を保証するものでもありません。
- 汎用 shell 実行 API ではありません。
- 呼び出し元を単独で認可したり、すべての run を分離したり、親からの cancellation を自動伝播したりはしません。
- Codex の認証情報を含まず、Codex アカウントも提供しません。

**完成した自律型エージェントプラットフォームではありません。**

## OpenBot との関係

Northstar は独立したプロジェクトで、OpenBot-compatible な統合を対象としています。OpenBot、CopilotKit、またはそのメンテナーとは提携しておらず、公式な承認も受けていません。Sidecar は OpenBot 形式のランタイムに統合できますが、upstream の OpenBot リポジトリの一部であるとは主張しません。

Compatibility は統合対象を示すものであり、所有権、推奨、セキュリティ上の同等性を意味しません。

## セキュリティ境界

Sidecar は Unix 権限だけで呼び出し元を認証します。本番統合では、呼び出し元の認可と identity binding、run または actor ごとの workspace 分離、親からの cancellation 伝播、機密 prompt を記録しない observability、health check と rollback、native Linux での並行性とプロセスツリーの検証、Codex のアカウント・ネットワーク・ツール設定のレビューも必要です。

Unix socket を TCP proxy 経由で公開しないでください。API key、OAuth token、Codex login state、private key、本番 `.env` ファイル、ユーザー transcript をコミットしないでください。

## プロジェクトの状態

これは Northstar の最初の公開コンポーネントです。より広い Northstar Agent OS ランタイムは段階的に開発されています。ランタイムの identity binding、run ごとの workspace 認可、cancellation 伝播、native Linux での end-to-end 検証、本番デプロイ統合は、ホスト側の責任または今後の作業として残っています。**このリポジトリは完成した自律型エージェントプラットフォームではありません。**

プロセスグループの後処理は対象となる native Linux ディストリビューションで検証してください。モバイル Linux のシグナルと PID 回収の動作は、代表的とは限りません。

## コントリビューションとメンテナンス

証拠、テスト、セキュリティ、互換性、rollback の要件は [CONTRIBUTING.md](../CONTRIBUTING.md) を参照してください。セキュリティ報告は [SECURITY.md](../SECURITY.md) を参照してください。English is the canonical source for project scope; translations should be updated when it changes.

## ライセンス

MIT。[LICENSE](../LICENSE) を参照してください。

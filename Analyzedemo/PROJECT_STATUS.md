# プロジェクト進捗

最終更新: 2026-10-20

## 現在の状態

- 対象: AI支援型サイバー攻撃検知・説明システム
- 実装場所: `FinalReport/team2_project/`
- 全体状態: Copilot利用フラグ有効（CLIサインイン・イベントごとの同意・実モデル呼び出し待ち）
- ローカルダッシュボード: 起動中、`http://127.0.0.1:8501`（health endpoint: HTTP 200）
- 作業方針: `MASTER_PROMPT.md` を要件仕様として扱い、要件ごとに実装と検証を行う。
- 変更前の状態: 対象フォルダーには仕様書とアウトラインのみ。ワークスペース全体は未コミット・未追跡ファイルが多いため、他のファイルを変更・削除しない。

## チームと担当案

| メンバー | GitHub | 担当案 | 貢献記録 |
|---|---|---|---|
| 山内光 | [Ko-Yamauchi](https://github.com/Ko-Yamauchi) | イベントモデル、入力検証、ルール検知、ローカル統計型AI検知 | 実作業の証跡未記録 |
| 石川涼太 | [ryota713](https://github.com/ryota713) | Streamlitダッシュボード、インポート/エクスポート、画面テスト | 実作業の証跡未記録 |
| 後藤妙恵 | [taegoto](https://github.com/taegoto) | サニタイズ、任意のCopilot SDK統合、評価、プライバシー文書 | 実作業の証跡未記録 |

氏名とユーザー名はユーザー提供値。プロフィールや貢献履歴を独立検証したものではない。担当案は実装計画であり、本人が実施した作業を示すものではない。実際の完了タスク、コミット、PR、テスト結果のみを `CONTRIBUTIONS.md` に記録する。

## フェーズ

| フェーズ | 内容 | 状態 | 完了条件 |
|---|---|---|---|
| 0 | 仕様・ワークスペース・チーム情報・実行環境の確認 | 完了 | 仕様を通読し、3名の情報を取得。Python/依存/Dockerの状態を確認 |
| 1 | イベントモデル、検証、サニタイズ、ルール検知、ローカルAI検知 | 完了 | 正常/不審/二重エンコード/誤検知候補/反復認証/AI失敗を含むテスト通過 |
| 2 | SQLite、CSV/JSON入出力、評価指標 | 完了 | 入力制限、重複、機密値、数式注入、保存/読み戻し、3検知チャネル比較をテスト |
| 3 | Streamlitダッシュボード | 完了 | 空状態、合成イベント、全ページ、手動検知、UTC期間/カテゴリ/source/severity表示をAppTestで確認 |
| 4 | 任意Copilot SDK説明、設定、エラー処理 | 実装完了・実Copilot呼び出し未検証 | 空モード/ツールなし、最小化/サニタイズ、timeout、認証失敗/ランタイム/空応答を6件のモックテストで検証 |
| 5 | Docker/Juice Shop、モックデモ、文書、CI、全体検証 | 部分完了（環境制約） | README/合成データ/CI/loopback限定Composeを作成。Compose/CI YAMLを構文確認。Docker実行とGitHub Actions実行は未検証 |

## 環境確認

- Python: 3.14.3
- 利用可能: pytest、ruff、streamlit、pandas、github-copilot-sdk、python-dotenv
- scikit-learn: 未導入。初期のローカルAI検知は追加の重い依存を避けた統計方式を採用する。
- 最終テスト: `python -m pytest -q` で25 passed。
- 最終Lint: `ruff check .` でAll checks passed。
- VS Code診断: プロジェクト内のエラーなし。
- UI操作: Streamlit AppTestで空状態、合成イベント登録、全ナビゲーション画面、イベント詳細、手動SQLi例を確認。Copilotは既定無効でボタンが隠れ、設定有効化と同意後のみボタンが表示されることを確認。説明ボタンは押していない。
- Compose/CI設定: PyYAMLで両YAMLを解析。Composeは`bkimminich/juice-shop:v20.3.0`、`127.0.0.1:3000:3000`を確認。
- Docker: コマンド未検出。Compose/Juice Shopの実行確認はDockerが使える環境で別途必要。モックイベントモードはDockerなしで検証する。
- 再開手順の再確認（2026-10-19）: Git対象ディレクトリはクリーン。Docker CLIと標準インストール先のDocker Desktopは見つからず、port 3000は未使用。Docker未導入のためCompose起動/停止は実施不能で、他ファイルは変更していない。
- Copilot SDK: `github-copilot-sdk`を導入。説明ロジック、空モード/ツールなし、利用者向けエラー処理を6件のモックテストで検証。`.env`の`COPILOT_ENABLED=true`、`COPILOT_MODEL=auto`を確認し、`.env`はGitignore対象。Copilot CLI 1.0.98を導入済み。CLIサインイン、初回ランタイム取得、実モデル要求は未実施。Copilot利用枠/モデル倍率はアカウントごとに未確認。
- CI: GitHub Actionsは設定済み。リポジトリにpushしていないためGitHub上でのジョブ実行は未確認。Python 3.11はCI対象だが、この環境での実行は未確認。
- SettingsのCopilot同意チェックは未選択。外部Copilot要求、利用枠消費、公開、GitHubへのpushは実施していない。Copilotを使う際は新しいターミナルでローカルCLIにサインインし、利用枠を確認してからイベント単位で明示的に要求する。

## 再開手順

1. このファイルと `MASTER_PROMPT.md` を読み、未完了フェーズと未検証項目を確認する。
2. `FinalReport/team2_project/` 内だけを変更し、ワークスペースの既存未追跡ファイルを保持する。
3. Dockerが使える環境で`docker compose --profile demo up -d`を実行し、localhostへの起動/停止を検証する。
4. Copilotを試す場合は、Copilotプラン/利用枠を再確認し、ユーザーがローカルCLIでサインインしたうえで`.env`の`COPILOT_ENABLED=true`を設定し、合成イベントで説明を手動要求する。初回SDKランタイム取得のため外部通信が必要になる場合がある。
5. GitHub Actionsはユーザーが許可したリポジトリへpushした後に実行確認する。pushや公開はこの作業では行わない。
6. 実際のチームメンバー作業を確認できたら、Commit/PR/テスト証跡とともに`CONTRIBUTIONS.md`へ追記する。既存の未記録を推測で埋めない。
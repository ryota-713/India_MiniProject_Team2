# AI支援型サイバー攻撃検知・説明システム

合成イベントや許可されたローカル観測データを、ルールベース検知とローカル統計型AI検知の両方で調べる教育用デモです。検知結果は攻撃成功や侵害の証明ではありません。認定IDSとして使用しないでください。

## 起動

Python 3.11以降を用意し、プロジェクトディレクトリで実行します。

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
streamlit run app.py --server.address 127.0.0.1
```

ブラウザーで `http://127.0.0.1:8501` を開きます。初期状態ではイベントを自動生成しません。Overviewの「合成デモイベントを読み込む」を押すと、明示的に合成データを登録して検知を試せます。

## デモの流れ

1. Overviewで合成イベントを読み込み、severity/source/category/dateのフィルターとイベント詳細を確認します。
2. Import & Testで合成CSV/JSONを取り込むか、手動イベントをローカル分析します。Request bodyは取り込みません。
3. Detection Rulesで各検知ルールの目的と制限を確認します。
4. Evaluation & Reportsで合成ラベル付きイベントに対するRules / Local statistical AI / HybridのPrecision、Recall、F1、False Positive Rate、混同行列を比べ、JSON/CSVを出力します。
5. Copilotを使う場合は、下記のデータ送信条件を読み、ローカルCLIを認証し、UI上で同意してからイベントごとに手動実行します。

## 入力データ

JSONはイベント配列、または`events`配列を持つオブジェクトです。CSVは同じフィールド名のヘッダーを使います。

| フィールド | 必須 | 形式 |
|---|---|---|
| `event_id` | 任意 | 64文字以内。省略時は入力内容から決定的なIDを生成 |
| `timestamp` | 必須 | タイムゾーン付きISO-8601 |
| `source` | 必須 | 100文字以内のイベント起源 |
| `method` | 任意 | 大文字ASCII 1〜16文字 |
| `path` | 必須 | `/`で始まる2048文字以内のpath/route |
| `status_code` | 任意 | 100〜599の整数 |
| `user_agent` | 任意 | 512文字以内 |

Request body、Cookie、Authorization headerなどの未定義フィールドは拒否します。ファイルはUTF-8、最大5 MiB、最大10,000イベントです。パスワード/token等の一般的な形式はマスキングしますが、サニタイズが全ての機密値を見つける保証はありません。実データを使う場合は利用者が送信前に確認してください。

サンプルと評価データは `data/sample_events.json` と `data/labeled_evaluation.json` にあります。どちらも合成データです。

## 検知と評価の読み方

- SQLi/XSS/Path traversal/認証失敗反復をルールで検知し、ルールIDと根拠を返します。
- ローカル統計AIは固定の正常形状ベースラインに対するrobust median/MAD偏差を調べます。最大偏差を0〜1に正規化した表示スコアは確率ではありません。
- `Hybrid`はルールまたはローカルAIのどちらかが要確認としたイベントをまとめて表示します。各方式の判定・根拠・不一致は別々に保持します。
- ベースラインとラベル付き評価セットは小規模な合成例です。表示される指標を実運用性能として解釈しないでください。未知の正常経路が異常扱いされる場合があります。
- `AUTH-REPEAT-001`は同じsourceから5分以内に401/403が5件以上ある場合に一致します。共有sourceでは誤検知があり得ます。

## Copilot SDK説明（任意）

説明生成にはGitHub公式の[Copilot SDK](https://github.com/github/copilot-sdk)のPythonパッケージ`github-copilot-sdk`を使います。SDKはCopilot CLIランタイムをアプリから呼び出し、ローカルのCopilot CLIログインを利用します。SDK初回実行時にランタイムがダウンロードされる場合があります。

GitHub Copilot CLIをインストールしてユーザー自身のGitHubアカウントでサインインしてください。SDKの利用にはCopilotプランと利用枠が必要です。要求の使用量やモデル倍率はプラン・モデルにより異なり変更されるため、[Copilotプラン](https://github.com/features/copilot/plans)と[利用量・課金情報](https://docs.github.com/en/copilot/concepts/billing/copilot-requests)を事前に確認してください。無制限または無料の利用を前提にせず、BYOKなど別プロバイダーへ自動で切り替えることもありません。

設定はローカルの`.env`だけに保存します。

```powershell
Copy-Item .env.example .env
```

`COPILOT_ENABLED=true`で機能を有効化し、必要に応じて`COPILOT_MODEL`を設定します。GitHubトークンや個人アクセストークンを`.env`に貼り付けないでください。認証はローカルのCopilot CLIログインを使います。Settingsで同意しても送信は始まらず、Overviewで特定イベントの説明ボタンを押した場合だけCopilotへ要求します。

送信するのはサニタイズ済みpath、method/status、ルール根拠、ローカル統計AIの判定です。Source、User-Agent、Request bodyは送信しません。SDKセッションは`mode="empty"`かつツールなしで作成し、shell/file/MCP等の操作ツール、session store、memory、skills、telemetryを無効化します。処理はタイムアウトを設定し、再試行しません。成功した説明だけをプロセス内でキャッシュします。Copilotへ送信したプロンプトはGitHub Copilotサービスで処理されるため、実データの送信は避け、合成イベントでデモしてください。説明は仮説であり、検知根拠ではありません。

Copilotを有効にしなくても、ルール検知、ローカル統計AI、ダッシュボード、評価、レポートは動作します。

## Juice Shop（任意）

Docker Desktopが利用できる場合にだけ起動します。ComposeはOWASP Juice Shop `v20.3.0`を固定し、ホストのloopback `127.0.0.1:3000`だけに公開します。

```powershell
docker compose --profile demo up -d
```

`http://127.0.0.1:3000`でアクセスできます。このプロジェクトはJuice Shopへの攻撃、スキャン、リクエスト自動送信、全通信の自動監視を実装していません。Juice Shopのログを自動収集する機能もありません。明示的に許可されたローカルデモデータだけを扱ってください。終了するには`docker compose --profile demo down`を実行します。

Dockerが使えない場合はComposeを起動せず、同梱の合成イベントでデモできます。

## 検証

```powershell
ruff check .
python -m pytest -q
```

GitHub ActionsはPython 3.11/3.14で同じ品質チェックを実行します。SQLiteはデフォルトで`data/events.sqlite3`に検知結果を保存します。保持期間は自動設定していません。削除が必要な場合はアプリを停止し、対象DBファイルを確認してから手動で削除してください。

## 制限とプライバシー

- デフォルトのダッシュボードは127.0.0.1だけで起動します。公開ネットワークにbindしないでください。
- 検知は教育用パターン判定であり、攻撃の成否、侵害、システム全体の安全性は判断しません。
- 正規化・ルール・統計ベースラインには限界と誤検知があります。小規模合成データの評価値は一般化できません。
- Copilot説明を有効化すると、上記のサニタイズ済み最小フィールドがGitHub Copilotサービスへ送信されます。送信先の規約とプランの利用条件を確認してください。
- AIが生成した文章やイベント内の文字列を、シェルコマンドや実行可能コードとして扱いません。
- 今回確認した実行環境にはDockerがありません。Juice Shop Composeの起動・停止は未検証です。Copilot CLIの認証もしていないため、Copilotサービスへの実通信は未検証です。

再開時は[PROJECT_STATUS.md](PROJECT_STATUS.md)の未完了フェーズと検証制約を確認してください。チームの実貢献は[CONTRIBUTIONS.md](CONTRIBUTIONS.md)に証跡を伴って記録します。
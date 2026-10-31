# ARO

[English](README.md) · [한국어](README.ko.md) · [日本語](README.ja.md) · [简体中文](README.zh-CN.md)

AROは、LinuxまたはWindowsサーバーを運用する開発者向けのエージェントスキルです。
ローカルのソフトウェア一覧を毎回更新し、関連するセキュリティ勧告を確認して、実際の
リスクを短く説明し、承認できる具体的な更新計画を作成します。

**Python 3.11以上**が必要です。コアはPython標準ライブラリのみを使用し、Bashと
PowerShellのランチャーを同梱しています。前提ソフトウェアや任意のスキャナーを
自動インストールすることはありません。

## インストール

Node.js/npmが利用できる場合は、[Skills CLI](https://github.com/vercel-labs/skills/blob/main/docs/commands.md)を使います。

```bash
npx skills add HHC225/ARO --skill aro
```

インストーラーでエージェントとインストール範囲を選択します。`SKILL.md`を読み、
ローカルでPythonを実行できるエージェントなら、プロジェクトディレクトリから
次のように手動でコピーすることもできます。

```bash
git clone https://github.com/HHC225/ARO.git
mkdir -p .agents/skills
cp -R ARO/skills/aro .agents/skills/aro
```

クライアントに応じて`.agents/skills`を`.claude/skills`または`.codex/skills`に
置き換えてください。スクリプトと参照文書を含む`skills/aro`の**フォルダー全体**を
コピーします。コピーせずにリポジトリから直接実行することもできます。Windows
PowerShellの場合:

```powershell
git clone https://github.com/HHC225/ARO.git
New-Item -ItemType Directory -Force .agents/skills | Out-Null
Copy-Item -Recurse ARO/skills/aro .agents/skills/aro
```

インストールでは外部コードをダウンロードするため、使用前に確認してください。
Skillsインストーラーの動作やテレメトリ設定は、AROスキャナーとは別です。
ChatGPT専用のインストールは不要です。

## エージェントで使う

**「$aroでこのサーバーとアプリを確認し、リスクを短く説明して、私が承認する
更新計画を作って」**と依頼してください。スキルの指示は英語ですが、エージェントは
希望する言語で結果を説明できます。

初回の確認で永続的なソフトウェア一覧を作成します。その後も毎回調査し直し、
追加・削除・バージョン変更を記録します。結果は**コンポーネント · 現在 → 修正
バージョン · 実際のリスクと理由 · 出典リンク**の短い行で示します。バージョン不明、
公開範囲不明、情報源の失敗も結果の制約として明示します。非公開の出所が判明している
npm/Cargo/Python項目は、未選択の根拠としてローカル一覧に保持し、外部照会しません。

## 直接実行する

`check --refresh`は有効なキャッシュがあっても最新のアドバイザリを再取得します。`--offline`とは併用できません。

リポジトリから実行します。

```bash
python3 skills/aro/scripts/aro.py check --root /srv/my-app
python3 skills/aro/scripts/aro.py check --root /srv/my-app --format json
bash skills/aro/scripts/aro.sh check --root /srv/my-app
```

Windowsでは必要に応じてPython 3.11以上を`python`または`py -3`で実行します。

```powershell
python skills/aro/scripts/aro.py check --root C:/apps/my-app
powershell -File skills/aro/scripts/aro.ps1 check --root C:/apps/my-app
```

コピーしてインストールした場合は、上のパスを実際の配置先に変更してください。

| コマンド | 用途 |
| --- | --- |
| `init` / `scan` | 勧告を問い合わせず、ソフトウェア一覧のみ更新 |
| `check` | 再調査し、関連する勧告を確認 |
| `sources` | 検出したソフトウェア向けに選択された情報源を表示 |
| `config --show` | 有効な設定を表示 |
| `exposure` | 確認済みのネットワーク情報やコンポーネントへの到達性を記録 |
| `plan --finding ID --target-version VERSION` | 範囲を限定した正確な更新計画を保存 |
| `apply --plan PATH --approve HASH` | 事前検証後に、その承認済み計画を実行 |

`--root PATH`は複数指定でき、指定したパスは設定に保存されます。保存済みのパスが
なければ、現在のディレクトリと一般的なアプリの配置先を、ファイル数・深さ・時間の
上限内で探索します。予測可能な調査範囲が必要ならパスを明示してください。
`--state-dir PATH`で保存先を指定し、`check --offline`で外部問い合わせなしに
キャッシュを使い、`--format json`で詳細な構造化結果を取得できます。

`check --fail-on high`、`critical`、`any`、`none`で検出結果の失敗基準を選べます。
既定値は`none`です。終了コードは、`0`が基準未満で完了、`1`が基準に該当する検出、
`2`がエラーまたは不完全な確認、`3`が承認や古い計画の拒否です。不完全な確認の
状態を優先します。検出がなくても、調査範囲を確認してください。

## 調査範囲と制約

アクセス可能なOS/パッケージ管理メタデータ、ランタイム、プロセス、待受ポート、
対応するプロジェクトのmanifest/lockfile、Dockerメタデータを収集します。
導入済みの**Syft**と**Trivy**は、対応するSBOMやディストリビューション別の
ホスト/コンテナー調査を補います。ツール不足、権限エラー、探索上限、バージョン不明は
調査の欠落として示します。独自バイナリやコンテナー内の全パッケージの検出は
保証しません。

検出したソフトウェアに応じて、エコシステムの勧告、悪用実績、該当するベンダー/
ディストリビューション/ランタイムの根拠を選択します。正確なアダプターは
[情報源の文書](skills/aro/references/sources.md)と`sources`の結果を参照してください。
ディストリビューションのバックポート修正は、上流のバージョン番号との比較ではなく、
ディストリビューション側の根拠で評価します。CVE番号がない勧告も対象になります。

両プラットフォームの実装範囲は、利用可能なメタデータとツールによって制限されます。

| 対象 | プラットフォームと対応する根拠 | 勧告の情報源 / 制約 |
| --- | --- | --- |
| Linux OS | dpkg、RPM、apkのパッケージメタデータ | 対応Debian/Ubuntuリリースはネイティブなソースパッケージ/バージョンでOSVを直接照会し、バックポートを保持。他のディストリビューションは任意のTrivy。非対応リリースは欠落を明示。 |
| Windows OS | OS/build、導入済みソフトウェア、更新メタデータ | Windows Update Agentによる適用可能な未導入セキュリティ更新の読み取り専用検索。設定された更新サービス/ポリシーに依存し、OS更新の導入は手動。 |
| Pythonプロジェクト | Linux/Windows: 固定版の`requirements*.txt`、`Pipfile.lock`、`poetry.lock`、`uv.lock`、導入済み配布メタデータ | OSV PyPI。未解決のmanifest範囲は欠落。 |
| JavaScriptプロジェクト | Linux/Windows: `package-lock.json`、`npm-shrinkwrap.json` | OSV npm。Yarn/pnpmのlockfile用ネイティブパーサーはなし。 |
| その他のlockfile | Linux/Windows: `Cargo.lock`、`go.mod`/`go.sum`、`composer.lock`、`Gemfile.lock`、`packages.lock.json`/`project.assets.json`、正確な`gradle.lockfile`座標 | OSV crates.io、Go、Packagist、RubyGems、NuGet、Maven。解決済みlockがないMaven/Gradle manifestは欠落。完全なMaven resolverではない。`go.sum`だけでは現在選択された依存関係を証明しない。 |
| ランタイム | 確認可能なPython、Node.js、Goなどのバージョン | 公式CPython/Node/Go情報。PHP/Ruby/.NET/Rustのリポジトリフィードは部分的。JDKベンダー照合は非対応。ディストリビューション版はバックポートの確認が必要。 |
| コンテナー / SBOM | アクセス可能なDockerメタデータと導入済みSyft/Trivy | 任意の詳細調査とローカルの不変イメージIDのOS検出。ローカルデーモンと利用可能なスキャナーDBが必要で、完全なイメージ調査は保証しない。 |

CISA KEVは正確なCVE識別子で既知の悪用情報を追加します。未掲載は悪用がない証明では
ありません。Windows WUA検索は更新をダウンロード・導入せず、完全なMSRC CVEの適用性
判定エンジンでもありません。

**CGNATは安全の証明ではありません。** IPv6、トンネル、リバースプロキシ、ポート転送、
LAN経由のアクセス、ローカル権限昇格、ユーザー操作を伴う攻撃も関係します。
公開範囲が不明な場合は明示し、ホスト全体の観察を全コンポーネントの到達性に
自動適用しません。受信経路の制限だけでは外向きクライアントのリスクを下げず、
優先度の引き下げには、その検出に固有の新しい受信サービス攻撃経路の根拠も必要です。
確認済みの事実だけを記録してください。

```bash
python3 skills/aro/scripts/aro.py exposure --cgnat confirmed --public-ipv4 no --public-ipv6 no --inbound-forwarding no --tunnels no
```

## 具体的な計画を承認して更新

現在の検出結果と正確な対象バージョンから計画を作ります。

```bash
python3 skills/aro/scripts/aro.py plan --finding FINDING_ID --target-version VERSION
python3 skills/aro/scripts/aro.py apply --plan /path/to/plan.json --approve FULL_PLAN_HASH
```

`apply`の前に、計画内の正確な引数、対象、依存関係への影響、作業ディレクトリ、
一覧のハッシュ、有効期限、復旧の制約を確認します。承認はそのファイルと範囲に
適用されます。インストール状態の変化、期限切れ、計画の変更があれば、新しい計画と
承認が必要です。自動実行はapt/apk、AROを実行しているPython環境のpip、
manifest/lockfileのある曖昧さのない直接npm依存関係、検証済みの正確なWinGet IDに
限定します。pipは自身のインタープリター/prefixだけを対象とし、外部prefixのパッケージは
拒否します。npmの入れ子・別名・workspaceも拒否します。apt/apkは依存トランザクションを
シミュレーションし、実行直前に再検証します。pipは依存関係を変更せず、ビルド済みwheelのみを使います。npmは
lifecycle scriptを無効にしますが、間接依存関係やlockfileを変更する可能性があります。
dnf/RPM、一般的なWindows OS更新、コンテナーなどには手動手順を示します。計画は
30分で期限切れになります。修正バージョンが取得不能、またはアプリと非互換の場合も
あり、自動比較できるバージョン形式にも制約があります。

実行結果を記録し、成功や部分的な失敗の後にも再調査します。AROによる自動的な
権限昇格や、独立したサービス/OS再起動は行いません。ただしパッケージやベンダーの
インストールフックが**サービスを再起動する場合がある**ため、依存関係と停止時間も
承認範囲に含めてください。承認済みのアプリのヘルスチェックを実行するまで、サービスの
正常性は未検証です。パッケージ管理コマンドの正常終了だけでは修正完了としません。

## 状態、通信、プライバシー

状態はスキルと調査対象リポジトリの外に保存します。

- Linux: `${XDG_STATE_HOME:-~/.local/state}/aro`
- Windows: `%LOCALAPPDATA%/ARO`（未設定の場合は`~/AppData/Local/ARO`）

自動作成される`config.json`で、探索先、`exclude_packages`のパッケージ名glob、
ネットワーク観察、キャッシュ期間、探索上限を設定できます。`config --show`で確認し、
それ以外の変更は有効なJSONとして編集します。例は[運用手順](skills/aro/references/workflow.md)
を参照してください。状態には一覧/レポート、勧告キャッシュ、変更不可の計画、実行履歴が
含まれます。非公開に保ち、Gitには追加しないでください。

確認時はローカルのメタデータを読み、インストール済みソフトウェアやアプリのファイルを
変更しません。勧告サービスに**パッケージ名とバージョン**が送られることがありますが、
アプリのソースコードや認証情報はアップロードしません。開示できない非公開パッケージ名は、
初回のオンライン確認前に除外してください。ローカル結果にはパスやソフトウェア詳細が
含まれることがあります。

エージェントのブラウザーは不要ですが、スクリプトにはインターネット接続または利用可能な
キャッシュが必要です。オフライン、古いキャッシュ、情報源の失敗では、情報の時点と調査の
欠落を保持します。「確認された一致なし」は調査できた範囲の結果であり、安全の保証では
ありません。外部ルーター/ファイアウォール、非対応ソフトウェア、アクセス不能な場所は
不明のまま残ることがあります。

開発・検証は[CONTRIBUTING.md](CONTRIBUTING.md)、脆弱性の報告は
[SECURITY.md](SECURITY.md)、MITライセンスは[LICENSE](LICENSE)を参照してください。
配布用スキルは[`skills/aro`](skills/aro)にあり、Pythonパッケージとしてのインストールは
不要です。

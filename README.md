# AI Vulnerability Intelligence — SOC向け 緊急脆弱性ウォッチ

公開情報から、今日確認すべき重要な脆弱性をAIが選定・整理した**日次脆弱性ブリーフ**を、GitHub Pagesで公開するための静的サイトです。

SOC担当者が毎朝数分で、次を把握できることを目的にしています。

- 今日確認すべき重要な脆弱性
- 実悪用の有無 / CISA KEV掲載の有無 / 公開PoCの有無
- 対象製品と修正版、推奨対処
- なぜSOCとして優先すべきか
- 前回レポートから何が変化したか

## 公開URL

- サイト: <https://akilab.github.io/checknvd/>
- リポジトリ: <https://github.com/akilab/checknvd>

## リポジトリ構成

```text
/
├── index.html                  トップページ（一覧・サマリー・差分・絞り込み）
├── .nojekyll                   Jekyll処理を無効化（_ で始まるファイルを配信するため）
├── assets/
│   ├── style.css               トップページ用スタイル
│   ├── app.js                  トップページ用スクリプト（GitHub API取得・解析・描画）
│   └── report.css              日次レポート用スタイル
├── vuln/
│   ├── YYYY-MM-DD.html         日次レポート（一覧に表示される）
│   ├── _template.html          日次レポートの雛形（一覧には表示されない）
│   ├── test.html               既存の連携テスト用（一覧には表示されない）
│   └── 2026-08-05-test.html    既存の連携テスト用（一覧には表示されない）
├── tools/
│   ├── validate-reports.mjs    日次レポートの静的検証（npm不要）
│   └── serve.mjs               ローカル確認用の簡易HTTPサーバー（npm不要）
└── .claude/
    └── launch.json             ローカルプレビュー設定（サイトの動作には不要）
```

ビルドツール、npm、フレームワークは使用していません。HTML / CSS / Vanilla JavaScript のみです。

## 日次レポートのファイル命名規則

**`vuln/YYYY-MM-DD.html` のみが一覧に表示されます。**

| ファイル名 | 一覧表示 | 理由 |
| --- | --- | --- |
| `2026-08-05.html` | される | 規則どおり |
| `2026-08-05-test.html` | されない | 日付のみのファイル名ではない |
| `test.html` | されない | 日付形式ではない |
| `_template.html` | されない | 日付形式ではない |
| `2026-13-40.html` | されない | 日付として成立しない |
| `2026-08-05.md` | されない | HTML以外 |

日付は日本時間として扱われ、新しい順に表示されます。

## 仕組み

### GitHub Pages

`main` ブランチのルートをそのまま配信します。すべてのパスは相対パスで、プロジェクトページ（`/checknvd/` 配下）でも正しく解決されます。

### GitHub APIによる一覧取得

トップページは読み込み時に、未認証のGitHub Contents APIを呼び出します。

```text
https://api.github.com/repos/{owner}/{repo}/contents/vuln?ref=main
```

`owner` と `repo` は `xxx.github.io/リポジトリ名/` というURLから自動判定します。カスタムドメインなどで判定できない場合は、`assets/app.js` 冒頭の `CONFIG` に明示してください。

```js
const CONFIG = {
  owner: "akilab",
  repository: "checknvd",
  branch: "main",
  reportDirectory: "vuln",
  inspectLimit: 30    // 詳細解析する最新レポートの上限件数
};
```

一覧取得後、新しい順に最大 `inspectLimit` 件のレポート本体を取得し、`DOMParser` で解析して、サマリー・差分・絞り込みに使用します。それより古いレポートは、日付とファイル名のみで一覧・検索の対象になります。

**GitHubトークンは埋め込みません。** 公開リポジトリの未認証アクセスを前提としています。

### ChatGPT Workが追加するファイル

ChatGPT Workは `vuln/YYYY-MM-DD.html` を追加するだけで、トップページの更新は不要です。`vuln/_template.html` をコピーして `{{...}}` を置き換えるのが最も確実です。

## 日次レポートで維持すべきHTMLクラスと `data-*` 属性

トップページは**表示文言よりも `data-*` 属性を優先して解析します。** 属性がない古いレポートは、従来どおりバッジ文言のテキスト解析にフォールバックします。

### 必須クラス

| クラス | 用途 |
| --- | --- |
| `.case` | 脆弱性1件を囲む要素（`<article>` 推奨） |
| `.case h3` | CVE見出し（`data-cve` が無い場合のフォールバック） |
| `.product` | 対象製品（`data-product` が無い場合のフォールバック） |
| `.lead` | 1〜2行の概要（トップページのカードに表示） |
| `.badge` | 状態バッジ（`data-*` が無い場合のフォールバック解析対象） |
| `.summary-card` | 優先度サマリーのカード |

### `.case` に付ける `data-*` 属性

| 属性 | 値 | 必須 |
| --- | --- | --- |
| `data-cve` | `CVE-2026-18577` | 推奨 |
| `data-priority` | `P1` / `P2` / `P3` | 推奨 |
| `data-product` | 製品名 | 任意 |
| `data-exploited` | `true` / `false` / `unknown` | 推奨 |
| `data-kev` | `true` / `false` / `unknown` | 推奨 |
| `data-poc` | `true` / `false` / `unknown` | 推奨 |
| `data-cvss` | `9.8` | 任意 |
| `data-fixed` | `12.4.3` | 任意 |

```html
<article class="case" id="CVE-2026-18577"
  data-cve="CVE-2026-18577"
  data-priority="P1"
  data-product="Northwind Secure Gateway"
  data-exploited="true"
  data-kev="true"
  data-poc="false"
  data-cvss="9.8"
  data-fixed="12.4.3">
  <div class="case-head">
    <span class="badge p1" data-glyph="■">P1 即時確認</span>
    <h3>CVE-2026-18577</h3>
  </div>
  <p class="product">Northwind Secure Gateway 12.0 – 12.4.2</p>
  <p class="lead">認証不要でリモートコード実行が可能。</p>
  ...
</article>
```

`unknown` または属性なしでバッジからも判断できない場合、トップページは「取得不可」「―」と表示します。誤った値は表示しません。

### SOC Priority

CVSSとは別軸の、SOC運用上の優先度です。**AIが公開情報から判定した独自指標**であり、CVSSやベンダー深刻度とは異なります。

| | 判定の目安 |
| --- | --- |
| **P1 即時確認** | 実悪用が確認されている / CISA KEV掲載 / インターネットから認証不要で悪用可能 / 管理基盤・RMM・VPN・認証基盤・セキュリティ製品への重大な影響 / 広範囲への侵害拡大が想定される |
| **P2 速やかに確認** | 公開PoCがある / リモートコード実行 / 認証回避 / 任意ファイル読み取り / 広く利用される製品 / 重大な情報漏えいにつながる |
| **P3 継続監視** | CVSSは高いが攻撃条件が限定的 / 実悪用・KEV・PoCが未確認 / 利用有無を確認して継続監視する段階 |

## ローカル確認方法

`file://` で直接開くとGitHub APIへのfetchが失敗するため、必ずHTTP経由で開いてください。

```bash
node tools/serve.mjs
```

<http://localhost:8080/> が開けます。ポートを変える場合は `node tools/serve.mjs 3000` のように指定します。

ローカルではURLから `owner` / `repository` を判定できないため、エラー表示になります。実データで確認したい場合は、`assets/app.js` の `CONFIG.owner` と `CONFIG.repository` を一時的に設定してください（GitHub APIはCORSを許可しているため、localhostからでも取得できます）。

### 日次レポートの静的検証

```bash
node tools/validate-reports.mjs
```

次を確認し、エラーがあれば終了コード1を返します。

- 必要なファイル（`index.html`, `assets/*`）の存在
- どのファイルが一覧に載るか / 載らないか
- 各 `.case` の必須クラスと `data-*` 属性
- `data-priority` / `data-exploited` / `data-kev` / `data-poc` の値の妥当性
- 前日・翌日リンクの参照先が存在するか
- `.summary-card` と `.case` の件数の一致

### 手動での確認項目

1. トップページがHTTP経由で表示できる
2. `vuln/` 内のHTMLが日付の新しい順に並ぶ
3. `test.html` / `2026-08-05-test.html` / `_template.html` が一覧に表示されない
4. キーワード検索（CVE・製品名・概要・日付・ファイル名）が動作する
5. 年・月・SOC Priorityの絞り込みが動作する
6. 実悪用 / KEV / PoC の絞り込みが動作する
7. 最新レポートと前回レポートの比較が表示される
8. 月別アーカイブの月ボタンで一覧が絞り込まれる
9. モバイル幅（320px）で横スクロールが発生しない
10. ブラウザのコンソールにエラーが出ない

ブラウザのコンソールからは `window.__VULN_BRIEF__`（`CONFIG` / `state` / `load()` / `parseReport()`）で状態を確認できます。デバッグ用途のみで、外部からの入力は受け付けません。

## 既知の制約

- **GitHub APIの未認証レート制限**: IPあたり毎時60リクエストです。トップページは1回の読み込みで「一覧取得1回 + レポート本体を最大 `inspectLimit` 件」を消費します。制限に達すると403となり、画面にその旨が表示されます。時間を置いて再読み込みしてください。
- レポート本体の解析は最新 `inspectLimit`（既定30）件までです。それより古いレポートは、Priority・実悪用・KEV・PoCによる絞り込みの対象外になります（一覧・日付・ファイル名検索では表示されます）。
- 検索は取得済みの情報に対する部分一致で、全文検索ではありません。
- サンプルとして配置している `vuln/2026-08-05.html` と `vuln/2026-08-04.html` は、**製品名・CVE番号・バージョンがすべて架空**の構造見本です。実際の脆弱性情報ではありません。
- SOC PriorityはAIによる判定であり、対応判断は自組織の資産構成・公開状況・補完的統制をふまえて行ってください。
- 公開PoCへのリンクは安全性を確認したものではありません。自動実行はせず、検証環境以外で実行しないでください。
- レポート内のチェックリストは、チェック状態を保存しません（ページを再読み込みするとリセットされます）。

## セキュリティ上の方針

- GitHub APIおよび日次HTMLから取得した文字列は、DOMへ挿入する前にすべてエスケープします。
- GitHubトークンをHTML / JavaScriptへ埋め込みません。
- 外部リンクには `rel="noopener noreferrer"` を付けます。
- 外部CSSフレームワーク、外部JavaScriptライブラリ、外部フォントを読み込みません。

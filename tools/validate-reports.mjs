#!/usr/bin/env node
/**
 * 日次レポートの静的検証スクリプト（Node.js 標準機能のみ。npm不要）
 *
 *   node tools/validate-reports.mjs
 *
 * 確認内容:
 *   - 必要なファイル（index.html, assets/*）が存在するか
 *   - vuln/ のどのファイルが一覧に載るか（YYYY-MM-DD.html のみ）
 *   - 各レポートに必要なクラスと data-* 属性があるか
 *   - data-priority / data-exploited / data-kev / data-poc の値が正しいか
 *   - 前日・翌日リンクの参照先が存在するか
 *
 * エラーがある場合は終了コード 1 を返す。
 */

import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const REPORT_DIR = join(ROOT, "vuln");
const FILE_PATTERN = /^(\d{4})-(\d{2})-(\d{2})\.html?$/i;

const errors = [];
const warnings = [];
const notes = [];

const err = (file, message) => errors.push(`${file}: ${message}`);
const warn = (file, message) => warnings.push(`${file}: ${message}`);

/* ---------- 1. 必須ファイル ---------- */

for (const file of ["index.html", "assets/style.css", "assets/app.js", "assets/report.css"]) {
  if (!existsSync(join(ROOT, file))) err(file, "ファイルが存在しません。");
}

if (!existsSync(REPORT_DIR)) {
  err("vuln/", "レポートディレクトリが存在しません。");
  report();
}

/* ---------- 2. 一覧対象の判定 ---------- */

const allFiles = readdirSync(REPORT_DIR).filter((name) => /\.html?$/i.test(name));
const listed = [];
const skipped = [];

for (const name of allFiles) {
  const m = FILE_PATTERN.exec(name);
  if (!m) {
    skipped.push(`${name}（ファイル名が YYYY-MM-DD.html 形式ではない）`);
    continue;
  }
  const [, y, mo, d] = m;
  const date = new Date(Date.UTC(+y, +mo - 1, +d));
  const valid = date.getUTCFullYear() === +y && date.getUTCMonth() === +mo - 1 && date.getUTCDate() === +d;
  if (!valid) {
    err(name, `日付として成立しません（${y}-${mo}-${d}）。`);
    continue;
  }
  listed.push(name);
}

listed.sort().reverse();

/* ---------- 3. 各レポートの構造検証 ---------- */

const TRI_VALUES = new Set(["true", "false", "unknown"]);
const PRIORITIES = new Set(["P1", "P2", "P3"]);

function attr(tag, name) {
  const m = new RegExp(`${name}\\s*=\\s*"([^"]*)"`, "i").exec(tag);
  return m ? m[1].trim() : null;
}

for (const name of listed) {
  const html = readFileSync(join(REPORT_DIR, name), "utf8");

  if (!/<link[^>]+href="\.\.\/assets\/report\.css"/i.test(html)) {
    warn(name, '../assets/report.css を読み込んでいません（スタイルが適用されません）。');
  }
  if (!/lang="ja"/i.test(html)) warn(name, '<html lang="ja"> がありません。');

  const cases = [...html.matchAll(/<article\b([^>]*class="[^"]*\bcase\b[^"]*"[^>]*)>([\s\S]*?)<\/article>/gi)];
  if (!cases.length) {
    err(name, "article.case が1件もありません。トップページに脆弱性情報が表示されません。");
    continue;
  }

  const summaryCards = (html.match(/class="[^"]*\bsummary-card\b/gi) || []).length;
  if (summaryCards !== cases.length) {
    warn(name, `summary-card が ${summaryCards} 件、case が ${cases.length} 件で一致しません。`);
  }

  const seen = new Set();
  cases.forEach((match, index) => {
    const tag = match[1];
    const body = match[2];
    const label = `${name} [case ${index + 1}]`;

    const cve = attr(tag, "data-cve");
    if (!cve) {
      warn(label, "data-cve がありません（h3のテキスト解析にフォールバックします）。");
    } else {
      if (!/^CVE-\d{4}-\d{4,7}$/i.test(cve)) warn(label, `data-cve の形式が想定と異なります: ${cve}`);
      if (seen.has(cve.toUpperCase())) err(label, `同じレポート内で data-cve が重複しています: ${cve}`);
      seen.add(cve.toUpperCase());
    }

    const priority = attr(tag, "data-priority");
    if (!priority) warn(label, "data-priority がありません（バッジ文言から推定されます）。");
    else if (!PRIORITIES.has(priority.toUpperCase())) err(label, `data-priority は P1/P2/P3 のいずれかにしてください: ${priority}`);

    for (const key of ["data-exploited", "data-kev", "data-poc"]) {
      const value = attr(tag, key);
      if (value === null) {
        warn(label, `${key} がありません（バッジ文言から推定されます）。`);
      } else if (!TRI_VALUES.has(value.toLowerCase())) {
        err(label, `${key} は true / false / unknown にしてください: ${value}`);
      }
    }

    if (!/<h3\b/i.test(body)) err(label, "h3 見出しがありません。");
    if (!/class="[^"]*\bproduct\b/i.test(body) && !attr(tag, "data-product")) {
      err(label, ".product も data-product もありません。");
    }
    if (!/class="[^"]*\blead\b/i.test(body)) err(label, ".lead（1〜2行の概要）がありません。");
    if (!/class="[^"]*\bbadge\b/i.test(body)) warn(label, ".badge がありません。");
    if (!/class="checklist"/i.test(body)) warn(label, "SOC向け推奨アクションのチェックリストがありません。");
  });

  // 前日・翌日リンクの検証
  for (const rel of ["prev", "next"]) {
    const m = new RegExp(`<a[^>]+href="([^"]+\\.html?)"[^>]*rel="${rel}"`, "i").exec(html) ||
      new RegExp(`<a[^>]+rel="${rel}"[^>]*href="([^"]+\\.html?)"`, "i").exec(html);
    if (!m) continue;
    if (!existsSync(join(REPORT_DIR, m[1]))) {
      err(name, `rel="${rel}" のリンク先が存在しません: ${m[1]}`);
    }
  }
}

/* ---------- 4. 結果 ---------- */

notes.push(`一覧に表示されるレポート: ${listed.length}件`);
for (const name of listed) notes.push(`  ・${name}`);
if (skipped.length) {
  notes.push(`一覧対象外のHTML: ${skipped.length}件`);
  for (const s of skipped) notes.push(`  ・${s}`);
}

report();

function report() {
  console.log("AI Vulnerability Intelligence — レポート検証\n");
  for (const line of notes) console.log(line);

  if (warnings.length) {
    console.log(`\n警告 ${warnings.length}件`);
    for (const w of warnings) console.log(`  ! ${w}`);
  }
  if (errors.length) {
    console.log(`\nエラー ${errors.length}件`);
    for (const e of errors) console.log(`  x ${e}`);
    console.log("\n検証: 失敗");
    process.exit(1);
  }
  console.log("\n検証: 成功（エラーなし）");
  process.exit(0);
}

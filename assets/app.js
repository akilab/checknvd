/* AI Vulnerability Intelligence — トップページ用スクリプト
 *
 * GitHub API から vuln/ 配下のHTML一覧を取得し、日付の新しい順に表示する。
 * 各日次レポートは fetch + DOMParser で解析し、data-* 属性を優先、
 * 属性が無い古いレポートはテキスト解析へフォールバックする。
 *
 * 外部ライブラリには依存しない。GitHubトークンは埋め込まない（未認証アクセス前提）。
 */
(() => {
  "use strict";

  /* ------------------------------------------------------------------ *
   * 設定
   * owner / repository は *.github.io のURLから自動判定する。
   * カスタムドメイン等で判定できない場合のみ、ここへ明示的に設定する。
   * ------------------------------------------------------------------ */
  const CONFIG = {
    owner: "",              // 例: "akilab"
    repository: "",         // 例: "checknvd"
    branch: "main",
    reportDirectory: "vuln",
    inspectLimit: 30        // 詳細解析する最新レポートの上限件数
  };

  const FILE_PATTERN = /^(\d{4})-(\d{2})-(\d{2})\.html?$/i;

  const state = {
    reports: [],      // 全件（新しい順）
    inspected: 0,     // 詳細解析できた件数
    repo: null
  };

  const $ = (id) => document.getElementById(id);
  const el = {
    repoMeta: $("repoMeta"),
    repoLink: $("repoLink"),
    updatedMeta: $("updatedMeta"),
    totalMeta: $("totalMeta"),
    status: $("status"),
    reload: $("reload"),
    latestSection: $("latestSection"),
    hero: $("hero"),
    heroDate: $("heroDate"),
    heroFile: $("heroFile"),
    heroLink: $("heroLink"),
    heroFacts: $("heroFacts"),
    summarySection: $("summarySection"),
    stats: $("stats"),
    summaryNote: $("summaryNote"),
    changeSection: $("changeSection"),
    changeNote: $("changeNote"),
    changes: $("changes"),
    search: $("search"),
    yearFilter: $("yearFilter"),
    monthFilter: $("monthFilter"),
    priorityFilter: $("priorityFilter"),
    onlyExploited: $("onlyExploited"),
    onlyKev: $("onlyKev"),
    onlyPoc: $("onlyPoc"),
    resetFilters: $("resetFilters"),
    resultLine: $("resultLine"),
    cards: $("cards"),
    archive: $("archive"),
    archiveNote: $("archiveNote")
  };

  /* ------------------------------------------------------------------ *
   * ユーティリティ
   * ------------------------------------------------------------------ */

  function esc(value) {
    return String(value == null ? "" : value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function clean(text) {
    return String(text == null ? "" : text).replace(/\s+/g, " ").trim();
  }

  const dateFormatter = new Intl.DateTimeFormat("ja-JP", {
    year: "numeric", month: "long", day: "numeric", weekday: "short"
  });
  const stampFormatter = new Intl.DateTimeFormat("ja-JP", {
    dateStyle: "medium", timeStyle: "short"
  });

  function formatDate(iso) {
    const d = new Date(iso + "T00:00:00+09:00");
    return Number.isNaN(d.getTime()) ? iso : dateFormatter.format(d);
  }

  function isValidDate(y, m, d) {
    const date = new Date(Date.UTC(+y, +m - 1, +d));
    return date.getUTCFullYear() === +y &&
      date.getUTCMonth() === +m - 1 &&
      date.getUTCDate() === +d;
  }

  /* ------------------------------------------------------------------ *
   * 日次レポートの解析
   * data-* 属性を優先し、無ければ表示文言から推定する。
   * 真偽が判断できない場合は null（取得不可）を返す。
   * ------------------------------------------------------------------ */

  const TRUE_WORDS = ["true", "yes", "1", "あり", "有り", "確認済み", "掲載", "公開"];
  const FALSE_WORDS = ["false", "no", "0", "なし", "無し", "未確認", "非掲載", "未掲載", "非公開"];

  function triFromAttr(value) {
    if (value == null) return undefined;              // 属性なし → フォールバックへ
    const v = clean(value).toLowerCase();
    if (v === "" || v === "unknown" || v === "不明") return null;
    if (TRUE_WORDS.includes(v)) return true;
    if (FALSE_WORDS.includes(v)) return false;
    return undefined;
  }

  function triFromText(texts, keyPattern) {
    for (const raw of texts) {
      const text = clean(raw);
      if (!keyPattern.test(text)) continue;
      if (/(なし|無し|未確認|非掲載|未掲載|非公開|報告されていない|not\s*listed|none)/i.test(text)) return false;
      if (/(あり|有り|確認|掲載|公開|観測|yes)/i.test(text)) return true;
      return true; // 「CISA KEV」のようにキーワードのみの場合は該当扱い
    }
    return null;
  }

  function readTri(node, attr, texts, keyPattern) {
    const fromAttr = triFromAttr(node.getAttribute(attr));
    if (fromAttr !== undefined) return fromAttr;
    return triFromText(texts, keyPattern);
  }

  function readPriority(node, texts) {
    const attr = clean(node.getAttribute("data-priority")).toUpperCase();
    const fromAttr = attr.match(/P[1-3]/);
    if (fromAttr) return fromAttr[0];
    for (const raw of texts) {
      const text = clean(raw);
      const m = text.match(/\bP([1-3])\b/i);
      if (m) return "P" + m[1];
      if (/即時確認/.test(text)) return "P1";
      if (/速やかに/.test(text)) return "P2";
      if (/継続監視/.test(text)) return "P3";
    }
    return null;
  }

  function parseCase(node) {
    const heading = clean(node.querySelector("h3")?.textContent);
    const product = clean(node.getAttribute("data-product")) ||
      clean(node.querySelector(".product")?.textContent);
    const lead = clean(node.querySelector(".lead")?.textContent);
    const badges = [...node.querySelectorAll(".badge")]
      .map((b) => clean(b.textContent))
      .filter(Boolean);
    // フォールバック用のテキスト集合（バッジ優先、無ければ本文全体）
    const texts = badges.length ? badges : [clean(node.textContent)];

    const cveFromAttr = clean(node.getAttribute("data-cve")).toUpperCase();
    const cve = cveFromAttr ||
      (heading.match(/CVE-\d{4}-\d{4,7}/i)?.[0] || "").toUpperCase() ||
      heading;

    return {
      cve: cve || "(CVE番号なし)",
      product,
      lead,
      badges,
      priority: readPriority(node, texts),
      exploited: readTri(node, "data-exploited", texts, /実悪用|悪用|exploit/i),
      kev: readTri(node, "data-kev", texts, /kev/i),
      poc: readTri(node, "data-poc", texts, /poc|実証コード/i),
      fixed: clean(node.getAttribute("data-fixed")) ||
        clean(node.querySelector(".fixed")?.textContent)
    };
  }

  function parseReport(html) {
    const doc = new DOMParser().parseFromString(html, "text/html");
    const cases = [...doc.querySelectorAll(".case")].map(parseCase);
    const conclusion = clean(doc.querySelector(".conclusion-body, .conclusion")?.textContent);
    return { cases, conclusion };
  }

  const PRIORITY_RANK = { P1: 0, P2: 1, P3: 2 };

  function topCase(cases) {
    if (!cases.length) return null;
    return [...cases].sort((a, b) => {
      const ra = PRIORITY_RANK[a.priority] ?? 9;
      const rb = PRIORITY_RANK[b.priority] ?? 9;
      if (ra !== rb) return ra - rb;
      return cases.indexOf(a) - cases.indexOf(b);
    })[0];
  }

  function buildSearchable(report) {
    const parts = [report.name, report.iso, formatDate(report.iso)];
    for (const c of report.cases) {
      parts.push(c.cve, c.product, c.lead, c.fixed, c.priority, ...c.badges);
    }
    return parts.filter(Boolean).join(" ").toLowerCase();
  }

  /* ------------------------------------------------------------------ *
   * 取得
   * ------------------------------------------------------------------ */

  function detectRepo() {
    if (CONFIG.owner && CONFIG.repository) {
      return { owner: CONFIG.owner, repository: CONFIG.repository, detected: false };
    }
    const host = location.hostname.match(/^([^.]+)\.github\.io$/i);
    if (!host) {
      throw new Error(
        "GitHubリポジトリを自動判定できませんでした。assets/app.js の CONFIG.owner と CONFIG.repository を設定してください。"
      );
    }
    const owner = host[1];
    const first = location.pathname.split("/").filter(Boolean)[0];
    return { owner, repository: first || owner + ".github.io", detected: true };
  }

  async function fetchFileList(repo) {
    const api = "https://api.github.com/repos/" +
      encodeURIComponent(repo.owner) + "/" +
      encodeURIComponent(repo.repository) + "/contents/" +
      encodeURIComponent(CONFIG.reportDirectory) +
      "?ref=" + encodeURIComponent(CONFIG.branch);

    let res;
    try {
      res = await fetch(api, { headers: { Accept: "application/vnd.github+json" } });
    } catch {
      throw new Error("GitHub APIへ接続できませんでした。ネットワーク接続を確認して再読み込みしてください。");
    }

    if (res.status === 404) {
      throw new Error(
        `GitHub APIが ${repo.owner}/${repo.repository} の ${CONFIG.reportDirectory}/ を見つけられませんでした（404）。`
      );
    }
    if (res.status === 403) {
      throw new Error("GitHub APIの利用回数制限に達した可能性があります（403）。時間を置いて再読み込みしてください。");
    }
    if (!res.ok) {
      throw new Error(`GitHub APIからの取得に失敗しました（HTTP ${res.status}）。`);
    }

    let body;
    try {
      body = await res.json();
    } catch {
      throw new Error("GitHub APIの応答を解釈できませんでした。");
    }
    if (!Array.isArray(body)) {
      throw new Error("GitHub APIの応答形式が想定と異なります。");
    }
    return body;
  }

  function toReports(files) {
    return files
      .filter((f) => f && f.type === "file")
      .map((f) => {
        const m = FILE_PATTERN.exec(f.name);           // YYYY-MM-DD.html のみ対象
        if (!m || !isValidDate(m[1], m[2], m[3])) return null;
        const iso = `${m[1]}-${m[2]}-${m[3]}`;
        return {
          name: f.name,
          iso,
          year: m[1],
          month: m[2],
          url: `./${CONFIG.reportDirectory}/${encodeURIComponent(f.name)}`,
          parsed: false,
          cases: [],
          conclusion: "",
          searchable: ""
        };
      })
      .filter(Boolean)
      .sort((a, b) => (a.iso < b.iso ? 1 : a.iso > b.iso ? -1 : 0));
  }

  async function inspect(report) {
    try {
      const res = await fetch(report.url, { cache: "no-store" });
      if (!res.ok) throw new Error(String(res.status));
      const parsed = parseReport(await res.text());
      report.cases = parsed.cases;
      report.conclusion = parsed.conclusion;
      report.parsed = true;
    } catch {
      report.parsed = false;
      report.cases = [];
    }
    report.searchable = buildSearchable(report);
    return report;
  }

  /* ------------------------------------------------------------------ *
   * 表示
   * ------------------------------------------------------------------ */

  const triLabel = (v) => (v === true ? "あり" : v === false ? "なし" : "取得不可");

  function flagBadge(label, value, toneWhenTrue) {
    if (value === true) {
      return `<span class="badge ${toneWhenTrue}" data-glyph="●">${esc(label)}あり</span>`;
    }
    if (value === false) {
      return `<span class="badge off" data-glyph="○">${esc(label)}なし</span>`;
    }
    return `<span class="badge na" data-glyph="—">${esc(label)}不明</span>`;
  }

  function priorityBadge(priority) {
    if (!priority) return '<span class="badge na" data-glyph="—">Priority不明</span>';
    const text = priority === "P1" ? "P1 即時確認"
      : priority === "P2" ? "P2 速やかに確認"
        : "P3 継続監視";
    return `<span class="badge ${priority.toLowerCase()}" data-glyph="■">${esc(text)}</span>`;
  }

  function renderHero() {
    const latest = state.reports[0];
    if (!latest) {
      el.latestSection.hidden = true;
      return;
    }
    el.latestSection.hidden = false;

    const top = topCase(latest.cases);
    el.hero.setAttribute("data-top-priority", top?.priority || "");
    el.heroDate.textContent = formatDate(latest.iso);
    el.heroFile.textContent = `${CONFIG.reportDirectory}/${latest.name}`;
    el.heroLink.href = latest.url;
    el.heroLink.setAttribute("aria-label", `${formatDate(latest.iso)}のレポートを開く`);

    const facts = [
      ["掲載脆弱性数", latest.parsed ? `${latest.cases.length} 件` : "取得不可"],
      ["最優先CVE", top?.cve || (latest.parsed ? "該当なし" : "取得不可")],
      ["対象製品", top?.product || (latest.parsed ? "―" : "取得不可")],
      ["SOC Priority", top?.priority ? priorityBadge(top.priority) : "取得不可", true],
      ["実悪用", top ? flagBadge("", top.exploited, "on") : "取得不可", true],
      ["CISA KEV", top ? flagBadge("", top.kev, "on") : "取得不可", true],
      ["公開PoC", top ? flagBadge("", top.poc, "warn") : "取得不可", true]
    ];

    el.heroFacts.innerHTML = facts
      .map(([label, value, isHtml]) =>
        `<div><dt>${esc(label)}</dt><dd>${isHtml ? value : esc(value)}</dd></div>`)
      .join("");
  }

  function renderSummary() {
    const latest = state.reports[0];
    if (!latest) {
      el.summarySection.hidden = true;
      return;
    }
    el.summarySection.hidden = false;

    const cases = latest.cases;
    const known = (key) => cases.some((c) => c[key] !== null && c[key] !== undefined);
    const countTrue = (key) => cases.filter((c) => c[key] === true).length;
    const countPriority = (p) => cases.filter((c) => c.priority === p).length;
    const priorityKnown = cases.some((c) => c.priority);

    const items = [
      ["P1 即時確認", priorityKnown ? countPriority("P1") : null, "p1"],
      ["P2 速やかに確認", priorityKnown ? countPriority("P2") : null, "p2"],
      ["実悪用あり", known("exploited") ? countTrue("exploited") : null, "alert"],
      ["CISA KEV掲載", known("kev") ? countTrue("kev") : null, "alert"],
      ["公開PoCあり", known("poc") ? countTrue("poc") : null, "warn"]
    ];

    el.stats.innerHTML = items.map(([label, value, tone]) => {
      const na = value === null || !latest.parsed;
      const body = na
        ? '<span class="stat-value">―</span>'
        : `<span class="stat-value">${value}<span class="stat-unit">件</span></span>`;
      return `<div class="summary-card" data-tone="${na ? "na" : tone}">` +
        `<span class="stat-label">${esc(label)}</span>${body}</div>`;
    }).join("");

    el.summaryNote.textContent = latest.parsed
      ? `${formatDate(latest.iso)}のレポートから集計（全${cases.length}件）。「―」はレポートから判定できなかった項目です。`
      : "最新レポートを解析できませんでした。レポートを直接開いて確認してください。";
  }

  function fieldChanges(cve, now, before) {
    const rows = [];
    if (now.priority !== before.priority && (now.priority || before.priority)) {
      const up = (PRIORITY_RANK[now.priority] ?? 9) < (PRIORITY_RANK[before.priority] ?? 9);
      rows.push({
        kind: up ? "up" : "down",
        kindLabel: up ? "優先度↑" : "優先度↓",
        cve,
        text: `SOC Priority ${before.priority || "不明"} → ${now.priority || "不明"}`
      });
    }
    const flags = [
      ["exploited", "実悪用"],
      ["kev", "CISA KEV"],
      ["poc", "公開PoC"]
    ];
    for (const [key, label] of flags) {
      if (now[key] === before[key]) continue;
      const worse = now[key] === true;
      rows.push({
        kind: worse ? "up" : "down",
        kindLabel: worse ? "悪化" : "変化",
        cve,
        text: `${label} ${triLabel(before[key])} → ${triLabel(now[key])}`
      });
    }
    return rows;
  }

  function renderChanges() {
    const latest = state.reports[0];
    const previous = state.reports[1];

    if (!latest) {
      el.changeSection.hidden = true;
      return;
    }
    el.changeSection.hidden = false;

    if (!previous) {
      el.changeNote.textContent = "比較対象となる前回レポートがまだありません。";
      el.changes.innerHTML = '<li><span class="change-text">前回レポートがないため比較できません。</span></li>';
      return;
    }

    el.changeNote.textContent =
      `${formatDate(latest.iso)}（最新） と ${formatDate(previous.iso)}（前回） を比較しています。`;

    if (!latest.parsed || !previous.parsed) {
      el.changes.innerHTML =
        '<li><span class="change-text">いずれかのレポートを解析できなかったため、比較できませんでした。</span></li>';
      return;
    }

    const nowMap = new Map(latest.cases.map((c) => [c.cve, c]));
    const beforeMap = new Map(previous.cases.map((c) => [c.cve, c]));
    const rows = [];

    for (const [cve, c] of nowMap) {
      if (!beforeMap.has(cve)) {
        rows.push({
          kind: "new",
          kindLabel: "新規",
          cve,
          text: `${c.priority || "Priority不明"}${c.product ? " / " + c.product : ""} として新規掲載`
        });
      } else {
        rows.push(...fieldChanges(cve, c, beforeMap.get(cve)));
      }
    }
    for (const [cve] of beforeMap) {
      if (!nowMap.has(cve)) {
        rows.push({ kind: "gone", kindLabel: "掲載終了", cve, text: "今回のレポートには掲載されていません" });
      }
    }

    const order = { new: 0, up: 1, down: 2, gone: 3 };
    rows.sort((a, b) => (order[a.kind] ?? 9) - (order[b.kind] ?? 9));

    if (!rows.length) {
      el.changes.innerHTML =
        '<li><span class="change-text">前回レポートから重要な状態変化はありません。</span></li>';
      return;
    }

    el.changes.innerHTML = rows.map((r) =>
      `<li><span class="change-kind" data-kind="${esc(r.kind)}">${esc(r.kindLabel)}</span>` +
      `<span class="change-cve">${esc(r.cve)}</span>` +
      `<span class="change-text">${esc(r.text)}</span></li>`
    ).join("");
  }

  function currentFilters() {
    return {
      query: el.search.value.trim().toLowerCase(),
      year: el.yearFilter.value,
      month: el.monthFilter.value,
      priority: el.priorityFilter.value,
      exploited: el.onlyExploited.checked,
      kev: el.onlyKev.checked,
      poc: el.onlyPoc.checked
    };
  }

  function matches(report, f) {
    if (f.year && report.year !== f.year) return false;
    if (f.month && report.month !== f.month) return false;
    if (f.query && !report.searchable.includes(f.query)) return false;
    const needsCases = f.priority || f.exploited || f.kev || f.poc;
    if (needsCases) {
      if (!report.parsed || !report.cases.length) return false;
      if (f.priority && !report.cases.some((c) => c.priority === f.priority)) return false;
      if (f.exploited && !report.cases.some((c) => c.exploited === true)) return false;
      if (f.kev && !report.cases.some((c) => c.kev === true)) return false;
      if (f.poc && !report.cases.some((c) => c.poc === true)) return false;
    }
    return true;
  }

  function renderCards() {
    const f = currentFilters();
    const list = state.reports.filter((r) => matches(r, f));

    const notes = [`${list.length}件を表示 / 全${state.reports.length}件`];
    if (state.reports.length > state.inspected) {
      notes.push(`詳細解析は新しい${state.inspected}件（それ以前のレポートは日付とファイル名のみで絞り込まれます）`);
    }
    el.resultLine.textContent = notes.join(" ・ ");

    if (!list.length) {
      el.cards.innerHTML = '<p class="empty">条件に一致するレポートがありません。検索語や絞り込みを見直してください。</p>';
      return;
    }

    el.cards.innerHTML = list.map((r) => {
      const top = topCase(r.cases);
      const count = r.parsed ? `${r.cases.length}件掲載` : "詳細未解析";
      const cve = top ? esc(top.cve) : (r.parsed ? "掲載脆弱性なし" : "レポートを開いて確認");
      const product = top?.product ? `<p class="card-product">${esc(top.product)}</p>` : "";
      const lead = top?.lead ? `<p class="card-lead">${esc(top.lead)}</p>` : "";
      const badges = top
        ? priorityBadge(top.priority) +
          flagBadge("実悪用", top.exploited, "on") +
          flagBadge("KEV", top.kev, "on") +
          flagBadge("PoC", top.poc, "warn")
        : '<span class="badge na" data-glyph="—">情報取得不可</span>';

      return `<a class="card" href="${esc(r.url)}" data-top-priority="${esc(top?.priority || "")}">` +
        `<span class="card-head"><span class="card-date">${esc(formatDate(r.iso))}</span>` +
        `<span class="card-count">${esc(count)}</span></span>` +
        `<p class="card-file">${esc(CONFIG.reportDirectory + "/" + r.name)}</p>` +
        `<p class="card-cve">${cve}</p>${product}${lead}` +
        `<span class="badges">${badges}</span></a>`;
    }).join("");
  }

  function renderFilterOptions() {
    const years = [...new Set(state.reports.map((r) => r.year))].sort().reverse();
    el.yearFilter.innerHTML = '<option value="">すべての年</option>' +
      years.map((y) => `<option value="${esc(y)}">${esc(y)}年</option>`).join("");

    const months = [...new Set(state.reports.map((r) => r.month))].sort();
    el.monthFilter.innerHTML = '<option value="">すべての月</option>' +
      months.map((m) => `<option value="${esc(m)}">${esc(String(Number(m)))}月</option>`).join("");
  }

  function renderArchive() {
    if (!state.reports.length) {
      el.archive.innerHTML = '<p class="empty">レポートがまだありません。</p>';
      el.archiveNote.textContent = "";
      return;
    }
    const byYear = new Map();
    for (const r of state.reports) {
      if (!byYear.has(r.year)) byYear.set(r.year, new Map());
      const months = byYear.get(r.year);
      months.set(r.month, (months.get(r.month) || 0) + 1);
    }
    const years = [...byYear.keys()].sort().reverse();

    el.archive.innerHTML = years.map((year, index) => {
      const months = [...byYear.get(year).entries()].sort((a, b) => b[0].localeCompare(a[0]));
      const total = months.reduce((sum, [, n]) => sum + n, 0);
      const buttons = months.map(([month, n]) =>
        `<button type="button" class="month-btn" data-year="${esc(year)}" data-month="${esc(month)}">` +
        `${esc(String(Number(month)))}月<span class="month-count">${n}件</span></button>`
      ).join("");
      return `<details class="archive-year"${index === 0 ? " open" : ""}>` +
        `<summary>${esc(year)}年<span class="month-count"> ${total}件</span></summary>` +
        `<div class="archive-months">${buttons}</div></details>`;
    }).join("");

    el.archiveNote.textContent = "月を選ぶとレポート一覧が絞り込まれます。";
  }

  function onArchiveClick(event) {
    const btn = event.target.closest(".month-btn");
    if (!btn) return;
    el.yearFilter.value = btn.dataset.year || "";
    el.monthFilter.value = btn.dataset.month || "";
    renderCards();
    document.getElementById("listSection").scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function resetFilters() {
    el.search.value = "";
    el.yearFilter.value = "";
    el.monthFilter.value = "";
    el.priorityFilter.value = "";
    el.onlyExploited.checked = false;
    el.onlyKev.checked = false;
    el.onlyPoc.checked = false;
    renderCards();
  }

  function setStatus(message, kind) {
    if (!message) {
      el.status.hidden = true;
      el.status.textContent = "";
      return;
    }
    el.status.hidden = false;
    el.status.className = kind === "error" ? "status is-error" : "status";
    el.status.textContent = message;
  }

  function showEmptyState() {
    el.latestSection.hidden = true;
    el.summarySection.hidden = true;
    el.changeSection.hidden = true;
    el.cards.innerHTML =
      `<p class="empty">${esc(CONFIG.reportDirectory)}/ に YYYY-MM-DD.html 形式の日次レポートがまだありません。</p>`;
    el.resultLine.textContent = "0件を表示 / 全0件";
    renderArchive();
  }

  /* ------------------------------------------------------------------ *
   * 読み込み
   * ------------------------------------------------------------------ */

  async function load() {
    el.reload.disabled = true;
    setStatus("GitHubからレポート一覧を取得しています。");

    try {
      const repo = detectRepo();
      state.repo = repo;
      el.repoMeta.textContent = `${repo.owner}/${repo.repository}`;
      el.repoLink.href = `https://github.com/${repo.owner}/${repo.repository}`;
      el.repoLink.hidden = false;

      const files = await fetchFileList(repo);
      state.reports = toReports(files);
      el.totalMeta.textContent = `${state.reports.length} 件`;

      renderFilterOptions();

      if (!state.reports.length) {
        state.inspected = 0;
        showEmptyState();
        setStatus("日次レポートが見つかりませんでした。ファイル名は YYYY-MM-DD.html 形式にしてください。");
        return;
      }

      setStatus(`レポートを解析しています（最新${Math.min(state.reports.length, CONFIG.inspectLimit)}件）。`);
      const targets = state.reports.slice(0, CONFIG.inspectLimit);
      await Promise.all(targets.map(inspect));
      state.inspected = targets.filter((r) => r.parsed).length;
      for (const r of state.reports) {
        if (!r.searchable) r.searchable = buildSearchable(r);
      }

      renderHero();
      renderSummary();
      renderChanges();
      renderArchive();
      renderCards();

      el.updatedMeta.textContent = stampFormatter.format(new Date());
      setStatus(`レポート${state.reports.length}件を読み込みました。`);
      window.setTimeout(() => {
        if (!el.status.classList.contains("is-error")) setStatus("");
      }, 4000);
    } catch (error) {
      state.reports = [];
      state.inspected = 0;
      el.totalMeta.textContent = "―";
      showEmptyState();
      el.resultLine.textContent = "";
      el.cards.innerHTML = "";
      setStatus(error && error.message ? error.message : "レポート一覧の取得に失敗しました。", "error");
    } finally {
      el.reload.disabled = false;
    }
  }

  /* ------------------------------------------------------------------ *
   * イベント登録
   * ------------------------------------------------------------------ */

  el.search.addEventListener("input", renderCards);
  el.yearFilter.addEventListener("change", renderCards);
  el.monthFilter.addEventListener("change", renderCards);
  el.priorityFilter.addEventListener("change", renderCards);
  el.onlyExploited.addEventListener("change", renderCards);
  el.onlyKev.addEventListener("change", renderCards);
  el.onlyPoc.addEventListener("change", renderCards);
  el.resetFilters.addEventListener("click", resetFilters);
  el.reload.addEventListener("click", load);
  el.archive.addEventListener("click", onArchiveClick);

  // 動作確認・デバッグ用（外部からの入力は受け取らない）
  window.__VULN_BRIEF__ = { CONFIG, state, load, parseReport, triFromText, readPriority };

  load();
})();

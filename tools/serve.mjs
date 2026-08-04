#!/usr/bin/env node
/**
 * ローカル確認用の簡易静的HTTPサーバー（Node.js 標準機能のみ。npm不要）
 *
 *   node tools/serve.mjs          → http://localhost:8080
 *   node tools/serve.mjs 3000     → ポート指定
 *
 * file:// で index.html を直接開くと GitHub API への fetch が失敗するため、
 * ローカル確認では必ずHTTP経由で開くこと。
 */

import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { join, resolve, extname, normalize, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const PORT = Number(process.argv[2]) || 8080;

const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".txt": "text/plain; charset=utf-8"
};

createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://localhost:${PORT}`);
    let pathname = decodeURIComponent(url.pathname);
    if (pathname.endsWith("/")) pathname += "index.html";

    // ルート外へのアクセスを防ぐ
    const target = normalize(join(ROOT, pathname));
    if (!target.startsWith(ROOT)) {
      res.writeHead(403).end("Forbidden");
      return;
    }

    const info = await stat(target);
    const file = info.isDirectory() ? join(target, "index.html") : target;
    const body = await readFile(file);

    res.writeHead(200, {
      "Content-Type": TYPES[extname(file).toLowerCase()] || "application/octet-stream",
      "Cache-Control": "no-store"
    }).end(body);
  } catch {
    res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" }).end("404 Not Found");
  }
}).listen(PORT, () => {
  console.log(`http://localhost:${PORT}/ で配信中（Ctrl+C で停止）`);
});

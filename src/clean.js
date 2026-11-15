import { mkdirSync, readFileSync, writeFileSync, copyFileSync, lstatSync, existsSync, readdirSync } from "node:fs";
import path from "node:path";
import { walk, stripHidden } from "./scan.js";


// Write a sanitised copy: invisible characters removed, HTML comments dropped from docs, symlinks skipped.
export function cleanCopy(root, out) {
  if (existsSync(out) && readdirSync(out).length) throw new Error(`${out} already exists and is not empty`);
  let changed = 0, copied = 0;
  for (const f of walk(root)) {
    if (f.symlink || f.truncated) continue;
    const src = path.join(root, f.rel);
    const clean = stripHidden(f.rel);
    const dst = path.join(out, clean);
    if (!path.resolve(dst).startsWith(path.resolve(out) + path.sep)) continue; // never write outside out/
    mkdirSync(path.dirname(dst), { recursive: true });
    const buf = readFileSync(src);
    if (buf.includes(0) || lstatSync(src).size > 2 * 1024 * 1024) { copyFileSync(src, dst); copied++; continue; }
    let text = buf.toString("utf8");
    const before = text;
    text = stripHidden(text);
    if (/\.(md|mdx|markdown|html?|rst|txt)$/i.test(f.rel)) text = text.replace(/<!--[\s\S]*?-->/g, "");
    if (text !== before || clean !== f.rel) changed++;
    writeFileSync(dst, text);
    copied++;
  }
  return { copied, changed };
}

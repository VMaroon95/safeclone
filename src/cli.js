import { existsSync, statSync } from "node:fs";
import path from "node:path";
import { scanDir, severityRank, safe } from "./scan.js";
import { cloneRepo, defaultDest, validateUrl } from "./clone.js";
import { cleanCopy } from "./clean.js";

const HELP = `safeclone: check a repo for hidden prompt-injection before your AI agent reads it

Usage:
  safeclone <git-url> [--dest DIR]    clone safely (no hooks, no submodules), then scan
  safeclone scan [DIR]                scan an existing folder (default: .)
  safeclone scan DIR --clean OUT      also write a sanitised copy to OUT

Options:
  --json                machine-readable output
  --fail-on LEVEL       exit 1 at or above: high (default), medium, low, never
  --dest DIR            clone destination (default: repo name)

Never executes anything from the scanned repo. Output is escaped so hidden
characters in the repo cannot reach your terminal or an agent reading this report.
Exit codes: 0 below threshold, 1 findings at/above threshold, 2 error.`;

const ICON = { high: "HIGH  ", medium: "MEDIUM", low: "LOW   " };

function parse(argv) {
  const o = { _: [], json: false, failOn: "high", dest: null, clean: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--json") o.json = true;
    else if (a === "-h" || a === "--help") o.help = true;
    else if (a === "--fail-on" || a === "--dest" || a === "--clean") {
      const v = argv[++i];
      if (v === undefined || v.startsWith("--")) throw new Error(`${a} needs a value`);
      if (a === "--fail-on") { if (!["high", "medium", "low", "never"].includes(v)) throw new Error("--fail-on must be high, medium, low or never"); o.failOn = v; }
      else o[a === "--dest" ? "dest" : "clean"] = v;
    } else if (a.startsWith("-")) throw new Error(`unknown option: ${a}`);
    else o._.push(a);
  }
  return o;
}

export function render(result, target) {
  const lines = [`safeclone: scanned ${result.files} files in ${safe(target)}${result.truncated ? " (file limit reached, partial scan)" : ""}`];
  const counts = { high: 0, medium: 0, low: 0 };
  for (const f of result.findings) {
    counts[f.severity]++;
    lines.push(`  ${ICON[f.severity]} ${safe(f.file)}${f.line ? `:${f.line}` : ""}  [${f.rule}]\n         ${safe(f.detail, 400)}`);
  }
  lines.push(result.findings.length ? `\n${counts.high} high, ${counts.medium} medium, ${counts.low} low` : "no findings");
  if (counts.high) lines.push("Do not point an AI agent at this repo until you have reviewed the HIGH findings.");
  return lines.join("\n");
}

export async function main(argv) {
  try {
    const o = parse(argv);
    const [first, second] = o._;
    if (o.help || !first) { console.log(HELP); return first || o.help ? 0 : 2; }
    let dir, label;
    if (first === "scan") {
      dir = second ?? ".";
      if (!existsSync(dir) || !statSync(dir).isDirectory()) throw new Error(`not a directory: ${dir}`);
      label = dir;
    } else {
      validateUrl(first);
      dir = o.dest ?? defaultDest(first);
      if (existsSync(dir)) throw new Error(`${dir} already exists; pass --dest`);
      console.error(`cloning ${first} (hooks off, no submodules)…`);
      cloneRepo(first, dir);
      label = dir;
    }
    const result = scanDir(dir);
    if (o.clean) {
      const r = cleanCopy(dir, o.clean);
      console.error(`sanitised copy: ${o.clean} (${r.copied} files, ${r.changed} modified)`);
    }
    if (o.json) console.log(JSON.stringify({ target: path.resolve(dir), ...result, findings: result.findings.map((f) => ({ ...f, file: safe(f.file), detail: safe(f.detail, 400) })) }, null, 2));
    else console.log(render(result, label));
    if (o.failOn === "never") return 0;
    const min = severityRank(o.failOn);
    return result.findings.some((f) => severityRank(f.severity) >= min) ? 1 : 0;
  } catch (e) {
    console.error(`error: ${e.message}`);
    return 2;
  }
}

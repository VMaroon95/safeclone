import { readdirSync, readFileSync, lstatSync } from "node:fs";
import path from "node:path";
import { INVISIBLE, INJECTION, AGENT_FILES, AGENT_CONFIGS, DOC_FILES, TAG_RE, HIDDEN_TAG_RULES, HIDDEN_RE, ANY_INVISIBLE_RE, isAgentPath, normalizeForMatch } from "./rules.js";

const MAX_FILE = 2 * 1024 * 1024;
const MAX_FILES = 20000;
const SKIP_DIRS = new Set([".git", "node_modules", ".venv", "venv", "dist", "build", "__pycache__", "target", ".next"]);
const RISKY_SCRIPTS = ["preinstall", "install", "postinstall", "prepare", "prepublish", "prepack"];
const SEV = { high: 3, medium: 2, low: 1 };
export const severityRank = (s) => SEV[s] ?? 0;

// Make attacker-controlled text safe to print: no invisible, control or tag characters reach the terminal or an agent.
export function safe(s, max = 140) {
  let out = "";
  for (const ch of String(s)) {
    const cp = ch.codePointAt(0);
    if (cp === 9 || (cp >= 32 && cp < 127) || (cp > 160 && !ANY_INVISIBLE_RE.test(ch))) out += ch;
    else out += `\\u{${cp.toString(16)}}`;
    if (out.length > max) return out.slice(0, max) + "…";
  }
  return out;
}
// ZWJ/ZWNJ and a leading BOM have ordinary uses (emoji sequences, Persian/Indic text, UTF-8 files); everything else hidden is not.
const EMOJI = /[\p{Extended_Pictographic}\p{Emoji_Modifier}\uFE0F]/u;
const NON_ASCII_LETTER = /[^\x00-\x7f]/u;
function isLegit(text, off, ch) {
  if (ch === "\uFEFF") return off === 0;
  if (ch !== "\u200D" && ch !== "\u200C") return false;
  const prev = [...text.slice(Math.max(0, off - 2), off)].pop() ?? "", next = String.fromCodePoint(text.codePointAt(off + 1) ?? 0x41);
  return (EMOJI.test(prev) && EMOJI.test(next)) || (NON_ASCII_LETTER.test(prev) && /[\p{L}\p{M}]/u.test(prev) && NON_ASCII_LETTER.test(next) && /[\p{L}\p{M}]/u.test(next));
}
// Remove hidden characters that have no legitimate use here. Used by the sanitised copy.
export function stripHidden(text) {
  return text.replace(HIDDEN_RE, (ch, off) => (isLegit(text, off, ch) ? ch : ""));
}
function countHidden(text, re) {
  const g = new RegExp(re.source, "gu");
  let n = 0, first = -1, m;
  while ((m = g.exec(text))) if (!isLegit(text, m.index, m[0])) { n++; if (first < 0) first = m.index; }
  return { n, first };
}

// Decode the hidden ASCII message in a run of tag characters.
export function decodeTags(s) {
  let out = "";
  for (const ch of s) {
    const cp = ch.codePointAt(0);
    if (cp >= 0xe0020 && cp <= 0xe007e) out += String.fromCharCode(cp - 0xe0000);
  }
  return out;
}

export function* walk(root, state = { n: 0 }, rel = "", onlyAgent = false) {
  let entries;
  try { entries = readdirSync(path.join(root, rel), { withFileTypes: true }); } catch { return; }
  for (const e of entries.sort((a, b) => (a.name < b.name ? -1 : 1))) {
    const r = rel ? `${rel}/${e.name}` : e.name;
    if (e.isSymbolicLink()) { if (!onlyAgent || isAgentPath(r)) yield { rel: r, symlink: true }; continue; }
    // Build and vendor folders are skipped for speed, but agents still load instruction files from inside them.
    if (e.isDirectory()) { if (e.name !== ".git") yield* walk(root, state, r, onlyAgent || SKIP_DIRS.has(e.name)); continue; }
    if (!e.isFile() || (onlyAgent && !isAgentPath(r))) continue;
    if (++state.n > MAX_FILES) { yield { rel: r, truncated: true }; return; }
    yield { rel: r };
  }
}

function lineOf(text, index) {
  let n = 1;
  for (let i = 0; i < index; i++) if (text.charCodeAt(i) === 10) n++;
  return n;
}

export function scanText(rel, text) {
  const findings = [];
  const add = (f) => findings.push({ file: rel, ...f });
  const isAgentFile = AGENT_FILES.some((r) => r.test(rel));
  const isAgentCfg = AGENT_CONFIGS.some((r) => r.test(rel));
  const isDoc = DOC_FILES.test(rel) || isAgentFile;

  for (const { re, rule, severity, why } of INVISIBLE) {
    const { n: count, first } = countHidden(text, re);
    if (!count) continue;
    // Emoji legitimately use variation selectors; only report those in agent files or in bulk.
    if (rule === "variation-selectors" && !isAgentFile && count < 5) continue;
    const f = { line: lineOf(text, first), severity, rule, detail: `${why}, ${count} occurrence(s)` };
    if (rule === "unicode-tags") {
      const hidden = decodeTags(text);
      if (hidden) f.detail += `; hidden message decodes to: "${safe(hidden, 120)}"`;
    }
    if (isAgentFile && severity === "medium") f.severity = "high";
    add(f);
  }

  if (isDoc) {
    // Comments are invisible when rendered, so an agent reads what the human doesn't.
    // Comments are invisible when rendered, so an agent reads what the human doesn't. An unterminated one hides the rest of the file.
    for (let at = text.indexOf("<!--"), seenC = 0; at !== -1 && seenC < 200; at = text.indexOf("<!--", at + 4), seenC++) {
      const close = text.indexOf("-->", at + 4);
      const unterminated = close === -1;
      const body = text.slice(at + 4, unterminated ? Math.min(text.length, at + 4 + 20000) : close).trim();
      if (unterminated) add({ line: lineOf(text, at), severity: "medium", rule: "unterminated-comment", detail: `HTML comment is never closed, so everything after it is hidden when rendered: "${safe(body, 100)}"` });
      if (body.length < 12) { if (unterminated) break; at = close; continue; }
      const hits = INJECTION.filter(([re]) => re.test(body)).map(([, why]) => why);
      if (hits.length) add({ line: lineOf(text, at), severity: "high", rule: "hidden-comment-injection", detail: `HTML comment ${hits.join("; ")}: "${safe(body, 100)}"` });
      else if (!unterminated && (isAgentFile || body.length > 200)) add({ line: lineOf(text, at), severity: "low", rule: "hidden-comment", detail: `HTML comment not shown when rendered: "${safe(body, 100)}"` });
      if (unterminated) break;
      at = close;
    }
    let m;
    const mdComment = /^\[\/\/\]: # \((.*)\)$/gm;
    while ((m = mdComment.exec(text))) if (m[1].length > 12) add({ line: lineOf(text, m.index), severity: "low", rule: "hidden-comment", detail: `Markdown comment: "${safe(m[1], 100)}"` });
    const tagRe = new RegExp(TAG_RE.source, "g");
    const seen = new Set();
    let t;
    while ((t = tagRe.exec(text)) && seen.size < 20) {
      for (const [re, why] of HIDDEN_TAG_RULES) {
        if (!re.test(t[0]) || seen.has(why)) continue;
        seen.add(why);
        add({ line: lineOf(text, t.index), severity: "medium", rule: "hidden-html", detail: `${why}: "${safe(t[0], 100)}"` });
      }
    }
    const norm = normalizeForMatch(text);
    for (const [re, why] of INJECTION) {
      const mm = re.exec(text);
      if (mm) { add({ line: lineOf(text, mm.index), severity: isAgentFile ? "high" : "medium", rule: "injection-phrase", detail: `${why}: "${safe(mm[0], 100)}"` }); continue; }
      const nm = norm === text ? null : re.exec(norm);
      if (nm) add({ line: lineOf(norm, nm.index), severity: "high", rule: "obfuscated-injection", detail: `${why}, disguised with invisible, look-alike or spaced-out characters: "${safe(nm[0], 100)}"` });
    }
  }

  if (isDoc) {
    const b64 = /[A-Za-z0-9+/]{300,}={0,2}/.exec(text);
    if (b64) add({ line: lineOf(text, b64.index), severity: "low", rule: "base64-blob", detail: `${b64[0].length}-character base64-looking blob` });
  }

  if (/(^|\/)package\.json$/.test(rel)) {
    try {
      const scripts = JSON.parse(text).scripts ?? {};
      for (const k of RISKY_SCRIPTS) if (scripts[k]) add({ line: 1, severity: /curl|wget|base64|eval|\bnc\b|powershell/i.test(scripts[k]) ? "high" : "medium", rule: "install-script", detail: `"${k}" runs on install: ${safe(scripts[k], 100)}` });
    } catch { /* not valid JSON: ignore */ }
  }
  if (/(^|\/)\.vscode\/tasks\.json$/.test(rel) && /folderOpen/.test(text)) add({ line: lineOf(text, text.indexOf("folderOpen")), severity: "high", rule: "auto-run-task", detail: "VS Code task set to run automatically when the folder opens" });
  if (/(^|\/)\.devcontainer\/devcontainer\.json$/.test(rel)) {
    const m = /"(postCreateCommand|postStartCommand|postAttachCommand|initializeCommand|onCreateCommand)"\s*:/.exec(text);
    if (m) add({ line: lineOf(text, m.index), severity: m[1] === "initializeCommand" ? "high" : "medium", rule: "devcontainer-command", detail: `${m[1]} runs commands automatically` });
  }
  if (isAgentCfg) {
    if (/\.claude\/settings/.test(rel) && /"hooks"\s*:/.test(text)) add({ line: 1, severity: "high", rule: "agent-hooks", detail: "Claude Code hooks run shell commands automatically" });
    if (/\.claude\/settings/.test(rel) && /"(allow|permissions)"[\s\S]{0,200}(Bash\(\*\)|"Bash"|\*\*)/.test(text)) add({ line: 1, severity: "high", rule: "broad-permissions", detail: "pre-approves broad shell access" });
    if (/mcp\.json$/.test(rel)) {
      try {
        const j = JSON.parse(text);
        for (const [name, s] of Object.entries(j?.mcpServers ?? j?.servers ?? {})) {
          const sv = s && typeof s === "object" ? s : {};
          const run = [sv.command ?? sv.url, ...(Array.isArray(sv.args) ? sv.args : [])].join(" ");
          add({ line: 1, severity: "medium", rule: "mcp-server", detail: `defines MCP server "${safe(name, 40)}" that would run: ${safe(run, 100)}` });
        }
      } catch { /* ignore */ }
    }
  }
  return findings;
}

// Decode a file the way an agent would see it. UTF-16 (with or without BOM) must not be a way to dodge the scanner.
function decode(buf, rel) {
  if (buf[0] === 0xff && buf[1] === 0xfe) return buf.subarray(2).toString("utf16le");
  if (buf[0] === 0xfe && buf[1] === 0xff) return Buffer.from(buf.subarray(2)).swap16().toString("utf16le");
  if (!buf.includes(0)) return buf.toString("utf8");
  const sample = buf.subarray(0, 4096);
  let odd = 0, even = 0;
  for (let i = 0; i < sample.length; i++) if (sample[i] === 0) (i % 2 ? odd++ : even++);
  const half = sample.length / 2;
  if (odd > half * 0.3 && even === 0) return buf.toString("utf16le");
  if (even > half * 0.3 && odd === 0) return Buffer.from(buf).swap16().toString("utf16le");
  // A few stray NULs in a file an agent will read are a way to dodge the scanner, not a sign of a binary.
  if (isAgentPath(rel) || DOC_FILES.test(rel)) return buf.toString("utf8").replace(/\0/g, "");
  return null; // binary
}

export function scanDir(root) {
  const findings = [];
  let files = 0, truncated = false;
  for (const f of walk(root)) {
    if (f.truncated) { truncated = true; continue; }
    const agent = isAgentPath(f.rel);
    if (/[​-‏‪-‮⁠-⁤⁦-⁩\u{E0000}-\u{E007F}]/u.test(f.rel)) findings.push({ file: safe(f.rel), line: 0, severity: "high", rule: "invisible-filename", detail: "file or folder name contains invisible characters" });
    if (f.symlink) { findings.push({ file: f.rel, line: 0, severity: agent ? "high" : "low", rule: "symlink", detail: agent ? "agent instruction/config file is a symbolic link (can point outside the repo)" : "symbolic link (can point outside the repo)" }); continue; }
    const full = path.join(root, f.rel);
    let st;
    try { st = lstatSync(full); } catch { continue; }
    let buf;
    try { buf = readFileSync(full); } catch { continue; }
    if (st.size > MAX_FILE) {
      findings.push({ file: f.rel, line: 0, severity: agent ? "high" : "low", rule: "skipped-large", detail: `file over ${MAX_FILE} bytes${agent ? " (an agent would read all of it); only the first part was scanned" : " not scanned"}` });
      if (!agent) continue;
      buf = buf.subarray(0, MAX_FILE);
    }
    const text = decode(buf, f.rel);
    if (text === null) continue;
    files++;
    findings.push(...scanText(f.rel, text));
  }
  findings.sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || a.file.localeCompare(b.file) || a.line - b.line);
  return { files, truncated, findings };
}

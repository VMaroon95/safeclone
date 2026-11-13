import { readdirSync, readFileSync, lstatSync } from "node:fs";
import path from "node:path";
import { INVISIBLE, INJECTION, AGENT_FILES, AGENT_CONFIGS, DOC_FILES, TAG_RE, HIDDEN_TAG_RULES } from "./rules.js";

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
    if (cp === 9 || (cp >= 32 && cp < 127) || (cp > 160 && !isInvisible(cp))) out += ch;
    else out += `\\u{${cp.toString(16)}}`;
    if (out.length > max) return out.slice(0, max) + "…";
  }
  return out;
}
function isInvisible(cp) {
  return (cp >= 0x200b && cp <= 0x200f) || (cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2060 && cp <= 0x206f) ||
    cp === 0xfeff || cp === 0xad || cp === 0x180e || (cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0xe0000 && cp <= 0xe0fff);
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

export function* walk(root, state = { n: 0 }, rel = "") {
  let entries;
  try { entries = readdirSync(path.join(root, rel), { withFileTypes: true }); } catch { return; }
  for (const e of entries.sort((a, b) => (a.name < b.name ? -1 : 1))) {
    const r = rel ? `${rel}/${e.name}` : e.name;
    if (e.isSymbolicLink()) { yield { rel: r, symlink: true }; continue; }
    if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) yield* walk(root, state, r); continue; }
    if (!e.isFile()) continue;
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
    const g = new RegExp(re.source, "gu");
    const m = g.exec(text);
    if (!m) continue;
    // Emoji legitimately use variation selectors and ZWJ; only report those in agent files or in bulk.
    const count = (text.match(g) ?? []).length;
    if (rule === "variation-selectors" && !isAgentFile && count < 5) continue;
    const f = { line: lineOf(text, m.index), severity, rule, detail: `${why}, ${count} occurrence(s)` };
    if (rule === "unicode-tags") {
      const hidden = decodeTags(text);
      if (hidden) f.detail += `; hidden message decodes to: "${safe(hidden, 120)}"`;
    }
    if (isAgentFile && severity === "medium") f.severity = "high";
    add(f);
  }

  if (isDoc) {
    // Comments are invisible when rendered, so an agent reads what the human doesn't.
    const commentRe = /<!--([\s\S]*?)-->/g;
    let m;
    while ((m = commentRe.exec(text))) {
      const body = m[1].trim();
      if (body.length < 12) continue;
      const hits = INJECTION.filter(([re]) => re.test(body)).map(([, why]) => why);
      if (hits.length) add({ line: lineOf(text, m.index), severity: "high", rule: "hidden-comment-injection", detail: `HTML comment ${hits.join("; ")}: "${safe(body, 100)}"` });
      else if (isAgentFile || body.length > 200) add({ line: lineOf(text, m.index), severity: "low", rule: "hidden-comment", detail: `HTML comment not shown when rendered: "${safe(body, 100)}"` });
    }
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
    for (const [re, why] of INJECTION) {
      const mm = re.exec(text);
      if (mm) add({ line: lineOf(text, mm.index), severity: isAgentFile ? "high" : "medium", rule: "injection-phrase", detail: `${why}: "${safe(mm[0], 100)}"` });
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
        const servers = Object.entries(JSON.parse(text).mcpServers ?? JSON.parse(text).servers ?? {});
        for (const [name, s] of servers) add({ line: 1, severity: "medium", rule: "mcp-server", detail: `defines MCP server "${safe(name, 40)}" that would run: ${safe([s.command ?? s.url, ...(s.args ?? [])].join(" "), 100)}` });
      } catch { /* ignore */ }
    }
  }
  return findings;
}

export function scanDir(root) {
  const findings = [];
  let files = 0, truncated = false;
  for (const f of walk(root)) {
    if (f.truncated) { truncated = true; continue; }
    if (f.symlink) { findings.push({ file: f.rel, line: 0, severity: "low", rule: "symlink", detail: "symbolic link (can point outside the repo)" }); continue; }
    const full = path.join(root, f.rel);
    let st;
    try { st = lstatSync(full); } catch { continue; }
    if (st.size > MAX_FILE) { findings.push({ file: f.rel, line: 0, severity: "low", rule: "skipped-large", detail: `file over ${MAX_FILE} bytes not scanned` }); continue; }
    let buf;
    try { buf = readFileSync(full); } catch { continue; }
    if (buf.includes(0)) continue; // binary
    files++;
    findings.push(...scanText(f.rel, buf.toString("utf8")));
    if (/(^|\/)[^/]*[​-‏‪-‮⁠-⁤\u{E0000}-\u{E007F}][^/]*$/u.test(f.rel)) findings.push({ file: safe(f.rel), line: 0, severity: "high", rule: "invisible-filename", detail: "file name contains invisible characters" });
  }
  findings.sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || a.file.localeCompare(b.file) || a.line - b.line);
  return { files, truncated, findings };
}

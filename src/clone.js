import { spawnSync } from "node:child_process";
import path from "node:path";

// Only network transports. Blocks ext::, fd::, file:// and option-looking values (argument injection).
const URL_OK = /^(https:\/\/[A-Za-z0-9][\w.-]*(:\d+)?\/[\w.\/~%+-]+|ssh:\/\/([A-Za-z0-9][\w.-]*@)?[A-Za-z0-9][\w.-]*(:\d+)?\/[\w.\/~%+-]+|[A-Za-z0-9][\w.-]*@[A-Za-z0-9][\w.-]*:[\w.\/~%+-]+)$/;

export function validateUrl(url, { allowLocal = false } = {}) {
  if (typeof url !== "string" || !url || url.startsWith("-")) throw new Error("invalid repository URL");
  if (allowLocal && path.isAbsolute(url)) return url; // used by tests only
  if (!URL_OK.test(url) || url.includes("..")) throw new Error(`refusing URL (only https:// and ssh remotes are allowed): ${url.slice(0, 80)}`);
  return url;
}

export function defaultDest(url) {
  const base = url.replace(/\/+$/, "").split(/[/:]/).pop().replace(/\.git$/, "");
  if (!/^[\w.-]+$/.test(base) || base.startsWith(".")) throw new Error("could not derive a safe folder name; pass --dest");
  return base;
}

// Arguments that neutralise the common clone-time attack surface.
export function cloneArgs(url, dest, { depth = 1 } = {}) {
  return [
    "-c", "core.hooksPath=/dev/null",      // no hooks
    "-c", "core.fsmonitor=false",          // fsmonitor can run commands
    "-c", "protocol.ext.allow=never",
    "-c", "protocol.file.allow=never",
    "-c", "core.symlinks=false",           // checkout symlinks as plain files
    "clone", "--no-recurse-submodules", "--depth", String(depth), "--", url, dest,
  ];
}

export function cloneRepo(url, dest, opts = {}) {
  validateUrl(url, opts);
  const args = cloneArgs(url, dest);
  if (opts.allowLocal) args.splice(args.indexOf("protocol.file.allow=never"), 1, "protocol.file.allow=always");
  const env = { ...process.env, GIT_TERMINAL_PROMPT: "0", GIT_ALLOW_PROTOCOL: opts.allowLocal ? "file:https:ssh" : "https:ssh" };
  const r = spawnSync("git", args, { env, encoding: "utf8", shell: false, timeout: 300000 });
  if (r.status !== 0) throw new Error(`git clone failed: ${(r.stderr || r.error?.message || "").trim().split("\n").slice(-3).join(" ")}`);
}

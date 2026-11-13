# safeclone

**Check a repo for hidden prompt-injection before your AI agent reads it.**

Coding agents (Claude Code, Cursor, Copilot, Cline…) treat text in a repo as instructions. Attackers hide that text where humans don't look. safeclone finds it, offline, with zero dependencies, and never executes anything from the repo.

```bash
npx safeclone https://github.com/someone/unknown-repo   # clone safely, then scan
npx safeclone scan ./already-cloned                     # scan a folder
npx safeclone scan . --clean ../clean-copy              # also write a sanitised copy
```

## What it finds

| Rule | Example |
|---|---|
| `unicode-tags` (high) | Invisible Unicode "tag" characters that smuggle a whole ASCII message. The hidden text is decoded in the report. |
| `bidi-override` (high) | Trojan Source: right-to-left overrides that make code read differently than it runs |
| `zero-width` (medium; high in agent files) | Zero-width / invisible characters |
| `hidden-comment-injection` (high) | `<!-- AI agents: ignore previous instructions … -->` in a README |
| `hidden-html` (medium) | Text hidden with `display:none`, `font-size:0`, the `hidden` attribute |
| `injection-phrase` (medium; high in `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, skills…) | "ignore previous instructions", "don't tell the user", `curl … \| sh`, "send the .env", "disable safety" |
| `install-script` / `auto-run-task` / `devcontainer-command` | `postinstall` scripts, VS Code `folderOpen` tasks, devcontainer commands |
| `agent-hooks` / `broad-permissions` / `mcp-server` | `.claude/settings.json` hooks, blanket Bash approval, MCP servers a repo would start |
| `invisible-filename`, `symlink`, `base64-blob` | Housekeeping signals |

Exit code 1 when anything at or above `--fail-on` (default `high`) is found, so it works in CI and scripts.

## Safe by construction

- **Safe clone:** `git clone` with hooks off (`core.hooksPath=/dev/null`), no submodules, `ext::`/`file:` protocols blocked, symlinks not checked out, and only `https://` / `ssh` URLs accepted. Option-looking URLs (`--upload-pack=…`) are rejected.
- **Escaped output:** the report itself is escaped, so hidden characters in a repo can't reach your terminal or an agent that reads the report.
- **Linear-time scanning:** tested against inputs built to cause regex backtracking. Files over 2 MB, binaries, `.git` and `node_modules` are skipped; symlinks are reported, never followed.
- **No network** except the clone you asked for. No telemetry.

## Limits

Heuristics find known tricks; they cannot prove a repo is safe. A clean report means "nothing matched", not "trustworthy". Phrases are matched in English. Binary files and code logic are not analysed.

## Related

[mcp-lock](https://github.com/VMaroon95/mcp-lock) pins MCP server tool descriptions the same way, for the other half of the problem.

```bash
npm test
```

MIT licensed.

// Detection rules. Each text rule returns findings for one file's content.
// Severity: high = very likely malicious or directly executes; medium = suspicious; low = review.

export const INVISIBLE = [
  // Unicode "tag" block: maps 1:1 to ASCII, renders as nothing. Classic "ASCII smuggling".
  { re: /[\u{E0000}-\u{E007F}]/u, rule: "unicode-tags", severity: "high", why: "invisible Unicode tag characters (can hide a full ASCII message)" },
  { re: /[‪-‮⁦-⁩]/u, rule: "bidi-override", severity: "high", why: "bidirectional override characters (Trojan Source)" },
  { re: /[​-‏⁠-⁤﻿­᠎]/u, rule: "zero-width", severity: "medium", why: "zero-width or invisible characters" },
  { re: /[︀-️\u{E0100}-\u{E01EF}]/u, rule: "variation-selectors", severity: "low", why: "variation selectors (can encode hidden data; also appear in emoji)" },
];

// Phrases that try to steer a model. Heuristic: they flag for human review, they do not prove intent.
export const INJECTION = [
  [/ignore (all |any )?(previous|prior|above|earlier) (instructions|prompts?|rules)/i, "tries to override earlier instructions"],
  [/(disregard|forget) (all |any )?(previous|prior|above|your) (instructions|rules|guidelines)/i, "tries to override earlier instructions"],
  [/\b(do not|don't|never) (tell|inform|mention|reveal|show|notify)[^.\n]{0,50}\b(user|human|developer)\b/i, "asks to hide actions from the user"],
  [/<\s*(important|system|instructions?|admin)\s*>/i, "pseudo-system tag"],
  [/\b(you are now|from now on you|new instructions:|system prompt:)/i, "role or instruction reset"],
  [/\b(curl|wget)\b[^\n|]{0,200}\|\s*(sudo\s+)?(ba|z)?sh\b/i, "pipes a download into a shell"],
  [/\b(send|upload|post|exfiltrate|email|forward)\b[^.\n]{0,60}(\.ssh|\.env\b|id_rsa|credentials|secrets?|api[_ -]?keys?|\.aws|keychain)/i, "asks to send secrets somewhere"],
  [/\bcat\b[^\n]{0,40}(\.ssh\/|\.aws\/credentials|\.env\b)/i, "reads secret files"],
  [/\b(disable|turn off|skip|bypass)\b[^.\n]{0,40}(safety|security|permission|sandbox|confirmation|approval)/i, "asks to disable safeguards"],
  [/\brm\s+-rf?\s+(\/|~|\$HOME)/i, "destructive delete command"],
];

// Files that agents load automatically as trusted instructions or config.
export const AGENT_FILES = [
  /(^|\/)(CLAUDE|AGENTS|GEMINI|COPILOT)\.md$/i,
  /(^|\/)\.cursorrules$/i, /(^|\/)\.cursor\/rules\//i, /(^|\/)\.windsurfrules$/i,
  /(^|\/)\.github\/copilot-instructions\.md$/i,
  /(^|\/)\.claude\/(commands|agents|skills)\//i, /(^|\/)SKILL\.md$/i,
  /(^|\/)\.clinerules/i, /(^|\/)\.continue\//i,
];
export const AGENT_CONFIGS = [/(^|\/)\.mcp\.json$/i, /(^|\/)\.claude\/settings(\.local)?\.json$/i, /(^|\/)\.cursor\/mcp\.json$/i, /(^|\/)\.vscode\/mcp\.json$/i];
export const DOC_FILES = /\.(md|mdx|markdown|rst|txt|adoc|html?|ya?ml|json|toml)$/i;

// Checked per tag (bounded length) so hostile input cannot trigger quadratic regex backtracking.
export const TAG_RE = /<([a-zA-Z][\w-]*)\b[^<>]{0,500}>/g;
export const HIDDEN_TAG_RULES = [
  [/style\s*=\s*["'][^"']*(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0|color\s*:\s*(white|#fff(fff)?)\b)[^"']*["']/i, "text hidden with CSS"],
  [/\shidden(\s|=|\/|>|$)/i, "element with the hidden attribute"],
];

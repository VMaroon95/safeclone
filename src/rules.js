// Detection rules. Each text rule returns findings for one file's content.
// Severity: high = very likely malicious or directly executes; medium = suspicious; low = review.

// One shared definition of "invisible", so scanning, printing and cleaning agree.
const BIDI = "\\u202A-\\u202E\\u2066-\\u2069";
const ZW = "\\u200B-\\u200F\\u2028\\u2029\\u2060-\\u2064\\u206A-\\u206F\\uFEFF\\u00AD\\u034F\\u061C\\u115F\\u1160\\u17B4\\u17B5\\u180B-\\u180E\\u3164\\uFFA0\\u2800\\u{1D173}-\\u{1D17A}";
const TAGS = "\\u{E0000}-\\u{E007F}";
const VS = "\\uFE00-\\uFE0F\\u{E0100}-\\u{E01EF}";
export const HIDDEN_RE = new RegExp(`[${BIDI}${ZW}${TAGS}]`, "gu");           // removed by the sanitised copy
export const ANY_INVISIBLE_RE = new RegExp(`[${BIDI}${ZW}${TAGS}${VS}]`, "u"); // escaped when printed

export const INVISIBLE = [
  // Unicode "tag" block: maps 1:1 to ASCII, renders as nothing. Classic "ASCII smuggling".
  { re: new RegExp(`[${TAGS}]`, "u"), rule: "unicode-tags", severity: "high", why: "invisible Unicode tag characters (can hide a full ASCII message)" },
  { re: new RegExp(`[${BIDI}]`, "u"), rule: "bidi-override", severity: "high", why: "bidirectional override or isolate characters (Trojan Source)" },
  { re: new RegExp(`[${ZW}]`, "u"), rule: "zero-width", severity: "medium", why: "zero-width or invisible characters" },
  { re: new RegExp(`[${VS}]`, "u"), rule: "variation-selectors", severity: "low", why: "variation selectors (can encode hidden data; also appear in emoji)" },
];

// Phrases that try to steer a model. Heuristic: they flag for human review, they do not prove intent.
export const INJECTION = [
  [/ignore\s+(all\s+|any\s+|the\s+)?(previous|prior|above|earlier)\s+(instructions|prompts?|rules)/i, "tries to override earlier instructions"],
  [/(disregard|forget)\s+(?:(?:all|any|the|your)\s+)*(previous|prior|above|earlier|your)\s+(instructions|rules|guidelines)/i, "tries to override earlier instructions"],
  [/\bforget\s+(everything|all)\s+(you|that|above|prior|previous)/i, "tries to override earlier instructions"],
  [/\b(do\s+not|don't|never|must\s+not|should\s+not|mustn't|shouldn't)\s+(tell|inform|mention|reveal|show|notify|disclose|let)[^.\n]{0,50}\b(user|human|developer|owner|operator)\b/i, "asks to hide actions from the user"],
  [/<\s*(important|system|instructions?|admin)\s*>/i, "pseudo-system tag"],
  [/\b(you are now|from now on you|new instructions:|system prompt:)/i, "role or instruction reset"],
  [/\b(curl|wget)\b[^\n|]{0,200}\|\s*(sudo\s+)?(ba|z)?sh\b/i, "pipes a download into a shell"],
  [/\b(send|upload|post|exfiltrate|email|forward)\b[^.\n]{0,60}(\.ssh|\.env\b|id_rsa|credentials|secrets?|api[_ -]?keys?|\.aws|keychain)/i, "asks to send secrets somewhere"],
  [/\bcat\b[^\n]{0,40}(\.ssh\/|\.aws\/credentials|\.env\b)/i, "reads secret files"],
  [/\b(disable|turn off|skip|bypass)\b[^.\n]{0,40}(safety|security|permission|sandbox|confirmation|approval)/i, "asks to disable safeguards"],
  [/\brm\s+-rf?\s+(\/|~|\$HOME)/i, "destructive delete command"],
];

// Latin look-alikes from Cyrillic and Greek, used to see through homoglyph evasion.
const CONFUSABLES = Object.fromEntries(
  "аa вb еe кk мm нh оo рp сc тt уy хx іi јj ѕs һh ԁd ɡg ӏl ΑA ΒB ΕE ΖZ ΗH ΙI ΚK ΜM ΝN ΟO ΡP ΤT ΥY ΧX αa εe ιi κk νv οo ρp τt υu χx".split(" ").map((p) => [p[0], p[1]]));

// Text as a model would read it: invisibles gone, compatibility forms folded, look-alikes mapped, spaced-out letters joined.
export function normalizeForMatch(text) {
  let t = text.replace(new RegExp(HIDDEN_RE.source + "|[\\uFE00-\\uFE0F]", "gu"), "").normalize("NFKC");
  t = t.replace(/[^\x00-\x7f]/gu, (c) => CONFUSABLES[c] ?? CONFUSABLES[c.toLowerCase()] ?? c);
  t = t.replace(/[ \t]+/g, " ");
  return t.replace(/\b(?:[A-Za-z] ){3,}[A-Za-z]\b/g, (m) => m.replace(/ /g, ""));
}

// Files that agents load automatically as trusted instructions or config.
export const AGENT_FILES = [
  /(^|\/)(CLAUDE|AGENTS|GEMINI|COPILOT)\.md$/i,
  /(^|\/)\.cursorrules$/i, /(^|\/)\.cursor\/rules\//i, /(^|\/)\.windsurfrules$/i,
  /(^|\/)\.github\/copilot-instructions\.md$/i,
  /(^|\/)\.claude\/(commands|agents|skills)\//i, /(^|\/)SKILL\.md$/i,
  /(^|\/)\.clinerules/i, /(^|\/)\.continue\//i,
];
export const AGENT_CONFIGS = [/(^|\/)\.mcp\.json$/i, /(^|\/)\.claude\/settings(\.local)?\.json$/i, /(^|\/)\.cursor\/mcp\.json$/i, /(^|\/)\.vscode\/mcp\.json$/i];
export const isAgentPath = (rel) => AGENT_FILES.some((r) => r.test(rel)) || AGENT_CONFIGS.some((r) => r.test(rel));
export const DOC_FILES = /(\.(md|mdx|markdown|rst|txt|adoc|html?|ya?ml|json|toml)|(^|\/)(README|LICENSE|CONTRIBUTING|INSTALL|NOTICE))$/i;

// Checked per tag (bounded length) so hostile input cannot trigger quadratic regex backtracking.
export const TAG_RE = /<([a-zA-Z][\w-]*)\b[^<>]{0,500}>/g;
export const HIDDEN_TAG_RULES = [
  [/style\s*=\s*["'][^"']*(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0|color\s*:\s*(white|#fff(fff)?)\b)[^"']*["']/i, "text hidden with CSS"],
  [/\shidden(\s|=|\/|>|$)/i, "element with the hidden attribute"],
];

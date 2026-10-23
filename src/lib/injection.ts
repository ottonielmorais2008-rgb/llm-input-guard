import { normalizeForMatch, originalSpan } from "./normalize";
import type { Finding } from "./types";

export interface RuleInfo {
  id: string;
  description: string;
}

interface Rule {
  id: string;
  description: string;
  patterns: readonly RegExp[];
}

/**
 * Letters may be split by spaces, dots, or underscores (`i.g.n.o.r.e`).
 * The gap is only whitespace and punctuation, so this stays linear.
 */
function looseWord(word: string): string {
  return word.split("").join("[\\s._-]*");
}

function looseAlt(words: readonly string[]): string {
  return `(?:${words.map(looseWord).join("|")})`;
}

const IGNORE_WORDS = ["ignore", "disregard", "forget", "override"] as const;
const TARGET_WORDS = ["previous", "prior", "above", "earlier", "original", "all", "any"] as const;
const OBJECT_WORDS = [
  "instructions",
  "instruction",
  "prompts",
  "prompt",
  "rules",
  "rule",
  "guidelines",
  "directives",
  "commands",
] as const;
const FILLER = "(?:all|any|the|of|your|my|our|these|those|and)";
const PRIOR = "(?:previous|prior|above|earlier|original)";
const OBJECT = "(?:instructions?|prompts?|rules?|guidelines?|directives?|commands?)";

const RULES: readonly Rule[] = [
  {
    id: "ignore-previous",
    description: "Tells the model to ignore, forget, or override earlier instructions.",
    patterns: [
      // Filler is a closed list ("the", "all", "your"). An open word gap
      // also matched benign lines such as "ignore previous formatting rules".
      new RegExp(
        `\\b(?:ignore|disregard|forget|override)\\b(?:\\s+${FILLER})*\\s+${PRIOR}\\s+${OBJECT}\\b`,
        "g",
      ),
      new RegExp(
        `\\b(?:ignore|disregard|forget|override)\\s+(?:all|any)(?:\\s+(?:of|the|your|my))*\\s+${OBJECT}\\b`,
        "g",
      ),
      new RegExp(
        `\\b${looseAlt(IGNORE_WORDS)}[\\s._-]+(?:${looseAlt(["all", "any"])}[\\s._-]+)?${looseAlt(TARGET_WORDS)}[\\s._-]+${looseAlt(OBJECT_WORDS)}\\b`,
        "g",
      ),
    ],
  },
  {
    id: "system-impersonation",
    description: "Pretends the user message is a system, root, or jailbreak role.",
    patterns: [
      /\b(?:you are now|you(?:'|’)re now|from now on you are|pretend to be|pretend you are|act as)\s+(?:a |an |the )?(?:system|root|jailbreak)\b(?!\s+administrator)/g,
    ],
  },
  {
    id: "jailbreak-persona",
    description: "Names a jailbreak persona such as DAN, developer mode, or “do anything now”.",
    patterns: [
      // The bare word "jailbreak" is intentionally absent: "act as jailbreak"
      // belongs to system-impersonation, and a mention of the topic is not a persona.
      /\b(?:do anything now|developer mode|jailbreak mode|enable dan(?: mode)?|you are dan(?: mode)?|act as dan(?: mode)?|dan mode|unfiltered mode|evil mode)\b/g,
      new RegExp(`\\b${looseWord("developer")}\\s+${looseWord("mode")}\\b`, "g"),
    ],
  },
  {
    id: "delimiter-smuggling",
    description: "Smuggles a fake chat turn with template tokens or system tags.",
    patterns: [
      /<\|im_start\|>|<\|im_end\|>|<\|system\|>|\[inst\]|\[\/inst\]|<<sys>>|<<\/sys>>|<\s*\/\s*system\s*>|(?:^|\n)\s*<\s*system\s*>\s*(?=\n|$)|(?:^|\n)\s*###\s*system\b|\[system\]/g,
    ],
  },
  {
    id: "policy-bypass",
    description: "Asks to disable safety filters, guardrails, or content policy.",
    patterns: [
      /\b(?:disable|bypass|turn off|remove|skip|override)\b(?:\s+[a-z]+){0,4}\s+(?:safety filters?|content filters?|safeguards?|guardrails?|content policy|restrictions|ethical guidelines)\b/g,
    ],
  },
  {
    id: "prompt-exfiltration",
    description: "Asks the model to reveal its hidden or system prompt.",
    patterns: [
      /\b(?:reveal|print|show|dump|repeat|leak|output|display)\b(?:\s+[a-z]+){0,6}\s+(?:system prompt|hidden prompt|hidden instructions|initial prompt|developer message|developer prompt|confidential instructions)\b/g,
    ],
  },
];

export const INJECTION_RULES: readonly RuleInfo[] = [
  ...RULES.map((rule) => ({ id: rule.id, description: rule.description })),
  {
    id: "encoded-payload",
    description: "Hides one of the phrases above in base64, percent-encoding, or hex escapes.",
  },
];

const BASE64_PATTERN =
  /(?:^|[^A-Za-z0-9+/])([A-Za-z0-9+/]{24,}={0,2})(?![A-Za-z0-9+/])/g;
const PERCENT_PATTERN = /(?:%[0-9A-Fa-f]{2}){8,}/g;
const UNICODE_ESCAPE_PATTERN = /(?:\\u[0-9A-Fa-f]{4}){6,}/g;
const HEX_ESCAPE_PATTERN = /(?:\\x[0-9A-Fa-f]{2}){6,}/g;

export function findInjection(text: string): Finding[] {
  const direct = matchRules(text);
  const encoded = matchEncoded(text);
  return dedupe([...direct, ...encoded]);
}

function matchRules(text: string): Finding[] {
  const normalized = normalizeForMatch(text);
  const findings: Finding[] = [];

  for (const rule of RULES) {
    for (const pattern of rule.patterns) {
      for (const match of collect(pattern, normalized.text)) {
        const start = match.index;
        if (start === undefined) continue;
        const span = originalSpan(text, normalized, start, start + match[0].length);
        if (!span) continue;
        findings.push({
          kind: "prompt_injection",
          ruleId: rule.id,
          message: rule.description,
          start: span.start,
          end: span.end,
          snippet: compactSnippet(text.slice(span.start, span.end)),
        });
      }
    }
  }

  return findings;
}

function matchEncoded(text: string): Finding[] {
  const findings: Finding[] = [];
  for (const blob of collectBlobs(text)) {
    const hidden = matchingRules(blob.decoded);
    if (hidden.length === 0) continue;
    const names = hidden.map((rule) => rule.id).join(", ");
    findings.push({
      kind: "prompt_injection",
      ruleId: "encoded-payload",
      message: `Encoded payload hides a blocked phrase (${names}).`,
      start: blob.start,
      end: blob.end,
      snippet: compactSnippet(text.slice(blob.start, blob.end)),
    });
  }
  return findings;
}

interface DecodedBlob {
  start: number;
  end: number;
  decoded: string;
}

function collectBlobs(text: string): DecodedBlob[] {
  const blobs: DecodedBlob[] = [];

  for (const match of collect(BASE64_PATTERN, text)) {
    const token = match[1];
    const start = match.index;
    if (!token || start === undefined) continue;
    const offset = match[0].lastIndexOf(token);
    const decoded = decodeBase64(token);
    if (!decoded || !isMostlyText(decoded)) continue;
    blobs.push({ start: start + offset, end: start + offset + token.length, decoded });
  }

  pushSimple(blobs, text, PERCENT_PATTERN, decodePercent);
  pushSimple(blobs, text, UNICODE_ESCAPE_PATTERN, decodeUnicodeEscapes);
  pushSimple(blobs, text, HEX_ESCAPE_PATTERN, decodeHexEscapes);
  return blobs;
}

function pushSimple(
  blobs: DecodedBlob[],
  text: string,
  pattern: RegExp,
  decode: (raw: string) => string | null,
): void {
  for (const match of collect(pattern, text)) {
    const start = match.index;
    if (start === undefined) continue;
    const decoded = decode(match[0]);
    if (!decoded || !isMostlyText(decoded)) continue;
    blobs.push({ start, end: start + match[0].length, decoded });
  }
}

function matchingRules(text: string): Rule[] {
  const normalized = normalizeForMatch(text).text;
  return RULES.filter((rule) =>
    rule.patterns.some((pattern) => collect(pattern, normalized).length > 0),
  );
}

function collect(pattern: RegExp, text: string): RegExpMatchArray[] {
  const flags = pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`;
  return [...text.matchAll(new RegExp(pattern.source, flags))];
}

function decodeBase64(token: string): string | null {
  if (token.length % 4 !== 0) return null;
  try {
    const binary = atob(token);
    const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
    return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  } catch {
    return null;
  }
}

function decodePercent(raw: string): string | null {
  const bytes: number[] = [];
  for (let i = 0; i < raw.length; i += 3) {
    const value = Number.parseInt(raw.slice(i + 1, i + 3), 16);
    if (Number.isNaN(value)) return null;
    bytes.push(value);
  }
  return new TextDecoder("utf-8", { fatal: false }).decode(Uint8Array.from(bytes));
}

function decodeUnicodeEscapes(raw: string): string | null {
  return raw.replace(/\\u([0-9A-Fa-f]{4})/g, (_match, hex: string) =>
    String.fromCharCode(Number.parseInt(hex, 16)),
  );
}

function decodeHexEscapes(raw: string): string | null {
  return raw.replace(/\\x([0-9A-Fa-f]{2})/g, (_match, hex: string) =>
    String.fromCharCode(Number.parseInt(hex, 16)),
  );
}

function isMostlyText(value: string): boolean {
  const chars = [...value];
  if (chars.length < 8) return false;
  let printable = 0;
  for (const char of chars) {
    const code = char.codePointAt(0) ?? 0;
    if (code === 9 || code === 10 || code === 13 || (code >= 32 && code < 127)) {
      printable += 1;
    }
  }
  return printable / chars.length >= 0.9;
}

function compactSnippet(value: string): string {
  const compact = value.replace(/\s+/g, " ").trim();
  if (compact.length <= 80) return compact;
  return `${compact.slice(0, 77)}...`;
}

function dedupe(findings: Finding[]): Finding[] {
  // Longer span first so "enable dan mode" wins over the shorter "enable dan".
  const sorted = [...findings].sort(
    (a, b) => b.end - b.start - (a.end - a.start) || a.start - b.start,
  );
  const kept: Finding[] = [];
  for (const finding of sorted) {
    const sameRuleOverlap = kept.some(
      (existing) =>
        existing.ruleId === finding.ruleId &&
        finding.start < existing.end &&
        existing.start < finding.end,
    );
    if (!sameRuleOverlap) kept.push(finding);
  }
  return kept.sort((a, b) => a.start - b.start || a.end - b.end);
}

import type { Finding } from "./types";

export interface RuleInfo {
  id: string;
  description: string;
}

/** Portuguese mobiles use the national prefixes 91, 92, 93, and 96. */
const PHONE_PATTERN =
  /(?<!\d)(?:(?:\+\s*351|00\s*351|\(\s*\+\s*351\s*\))[\s.-]*)?9[1236](?:[\s.-]*\d){7}(?!\d)/g;

const EMAIL_PATTERN =
  /\b[A-Za-z0-9](?:[A-Za-z0-9._%+-]*[A-Za-z0-9])?@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z]{2,})+\b/g;

const CARD_PATTERN =
  /\b(?:\d{13,19}|\d{4}(?:[ -]\d{4}){3}|\d{4}[ -]\d{6}[ -]\d{5})\b/g;

/**
 * Printed IBANs are grouped in blocks of four. The final block can be shorter.
 * A following word cannot join the match unless it is itself an IBAN block.
 */
const IBAN_PATTERN =
  /\b[A-Za-z]{2}\d{2}(?:[ ]?[A-Za-z0-9]{4}){2,7}(?:[ ]?[A-Za-z0-9]{1,4})?\b/g;

const IBAN_LENGTHS: Readonly<Record<string, number>> = {
  AL: 28,
  AD: 24,
  AT: 20,
  AZ: 28,
  BE: 16,
  BH: 22,
  BA: 20,
  BR: 29,
  BG: 22,
  CR: 22,
  HR: 21,
  CY: 28,
  CZ: 24,
  DK: 18,
  DO: 28,
  EE: 20,
  FO: 18,
  FI: 18,
  FR: 27,
  GE: 22,
  DE: 22,
  GI: 23,
  GR: 27,
  GL: 18,
  GT: 28,
  HU: 28,
  IS: 26,
  IE: 22,
  IL: 23,
  IT: 27,
  JO: 30,
  KZ: 20,
  XK: 20,
  KW: 30,
  LV: 21,
  LB: 28,
  LI: 21,
  LT: 20,
  LU: 20,
  MT: 31,
  MR: 27,
  MU: 30,
  MD: 24,
  MC: 27,
  ME: 22,
  NL: 18,
  MK: 19,
  NO: 15,
  PK: 24,
  PS: 29,
  PL: 28,
  PT: 25,
  QA: 29,
  RO: 24,
  LC: 32,
  SM: 27,
  ST: 25,
  SA: 24,
  RS: 22,
  SC: 31,
  SK: 24,
  SI: 19,
  ES: 24,
  SE: 24,
  CH: 21,
  TL: 23,
  TN: 24,
  TR: 26,
  UA: 29,
  AE: 23,
  GB: 22,
  VG: 24,
};

type PiiRuleId = "pii-email" | "pii-phone" | "pii-iban" | "pii-card";

interface PiiHit {
  ruleId: PiiRuleId;
  message: string;
  start: number;
  end: number;
  snippet: string;
  priority: number;
}

export const PII_RULES: readonly RuleInfo[] = [
  { id: "pii-email", description: "Email address." },
  {
    id: "pii-phone",
    description: "Portuguese mobile number (prefixes 91, 92, 93, 96), with an optional +351 or 00351.",
  },
  { id: "pii-iban", description: "IBAN whose country length and mod-97 checksum both check out." },
  {
    id: "pii-card",
    description: "Payment card number with a known brand prefix and a valid Luhn checksum.",
  },
];

export function findPii(text: string): Finding[] {
  const hits = [
    ...findEmails(text),
    ...findPhones(text),
    ...findIbans(text),
    ...findCards(text),
  ];
  return resolveOverlaps(hits).map((hit) => ({
    kind: "pii",
    ruleId: hit.ruleId,
    message: hit.message,
    start: hit.start,
    end: hit.end,
    snippet: hit.snippet,
  }));
}

export function redactPii(text: string, findings: readonly Finding[]): string {
  const spans = findings
    .filter((finding) => finding.kind === "pii")
    .sort((a, b) => b.start - a.start);

  let redacted = text;
  for (const span of spans) {
    redacted = redacted.slice(0, span.start) + tagFor(span.ruleId) + redacted.slice(span.end);
  }
  return redacted;
}

function findEmails(text: string): PiiHit[] {
  return collect(EMAIL_PATTERN, text).map((match) =>
    hit("pii-email", "Email address.", match, maskEmail(match[0]), 2),
  );
}

function findPhones(text: string): PiiHit[] {
  return collect(PHONE_PATTERN, text).map((match) =>
    hit("pii-phone", "Portuguese mobile phone number.", match, maskPhone(match[0]), 1),
  );
}

function findIbans(text: string): PiiHit[] {
  const hits: PiiHit[] = [];
  for (const match of collect(IBAN_PATTERN, text)) {
    if (!isValidIban(match[0])) continue;
    hits.push(hit("pii-iban", "IBAN.", match, maskIban(match[0]), 3));
  }
  return hits;
}

function findCards(text: string): PiiHit[] {
  const hits: PiiHit[] = [];
  for (const match of collect(CARD_PATTERN, text)) {
    const digits = match[0].replace(/\D/g, "");
    if (!isCardBrand(digits) || !luhnOk(digits)) continue;
    hits.push(hit("pii-card", "Payment card number.", match, maskCard(digits), 4));
  }
  return hits;
}

/**
 * Keep the higher-priority span when two detectors cover the same characters.
 * Cards outrank IBANs, which outrank emails, which outrank phone numbers.
 */
function resolveOverlaps(hits: PiiHit[]): PiiHit[] {
  const ordered = [...hits].sort(
    (a, b) => b.priority - a.priority || b.end - b.start - (a.end - a.start) || a.start - b.start,
  );
  const kept: PiiHit[] = [];
  for (const candidate of ordered) {
    const overlaps = kept.some(
      (existing) => candidate.start < existing.end && existing.start < candidate.end,
    );
    if (!overlaps) kept.push(candidate);
  }
  return kept.sort((a, b) => a.start - b.start || a.end - b.end);
}

function hit(
  ruleId: PiiRuleId,
  message: string,
  match: RegExpMatchArray,
  snippet: string,
  priority: number,
): PiiHit {
  const start = match.index ?? 0;
  return {
    ruleId,
    message,
    start,
    end: start + match[0].length,
    snippet,
    priority,
  };
}

function collect(pattern: RegExp, text: string): RegExpMatchArray[] {
  const flags = pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`;
  return [...text.matchAll(new RegExp(pattern.source, flags))];
}

function isValidIban(raw: string): boolean {
  const compact = raw.replace(/ /g, "").toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]+$/.test(compact)) return false;
  if (compact.length < 15 || compact.length > 34) return false;
  const expected = IBAN_LENGTHS[compact.slice(0, 2)];
  if (expected !== undefined && compact.length !== expected) return false;
  return ibanChecksumOk(compact);
}

/**
 * ISO 13616: move the first four characters to the end, expand letters
 * (A=10 … Z=35), and require the integer value mod 97 to equal 1.
 */
function ibanChecksumOk(iban: string): boolean {
  const rearranged = iban.slice(4) + iban.slice(0, 4);
  let remainder = 0;
  for (const char of rearranged) {
    const code = char.charCodeAt(0);
    const digits = code >= 65 && code <= 90 ? String(code - 55) : char;
    for (const digit of digits) {
      remainder = (remainder * 10 + (digit.charCodeAt(0) - 48)) % 97;
    }
  }
  return remainder === 1;
}

function isCardBrand(digits: string): boolean {
  if (/^4\d{12}$/.test(digits) || /^4\d{15}$/.test(digits) || /^4\d{18}$/.test(digits)) {
    return true;
  }
  if (digits.length === 15 && /^3[47]\d{13}$/.test(digits)) return true;
  if (digits.length === 16 && /^5[1-5]\d{14}$/.test(digits)) return true;
  if (digits.length === 16 && isMastercard2Series(digits)) return true;
  if (digits.length === 16 && /^6(?:011|5\d{2}|4[4-9]\d)\d{12}$/.test(digits)) return true;
  return false;
}

function isMastercard2Series(digits: string): boolean {
  const prefix = Number.parseInt(digits.slice(0, 4), 10);
  return prefix >= 2221 && prefix <= 2720;
}

/** Double every second digit from the right. The total must be divisible by 10. */
function luhnOk(digits: string): boolean {
  let sum = 0;
  let doubleNext = false;
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    const char = digits.charAt(i);
    let value = char.charCodeAt(0) - 48;
    if (value < 0 || value > 9) return false;
    if (doubleNext) {
      value *= 2;
      if (value > 9) value -= 9;
    }
    sum += value;
    doubleNext = !doubleNext;
  }
  return sum % 10 === 0;
}

function tagFor(ruleId: string): string {
  switch (ruleId) {
    case "pii-email":
      return "[REDACTED_EMAIL]";
    case "pii-phone":
      return "[REDACTED_PHONE]";
    case "pii-iban":
      return "[REDACTED_IBAN]";
    case "pii-card":
      return "[REDACTED_CARD]";
    default:
      throw new Error(`No redaction tag for ${ruleId}`);
  }
}

function maskEmail(value: string): string {
  const at = value.indexOf("@");
  if (at <= 0) return "[REDACTED_EMAIL]";
  return `${value.charAt(0)}…@${value.slice(at + 1)}`;
}

function maskPhone(value: string): string {
  const digits = value.replace(/\D/g, "");
  const tail = digits.slice(-2);
  if (value.trimStart().startsWith("+") || value.trimStart().startsWith("00")) {
    return `+351 …${tail}`;
  }
  return `${digits.slice(0, 3)}…${tail}`;
}

function maskIban(value: string): string {
  const compact = value.replace(/ /g, "").toUpperCase();
  return `${compact.slice(0, 4)}…${compact.slice(-4)}`;
}

function maskCard(digits: string): string {
  return `•••• ${digits.slice(-4)}`;
}

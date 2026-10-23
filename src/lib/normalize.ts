/**
 * Fold text so injection rules can see past cheap obfuscation:
 * case, Unicode compatibility forms, a few homoglyphs, leet digits, and
 * zero-width characters. The index map sends a match back to the original string.
 */

const ZERO_WIDTH = new Set<string>([
  "\u200B",
  "\u200C",
  "\u200D",
  "\u2060",
  "\uFEFF",
  "\u00AD",
  "\u180E",
]);

/** Lowercase lookalikes that survive NFKC and still read as Latin letters. */
const HOMOGLYPHS: Readonly<Record<string, string>> = {
  "\u0430": "a",
  "\u0435": "e",
  "\u043e": "o",
  "\u0440": "p",
  "\u0441": "c",
  "\u0443": "y",
  "\u0445": "x",
  "\u0456": "i",
  "\u0455": "s",
  "\u0458": "j",
  "\u03bf": "o",
  "\u03b9": "i",
  "\u0261": "g",
};

/**
 * Digit lookalikes used inside words (`1gn0re`). Applied only while matching
 * injection phrases, never while matching numbers such as phones or cards.
 */
const LEET: Readonly<Record<string, string>> = {
  "0": "o",
  "1": "i",
  "3": "e",
  "4": "a",
  "5": "s",
  "7": "t",
  "@": "a",
  $: "s",
};

export interface NormalizedText {
  text: string;
  /** `map[i]` is the UTF-16 index in the source for normalized code unit `i`. */
  map: number[];
}

export function normalizeForMatch(input: string): NormalizedText {
  let text = "";
  const map: number[] = [];
  let unit = 0;

  for (const char of input) {
    const source = unit;
    unit += char.length;
    if (ZERO_WIDTH.has(char)) continue;

    const folded = foldChar(char);
    for (let i = 0; i < folded.length; i += 1) {
      text += folded.charAt(i);
      map.push(source);
    }
  }

  if (map.length !== text.length) {
    throw new Error("Normalization map drifted from the folded text");
  }

  return { text, map };
}

export function originalSpan(
  input: string,
  normalized: NormalizedText,
  start: number,
  end: number,
): { start: number; end: number } | null {
  if (start < 0 || end <= start || end > normalized.map.length) return null;
  const origStart = normalized.map[start];
  const last = normalized.map[end - 1];
  if (origStart === undefined || last === undefined) return null;
  const code = input.codePointAt(last);
  const width = code !== undefined && code > 0xffff ? 2 : 1;
  return { start: origStart, end: last + width };
}

function foldChar(char: string): string {
  const compatible = char.normalize("NFKC").toLowerCase();
  let folded = "";
  for (const part of compatible) {
    folded += HOMOGLYPHS[part] ?? LEET[part] ?? part;
  }
  return folded;
}

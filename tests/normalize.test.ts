import { describe, expect, it } from "vitest";
import { normalizeForMatch, originalSpan } from "../src/lib/normalize";

describe("normalizeForMatch", () => {
  it("drops zero-width characters and maps the span back", () => {
    const input = "ig\u200Bnore";
    const normalized = normalizeForMatch(input);
    expect(normalized.text).toBe("ignore");
    expect(normalized.map).toHaveLength(normalized.text.length);
    const span = originalSpan(input, normalized, 0, normalized.text.length);
    expect(span).toEqual({ start: 0, end: input.length });
  });

  it("folds leet digits inside words", () => {
    expect(normalizeForMatch("1gn0re").text).toBe("ignore");
  });

  it("folds cyrillic lookalikes", () => {
    expect(normalizeForMatch("ign\u043ere").text).toBe("ignore");
  });

  it("folds fullwidth letters through compatibility normalization", () => {
    const input = "ＩＧＮＯＲＥ";
    expect(normalizeForMatch(input).text).toBe("ignore");
  });
});

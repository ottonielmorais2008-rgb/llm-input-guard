import { describe, expect, it } from "vitest";
import { scan } from "../src/lib/index";

function redact(text: string): string {
  return scan(text, { mode: "redact" }).redactedText;
}

describe("email", () => {
  it("redacts an address and masks the finding", () => {
    const email = "maria.silva@example.com";
    const result = scan(`Contact ${email} today.`, { mode: "redact" });
    expect(result.findings.map((finding) => finding.ruleId)).toEqual(["pii-email"]);
    expect(result.redactedText).toBe("Contact [REDACTED_EMAIL] today.");
    expect(result.findings[0]?.snippet).toBe("m…@example.com");
    expect(result.findings[0]?.snippet).not.toContain("maria.silva");
  });

  it("accepts a plus-tag and a mixed-case address", () => {
    expect(redact("Write user+tag@example.co.uk please.")).toBe(
      "Write [REDACTED_EMAIL] please.",
    );
    expect(redact("Write Maria.Silva@Example.com please.")).toBe(
      "Write [REDACTED_EMAIL] please.",
    );
  });

  it("ignores text that is not an address", () => {
    expect(scan("not-an-email").findings).toEqual([]);
    expect(scan("a@b.c").findings).toEqual([]);
  });
});

describe("Portuguese mobile numbers", () => {
  it.each([
    "912345678",
    "912 345 678",
    "912-345-678",
    "+351 912 345 678",
    "+351912345678",
    "00351 912 345 678",
    "(+351) 912 345 678",
    "961234567",
    "93 211 1223",
  ])("redacts %s", (phone) => {
    const result = scan(`Call ${phone} now.`, { mode: "redact" });
    expect(result.findings.map((finding) => finding.ruleId)).toEqual(["pii-phone"]);
    expect(result.redactedText).toBe("Call [REDACTED_PHONE] now.");
    expect(result.redactedText).not.toContain(phone.replace(/\D/g, ""));
    expect(result.findings[0]?.snippet).not.toContain(phone);
  });

  it("masks international and national snippets differently", () => {
    expect(scan("+351 912 345 678").findings[0]?.snippet).toBe("+351 …78");
    expect(scan("912345678").findings[0]?.snippet).toBe("912…78");
  });

  it("does not treat a landline or a short code as a mobile", () => {
    expect(scan("Call +351 212 345 678 now.").findings).toEqual([]);
    expect(scan("Call 212345678 now.").findings).toEqual([]);
    expect(scan("ext 9123").findings).toEqual([]);
    expect(scan("ref 9123456789").findings).toEqual([]);
  });
});

describe("IBAN", () => {
  it.each([
    "PT50000201231234567890154",
    "PT50 0002 0123 1234 5678 9015 4",
    "pt50 0002 0123 1234 5678 9015 4",
    "DE89370400440532013000",
    "DE89 3704 0044 0532 0130 00",
    "GB82 WEST 1234 5698 7654 32",
    "FR1420041010050500013M02606",
  ])("redacts %s", (iban) => {
    const result = scan(`Pay ${iban} today.`, { mode: "redact" });
    expect(result.findings.map((finding) => finding.ruleId)).toEqual(["pii-iban"]);
    expect(result.redactedText).toBe("Pay [REDACTED_IBAN] today.");
    expect(result.redactedText).not.toContain(iban.replace(/ /g, ""));
  });

  it("rejects a bad checksum and a truncated candidate", () => {
    expect(scan("PT99 0002 0123 1234 5678 9015 4").findings).toEqual([]);
    expect(scan("GB82 WEST").findings).toEqual([]);
  });

  it("does not also flag digit groups inside a valid IBAN as a card", () => {
    const result = scan("DE89 3704 0044 0532 0130 00");
    expect(result.findings.map((finding) => finding.ruleId)).toEqual(["pii-iban"]);
  });
});

describe("payment cards", () => {
  it.each([
    "4242424242424242",
    "4242 4242 4242 4242",
    "4242-4242-4242-4242",
    "5555555555554444",
    "5555 5555 5555 4444",
    "378282246310005",
    "3782 822463 10005",
    "2221000000000009",
    "6011000000000004",
  ])("redacts %s", (card) => {
    const result = scan(`Card ${card} ok.`, { mode: "redact" });
    expect(result.findings.map((finding) => finding.ruleId)).toEqual(["pii-card"]);
    expect(result.redactedText).toBe("Card [REDACTED_CARD] ok.");
    const digits = card.replace(/\D/g, "");
    expect(result.redactedText).not.toContain(digits);
    expect(result.findings[0]?.snippet).toBe(`•••• ${digits.slice(-4)}`);
    expect(result.findings[0]?.snippet).not.toContain(digits.slice(0, 6));
  });

  it("rejects numbers that fail Luhn or have no brand prefix", () => {
    expect(scan("4242 4242 4242 4241").findings).toEqual([]);
    expect(scan("0000000000000000").findings).toEqual([]);
    expect(scan("4242 4242 4242").findings).toEqual([]);
  });
});

describe("several personal-data values", () => {
  it("replaces each one and leaves the surrounding words", () => {
    const text =
      "Mail a@example.com, call +351 912 345 678, IBAN PT50 0002 0123 1234 5678 9015 4, card 4242 4242 4242 4242.";
    expect(redact(text)).toBe(
      "Mail [REDACTED_EMAIL], call [REDACTED_PHONE], IBAN [REDACTED_IBAN], card [REDACTED_CARD].",
    );
  });
});

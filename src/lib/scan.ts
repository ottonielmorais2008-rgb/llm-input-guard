import { findInjection } from "./injection";
import { findPii, redactPii } from "./pii";
import type { Finding, ScanAction, ScanMode, ScanOptions, ScanResult } from "./types";

/** Requests longer than this are rejected instead of running the rule set. */
export const MAX_INPUT_CHARS = 100_000;

/**
 * Scan untrusted text before it is forwarded to a language model.
 *
 * The check is local: phrase rules, a few obfuscation folds, and checksums.
 * It does not call a model and it does not decide that text is safe in general.
 * It only reports the patterns this package knows about.
 *
 * - `block` (default): `ok` is true only when nothing matched.
 * - `redact`: personal data is replaced. `ok` stays true when that was the only
 *   problem. An injection match still sets `ok` to false, because masking the
 *   surrounding personal data does not remove the instruction override.
 *
 * `redactedText` always has personal data masked, including when `ok` is false,
 * so a review screen can show it. Forward that string only when `ok` is true.
 */
export function scan(text: string, options?: ScanOptions): ScanResult {
  if (typeof text !== "string") {
    throw new TypeError("scan() expects text to be a string");
  }

  const mode = options?.mode ?? "block";
  assertMode(mode);

  if (text.length > MAX_INPUT_CHARS) {
    throw new RangeError(`scan() accepts at most ${MAX_INPUT_CHARS} characters`);
  }

  const findings = [...findInjection(text), ...findPii(text)].sort(
    (a, b) => a.start - b.start || a.end - b.end,
  );
  const redactedText = redactPii(text, findings);
  const decision = decide(mode, findings);

  return {
    ok: decision.ok,
    mode,
    action: decision.action,
    findings,
    redactedText,
  };
}

function decide(mode: ScanMode, findings: readonly Finding[]): { ok: boolean; action: ScanAction } {
  const hasInjection = findings.some((finding) => finding.kind === "prompt_injection");
  const hasPii = findings.some((finding) => finding.kind === "pii");

  switch (mode) {
    case "block":
      if (hasInjection || hasPii) return { ok: false, action: "block" };
      return { ok: true, action: "allow" };
    case "redact":
      if (hasInjection) return { ok: false, action: "block" };
      if (hasPii) return { ok: true, action: "redact" };
      return { ok: true, action: "allow" };
    default: {
      const unknown: never = mode;
      throw new Error(`Unknown scan mode: ${String(unknown)}`);
    }
  }
}

function assertMode(mode: ScanMode): void {
  switch (mode) {
    case "block":
    case "redact":
      return;
    default: {
      const unknown: never = mode;
      throw new Error(`Unknown scan mode: ${String(unknown)}`);
    }
  }
}

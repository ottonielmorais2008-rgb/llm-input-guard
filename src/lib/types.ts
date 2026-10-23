/** Policy applied by {@link ScanOptions.mode}. */
export type ScanMode = "block" | "redact";

/**
 * What the caller should do with the text.
 * - `allow`: forward the original text
 * - `redact`: forward `redactedText` (personal data already replaced)
 * - `block`: do not forward anything
 */
export type ScanAction = "allow" | "block" | "redact";

export type FindingKind = "prompt_injection" | "pii";

export interface Finding {
  kind: FindingKind;
  /** Stable rule identifier, for example `ignore-previous` or `pii-email`. */
  ruleId: string;
  message: string;
  /** Inclusive start index in the original text (UTF-16). */
  start: number;
  /** Exclusive end index in the original text (UTF-16). */
  end: number;
  /**
   * Short preview of the match. Personal data is masked.
   * Injection snippets keep the matched wording so a reviewer can see why it fired.
   */
  snippet: string;
}

export interface ScanOptions {
  /**
   * `block` (default) refuses the text when any rule matches.
   * `redact` masks personal data and still refuses the text when an injection rule matches.
   */
  mode?: ScanMode;
}

export interface ScanResult {
  /**
   * True only when the text may be forwarded.
   * In `redact` mode that means forwarding {@link ScanResult.redactedText}.
   */
  ok: boolean;
  mode: ScanMode;
  action: ScanAction;
  findings: Finding[];
  /**
   * Original text with personal-data spans replaced by tags such as `[REDACTED_EMAIL]`.
   * Injection wording is left in place. Display this freely; forward it only when `ok` is true.
   */
  redactedText: string;
}

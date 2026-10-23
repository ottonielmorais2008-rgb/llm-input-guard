# LLM Input Guard

A small TypeScript gate that scans text **before** it is sent to a language model. It looks for prompt-injection phrasing and for a few kinds of personal data, then either blocks the text or returns a copy with that personal data replaced.

The demo uses local rules only. It does not call a model, and it does not need an API key.

## Why

Anything you paste into a model can carry two problems at once:

- Someone can try to override the instructions the application already gave the model ("ignore previous instructions", a fake system tag, a jailbreak persona).
- The text can contain personal data that should not be in the request: an email, a phone number, an IBAN, a card number.

A cheap check in front of the model call catches the obvious cases without paying for a second model. It is a heuristic. New wording gets through, and some innocent sentences look like the phrases on the list. Treat a block as a reason to review, not as proof of an attack.

## How to run

Requires Node.js 20 or newer.

```bash
npm install
npm run dev
```

Open the printed local URL. Paste text, switch between **Block** and **Redact**, or load a sample. The scan runs in the browser.

```bash
npm test          # Vitest
npm run lint      # ESLint
npm run typecheck # tsc --noEmit
npm run build     # production build of the demo
npm run ci        # all of the above
```

GitHub Actions runs install, lint, typecheck, test, and the demo build on every push and pull request.

### Optional environment file

```bash
cp .env.example .env
```

`.env` is gitignored. `LLM_API_KEY` is reserved for a future server-side check. This package never reads it, and the name is intentionally **not** prefixed with `VITE_`, so a bundler will not put it in the browser.

## API

```ts
import { scan } from "./src/lib/index";

const result = scan(text, { mode: "redact" });
// result.ok, result.action, result.findings, result.redactedText
```

```ts
scan(text: string, options?: { mode?: "block" | "redact" }): {
  ok: boolean;
  mode: "block" | "redact";
  action: "allow" | "block" | "redact";
  findings: Finding[];
  redactedText: string;
}
```

`mode` defaults to `"block"`.

| Mode | What matched | `ok` | `action` | What to forward |
| --- | --- | --- | --- | --- |
| `block` | nothing | `true` | `allow` | the original text |
| `block` | injection or personal data | `false` | `block` | nothing |
| `redact` | nothing | `true` | `allow` | the original text |
| `redact` | personal data only | `true` | `redact` | `redactedText` |
| `redact` | any injection | `false` | `block` | nothing |

`redactedText` always has personal data replaced, even when `ok` is false, so a review screen can show it. Injection wording is left visible on purpose. Forward `redactedText` only when `ok` is true.

Personal-data tags:

- `[REDACTED_EMAIL]`
- `[REDACTED_PHONE]`
- `[REDACTED_IBAN]`
- `[REDACTED_CARD]`

Findings for personal data carry a masked snippet (`m…@example.com`, `•••• 4242`), not the raw value. `scan` throws `TypeError` on a non-string and `RangeError` above 100,000 characters.

## What the rules cover

**Prompt injection** (case-insensitive, after a light fold for zero-width characters, compatibility forms, a few homoglyphs, and leet digits):

1. `ignore-previous` — ignore, forget, or override earlier instructions, including letters split by spaces or dots (`i.g.n.o.r.e`).
2. `system-impersonation` — "pretend to be the system", "you are now root", and similar role swaps. "Act as a careful editor" does not match.
3. `jailbreak-persona` — DAN, developer mode, "do anything now", "jailbreak mode".
4. `delimiter-smuggling` — chat-template tokens such as `<|im_start|>`, `[INST]`, `<<SYS>>`, and a `<system>` tag on its own line.
5. `policy-bypass` — disable safety filters, guardrails, or content policy.
6. `prompt-exfiltration` — ask the model to reveal its system or hidden prompt.
7. `encoded-payload` — base64, percent-encoding, or `\u` / `\x` escapes that decode to one of the phrases above.

**Personal data:**

- Email addresses.
- Portuguese mobile numbers. National prefixes are 91, 92, 93, and 96, written as `912345678`, `912 345 678`, `+351 912 345 678`, `00351 …`, or `(+351) …`. Landlines (for example a number starting with 21) are not matched.
- IBANs. The country length is checked when it is known, and the ISO 13616 mod-97 checksum must pass. `PT50 0002 0123 1234 5678 9015 4` matches; the same shape with a bad check digit does not.
- Payment card numbers with a Visa, Mastercard, American Express, or Discover prefix and a valid Luhn checksum. A 16-digit string that fails Luhn, including `4242 4242 4242 4241`, is left alone.

## Layout

```
src/lib/       scan(), injection rules, PII rules
src/demo/      Vite + React UI
tests/         Vitest
```

## Skills shown

- A small, documented TypeScript API with an explicit allow / block / redact decision.
- Deterministic detectors: regular expressions, a normalization map back to the original offsets, the Luhn check, and the IBAN mod-97 check.
- A Vite + React demo that runs the same functions as the tests.
- Vitest coverage for each injection family, obfuscated variants, and each personal-data type.
- GitHub Actions for install, lint, typecheck, test, and the demo build.
- No secrets in git. `.env` is ignored; `.env.example` ships empty.

## What went wrong

**The word "jailbreak" matched twice.** The first Vitest run failed on `Act as jailbreak.` The persona rule contained the bare word `jailbreak`, so that sentence also matched the system-impersonation rule. The same keyword would have flagged a sentence that only mentioned the topic. I removed it. Persona hits are phrases such as "DAN mode", "developer mode", "do anything now", and "jailbreak mode". "Act as jailbreak" stays on the impersonation rule only.

**An open gap in the instruction rule flagged ordinary sentences.** After the suite was green I tried a few harmless lines. `Ignore previous formatting rules.` was blocked, because the pattern allowed any short run of words between "previous" and "rules", and "formatting" sat in that gap. `Do not disable the safety cover on the machine.` matched because the policy rule treated the bare word "safety" as the thing being disabled. I replaced the open gap with a closed filler list (`the`, `all`, `your`, and similar) and dropped bare "safety", keeping objects such as "safety filters" and "guardrails". Both sentences are now regression tests.

## License

MIT. See [LICENSE](LICENSE).

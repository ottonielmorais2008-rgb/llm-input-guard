import { useMemo, useState } from "react";
import {
  INJECTION_RULES,
  MAX_INPUT_CHARS,
  PII_RULES,
  scan,
  type Finding,
  type ScanAction,
  type ScanMode,
  type ScanResult,
} from "../lib/index";
import { INITIAL_SAMPLE_ID, SAMPLES } from "./samples";

const INITIAL_TEXT = textForSample(INITIAL_SAMPLE_ID);

export function App() {
  const [text, setText] = useState(INITIAL_TEXT);
  const [mode, setMode] = useState<ScanMode>("block");
  const tooLong = text.length > MAX_INPUT_CHARS;
  const result = useMemo(
    () => (tooLong ? null : scan(text, { mode })),
    [mode, text, tooLong],
  );
  const activeSample = SAMPLES.find((sample) => sample.text === text)?.id ?? null;

  return (
    <div className="page">
      <header className="masthead">
        <p className="kicker">Local pre-flight</p>
        <h1>LLM Input Guard</h1>
        <p className="lede">
          Scan text for prompt injection and personal data before it reaches a model. The rules
          run in this browser. Nothing is uploaded.
        </p>
      </header>

      <main className="layout">
        <section className="panel" aria-labelledby="input-heading">
          <div className="panel-head">
            <h2 id="input-heading">Input</h2>
            <p className="count">{text.length.toLocaleString("en-US")} characters</p>
          </div>

          <fieldset className="mode">
            <legend>Mode</legend>
            <label className={mode === "block" ? "mode-option is-active" : "mode-option"}>
              <input
                type="radio"
                name="mode"
                value="block"
                checked={mode === "block"}
                onChange={() => setMode("block")}
              />
              <span>Block</span>
              <small>Refuse the text when any rule matches.</small>
            </label>
            <label className={mode === "redact" ? "mode-option is-active" : "mode-option"}>
              <input
                type="radio"
                name="mode"
                value="redact"
                checked={mode === "redact"}
                onChange={() => setMode("redact")}
              />
              <span>Redact</span>
              <small>Mask personal data. Injection still refuses the text.</small>
            </label>
          </fieldset>

          <div className="samples" role="group" aria-label="Sample texts">
            {SAMPLES.map((sample) => (
              <button
                key={sample.id}
                type="button"
                className="chip"
                aria-pressed={activeSample === sample.id}
                onClick={() => setText(sample.text)}
              >
                {sample.label}
              </button>
            ))}
          </div>

          <label className="field" htmlFor="prompt">
            Text to scan
          </label>
          <textarea
            id="prompt"
            value={text}
            onChange={(event) => setText(event.target.value)}
            spellCheck={false}
            autoComplete="off"
            placeholder="Paste a prompt, an email, or a phone number."
          />
        </section>

        <section className="panel" aria-labelledby="decision-heading">
          <div className="panel-head">
            <h2 id="decision-heading">Decision</h2>
          </div>
          {tooLong || result === null ? (
            <p className="verdict" data-action="block" role="status">
              <span className="verdict-label">Block</span>
              <span className="verdict-detail">
                Paste at most {MAX_INPUT_CHARS.toLocaleString("en-US")} characters.
              </span>
            </p>
          ) : (
            <Decision result={result} text={text} />
          )}
        </section>
      </main>

      <section className="reference" aria-labelledby="rules-heading">
        <h2 id="rules-heading">Rules in this demo</h2>
        <div className="rule-columns">
          <div>
            <h3>Prompt injection</h3>
            <ul>
              {INJECTION_RULES.map((rule) => (
                <li key={rule.id}>
                  <code>{rule.id}</code>
                  <span>{rule.description}</span>
                </li>
              ))}
            </ul>
          </div>
          <div>
            <h3>Personal data</h3>
            <ul>
              {PII_RULES.map((rule) => (
                <li key={rule.id}>
                  <code>{rule.id}</code>
                  <span>{rule.description}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </section>

      <footer>
        <p>
          Heuristic gate, not a guarantee. Phrase lists miss new attacks, and a nine-digit id can
          look like a mobile number. Keep a human on high-stakes traffic.
        </p>
      </footer>
    </div>
  );
}

function Decision({ result, text }: { result: ScanResult; text: string }) {
  const copy = verdictCopy(result.action, text);
  const injectionCount = result.findings.filter((finding) => finding.kind === "prompt_injection").length;
  const piiCount = result.findings.filter((finding) => finding.kind === "pii").length;

  return (
    <>
      <p className="verdict" data-action={result.action} role="status">
        <span className="verdict-label">{copy.title}</span>
        <span className="verdict-detail">{copy.detail}</span>
      </p>
      <dl className="stats">
        <div>
          <dt>Forward?</dt>
          <dd>{result.ok ? "Yes" : "No"}</dd>
        </div>
        <div>
          <dt>Injection</dt>
          <dd>{injectionCount}</dd>
        </div>
        <div>
          <dt>Personal data</dt>
          <dd>{piiCount}</dd>
        </div>
      </dl>
      <h3 className="subhead">Findings</h3>
      {result.findings.length === 0 ? (
        <p className="empty">No rules matched.</p>
      ) : (
        <ul className="findings">
          {result.findings.map((finding) => (
            <FindingRow key={`${finding.ruleId}-${finding.start}-${finding.end}`} finding={finding} />
          ))}
        </ul>
      )}
      <h3 className="subhead">{outputLabel(result.action)}</h3>
      <pre className="output">{result.redactedText.length > 0 ? result.redactedText : " "}</pre>
    </>
  );
}

function FindingRow({ finding }: { finding: Finding }) {
  const kindLabel = finding.kind === "prompt_injection" ? "Injection" : "Personal data";
  return (
    <li className="finding">
      <div className="finding-top">
        <span className={`kind kind-${finding.kind}`}>{kindLabel}</span>
        <code>{finding.ruleId}</code>
      </div>
      <p>{finding.message}</p>
      <p className="snippet">{finding.snippet}</p>
    </li>
  );
}

function verdictCopy(action: ScanAction, text: string): { title: string; detail: string } {
  if (text.trim().length === 0 && action === "allow") {
    return {
      title: "Allow",
      detail: "Nothing to scan yet. Paste a prompt or load a sample.",
    };
  }

  switch (action) {
    case "allow":
      return {
        title: "Allow",
        detail: "No injection or personal data in the rules this demo knows. The text can be forwarded.",
      };
    case "redact":
      return {
        title: "Redact",
        detail: "Personal data was replaced. Forward the redacted text, not the original.",
      };
    case "block":
      return {
        title: "Block",
        detail:
          "Do not forward this text. Personal data below is masked for display; injection wording stays visible so you can see the match.",
      };
    default: {
      const unknown: never = action;
      return { title: "Block", detail: `Unknown action ${String(unknown)}.` };
    }
  }
}

function outputLabel(action: ScanAction): string {
  switch (action) {
    case "allow":
      return "Text to forward";
    case "redact":
      return "Redacted text to forward";
    case "block":
      return "Masked preview — do not forward";
    default: {
      const unknown: never = action;
      return String(unknown);
    }
  }
}

function textForSample(id: string): string {
  const sample = SAMPLES.find((item) => item.id === id);
  if (!sample) {
    throw new Error(`Missing sample ${id}`);
  }
  return sample.text;
}

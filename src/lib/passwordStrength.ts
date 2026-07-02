import { zxcvbn, zxcvbnOptions } from "@zxcvbn-ts/core";
import * as common from "@zxcvbn-ts/language-common";
import * as en from "@zxcvbn-ts/language-en";

let configured = false;
function configure() {
  if (configured) return;
  zxcvbnOptions.setOptions({
    dictionary: { ...common.dictionary, ...en.dictionary },
    graphs: common.adjacencyGraphs,
    translations: en.translations,
  });
  configured = true;
}

export const STRENGTH_LABELS = [
  "Very weak",
  "Weak",
  "Fair",
  "Strong",
  "Very strong",
] as const;

export type StrengthScore = 0 | 1 | 2 | 3 | 4;

export interface Strength {
  score: StrengthScore;
  warning: string;
  suggestions: string[];
}

/** Score `pw` with zxcvbn (0–4) plus human feedback. */
export function estimateStrength(pw: string): Strength {
  configure();
  const r = zxcvbn(pw);
  return {
    score: r.score as StrengthScore,
    warning: r.feedback.warning ?? "",
    suggestions: r.feedback.suggestions ?? [],
  };
}

/** A password is "weak" (worth warning about) below zxcvbn score 3. */
export function isWeak(score: number): boolean {
  return score < 3;
}

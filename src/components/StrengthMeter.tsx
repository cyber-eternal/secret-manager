import { useMemo } from "react";
import { estimateStrength, STRENGTH_LABELS, isWeak } from "../lib/passwordStrength";

const BAR_COLORS = [
  "bg-danger",
  "bg-danger",
  "bg-amber-500",
  "bg-emerald-500",
  "bg-emerald-500",
];

export function StrengthMeter({ password }: { password: string }) {
  const s = useMemo(() => estimateStrength(password), [password]);
  if (!password) return null;

  const hint = s.warning || s.suggestions[0] || "";
  return (
    <div className="mt-2" aria-live="polite">
      <div className="flex gap-1">
        {[0, 1, 2, 3].map((i) => (
          <span
            key={i}
            className={`h-1.5 flex-1 rounded-full ${
              i <= s.score - 1 ? BAR_COLORS[s.score] : "bg-border"
            }`}
          />
        ))}
      </div>
      <p className="mt-1 text-[11.5px] text-text-muted">
        <span className={isWeak(s.score) ? "text-danger" : "text-text"}>
          {STRENGTH_LABELS[s.score]}
        </span>
        {hint ? ` — ${hint}` : ""}
      </p>
    </div>
  );
}

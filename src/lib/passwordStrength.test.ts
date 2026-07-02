import { describe, it, expect } from "vitest";
import { estimateStrength, isWeak, STRENGTH_LABELS } from "./passwordStrength";

describe("passwordStrength", () => {
  it("scores an empty password as 0 (weak)", () => {
    const r = estimateStrength("");
    expect(r.score).toBe(0);
    expect(isWeak(r.score)).toBe(true);
  });

  it("scores a long random passphrase as strong (>=3, not weak)", () => {
    const r = estimateStrength("correct-horse-battery-staple-92xQ");
    expect(r.score).toBeGreaterThanOrEqual(3);
    expect(isWeak(r.score)).toBe(false);
  });

  it("exposes a label per score", () => {
    expect(STRENGTH_LABELS).toHaveLength(5);
  });
});

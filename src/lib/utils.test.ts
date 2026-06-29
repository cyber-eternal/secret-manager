import { describe, it, expect } from "vitest";
import {
  formatRelativeTime,
  validateMasterPassword,
  normalizeTags,
  maskValue,
  errMessage,
} from "./utils";

describe("formatRelativeTime", () => {
  const now = 1_000_000_000_000;
  it("reports just now for small diffs", () => {
    expect(formatRelativeTime(now - 5_000, now)).toBe("just now");
  });
  it("reports minutes/hours/days", () => {
    expect(formatRelativeTime(now - 5 * 60_000, now)).toBe("5m ago");
    expect(formatRelativeTime(now - 3 * 3_600_000, now)).toBe("3h ago");
    expect(formatRelativeTime(now - 2 * 86_400_000, now)).toBe("2d ago");
  });
});

describe("validateMasterPassword", () => {
  it("rejects short passwords", () => {
    expect(validateMasterPassword("short").ok).toBe(false);
  });
  it("rejects mismatched confirmation", () => {
    expect(validateMasterPassword("longenough", "different").ok).toBe(false);
  });
  it("accepts a valid matching password", () => {
    expect(validateMasterPassword("longenough", "longenough").ok).toBe(true);
  });
});

describe("normalizeTags", () => {
  it("trims, dedupes case-insensitively, and keeps order", () => {
    expect(normalizeTags([" prod ", "PROD", "api", "", "db"])).toEqual([
      "prod",
      "api",
      "db",
    ]);
  });
});

describe("maskValue / errMessage", () => {
  it("masks with bullets", () => {
    expect(maskValue()).toMatch(/^•+$/);
  });
  it("extracts string errors verbatim", () => {
    expect(errMessage("Wrong master password")).toBe("Wrong master password");
    expect(errMessage(new Error("boom"))).toBe("boom");
  });
});

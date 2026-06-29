import { describe, it, expect } from "vitest";
import { summarizeImport } from "./transfer";
import type { ImportSummary } from "./types";

const base: ImportSummary = {
  projects_created: 0,
  projects_merged: 0,
  secrets_imported: 0,
  secrets_overwritten: 0,
  secrets_skipped: 0,
};

describe("summarizeImport", () => {
  it("describes added/overwritten/skipped and new projects", () => {
    expect(
      summarizeImport({
        ...base,
        projects_created: 2,
        secrets_imported: 5,
        secrets_skipped: 1,
      }),
    ).toBe("2 new projects · 5 added, 1 skipped");
  });

  it("handles overwrite-only with no new projects", () => {
    expect(summarizeImport({ ...base, secrets_overwritten: 3 })).toBe(
      "3 overwritten",
    );
  });

  it("reports no secrets when nothing changed", () => {
    expect(summarizeImport(base)).toBe("no secrets");
  });
});

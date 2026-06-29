import { describe, it, expect, beforeEach } from "vitest";
import { useSettings, resolveTheme, applyTheme } from "./settings";

describe("settings store", () => {
  beforeEach(() => {
    useSettings.setState({
      theme: "dark",
      autoLockMinutes: 5,
      clipboardClearSeconds: 30,
      customVaultPath: null,
    });
  });

  it("updates values through setters", () => {
    useSettings.getState().setAutoLock(15);
    useSettings.getState().setClipboardClear(10);
    useSettings.getState().setCustomVaultPath("/tmp/v.db");
    const s = useSettings.getState();
    expect(s.autoLockMinutes).toBe(15);
    expect(s.clipboardClearSeconds).toBe(10);
    expect(s.customVaultPath).toBe("/tmp/v.db");
  });

  it("resolves explicit themes", () => {
    expect(resolveTheme("dark")).toBe("dark");
    expect(resolveTheme("light")).toBe("light");
  });

  it("applies the dark class to <html>", () => {
    applyTheme("light");
    expect(document.documentElement.classList.contains("dark")).toBe(false);
    applyTheme("dark");
    expect(document.documentElement.classList.contains("dark")).toBe(true);
  });
});

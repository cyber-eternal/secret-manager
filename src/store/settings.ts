// Local UI/app preferences, persisted to localStorage. These are non-secret.

import { create } from "zustand";
import { persist } from "zustand/middleware";
import type { ThemePref } from "../lib/types";

export type AutoLockMinutes = 1 | 5 | 15 | 0; // 0 = never

interface SettingsState {
  theme: ThemePref;
  autoLockMinutes: AutoLockMinutes;
  clipboardClearSeconds: number;
  customVaultPath: string | null;
  setTheme: (t: ThemePref) => void;
  setAutoLock: (m: AutoLockMinutes) => void;
  setClipboardClear: (s: number) => void;
  setCustomVaultPath: (p: string | null) => void;
}

export const useSettings = create<SettingsState>()(
  persist(
    (set) => ({
      theme: "dark",
      autoLockMinutes: 5,
      clipboardClearSeconds: 30,
      customVaultPath: null,
      setTheme: (theme) => set({ theme }),
      setAutoLock: (autoLockMinutes) => set({ autoLockMinutes }),
      setClipboardClear: (clipboardClearSeconds) => set({ clipboardClearSeconds }),
      setCustomVaultPath: (customVaultPath) => set({ customVaultPath }),
    }),
    { name: "secret-manager-settings" },
  ),
);

/** Resolve the effective theme (dark/light) from preference + system. */
export function resolveTheme(pref: ThemePref): "dark" | "light" {
  if (pref === "system") {
    const m =
      typeof window !== "undefined" && window.matchMedia
        ? window.matchMedia("(prefers-color-scheme: light)").matches
        : false;
    return m ? "light" : "dark";
  }
  return pref;
}

/** Apply the theme class to <html>. */
export function applyTheme(pref: ThemePref): void {
  if (typeof document === "undefined") return;
  const resolved = resolveTheme(pref);
  document.documentElement.classList.toggle("dark", resolved === "dark");
}

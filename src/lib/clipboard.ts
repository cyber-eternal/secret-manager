// Clipboard helpers with auto-clear, backed by the Tauri clipboard plugin.

import {
  writeText,
  clear,
  readText,
} from "@tauri-apps/plugin-clipboard-manager";

let clearTimer: ReturnType<typeof setTimeout> | null = null;

/**
 * Copy `text` to the clipboard and schedule an auto-clear after `seconds`.
 * The clipboard is only cleared if it still holds `text` (so we don't wipe
 * something the user copied afterwards).
 */
export async function copyWithAutoClear(
  text: string,
  seconds: number,
): Promise<void> {
  await writeText(text);
  if (clearTimer) clearTimeout(clearTimer);
  if (seconds <= 0) return;
  clearTimer = setTimeout(async () => {
    try {
      const current = await readText();
      if (current === text) await clear();
    } catch {
      /* clipboard may be unavailable; ignore */
    }
  }, seconds * 1000);
}

import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

/** Merge Tailwind class names, resolving conflicts. */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}

/** Human-friendly relative time for a unix-ms timestamp. */
export function formatRelativeTime(ms: number, now: number = Date.now()): string {
  const diff = Math.max(0, now - ms);
  const sec = Math.floor(diff / 1000);
  if (sec < 45) return "just now";
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  const day = Math.floor(hr / 24);
  if (day < 30) return `${day}d ago`;
  const mo = Math.floor(day / 30);
  if (mo < 12) return `${mo}mo ago`;
  return `${Math.floor(mo / 12)}y ago`;
}

/** A fixed-width mask for a hidden secret value. */
export function maskValue(): string {
  return "•".repeat(12);
}

export interface PasswordCheck {
  ok: boolean;
  message?: string;
}

/** Minimal master-password policy used by the create-vault flow. */
export function validateMasterPassword(pw: string, confirm?: string): PasswordCheck {
  if (pw.length < 8) {
    return { ok: false, message: "Use at least 8 characters." };
  }
  if (confirm !== undefined && pw !== confirm) {
    return { ok: false, message: "Passwords do not match." };
  }
  return { ok: true };
}

/** Normalize and de-duplicate a list of tag strings. */
export function normalizeTags(tags: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const t of tags) {
    const v = t.trim();
    if (v && !seen.has(v.toLowerCase())) {
      seen.add(v.toLowerCase());
      out.push(v);
    }
  }
  return out;
}

/** Extract a readable message from an unknown thrown value (Tauri errors are strings). */
export function errMessage(e: unknown): string {
  if (typeof e === "string") return e;
  if (e instanceof Error) return e.message;
  return String(e);
}

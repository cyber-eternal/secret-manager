// Export/import flows that drive native save/open dialogs, then call the
// backend. Two export formats:
//   - json  → plaintext bundle (decrypted values)
//   - vault → passphrase-encrypted ".smvault" file (portable, sealed)

import { save, open } from "@tauri-apps/plugin-dialog";
import {
  exportAll,
  exportProject,
  importFile,
  importIsEncrypted,
} from "./tauri";
import type { ImportMode, ImportSummary } from "./types";

export interface ExportOptions {
  encrypted: boolean;
  passphrase?: string;
}

const JSON_FILTER = [{ name: "JSON", extensions: ["json"] }];
const VAULT_FILTER = [{ name: "Vault file", extensions: ["smvault"] }];

function slug(name: string): string {
  return name.trim().replace(/[^a-z0-9-_]+/gi, "-").replace(/^-+|-+$/g, "") || "project";
}

function stamp(): string {
  return new Date().toISOString().slice(0, 10);
}

function ext(o: ExportOptions): string {
  return o.encrypted ? "smvault" : "json";
}

/** Export the whole vault. Returns the chosen path, or null if cancelled. */
export async function exportAllFlow(o: ExportOptions): Promise<string | null> {
  const path = await save({
    title: "Export all projects and secrets",
    defaultPath: `secret-manager-${stamp()}.${ext(o)}`,
    filters: o.encrypted ? VAULT_FILTER : JSON_FILTER,
  });
  if (!path) return null;
  await exportAll(path, o.encrypted, o.passphrase);
  return path;
}

/** Export one project. Returns the chosen path, or null if cancelled. */
export async function exportProjectFlow(
  projectId: string,
  projectName: string,
  o: ExportOptions,
): Promise<string | null> {
  const path = await save({
    title: `Export "${projectName}"`,
    defaultPath: `${slug(projectName)}-${stamp()}.${ext(o)}`,
    filters: o.encrypted ? VAULT_FILTER : JSON_FILTER,
  });
  if (!path) return null;
  await exportProject(projectId, path, o.encrypted, o.passphrase);
  return path;
}

export interface PickedImport {
  path: string;
  encrypted: boolean;
}

/** Open a file picker for import; reports whether the file is encrypted. */
export async function pickImportFile(): Promise<PickedImport | null> {
  const picked = await open({
    title: "Import projects and secrets",
    multiple: false,
    directory: false,
    filters: [{ name: "Export or vault file", extensions: ["json", "smvault"] }],
  });
  if (typeof picked !== "string") return null;
  const encrypted = await importIsEncrypted(picked);
  return { path: picked, encrypted };
}

export function runImport(
  path: string,
  mode: ImportMode,
  passphrase?: string,
): Promise<ImportSummary> {
  return importFile(path, mode, passphrase);
}

/** One-line human summary of an import result. */
export function summarizeImport(s: ImportSummary): string {
  const parts: string[] = [];
  if (s.secrets_imported) parts.push(`${s.secrets_imported} added`);
  if (s.secrets_overwritten) parts.push(`${s.secrets_overwritten} overwritten`);
  if (s.secrets_skipped) parts.push(`${s.secrets_skipped} skipped`);
  const projectsNew = s.projects_created
    ? `${s.projects_created} new project${s.projects_created > 1 ? "s" : ""}`
    : "";
  const secrets = parts.length ? parts.join(", ") : "no secrets";
  return [projectsNew, secrets].filter(Boolean).join(" · ");
}

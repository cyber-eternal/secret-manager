// Mirrors the Rust structs in src-tauri/src/models.rs.

export interface Project {
  id: string;
  name: string;
  description: string | null;
  created_at: number;
  updated_at: number;
}

/** Secret including its decrypted value (returned by get/add/update). */
export interface Secret {
  id: string;
  project_id: string;
  key: string;
  value: string;
  description: string | null;
  tags: string[];
  created_at: number;
  updated_at: number;
}

/** Secret without its value (list/search). */
export interface SecretMeta {
  id: string;
  project_id: string;
  key: string;
  description: string | null;
  tags: string[];
  created_at: number;
  updated_at: number;
}

export interface Tag {
  id: string;
  name: string;
}

export type ThemePref = "dark" | "light" | "system";

export type ImportMode = "skip" | "overwrite";

export interface ImportSummary {
  projects_created: number;
  projects_merged: number;
  secrets_imported: number;
  secrets_overwritten: number;
  secrets_skipped: number;
}

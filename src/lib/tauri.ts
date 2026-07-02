// Typed wrappers around Tauri `invoke()` calls. The rest of the app must go
// through these — no raw invoke() elsewhere.

import { invoke } from "@tauri-apps/api/core";
import type {
  ImportMode,
  ImportSummary,
  Project,
  Secret,
  SecretMeta,
  Tag,
} from "./types";

// ---- Vault ----
export const vaultExists = (vaultPath?: string) =>
  invoke<boolean>("vault_exists", { vaultPath });

export const vaultHasRecovery = (vaultPath?: string) =>
  invoke<boolean>("vault_has_recovery", { vaultPath });

/** Returns the one-time recovery codes; show them to the user immediately. */
export const createVault = (password: string, vaultPath?: string) =>
  invoke<string[]>("create_vault", { password, vaultPath });

export const unlockVault = (password: string, vaultPath?: string) =>
  invoke<boolean>("unlock_vault", { password, vaultPath });

export const recoverVault = (
  code: string,
  newPassword: string,
  vaultPath?: string,
) => invoke<void>("recover_vault", { code, newPassword, vaultPath });

export const regenerateRecoveryCodes = () =>
  invoke<string[]>("regenerate_recovery_codes");

export const deleteVault = (vaultPath?: string) =>
  invoke<void>("delete_vault", { vaultPath });

export const lockVault = () => invoke<void>("lock_vault");

export const vaultIsUnlocked = () => invoke<boolean>("vault_is_unlocked");

export const getVaultPath = () => invoke<string | null>("get_vault_path");

export const changeMasterPassword = (oldPassword: string, newPassword: string) =>
  invoke<void>("change_master_password", { oldPassword, newPassword });

export const biometricAvailable = () =>
  invoke<boolean>("biometric_available");

export const biometricEnrolled = (vaultPath?: string) =>
  invoke<boolean>("biometric_enrolled", { vaultPath });

export const biometricEnroll = () => invoke<void>("biometric_enroll");

export const biometricUnlock = (vaultPath?: string) =>
  invoke<boolean>("biometric_unlock", { vaultPath });

export const biometricDisable = (vaultPath?: string) =>
  invoke<void>("biometric_disable", { vaultPath });

export const migrationBackupExists = (vaultPath?: string) =>
  invoke<boolean>("migration_backup_exists", { vaultPath });

export const deleteMigrationBackup = (vaultPath?: string) =>
  invoke<void>("delete_migration_backup", { vaultPath });

// ---- Projects ----
export const createProject = (name: string, description?: string | null) =>
  invoke<Project>("create_project", { name, description: description ?? null });

export const listProjects = () => invoke<Project[]>("list_projects");

export const getProject = (id: string) => invoke<Project>("get_project", { id });

export const updateProject = (
  id: string,
  fields: { name?: string; description?: string | null },
) =>
  invoke<Project>("update_project", {
    id,
    name: fields.name ?? null,
    description: fields.description ?? null,
  });

export const deleteProject = (id: string) =>
  invoke<void>("delete_project", { id });

// ---- Secrets ----
export const addSecret = (input: {
  projectId: string;
  key: string;
  value: string;
  description?: string | null;
  tags?: string[];
}) =>
  invoke<Secret>("add_secret", {
    projectId: input.projectId,
    key: input.key,
    value: input.value,
    description: input.description ?? null,
    tags: input.tags ?? [],
  });

export const getSecret = (id: string) => invoke<Secret>("get_secret", { id });

export const listSecrets = (projectId: string) =>
  invoke<SecretMeta[]>("list_secrets", { projectId });

export const updateSecret = (
  id: string,
  fields: {
    key?: string;
    value?: string;
    description?: string | null;
    tags?: string[];
  },
) =>
  invoke<Secret>("update_secret", {
    id,
    key: fields.key ?? null,
    value: fields.value ?? null,
    description: fields.description ?? null,
    tags: fields.tags ?? null,
  });

export const deleteSecret = (id: string) =>
  invoke<void>("delete_secret", { id });

export const searchSecrets = (
  query: string,
  opts?: { projectId?: string; tags?: string[] },
) =>
  invoke<SecretMeta[]>("search_secrets", {
    query,
    projectId: opts?.projectId ?? null,
    tags: opts?.tags ?? null,
  });

export const listTags = () => invoke<Tag[]>("list_tags");

export const deleteTag = (id: string) => invoke<void>("delete_tag", { id });

// ---- Export / import ----
export const exportAll = (
  path: string,
  encrypted: boolean,
  passphrase?: string,
) => invoke<void>("export_all", { path, encrypted, passphrase: passphrase ?? null });

export const exportProject = (
  projectId: string,
  path: string,
  encrypted: boolean,
  passphrase?: string,
) =>
  invoke<void>("export_project", {
    projectId,
    path,
    encrypted,
    passphrase: passphrase ?? null,
  });

export const importIsEncrypted = (path: string) =>
  invoke<boolean>("import_is_encrypted", { path });

export const importFile = (
  path: string,
  mode: ImportMode,
  passphrase?: string,
) =>
  invoke<ImportSummary>("import_file", {
    path,
    mode,
    passphrase: passphrase ?? null,
  });

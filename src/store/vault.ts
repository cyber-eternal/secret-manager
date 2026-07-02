// Session + project state. Secret *values* are never stored here — only
// fetched on demand by the detail panel and cleared on unmount.

import { create } from "zustand";
import type { Project } from "../lib/types";
import * as api from "../lib/tauri";
import { useSettings } from "./settings";

interface VaultState {
  ready: boolean; // initial vault-existence check done
  hasVault: boolean;
  isUnlocked: boolean;
  /** One-time recovery codes to display right after vault creation/regeneration. */
  pendingRecoveryCodes: string[] | null;
  projects: Project[];
  activeProjectId: string | null;
  busy: boolean;
  error: string | null;

  init: () => Promise<void>;
  createVault: (password: string) => Promise<void>;
  unlock: (password: string) => Promise<void>;
  biometricUnlock: () => Promise<void>;
  recover: (code: string, newPassword: string) => Promise<void>;
  resetVault: () => Promise<void>;
  acknowledgeRecoveryCodes: () => void;
  lock: () => Promise<void>;
  refreshProjects: () => Promise<void>;
  setActiveProject: (id: string | null) => void;
  createProject: (name: string, description?: string) => Promise<Project>;
  updateProject: (
    id: string,
    fields: { name?: string; description?: string | null },
  ) => Promise<void>;
  deleteProject: (id: string) => Promise<void>;
}

function vaultPath(): string | undefined {
  return useSettings.getState().customVaultPath ?? undefined;
}

export const useVault = create<VaultState>((set, get) => ({
  ready: false,
  hasVault: false,
  isUnlocked: false,
  pendingRecoveryCodes: null,
  projects: [],
  activeProjectId: null,
  busy: false,
  error: null,

  init: async () => {
    const hasVault = await api.vaultExists(vaultPath());
    const isUnlocked = await api.vaultIsUnlocked();
    set({ ready: true, hasVault, isUnlocked });
    if (isUnlocked) await get().refreshProjects();
  },

  createVault: async (password) => {
    set({ busy: true, error: null });
    try {
      const codes = await api.createVault(password, vaultPath());
      set({ hasVault: true, isUnlocked: true, pendingRecoveryCodes: codes });
      await get().refreshProjects();
    } finally {
      set({ busy: false });
    }
  },

  unlock: async (password) => {
    set({ busy: true, error: null });
    try {
      await api.unlockVault(password, vaultPath());
      set({ isUnlocked: true });
      await get().refreshProjects();
    } finally {
      set({ busy: false });
    }
  },

  biometricUnlock: async () => {
    set({ busy: true, error: null });
    try {
      await api.biometricUnlock(vaultPath());
      set({ isUnlocked: true });
      await get().refreshProjects();
    } finally {
      set({ busy: false });
    }
  },

  recover: async (code, newPassword) => {
    set({ busy: true, error: null });
    try {
      await api.recoverVault(code, newPassword, vaultPath());
      set({ isUnlocked: true });
      await get().refreshProjects();
    } finally {
      set({ busy: false });
    }
  },

  resetVault: async () => {
    await api.deleteVault(vaultPath());
    set({
      hasVault: false,
      isUnlocked: false,
      pendingRecoveryCodes: null,
      projects: [],
      activeProjectId: null,
    });
  },

  acknowledgeRecoveryCodes: () => set({ pendingRecoveryCodes: null }),

  lock: async () => {
    await api.lockVault();
    set({ isUnlocked: false, projects: [], activeProjectId: null });
  },

  refreshProjects: async () => {
    const projects = await api.listProjects();
    const active = get().activeProjectId;
    const stillExists = active && projects.some((p) => p.id === active);
    set({
      projects,
      activeProjectId: stillExists ? active : projects[0]?.id ?? null,
    });
  },

  setActiveProject: (id) => set({ activeProjectId: id }),

  createProject: async (name, description) => {
    const project = await api.createProject(name, description ?? null);
    await get().refreshProjects();
    set({ activeProjectId: project.id });
    return project;
  },

  updateProject: async (id, fields) => {
    await api.updateProject(id, fields);
    await get().refreshProjects();
  },

  deleteProject: async (id) => {
    await api.deleteProject(id);
    const wasActive = get().activeProjectId === id;
    await get().refreshProjects();
    if (wasActive) {
      set({ activeProjectId: get().projects[0]?.id ?? null });
    }
  },
}));

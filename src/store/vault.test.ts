import { describe, it, expect, beforeEach, vi } from "vitest";
import type { Project } from "../lib/types";

// Mock the IPC layer so the store can be tested without a Tauri backend.
vi.mock("../lib/tauri", () => {
  let projects: Project[] = [];
  let nextId = 1;
  return {
    vaultExists: vi.fn(async () => true),
    vaultIsUnlocked: vi.fn(async () => false),
    createVault: vi.fn(async () => {}),
    unlockVault: vi.fn(async () => true),
    lockVault: vi.fn(async () => {}),
    listProjects: vi.fn(async () => [...projects]),
    createProject: vi.fn(async (name: string, description: string | null) => {
      const p: Project = {
        id: `p${nextId++}`,
        name,
        description,
        created_at: 0,
        updated_at: 0,
      };
      projects.push(p);
      return p;
    }),
    updateProject: vi.fn(async () => {}),
    deleteProject: vi.fn(async (id: string) => {
      projects = projects.filter((p) => p.id !== id);
    }),
    __reset: () => {
      projects = [];
      nextId = 1;
    },
  };
});

import { useVault } from "./vault";
import * as api from "../lib/tauri";

beforeEach(() => {
  (api as unknown as { __reset: () => void }).__reset();
  useVault.setState({
    ready: false,
    hasVault: false,
    isUnlocked: false,
    projects: [],
    activeProjectId: null,
    busy: false,
    error: null,
  });
  vi.clearAllMocks();
});

describe("vault store", () => {
  it("init records vault existence and unlock state", async () => {
    await useVault.getState().init();
    const s = useVault.getState();
    expect(s.ready).toBe(true);
    expect(s.hasVault).toBe(true);
    expect(s.isUnlocked).toBe(false);
  });

  it("unlock loads projects and sets active to the first", async () => {
    await useVault.getState().createProject("alpha");
    await useVault.getState().createProject("beta");
    // reset session, then unlock
    useVault.setState({ isUnlocked: false, projects: [], activeProjectId: null });

    await useVault.getState().unlock("pw");
    const s = useVault.getState();
    expect(s.isUnlocked).toBe(true);
    expect(s.projects.map((p) => p.name)).toEqual(["alpha", "beta"]);
    expect(s.activeProjectId).toBe(s.projects[0].id);
  });

  it("createProject makes it active", async () => {
    const p = await useVault.getState().createProject("gamma");
    expect(useVault.getState().activeProjectId).toBe(p.id);
  });

  it("deleteProject removes it and re-points active", async () => {
    const a = await useVault.getState().createProject("a");
    await useVault.getState().createProject("b");
    useVault.getState().setActiveProject(a.id);

    await useVault.getState().deleteProject(a.id);
    const s = useVault.getState();
    expect(s.projects.find((p) => p.id === a.id)).toBeUndefined();
    expect(s.activeProjectId).toBe(s.projects[0]?.id ?? null);
  });

  it("lock clears session state", async () => {
    await useVault.getState().createProject("x");
    useVault.setState({ isUnlocked: true });
    await useVault.getState().lock();
    const s = useVault.getState();
    expect(s.isUnlocked).toBe(false);
    expect(s.projects).toEqual([]);
    expect(s.activeProjectId).toBeNull();
  });
});

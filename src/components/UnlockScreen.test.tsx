import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("../lib/tauri", () => ({
  vaultExists: vi.fn(async () => false),
  vaultIsUnlocked: vi.fn(async () => false),
  createVault: vi.fn(async () => ["AAAAA-BBBBB"]),
  unlockVault: vi.fn(async () => true),
  recoverVault: vi.fn(async () => {}),
  deleteVault: vi.fn(async () => {}),
  lockVault: vi.fn(async () => {}),
  listProjects: vi.fn(async () => []),
  createProject: vi.fn(),
  updateProject: vi.fn(),
  deleteProject: vi.fn(),
  biometricAvailable: vi.fn(async () => false),
  biometricEnrolled: vi.fn(async () => false),
  biometricUnlock: vi.fn(async () => true),
  biometricDisable: vi.fn(async () => {}),
  biometricEnroll: vi.fn(async () => {}),
}));

import { UnlockScreen } from "./UnlockScreen";
import { useVault } from "../store/vault";
import * as api from "../lib/tauri";

beforeEach(() => {
  vi.clearAllMocks();
  useVault.setState({
    ready: true,
    hasVault: false,
    isUnlocked: false,
    projects: [],
    activeProjectId: null,
    busy: false,
    error: null,
  });
});

describe("UnlockScreen first-run", () => {
  it("shows the create-vault form and validates password length", async () => {
    const user = userEvent.setup();
    render(<UnlockScreen />);
    expect(screen.getByText("Create your vault")).toBeInTheDocument();

    const fields = screen.getAllByPlaceholderText("••••••••");
    await user.type(fields[0], "short");
    await user.type(fields[1], "short");
    await user.click(screen.getByRole("button", { name: /create vault/i }));

    expect(screen.getByRole("alert")).toHaveTextContent(/at least 8/i);
    expect(api.createVault).not.toHaveBeenCalled();
  });

  it("creates the vault when password is valid and matches", async () => {
    const user = userEvent.setup();
    render(<UnlockScreen />);
    const fields = screen.getAllByPlaceholderText("••••••••");
    await user.type(fields[0], "correct-horse-battery-staple-92xQ");
    await user.type(fields[1], "correct-horse-battery-staple-92xQ");
    await user.click(screen.getByRole("button", { name: /create vault/i }));

    await waitFor(() =>
      expect(api.createVault).toHaveBeenCalledWith(
        "correct-horse-battery-staple-92xQ",
        undefined,
      ),
    );
  });

  it("warns on a weak password, then creates it on a second click", async () => {
    const user = userEvent.setup();
    render(<UnlockScreen />);
    const fields = screen.getAllByPlaceholderText("••••••••");
    await user.type(fields[0], "supersecret");
    await user.type(fields[1], "supersecret");

    // First click: weak-password gate warns and does NOT create the vault.
    await user.click(screen.getByRole("button", { name: /create vault/i }));
    await waitFor(() =>
      expect(screen.getByRole("alert")).toHaveTextContent(/weak.*again/i),
    );
    expect(api.createVault).not.toHaveBeenCalled();

    // Second click: acknowledgement accepted, vault is created anyway.
    await user.click(screen.getByRole("button", { name: /create vault/i }));
    await waitFor(() =>
      expect(api.createVault).toHaveBeenCalledWith("supersecret", undefined),
    );
  });
});

describe("UnlockScreen unlock", () => {
  beforeEach(() => useVault.setState({ hasVault: true }));

  it("surfaces a backend error on wrong password", async () => {
    (api.unlockVault as unknown as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
      "Wrong master password",
    );
    const user = userEvent.setup();
    render(<UnlockScreen />);
    expect(screen.getByText("Unlock vault")).toBeInTheDocument();

    await user.type(screen.getByPlaceholderText("••••••••"), "nope");
    await user.click(screen.getByRole("button", { name: /^unlock$/i }));

    await waitFor(() =>
      expect(screen.getByRole("alert")).toHaveTextContent("Wrong master password"),
    );
  });

  it("toggles password visibility", async () => {
    const user = userEvent.setup();
    render(<UnlockScreen />);
    const field = screen.getByPlaceholderText("••••••••") as HTMLInputElement;
    expect(field.type).toBe("password");
    await user.click(screen.getByRole("button", { name: /show password/i }));
    expect(field.type).toBe("text");
  });

  it("recovers with a code and a new password", async () => {
    const user = userEvent.setup();
    render(<UnlockScreen />);
    await user.click(screen.getByRole("button", { name: /forgot your password/i }));
    expect(
      screen.getByRole("heading", { name: "Recover access" }),
    ).toBeInTheDocument();

    await user.type(
      screen.getByPlaceholderText(/XXXXX-/),
      "AAAAA-BBBBB",
    );
    const pwFields = screen.getAllByPlaceholderText("••••••••");
    await user.type(pwFields[0], "correct-horse-battery-staple-92xQ");
    await user.type(pwFields[1], "correct-horse-battery-staple-92xQ");
    await user.click(screen.getByRole("button", { name: /recover access/i }));

    await waitFor(() =>
      expect(api.recoverVault).toHaveBeenCalledWith(
        "AAAAA-BBBBB",
        "correct-horse-battery-staple-92xQ",
        undefined,
      ),
    );
  });
});
